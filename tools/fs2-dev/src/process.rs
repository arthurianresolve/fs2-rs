use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use wait_timeout::ChildExt;

use crate::{Result, invalid_data};

const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(3_600);
const MAX_PROCESS_TIMEOUT_SECONDS: u64 = 86_400;

pub(crate) fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
}

pub(crate) fn run(command: &mut Command, label: &str) -> Result<()> {
    println!("+ {label}");
    let execution = execute(command)?;
    if execution.outcome.succeeded() {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "{label} failed: {}",
            execution.outcome.description()
        )))
    }
}

pub(crate) fn capture(command: &mut Command, label: &str) -> Result<Output> {
    let temporary = tempfile::tempdir()?;
    let stdout_path = temporary.path().join("stdout");
    let stderr_path = temporary.path().join("stderr");
    command
        .stdout(Stdio::from(File::create(&stdout_path)?))
        .stderr(Stdio::from(File::create(&stderr_path)?));
    let execution = execute(command)?;
    let stdout = fs::read(&stdout_path)?;
    let stderr = fs::read(&stderr_path)?;
    if execution.outcome.succeeded() {
        Ok(Output {
            status: execution
                .status
                .ok_or_else(|| invalid_data("successful process has no exit status"))?,
            stdout,
            stderr,
        })
    } else {
        Err(invalid_data(format!(
            "{label} failed: {}\nstdout:\n{}\nstderr:\n{}",
            execution.outcome.description(),
            String::from_utf8_lossy(&stdout).trim(),
            String::from_utf8_lossy(&stderr).trim()
        )))
    }
}

pub(crate) fn toolchain_key() -> Result<String> {
    let identity = if let Some(toolchain) = std::env::var_os("RUSTUP_TOOLCHAIN") {
        display_os(&toolchain)
    } else {
        let output = capture(Command::new("rustc").arg("-vV"), "rustc -vV")?;
        String::from_utf8(output.stdout)?
    };
    Ok(identity
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect())
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum ProcessOutcome {
    Exited {
        code: i32,
    },
    Terminated,
    TimedOut {
        timeout_ms: u128,
        #[serde(skip_serializing_if = "Option::is_none")]
        kill_error: Option<String>,
    },
    SpawnFailed {
        error: String,
    },
    LogSetupFailed {
        error: String,
    },
    Skipped {
        reason: String,
    },
}

impl ProcessOutcome {
    fn succeeded(&self) -> bool {
        matches!(self, Self::Exited { code: 0 })
    }

    fn description(&self) -> String {
        match self {
            Self::Exited { code } => format!("native exit {code}"),
            Self::Terminated => "process terminated without an exit code".to_owned(),
            Self::TimedOut {
                timeout_ms,
                kill_error,
            } => kill_error.as_ref().map_or_else(
                || format!("process timed out after {timeout_ms} ms"),
                |error| format!("process timed out after {timeout_ms} ms; kill failed: {error}"),
            ),
            Self::SpawnFailed { error } => format!("process spawn failed: {error}"),
            Self::LogSetupFailed { error } => format!("process log setup failed: {error}"),
            Self::Skipped { reason } => format!("process skipped: {reason}"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProcessRecord {
    pub(crate) label: String,
    pub(crate) command: Vec<String>,
    pub(crate) current_dir: Option<String>,
    pub(crate) environment_overrides: BTreeMap<String, Option<String>>,
    pub(crate) outcome: ProcessOutcome,
    pub(crate) duration_ms: u128,
    pub(crate) stdout: PathBuf,
    pub(crate) stderr: PathBuf,
}

#[derive(Clone)]
struct ProcessContext {
    command: Vec<String>,
    current_dir: Option<String>,
    environment_overrides: BTreeMap<String, Option<String>>,
}

impl ProcessContext {
    fn capture(command: &Command) -> Self {
        Self {
            command: std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(display_os)
                .collect(),
            current_dir: command
                .get_current_dir()
                .map(|path| display_os(path.as_os_str()))
                .or_else(|| {
                    std::env::current_dir()
                        .ok()
                        .map(|path| display_os(path.as_os_str()))
                }),
            environment_overrides: command
                .get_envs()
                .map(|(name, value)| (display_os(name), value.map(display_os)))
                .collect(),
        }
    }

    fn record(
        &self,
        label: String,
        outcome: ProcessOutcome,
        duration_ms: u128,
        stdout: &Path,
        stderr: &Path,
    ) -> ProcessRecord {
        ProcessRecord {
            label,
            command: self.command.clone(),
            current_dir: self.current_dir.clone(),
            environment_overrides: self.environment_overrides.clone(),
            outcome,
            duration_ms,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }
    }
}

impl ProcessRecord {
    pub(crate) fn succeeded(&self) -> bool {
        self.outcome.succeeded()
    }

    pub(crate) fn failure_description(&self) -> String {
        self.outcome.description()
    }

    pub(crate) fn skipped(
        command: &Command,
        label: impl Into<String>,
        stdout: PathBuf,
        stderr: PathBuf,
        reason: impl Into<String>,
    ) -> Self {
        ProcessContext::capture(command).record(
            label.into(),
            ProcessOutcome::Skipped {
                reason: reason.into(),
            },
            0,
            &stdout,
            &stderr,
        )
    }
}

struct Execution {
    outcome: ProcessOutcome,
    status: Option<ExitStatus>,
    duration_ms: u128,
}

fn execute(command: &mut Command) -> Result<Execution> {
    let timeout = process_timeout()?;
    let started = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Ok(Execution {
                outcome: ProcessOutcome::SpawnFailed {
                    error: error.to_string(),
                },
                status: None,
                duration_ms: started.elapsed().as_millis(),
            });
        }
    };
    match child.wait_timeout(timeout)? {
        Some(status) => Ok(Execution {
            outcome: status.code().map_or(ProcessOutcome::Terminated, |code| {
                ProcessOutcome::Exited { code }
            }),
            status: Some(status),
            duration_ms: started.elapsed().as_millis(),
        }),
        None => {
            let kill_error = child.kill().err().map(|error| error.to_string());
            let status = child.wait().ok();
            Ok(Execution {
                outcome: ProcessOutcome::TimedOut {
                    timeout_ms: timeout.as_millis(),
                    kill_error,
                },
                status,
                duration_ms: started.elapsed().as_millis(),
            })
        }
    }
}

fn process_timeout() -> Result<Duration> {
    let Some(value) = std::env::var_os("FS2_DEV_PROCESS_TIMEOUT_SECONDS") else {
        return Ok(DEFAULT_PROCESS_TIMEOUT);
    };
    let value = display_os(&value);
    let seconds = value
        .parse::<u64>()
        .map_err(|_| invalid_data("FS2_DEV_PROCESS_TIMEOUT_SECONDS must be an integer"))?;
    if !(1..=MAX_PROCESS_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(invalid_data(
            "FS2_DEV_PROCESS_TIMEOUT_SECONDS is outside the supported range",
        ));
    }
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn run_logged(
    command: &mut Command,
    label: impl Into<String>,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ProcessRecord> {
    let context = ProcessContext::capture(command);
    let label = label.into();
    let failed = |outcome| context.record(label.clone(), outcome, 0, stdout_path, stderr_path);
    for path in [stdout_path, stderr_path] {
        if let Some(parent) = path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            return Ok(failed(ProcessOutcome::LogSetupFailed {
                error: error.to_string(),
            }));
        }
    }
    let stdout = match File::create(stdout_path) {
        Ok(stdout) => stdout,
        Err(error) => {
            return Ok(failed(ProcessOutcome::LogSetupFailed {
                error: error.to_string(),
            }));
        }
    };
    let stderr = match File::create(stderr_path) {
        Ok(stderr) => stderr,
        Err(error) => {
            return Ok(failed(ProcessOutcome::LogSetupFailed {
                error: error.to_string(),
            }));
        }
    };
    println!("+ {label}");
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let execution = execute(command)?;
    if let ProcessOutcome::SpawnFailed { error } = &execution.outcome {
        let _ = fs::write(stderr_path, format!("unable to start process: {error}\n"));
    }
    Ok(context.record(
        label,
        execution.outcome,
        execution.duration_ms,
        stdout_path,
        stderr_path,
    ))
}

pub(crate) fn display_os(value: &OsStr) -> String {
    if let Some(value) = value.to_str() {
        return value.to_owned();
    }
    #[cfg(unix)]
    {
        use std::fmt::Write as _;
        use std::os::unix::ffi::OsStrExt;
        let mut encoded = String::from("unix-bytes:");
        for byte in value.as_bytes() {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
    #[cfg(windows)]
    {
        use std::fmt::Write as _;
        use std::os::windows::ffi::OsStrExt;
        let mut encoded = String::from("windows-utf16:");
        for unit in value.encode_wide() {
            let _ = write!(encoded, "{unit:04x}");
        }
        encoded
    }
    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_processes_are_not_native_exits() {
        let mut command = Command::new("cargo");
        command
            .current_dir("repository")
            .arg("build")
            .env("RUSTFLAGS", "-Ctarget-cpu=native");
        let process = ProcessRecord::skipped(
            &command,
            "build",
            PathBuf::from("stdout"),
            PathBuf::from("stderr"),
            "setup failed",
        );
        assert!(!process.succeeded());
        assert_eq!(
            process.command,
            vec!["cargo".to_owned(), "build".to_owned()]
        );
        assert_eq!(process.current_dir.as_deref(), Some("repository"));
        assert_eq!(
            process.environment_overrides["RUSTFLAGS"],
            Some("-Ctarget-cpu=native".to_owned())
        );
        let serialized = serde_json::to_value(&process).unwrap();
        assert_eq!(serialized["outcome"]["kind"], "skipped");
        assert!(serialized.get("exit_code").is_none());
        assert!(matches!(&process.outcome, ProcessOutcome::Skipped { .. }));
    }
}
