use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use wait_timeout::ChildExt;

use crate::{Result, invalid_data};

mod containment;

use containment::ProcessContainment;

const DEFAULT_PROCESS_TIMEOUT: Duration = Duration::from_secs(3_600);
const MAX_PROCESS_TIMEOUT_SECONDS: u64 = 86_400;
const TERMINATION_REAP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
}

pub(crate) fn run(command: &mut Command, label: &str) -> Result<()> {
    println!("+ {label}");
    let execution = execute(command, process_timeout()?);
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
    let execution = execute(command, process_timeout()?);
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
    Terminated {
        detail: String,
    },
    TimedOut {
        timeout_ms: u128,
        reaped: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        kill_error: Option<String>,
    },
    SpawnFailed {
        error: String,
    },
    LogSetupFailed {
        error: String,
    },
    ContainmentFailed {
        error: String,
    },
    RunnerFailed {
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
            Self::Terminated { detail } => format!("process terminated: {detail}"),
            Self::TimedOut {
                timeout_ms,
                reaped,
                kill_error,
            } => kill_error.as_ref().map_or_else(
                || format!("process timed out after {timeout_ms} ms; reaped={reaped}"),
                |error| format!("process timed out after {timeout_ms} ms; kill failed: {error}"),
            ),
            Self::SpawnFailed { error } => format!("process spawn failed: {error}"),
            Self::LogSetupFailed { error } => format!("process log setup failed: {error}"),
            Self::ContainmentFailed { error } => {
                format!("process containment failed: {error}")
            }
            Self::RunnerFailed { error } => format!("process runner failed: {error}"),
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
    pub(crate) timeout_ms: Option<u128>,
    pub(crate) containment: &'static str,
    pub(crate) stdout: PathBuf,
    pub(crate) stderr: PathBuf,
}

#[derive(Clone)]
struct ProcessContext {
    command: Vec<String>,
    current_dir: Option<String>,
    environment_overrides: BTreeMap<String, Option<String>>,
}

#[derive(Clone, Copy)]
struct LogPaths<'a> {
    stdout: &'a Path,
    stderr: &'a Path,
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
        timeout_ms: Option<u128>,
        containment: &'static str,
        logs: LogPaths<'_>,
    ) -> ProcessRecord {
        ProcessRecord {
            label,
            command: self.command.clone(),
            current_dir: self.current_dir.clone(),
            environment_overrides: self.environment_overrides.clone(),
            outcome,
            duration_ms,
            timeout_ms,
            containment,
            stdout: logs.stdout.to_owned(),
            stderr: logs.stderr.to_owned(),
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

    pub(crate) fn may_still_be_running(&self) -> bool {
        matches!(self.outcome, ProcessOutcome::TimedOut { reaped: false, .. })
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
            process_timeout().ok().map(|timeout| timeout.as_millis()),
            ProcessContainment::METHOD,
            LogPaths {
                stdout: &stdout,
                stderr: &stderr,
            },
        )
    }
}

struct Execution {
    outcome: ProcessOutcome,
    status: Option<ExitStatus>,
    duration_ms: u128,
    timeout_ms: u128,
    containment: &'static str,
}

fn execute(command: &mut Command, timeout: Duration) -> Execution {
    let started = Instant::now();
    let mut containment = match ProcessContainment::configure(command) {
        Ok(containment) => containment,
        Err(error) => {
            return Execution {
                outcome: ProcessOutcome::ContainmentFailed {
                    error: error.to_string(),
                },
                status: None,
                duration_ms: started.elapsed().as_millis(),
                timeout_ms: timeout.as_millis(),
                containment: ProcessContainment::METHOD,
            };
        }
    };
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Execution {
                outcome: ProcessOutcome::SpawnFailed {
                    error: error.to_string(),
                },
                status: None,
                duration_ms: started.elapsed().as_millis(),
                timeout_ms: timeout.as_millis(),
                containment: ProcessContainment::METHOD,
            };
        }
    };
    if let Err(error) = containment.attach(&child) {
        let (status, cleanup_error) = terminate_and_reap(&containment, &mut child);
        let error = cleanup_error.map_or_else(
            || error.to_string(),
            |cleanup| format!("{error}; cleanup failed: {cleanup}"),
        );
        return Execution {
            outcome: ProcessOutcome::ContainmentFailed { error },
            status,
            duration_ms: started.elapsed().as_millis(),
            timeout_ms: timeout.as_millis(),
            containment: ProcessContainment::METHOD,
        };
    }
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => Execution {
            outcome: status_outcome(status),
            status: Some(status),
            duration_ms: started.elapsed().as_millis(),
            timeout_ms: timeout.as_millis(),
            containment: ProcessContainment::METHOD,
        },
        Ok(None) => {
            let (status, kill_error) = terminate_and_reap(&containment, &mut child);
            Execution {
                outcome: ProcessOutcome::TimedOut {
                    timeout_ms: timeout.as_millis(),
                    reaped: status.is_some(),
                    kill_error,
                },
                status,
                duration_ms: started.elapsed().as_millis(),
                timeout_ms: timeout.as_millis(),
                containment: ProcessContainment::METHOD,
            }
        }
        Err(error) => {
            let (status, cleanup_error) = terminate_and_reap(&containment, &mut child);
            let error = cleanup_error.map_or_else(
                || error.to_string(),
                |cleanup| format!("{error}; cleanup failed: {cleanup}"),
            );
            Execution {
                outcome: ProcessOutcome::RunnerFailed { error },
                status,
                duration_ms: started.elapsed().as_millis(),
                timeout_ms: timeout.as_millis(),
                containment: ProcessContainment::METHOD,
            }
        }
    }
}

fn terminate_and_reap(
    containment: &ProcessContainment,
    child: &mut std::process::Child,
) -> (Option<ExitStatus>, Option<String>) {
    let mut errors = Vec::new();
    if let Err(error) = containment.terminate(child) {
        errors.push(format!("containment termination failed: {error}"));
        if let Err(error) = child.kill() {
            errors.push(format!("direct child termination failed: {error}"));
        }
    }

    let status = match child.wait_timeout(TERMINATION_REAP_TIMEOUT) {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            if let Err(error) = child.kill() {
                errors.push(format!("direct child termination failed: {error}"));
            }
            match child.wait_timeout(TERMINATION_REAP_TIMEOUT) {
                Ok(Some(status)) => Some(status),
                Ok(None) => {
                    errors.push("process did not exit within the termination grace period".into());
                    None
                }
                Err(error) => {
                    errors.push(format!("unable to reap terminated process: {error}"));
                    None
                }
            }
        }
        Err(error) => {
            errors.push(format!("unable to reap terminated process: {error}"));
            None
        }
    };
    let error = (!errors.is_empty()).then(|| errors.join("; "));
    (status, error)
}

fn status_outcome(status: ExitStatus) -> ProcessOutcome {
    status.code().map_or_else(
        || ProcessOutcome::Terminated {
            detail: termination_detail(status),
        },
        |code| ProcessOutcome::Exited { code },
    )
}

#[cfg(unix)]
fn termination_detail(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt as _;

    status.signal().map_or_else(
        || "no exit code or signal was reported".to_owned(),
        |signal| {
            if status.core_dumped() {
                format!("signal {signal} (core dumped)")
            } else {
                format!("signal {signal}")
            }
        },
    )
}

#[cfg(not(unix))]
fn termination_detail(_status: ExitStatus) -> String {
    "no native exit code was reported".to_owned()
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
) -> ProcessRecord {
    let context = ProcessContext::capture(command);
    let label = label.into();
    let timeout = match process_timeout() {
        Ok(timeout) => timeout,
        Err(error) => {
            return context.record(
                label,
                ProcessOutcome::RunnerFailed {
                    error: error.to_string(),
                },
                0,
                None,
                ProcessContainment::METHOD,
                LogPaths {
                    stdout: stdout_path,
                    stderr: stderr_path,
                },
            );
        }
    };
    let timeout_ms = Some(timeout.as_millis());
    let failed = |outcome| {
        context.record(
            label.clone(),
            outcome,
            0,
            timeout_ms,
            ProcessContainment::METHOD,
            LogPaths {
                stdout: stdout_path,
                stderr: stderr_path,
            },
        )
    };
    for path in [stdout_path, stderr_path] {
        if let Some(parent) = path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            return failed(ProcessOutcome::LogSetupFailed {
                error: error.to_string(),
            });
        }
    }
    let stdout = match File::create(stdout_path) {
        Ok(stdout) => stdout,
        Err(error) => {
            return failed(ProcessOutcome::LogSetupFailed {
                error: error.to_string(),
            });
        }
    };
    let stderr = match File::create(stderr_path) {
        Ok(stderr) => stderr,
        Err(error) => {
            return failed(ProcessOutcome::LogSetupFailed {
                error: error.to_string(),
            });
        }
    };
    println!("+ {label}");
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let execution = execute(command, timeout);
    if let ProcessOutcome::SpawnFailed { error } = &execution.outcome {
        let _ = fs::write(stderr_path, format!("unable to start process: {error}\n"));
    }
    context.record(
        label,
        execution.outcome,
        execution.duration_ms,
        Some(execution.timeout_ms),
        execution.containment,
        LogPaths {
            stdout: stdout_path,
            stderr: stderr_path,
        },
    )
}

pub(crate) fn run_logged_attempt(
    command: &mut Command,
    label: impl Into<String>,
    stdout_path: &Path,
    stderr_path: &Path,
) -> ProcessRecord {
    run_logged(command, label, stdout_path, stderr_path)
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

    #[test]
    fn timed_out_processes_are_terminated_and_reaped() {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/C", "ping -n 30 127.0.0.1 >nul"]);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 30"]);
            command
        };

        let execution = execute(&mut command, Duration::from_millis(20));
        assert!(matches!(execution.outcome, ProcessOutcome::TimedOut { .. }));
        assert!(execution.status.is_some());
    }
}
