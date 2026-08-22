use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use serde::Serialize;

use crate::{Result, invalid_data};

pub(crate) fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
}

pub(crate) fn run(command: &mut Command, label: &str) -> Result<()> {
    println!("+ {label}");
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "{label} exited with {}",
            status
                .code()
                .map_or_else(|| "no exit code".to_owned(), |code| code.to_string())
        )))
    }
}

pub(crate) fn capture(command: &mut Command, label: &str) -> Result<Output> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        let detail = String::from_utf8_lossy(if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        });
        Err(invalid_data(format!("{label} failed: {}", detail.trim())))
    }
}

pub(crate) fn toolchain_key() -> Result<String> {
    let identity = if let Some(toolchain) = std::env::var_os("RUSTUP_TOOLCHAIN") {
        toolchain.to_string_lossy().into_owned()
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
    Exited { code: i32 },
    Terminated,
    SpawnFailed { error: String },
    LogSetupFailed { error: String },
    Skipped { reason: String },
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProcessRecord {
    pub(crate) label: String,
    pub(crate) command: Vec<String>,
    pub(crate) current_dir: Option<PathBuf>,
    pub(crate) environment_overrides: BTreeMap<String, Option<String>>,
    pub(crate) outcome: ProcessOutcome,
    pub(crate) duration_ms: u128,
    pub(crate) stdout: PathBuf,
    pub(crate) stderr: PathBuf,
}

impl ProcessRecord {
    pub(crate) fn succeeded(&self) -> bool {
        matches!(&self.outcome, ProcessOutcome::Exited { code: 0 })
    }

    pub(crate) fn failure_description(&self) -> String {
        match &self.outcome {
            ProcessOutcome::Exited { code } => format!("native exit {code}"),
            ProcessOutcome::Terminated => "process terminated without an exit code".to_owned(),
            ProcessOutcome::SpawnFailed { error } => format!("process spawn failed: {error}"),
            ProcessOutcome::LogSetupFailed { error } => {
                format!("process log setup failed: {error}")
            }
            ProcessOutcome::Skipped { reason } => format!("process skipped: {reason}"),
        }
    }

    pub(crate) fn skipped(
        label: impl Into<String>,
        stdout: PathBuf,
        stderr: PathBuf,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            command: Vec::new(),
            current_dir: std::env::current_dir().ok(),
            environment_overrides: BTreeMap::new(),
            outcome: ProcessOutcome::Skipped {
                reason: reason.into(),
            },
            duration_ms: 0,
            stdout,
            stderr,
        }
    }
}

pub(crate) fn run_logged(
    command: &mut Command,
    label: impl Into<String>,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ProcessRecord> {
    let rendered = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let current_dir = command
        .get_current_dir()
        .map(Path::to_owned)
        .or_else(|| std::env::current_dir().ok());
    let environment_overrides = command
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let label = label.into();
    let failed = |outcome| ProcessRecord {
        label: label.clone(),
        command: rendered.clone(),
        current_dir: current_dir.clone(),
        environment_overrides: environment_overrides.clone(),
        outcome,
        duration_ms: 0,
        stdout: stdout_path.to_owned(),
        stderr: stderr_path.to_owned(),
    };
    if let Some(parent) = stdout_path.parent()
        && let Err(error) = fs::create_dir_all(parent)
    {
        return Ok(failed(ProcessOutcome::LogSetupFailed {
            error: error.to_string(),
        }));
    }
    if let Some(parent) = stderr_path.parent()
        && let Err(error) = fs::create_dir_all(parent)
    {
        return Ok(failed(ProcessOutcome::LogSetupFailed {
            error: error.to_string(),
        }));
    }
    println!("+ {label}");
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
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let started = Instant::now();
    match command.status() {
        Ok(status) => Ok(ProcessRecord {
            label,
            command: rendered,
            current_dir,
            environment_overrides,
            outcome: status.code().map_or(ProcessOutcome::Terminated, |code| {
                ProcessOutcome::Exited { code }
            }),
            duration_ms: started.elapsed().as_millis(),
            stdout: stdout_path.to_owned(),
            stderr: stderr_path.to_owned(),
        }),
        Err(error) => {
            let _ = fs::write(stderr_path, format!("unable to start process: {error}\n"));
            Ok(ProcessRecord {
                label,
                command: rendered,
                current_dir,
                environment_overrides,
                outcome: ProcessOutcome::SpawnFailed {
                    error: error.to_string(),
                },
                duration_ms: started.elapsed().as_millis(),
                stdout: stdout_path.to_owned(),
                stderr: stderr_path.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_processes_are_not_native_exits() {
        let process = ProcessRecord::skipped(
            "build",
            PathBuf::from("stdout"),
            PathBuf::from("stderr"),
            "setup failed",
        );
        assert!(!process.succeeded());
        assert!(matches!(process.outcome, ProcessOutcome::Skipped { .. }));
    }
}
