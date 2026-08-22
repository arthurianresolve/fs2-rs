use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tempfile::NamedTempFile;

use crate::Result;

pub(crate) const SCHEMA_VERSION: u64 = 2;

#[derive(Serialize)]
pub(crate) struct ReportEnvelope<T> {
    schema_version: u64,
    status: &'static str,
    valid: bool,
    #[serde(flatten)]
    content: T,
}

impl<T> ReportEnvelope<T> {
    pub(crate) const fn new(status: &'static str, valid: bool, content: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            status,
            valid,
            content,
        }
    }
}

#[derive(Serialize)]
struct InvalidExecution<'a> {
    error: &'a str,
}

pub(crate) fn write_invalid(path: &Path, error: &str) -> Result<()> {
    write_json(
        path,
        &ReportEnvelope::new("invalid-execution", false, InvalidExecution { error }),
    )
}

pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("report path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_writes_are_atomic_and_never_replace_existing_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        write_json(&path, &serde_json::json!({ "run": 1 })).unwrap();
        assert!(write_json(&path, &serde_json::json!({ "run": 2 })).is_err());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap()).unwrap(),
            serde_json::json!({ "run": 1 })
        );
    }
}
