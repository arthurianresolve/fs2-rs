use std::fs::File;
use std::io::Result;

use crate::sys;

#[derive(Clone, Copy)]
pub(crate) struct AllocationState {
    pub(crate) allocated_size: u64,
    pub(crate) file_size: u64,
}

#[inline(always)]
pub(crate) fn allocated_size(file: &File) -> Result<u64> {
    sys::allocation_state(file).map(|state| state.allocated_size)
}

pub(crate) fn allocate(file: &File, len: u64) -> Result<()> {
    allocate_after_state(file, len, sys::allocation_state(file))
}

#[inline(always)]
fn allocate_after_state(file: &File, len: u64, state: Result<AllocationState>) -> Result<()> {
    let state = state?;
    if state.allocated_size < len {
        sys::allocate_space(file, len)?;
        return allocation_completion(
            file,
            state.file_size,
            len,
            sys::ALLOCATE_SPACE_EXTENDS_LENGTH,
        );
    }

    extend_file_length(file, state.file_size, len)
}

#[inline(always)]
fn allocation_completion(
    file: &File,
    file_size: u64,
    len: u64,
    allocation_extends_length: bool,
) -> Result<()> {
    if allocation_extends_length {
        return Ok(());
    }

    extend_file_length(file, file_size, len)
}

#[inline(always)]
fn extend_file_length(file: &File, file_size: u64, len: u64) -> Result<()> {
    if file_size < len {
        return extend_file_length_after_snapshot(
            file,
            file_size,
            len,
            file.metadata().map(|metadata| metadata.len()),
        );
    }
    Ok(())
}

#[inline(always)]
fn extend_file_length_after_snapshot(
    file: &File,
    file_size: u64,
    len: u64,
    current_file_size: Result<u64>,
) -> Result<()> {
    let current_file_size = current_file_size?;
    if should_extend_file_length(file_size, current_file_size, len) {
        file.set_len(len)?;
    }
    Ok(())
}

const fn should_extend_file_length(file_size: u64, current_file_size: u64, len: u64) -> bool {
    file_size < len && current_file_size < len
}

#[cfg(test)]
mod tests {
    use super::{
        AllocationState, allocate, allocate_after_state, allocation_completion, extend_file_length,
        extend_file_length_after_snapshot, should_extend_file_length,
    };
    use std::fs::OpenOptions;
    use std::io::Error;
    use tempfile::tempdir;

    #[test]
    fn accepts_already_allocated_zero_length() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        allocate(&file, 0).unwrap();
    }

    #[test]
    fn evaluates_file_length_extension_decision() {
        assert!(should_extend_file_length(0, 0, 1));
        assert!(!should_extend_file_length(1, 0, 1));
        assert!(!should_extend_file_length(0, 1, 1));
        assert!(!should_extend_file_length(1, 1, 1));
    }

    #[test]
    fn covers_platform_allocation_completion_variants() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        allocation_completion(&file, 0, 1, true).unwrap();
        allocation_completion(&file, 0, 1, false).unwrap();
    }

    #[test]
    fn propagates_allocation_state_errors() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        let error = Error::other("allocation state failed");
        assert!(allocate_after_state(&file, 1, Err(error)).is_err());
        assert!(
            allocate_after_state(
                &file,
                0,
                Ok(AllocationState {
                    allocated_size: 0,
                    file_size: 0,
                }),
            )
            .is_ok()
        );
    }

    #[test]
    fn preserves_a_file_that_grew_between_allocation_snapshots() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        file.set_len(1).unwrap();
        extend_file_length(&file, 0, 1).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 1);
    }

    #[test]
    fn propagates_file_length_snapshot_and_update_errors() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        let error = Error::other("file length snapshot failed");
        assert!(extend_file_length_after_snapshot(&file, 0, 1, Err(error)).is_err());

        drop(file);
        let readonly = OpenOptions::new().read(true).open(path).unwrap();
        assert!(extend_file_length_after_snapshot(&readonly, 0, 1, Ok(0)).is_err());
    }

    #[cfg(any(
        target_os = "windows",
        target_os = "freebsd",
        target_os = "android",
        target_os = "emscripten",
        target_os = "macos",
        target_os = "ios",
        all(target_os = "linux", not(target_env = "uclibc")),
    ))]
    #[test]
    fn allocates_physical_space_when_needed() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        allocate(&file, 4096).unwrap();
        assert!(file.metadata().unwrap().len() >= 4096);
    }

    #[cfg(any(
        all(target_os = "linux", target_env = "uclibc"),
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "redox",
        target_os = "haiku",
    ))]
    #[test]
    fn rejects_unsupported_reservation_when_needed() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        assert_eq!(
            allocate(&file, 4096).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}
