use std::fs::File;
use std::io::Result;

use crate::sys;

#[derive(Clone, Copy)]
pub(crate) struct AllocationState {
    pub(crate) allocated_size: u64,
    pub(crate) file_size: u64,
}

pub(crate) fn allocate(file: &File, len: u64) -> Result<()> {
    let state = sys::allocation_state(file)?;
    if state.allocated_size < len {
        sys::allocate_space(file, len)?;
    }

    if state.file_size < len && file.metadata()?.len() < len {
        file.set_len(len)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::allocate;
    use std::fs::OpenOptions;
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
