use std::fs::File;
use std::io::Result;

use crate::sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocationOutcome {
    AlreadyAllocated,
    PhysicallyReserved,
}

pub(crate) fn allocate(file: &File, len: u64) -> Result<()> {
    let _outcome = reserve(file, len)?;

    if file.metadata()?.len() < len {
        file.set_len(len)
    } else {
        Ok(())
    }
}

pub(crate) fn reserve(file: &File, len: u64) -> Result<AllocationOutcome> {
    if sys::allocated_size(file)? >= len {
        return Ok(AllocationOutcome::AlreadyAllocated);
    }

    sys::allocate_space(file, len)?;
    Ok(AllocationOutcome::PhysicallyReserved)
}

#[cfg(test)]
mod tests {
    use super::{AllocationOutcome, reserve};
    use std::fs::OpenOptions;
    use tempfile::tempdir;

    #[test]
    fn reports_already_allocated_for_zero_length() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        assert_eq!(
            reserve(&file, 0).unwrap(),
            AllocationOutcome::AlreadyAllocated
        );
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
    fn reports_physical_reservation_when_needed() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        assert_eq!(
            reserve(&file, 4096).unwrap(),
            AllocationOutcome::PhysicallyReserved
        );
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
    fn reports_unsupported_reservation_when_needed() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        assert_eq!(
            reserve(&file, 4096).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}
