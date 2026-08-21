use super::{
    AllocationState, allocate, allocate_with_state, extend_file_length_after_snapshot,
    should_extend_file_length,
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
    assert!(should_extend_file_length(0, 1));
    assert!(!should_extend_file_length(1, 1));
    assert!(!should_extend_file_length(1, 0));
    assert!(!should_extend_file_length(2, 1));
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
    assert!(allocate_with_state(&file, 1, Err(error)).is_err());
    assert!(
        allocate_with_state(
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
    extend_file_length_after_snapshot(&file, 1).unwrap();
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

    drop(file);
    let readonly = OpenOptions::new().read(true).open(path).unwrap();
    assert!(extend_file_length_after_snapshot(&readonly, 1).is_err());
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
