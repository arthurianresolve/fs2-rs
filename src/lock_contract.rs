use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::{FileExt, lock_contended_error};
use tempfile::tempdir;

fn open_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap()
}

#[test]
fn shared_locks_are_compatible_but_exclusive_locks_are_not() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = open_file(&path);
    let file2 = open_file(&path);
    let file3 = open_file(&path);

    file1.fs2_lock_shared().unwrap();
    file2.fs2_lock_shared().unwrap();
    assert_eq!(
        file3.fs2_try_lock_exclusive().unwrap_err().kind(),
        lock_contended_error().kind()
    );
    file1.fs2_unlock().unwrap();
    assert_eq!(
        file3.fs2_try_lock_exclusive().unwrap_err().kind(),
        lock_contended_error().kind()
    );
    file2.fs2_unlock().unwrap();
    file3.fs2_lock_exclusive().unwrap();
}

#[test]
fn exclusive_locks_block_shared_and_exclusive_locks() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = open_file(&path);
    let file2 = open_file(&path);

    file1.fs2_lock_exclusive().unwrap();
    assert_eq!(
        file2.fs2_try_lock_exclusive().unwrap_err().kind(),
        lock_contended_error().kind()
    );
    assert_eq!(
        file2.fs2_try_lock_shared().unwrap_err().kind(),
        lock_contended_error().kind()
    );
    file1.fs2_unlock().unwrap();
    file2.fs2_lock_exclusive().unwrap();
}

#[test]
fn dropping_a_lock_owner_releases_the_lock() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = open_file(&path);
    let file2 = open_file(&path);

    file1.fs2_lock_exclusive().unwrap();
    assert_eq!(
        file2.fs2_try_lock_shared().unwrap_err().kind(),
        lock_contended_error().kind()
    );
    drop(file1);
    file2.fs2_lock_shared().unwrap();
}
