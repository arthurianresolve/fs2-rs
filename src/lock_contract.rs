use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

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

fn assert_contended(result: std::io::Result<()>) {
    assert_eq!(result.unwrap_err().kind(), lock_contended_error().kind());
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
    assert_contended(file3.fs2_try_lock_exclusive());
    file1.fs2_unlock().unwrap();
    assert_contended(file3.fs2_try_lock_exclusive());
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
    assert_contended(file2.fs2_try_lock_exclusive());
    assert_contended(file2.fs2_try_lock_shared());
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
    assert_contended(file2.fs2_try_lock_shared());
    drop(file1);
    file2.fs2_lock_shared().unwrap();
}

#[test]
fn blocking_acquisition_completes_after_release() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = open_file(&path);
    let file2 = open_file(&path);
    let (ready_tx, ready_rx) = mpsc::channel();

    file1.fs2_lock_exclusive().unwrap();
    let worker = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        file2.fs2_lock_shared().unwrap();
        file2.fs2_unlock().unwrap();
    });

    ready_rx.recv().unwrap();
    file1.fs2_unlock().unwrap();
    worker.join().unwrap();
}

#[test]
fn legacy_lock_methods_share_the_contract() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = open_file(&path);
    let file2 = open_file(&path);

    FileExt::lock_shared(&file1).unwrap();
    assert_contended(FileExt::try_lock_exclusive(&file2));
    FileExt::unlock(&file1).unwrap();
    FileExt::lock_exclusive(&file2).unwrap();
    FileExt::unlock(&file2).unwrap();
}
