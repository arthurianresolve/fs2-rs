use std::fs;

use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

use crate::{FileExt, lock_contended_error};
use tempfile::tempdir;
#[test]
fn duplicate_new_handle() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();
    let file2 = file1.duplicate().unwrap();
    assert!(file1.as_raw_handle() != file2.as_raw_handle());
}

#[test]
fn duplicate_preserves_legacy_handle_inheritance() {
    let tempdir = tempdir().unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(tempdir.path().join("fs2"))
        .unwrap();
    let duplicate = file.duplicate().unwrap();
    let mut flags = 0;
    let result = unsafe {
        // SAFETY: `duplicate` owns a valid handle and `flags` is writable output storage.
        GetHandleInformation(duplicate.as_raw_handle(), &mut flags)
    };

    assert_ne!(result, 0, "{}", std::io::Error::last_os_error());
    assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
}

#[test]
fn try_clone_is_not_inheritable() {
    let tempdir = tempdir().unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(tempdir.path().join("fs2"))
        .unwrap()
        .try_clone()
        .unwrap();
    let mut flags = 0;
    let result = unsafe {
        // SAFETY: `file` owns a valid handle and `flags` is writable output storage.
        GetHandleInformation(file.as_raw_handle(), &mut flags)
    };

    assert_ne!(result, 0, "{}", std::io::Error::last_os_error());
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
}

/// A duplicated file handle does not have access to the original handle's locks.
#[test]
fn lock_duplicate_handle_independence() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();
    let file2 = file1.duplicate().unwrap();

    // Locking the original file handle will block the duplicate file handle from opening a lock.
    file1.fs2_lock_shared().unwrap();
    assert_eq!(
        file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );

    // Once the original file handle is unlocked, the duplicate handle can proceed with a lock.
    file1.fs2_unlock().unwrap();
    file2.fs2_lock_exclusive().unwrap();
}

/// A file handle may not be exclusively locked multiple times, or exclusively locked and then
/// shared locked.
#[test]
fn lock_non_reentrant() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();

    // Multiple exclusive locks fails.
    file.fs2_lock_exclusive().unwrap();
    assert_eq!(
        file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );
    file.fs2_unlock().unwrap();

    // Shared then Exclusive locks fails.
    file.fs2_lock_shared().unwrap();
    assert_eq!(
        file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );
}

/// A file handle can hold an exclusive lock and any number of shared locks, all of which must
/// be unlocked independently.
#[test]
fn lock_layering() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();

    // Open two shared locks on the file, and then try and fail to open an exclusive lock.
    file.fs2_lock_exclusive().unwrap();
    file.fs2_lock_shared().unwrap();
    file.fs2_lock_shared().unwrap();
    assert_eq!(
        file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );

    // Pop one of the shared locks and try again.
    file.fs2_unlock().unwrap();
    assert_eq!(
        file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );

    // Pop the second shared lock and try again.
    file.fs2_unlock().unwrap();
    assert_eq!(
        file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );

    // Pop the exclusive lock and finally succeed.
    file.fs2_unlock().unwrap();
    file.fs2_lock_exclusive().unwrap();
}

/// A file handle with multiple open locks will have all locks closed on drop.
#[test]
fn lock_layering_cleanup() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();
    let file2 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();

    // Open two shared locks on the file, and then try and fail to open an exclusive lock.
    file1.fs2_lock_shared().unwrap();
    assert_eq!(
        file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );

    drop(file1);
    file2.fs2_lock_exclusive().unwrap();
}

/// A file handle's locks will not be released until the original handle and all of its
/// duplicates have been closed. This on really smells like a bug in Windows.
#[test]
fn lock_duplicate_cleanup() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    let file1 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap();
    let file2 = file1.duplicate().unwrap();

    // Open a lock on the original handle, then close it.
    file1.fs2_lock_shared().unwrap();
    drop(file1);

    // Attempting to create a lock on the file with the duplicate handle will fail.
    assert_eq!(
        file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
        lock_contended_error().raw_os_error()
    );
}
