//! Extended utilities for working with files and filesystems in Rust.

#![doc(html_root_url = "https://docs.rs/fs2/0.5.0")]

mod allocation;
mod platform;
mod stats;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::PlatformAdapter;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::PlatformAdapter;

mod lock;

use std::fs::File;
use std::io::{Error, Result};
use std::path::Path;

pub use stats::FsStats;

/// Extension trait for `std::fs::File` which provides allocation, duplication and locking methods.
///
/// On Rust 1.97 and later, `std::fs::File` also has inherent locking methods
/// whose names overlap this trait. Inherent methods take precedence over
/// extension traits, so use the explicit `fs2_*` methods when calling the
/// `fs2` implementation: `file.fs2_lock_shared()`,
/// `file.fs2_try_lock_shared()`, and `file.fs2_unlock()`.
///
/// ## Notes on File Locks
///
/// This library provides whole-file locks in both shared (read) and exclusive
/// (read-write) varieties.
///
/// File locks are a cross-platform hazard since the file lock APIs exposed by
/// operating system kernels vary in subtle and not-so-subtle ways.
///
/// The API exposed by this library can be safely used across platforms as long
/// as the following rules are followed:
///
///   * Multiple locks should not be created on an individual `File` instance
///     concurrently.
///   * Duplicated files should not be locked without great care.
///   * Files to be locked should be opened with at least read or write
///     permissions.
///   * File locks may only be relied upon to be advisory.
///
/// See the tests in `lib.rs` for cross-platform lock behavior that may be
/// relied upon; see the tests in `unix.rs` and `windows.rs` for examples of
/// platform-specific behavior. File locks are implemented with
/// [`flock(2)`](http://man7.org/linux/man-pages/man2/flock.2.html) on Unix and
/// [`LockFile`](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365202(v=vs.85).aspx)
/// on Windows.
pub trait FileExt {
    /// Returns a duplicate instance of the file.
    ///
    /// The returned file will share the same file position as the original
    /// file.
    ///
    /// If using rustc version 1.9 or later, prefer using `File::try_clone` to this.
    ///
    /// # Notes
    ///
    /// This is implemented with
    /// [`dup(2)`](http://man7.org/linux/man-pages/man2/dup.2.html) on Unix and
    /// [`DuplicateHandle`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724251(v=vs.85).aspx)
    /// on Windows.
    fn duplicate(&self) -> Result<File>;

    /// Returns the amount of physical space allocated for a file.
    fn allocated_size(&self) -> Result<u64>;

    /// Ensures that at least `len` bytes of disk space are allocated for the
    /// file, and the file size is at least `len` bytes. After a successful call
    /// to `allocate`, subsequent writes to the file within the specified length
    /// are guaranteed not to fail because of lack of disk space.
    fn allocate(&self, len: u64) -> Result<()>;

    /// Locks the file for shared usage, blocking if the file is currently
    /// locked exclusively.
    fn fs2_lock_shared(&self) -> Result<()> {
        FileExt::lock_shared(self)
    }

    /// Locks the file for exclusive usage, blocking if the file is currently
    /// locked.
    fn fs2_lock_exclusive(&self) -> Result<()> {
        FileExt::lock_exclusive(self)
    }

    /// Locks the file for shared usage, or returns an error if the file is
    /// currently locked (see `lock_contended_error`).
    fn fs2_try_lock_shared(&self) -> Result<()> {
        FileExt::try_lock_shared(self)
    }

    /// Locks the file for exclusive usage, or returns an error if the file is
    /// currently locked (see `lock_contended_error`).
    fn fs2_try_lock_exclusive(&self) -> Result<()> {
        FileExt::try_lock_exclusive(self)
    }

    /// Unlocks the file.
    fn fs2_unlock(&self) -> Result<()> {
        FileExt::unlock(self)
    }

    /// Legacy shared-lock method. Prefer [`FileExt::fs2_lock_shared`] on Rust
    /// 1.97 and later.
    fn lock_shared(&self) -> Result<()>;

    /// Legacy exclusive-lock method. Prefer [`FileExt::fs2_lock_exclusive`].
    fn lock_exclusive(&self) -> Result<()>;

    /// Legacy non-blocking shared-lock method. Prefer
    /// [`FileExt::fs2_try_lock_shared`] on Rust 1.97 and later.
    fn try_lock_shared(&self) -> Result<()>;

    /// Legacy non-blocking exclusive-lock method. Prefer
    /// [`FileExt::fs2_try_lock_exclusive`].
    fn try_lock_exclusive(&self) -> Result<()>;

    /// Legacy unlock method. Prefer [`FileExt::fs2_unlock`] on Rust 1.97 and
    /// later.
    fn unlock(&self) -> Result<()>;
}

impl FileExt for File {
    fn duplicate(&self) -> Result<File> {
        <PlatformAdapter as platform::Platform>::duplicate(self)
    }
    fn allocated_size(&self) -> Result<u64> {
        <PlatformAdapter as platform::Platform>::allocated_size(self)
    }
    fn allocate(&self, len: u64) -> Result<()> {
        allocation::allocate::<PlatformAdapter>(self, len)
    }
    fn lock_shared(&self) -> Result<()> {
        lock::lock_shared::<PlatformAdapter>(self)
    }
    fn lock_exclusive(&self) -> Result<()> {
        lock::lock_exclusive::<PlatformAdapter>(self)
    }
    fn try_lock_shared(&self) -> Result<()> {
        lock::try_lock_shared::<PlatformAdapter>(self)
    }
    fn try_lock_exclusive(&self) -> Result<()> {
        lock::try_lock_exclusive::<PlatformAdapter>(self)
    }
    fn unlock(&self) -> Result<()> {
        lock::unlock::<PlatformAdapter>(self)
    }
}

/// Returns the error that a call to a try lock method on a contended file will
/// return.
pub fn lock_contended_error() -> Error {
    lock::contended_error::<PlatformAdapter>()
}

/// Get the stats of the file system containing the provided path.
pub fn statvfs<P>(path: P) -> Result<FsStats>
where
    P: AsRef<Path>,
{
    <PlatformAdapter as platform::Platform>::statvfs(path.as_ref())
}

/// Returns the number of free bytes in the file system containing the provided
/// path.
pub fn free_space<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.free_space())
}

/// Returns the available space in bytes to non-priveleged users in the file
/// system containing the provided path.
pub fn available_space<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.available_space())
}

/// Returns the total space in bytes in the file system containing the provided
/// path.
pub fn total_space<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.total_space())
}

/// Returns the filesystem's disk space allocation granularity in bytes.
/// The provided path may be for any file in the filesystem.
///
/// On Posix, this is equivalent to the filesystem's block size.
/// On Windows, this is equivalent to the filesystem's cluster size.
pub fn allocation_granularity<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.allocation_granularity())
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};

    use tempfile::tempdir;

    use super::*;

    /// Tests file duplication.
    #[test]
    fn duplicate() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let mut file1 = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let mut file2 = file1.duplicate().unwrap();

        // Write into the first file and then drop it.
        file1.write_all(b"foo").unwrap();
        drop(file1);

        let mut buf = vec![];

        // Read from the second file; since the position is shared it will already be at EOF.
        file2.read_to_end(&mut buf).unwrap();
        assert_eq!(0, buf.len());

        // Rewind and read.
        file2.seek(SeekFrom::Start(0)).unwrap();
        file2.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, &b"foo");
    }

    /// Tests shared file lock operations.
    #[test]
    fn lock_shared() {
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
        let file3 = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Concurrent shared access is OK, but not shared and exclusive.
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

        // Once all shared file locks are dropped, an exclusive lock may be created;
        file2.fs2_unlock().unwrap();
        file3.fs2_lock_exclusive().unwrap();
    }

    /// Tests exclusive file lock operations.
    #[test]
    fn lock_exclusive() {
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

        // No other access is possible once an exclusive lock is created.
        file1.fs2_lock_exclusive().unwrap();
        assert_eq!(
            file2.fs2_try_lock_exclusive().unwrap_err().kind(),
            lock_contended_error().kind()
        );
        assert_eq!(
            file2.fs2_try_lock_shared().unwrap_err().kind(),
            lock_contended_error().kind()
        );

        // Once the exclusive lock is dropped, the second file is able to create a lock.
        file1.fs2_unlock().unwrap();
        file2.fs2_lock_exclusive().unwrap();
    }

    /// Tests that a lock is released after the file that owns it is dropped.
    #[test]
    fn lock_cleanup() {
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

        file1.fs2_lock_exclusive().unwrap();
        assert_eq!(
            file2.fs2_try_lock_shared().unwrap_err().kind(),
            lock_contended_error().kind()
        );

        // Drop file1; the lock should be released.
        drop(file1);
        file2.fs2_lock_shared().unwrap();
    }

    /// Tests file allocation.
    #[test]
    fn allocate() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let blksize = allocation_granularity(&path).unwrap();

        // New files are created with no allocated size.
        assert_eq!(0, file.allocated_size().unwrap());
        assert_eq!(0, file.metadata().unwrap().len());

        // Allocate space for the file, checking that the allocated size steps
        // up by block size, and the file length matches the allocated size.

        file.allocate(2 * blksize - 1).unwrap();
        assert_eq!(2 * blksize, file.allocated_size().unwrap());
        assert_eq!(2 * blksize - 1, file.metadata().unwrap().len());

        // Truncate the file, checking that the allocated size steps down by
        // block size.

        file.set_len(blksize + 1).unwrap();
        assert_eq!(2 * blksize, file.allocated_size().unwrap());
        assert_eq!(blksize + 1, file.metadata().unwrap().len());
    }

    /// Checks filesystem space methods.
    #[test]
    fn filesystem_space() {
        let tempdir = tempdir().unwrap();
        let stats = statvfs(tempdir.path()).unwrap();
        let total_space = stats.total_space();
        let free_space = stats.free_space();
        let available_space = stats.available_space();

        assert!(total_space > free_space);
        assert!(total_space > available_space);
        assert!(available_space <= free_space);
    }
}
