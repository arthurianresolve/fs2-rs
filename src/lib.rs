//! Extended utilities for working with files and filesystems in Rust.

#![doc(html_root_url = "https://docs.rs/fs2/0.5.0")]

mod allocation;
mod lock;
#[cfg(test)]
mod lock_contract;
mod stats;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

use std::fs::File;
use std::io::{Error, Result};

pub use stats::{
    FsStats, FsStatsQuery, allocation_granularity, available_space, free_space, statvfs,
    total_space,
};

pub(crate) use stats::{FilesystemCounters, SpaceKind};

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
    /// On Unix this retains the historical `dup(2)` behavior, including an
    /// inheritable descriptor. Use [`File::try_clone`] when close-on-exec
    /// behavior is required. Windows uses the standard-library handle cloning
    /// implementation.
    fn duplicate(&self) -> Result<File>;

    /// Returns the amount of physical space allocated for a file.
    fn allocated_size(&self) -> Result<u64>;

    /// Ensures that at least `len` bytes of disk space are allocated for the
    /// file, and the file size is at least `len` bytes. After a successful call
    /// to `allocate`, subsequent writes to the file within the specified length
    /// are guaranteed not to fail because of lack of disk space.
    /// On platforms without a physical reservation primitive, this returns
    /// [`std::io::ErrorKind::Unsupported`] when additional space is needed.
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
    #[inline]
    fn duplicate(&self) -> Result<File> {
        sys::duplicate(self)
    }
    fn allocated_size(&self) -> Result<u64> {
        allocation::allocated_size(self)
    }
    fn allocate(&self, len: u64) -> Result<()> {
        allocation::allocate(self, len)
    }
    fn lock_shared(&self) -> Result<()> {
        lock::shared(self)
    }
    fn lock_exclusive(&self) -> Result<()> {
        lock::exclusive(self)
    }
    fn try_lock_shared(&self) -> Result<()> {
        lock::try_shared(self)
    }
    fn try_lock_exclusive(&self) -> Result<()> {
        lock::try_exclusive(self)
    }
    fn unlock(&self) -> Result<()> {
        lock::release(self)
    }
}

/// Returns the error that a call to a try lock method on a contended file will
/// return.
pub fn lock_contended_error() -> Error {
    sys::lock_error()
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

        // Allocation also restores the logical length when physical space is
        // already reserved. This protects the Windows metadata/set-length
        // path and the equivalent Unix fast path.
        file.allocate(2 * blksize - 1).unwrap();
        assert_eq!(2 * blksize, file.allocated_size().unwrap());
        assert_eq!(2 * blksize - 1, file.metadata().unwrap().len());

        // An allocation request that is already satisfied leaves both the
        // allocated space and the file length unchanged.
        file.allocate(2 * blksize - 1).unwrap();
        assert_eq!(2 * blksize, file.allocated_size().unwrap());
        assert_eq!(2 * blksize - 1, file.metadata().unwrap().len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allocate_reserves_sparse_file_blocks() {
        use std::os::unix::fs::MetadataExt;

        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2-sparse");
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let len = 4 * allocation_granularity(&path).unwrap();

        file.set_len(len).unwrap();
        assert_eq!(file.metadata().unwrap().len(), len);
        assert!(file.metadata().unwrap().blocks() * 512 < len);

        file.allocate(len).unwrap();

        assert!(file.allocated_size().unwrap() >= len);
        assert_eq!(file.metadata().unwrap().len(), len);
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
    fn allocate_is_idempotent() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2-idempotent");
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let block_size = allocation_granularity(&path).unwrap();
        let len = 2 * block_size;

        file.allocate(len).unwrap();
        file.allocate(len).unwrap();
        file.allocate(block_size).unwrap();

        assert!(file.allocated_size().unwrap() >= len);
        assert_eq!(file.metadata().unwrap().len(), len);
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "android",
        target_os = "emscripten",
        target_os = "macos",
        target_os = "ios",
        all(target_os = "linux", not(target_env = "uclibc")),
    ))]
    #[test]
    fn allocate_propagates_read_only_file_error() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2-read-only");
        drop(
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap(),
        );
        let file = fs::OpenOptions::new().read(true).open(path).unwrap();

        let error = file.allocate(4096).unwrap_err();

        assert!(error.raw_os_error().is_some());
    }

    #[test]
    fn allocate_rejects_unrepresentable_length() {
        let tempdir = tempdir().unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();

        assert_eq!(
            file.allocate(i64::MAX as u64 + 1).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
