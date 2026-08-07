use std::ffi::CString;
use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsFd, AsRawFd};
use std::path::Path;

use crate::{FsStats, LockMode, LockOperation};

pub(crate) fn duplicate(file: &File) -> Result<File> {
    let owned = file.as_fd().try_clone_to_owned()?;
    Ok(File::from(owned))
}

pub(crate) fn lock(file: &File, operation: LockOperation) -> Result<()> {
    let flag = match operation {
        LockOperation::Acquire { mode, nonblocking } => {
            let mode_flag = match mode {
                LockMode::Shared => libc::LOCK_SH,
                LockMode::Exclusive => libc::LOCK_EX,
            };
            if nonblocking {
                mode_flag | libc::LOCK_NB
            } else {
                mode_flag
            }
        }
        LockOperation::Release => libc::LOCK_UN,
    };

    flock(file, flag)
}

pub(crate) fn lock_error() -> Error {
    Error::from_raw_os_error(libc::EWOULDBLOCK)
}

#[cfg(not(target_os = "solaris"))]
fn flock(file: &File, flag: libc::c_int) -> Result<()> {
    let ret = unsafe {
        // SAFETY: `file` owns a valid descriptor for the duration of this call.
        libc::flock(file.as_raw_fd(), flag)
    };
    if ret < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Simulate flock() using fcntl(); primarily for Oracle Solaris.
#[cfg(target_os = "solaris")]
fn flock(file: &File, flag: libc::c_int) -> Result<()> {
    let mut fl = libc::flock {
        l_whence: 0,
        l_start: 0,
        l_len: 0,
        l_type: 0,
        l_pad: [0; 4],
        l_pid: 0,
        l_sysid: 0,
    };

    // In non-blocking mode, use F_SETLK for cmd, F_SETLKW otherwise, and don't forget to clear
    // LOCK_NB.
    let (cmd, operation) = match flag & libc::LOCK_NB {
        0 => (libc::F_SETLKW, flag),
        _ => (libc::F_SETLK, flag & !libc::LOCK_NB),
    };

    match operation {
        libc::LOCK_SH => fl.l_type |= libc::F_RDLCK,
        libc::LOCK_EX => fl.l_type |= libc::F_WRLCK,
        libc::LOCK_UN => fl.l_type |= libc::F_UNLCK,
        _ => return Err(Error::from_raw_os_error(libc::EINVAL)),
    }

    let ret = unsafe {
        // SAFETY: `file` owns a valid descriptor and `fl` is a valid flock structure.
        libc::fcntl(file.as_raw_fd(), cmd, &fl)
    };
    match ret {
        // Translate EACCES to EWOULDBLOCK
        -1 => match Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) => return Err(lock_error()),
            _ => return Err(Error::last_os_error()),
        },
        _ => Ok(()),
    }
}

pub(crate) fn allocated_size(file: &File) -> Result<u64> {
    file.metadata().map(|m| m.blocks() * 512)
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "android",
    target_os = "emscripten"
))]
#[cfg(not(all(target_os = "linux", target_env = "uclibc")))]
#[cfg(not(all(target_os = "linux", target_pointer_width = "32")))]
pub(crate) fn allocate_space(file: &File, len: u64) -> Result<()> {
    let len = libc::off_t::try_from(len)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "allocation length is too large"))?;
    let ret = unsafe {
        // SAFETY: `file` owns a valid descriptor and `len` fits the platform ABI type.
        libc::posix_fallocate(file.as_raw_fd(), 0, len)
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::from_raw_os_error(ret))
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "32"))]
#[cfg(not(target_env = "uclibc"))]
pub(crate) fn allocate_space(file: &File, len: u64) -> Result<()> {
    let len = libc::off64_t::try_from(len)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "allocation length is too large"))?;
    let ret = unsafe {
        // SAFETY: `file` owns a valid descriptor and `len` fits the platform ABI type.
        libc::posix_fallocate64(file.as_raw_fd(), 0, len)
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::from_raw_os_error(ret))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn allocate_space(file: &File, len: u64) -> Result<()> {
    let stat = file.metadata()?;

    if len > stat.blocks() as u64 * 512 {
        let len = libc::off_t::try_from(len)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "allocation length is too large"))?;
        let mut fstore = libc::fstore_t {
            fst_flags: libc::F_ALLOCATECONTIG,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: len,
            fst_bytesalloc: 0,
        };

        let ret = unsafe {
            // SAFETY: `file` owns a valid descriptor and `fstore` is a valid fstore structure.
            libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &fstore)
        };
        if ret == -1 {
            // Unable to allocate contiguous disk space; attempt to allocate non-contiguously.
            fstore.fst_flags = libc::F_ALLOCATEALL;
            let ret = unsafe {
                // SAFETY: `file` owns a valid descriptor and `fstore` is a valid fstore structure.
                libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &fstore)
            };
            if ret == -1 {
                return Err(Error::last_os_error());
            }
        }
    }

    Ok(())
}

#[cfg(any(
    all(target_os = "linux", target_env = "uclibc"),
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "redox",
    target_os = "haiku"
))]
pub(crate) fn allocate_space(_file: &File, _len: u64) -> Result<()> {
    // No file allocation API is available on these platforms.
    Ok(())
}

pub(crate) fn statvfs(path: &Path) -> Result<FsStats> {
    let cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contained a null"))?;

    // SAFETY: `libc::statvfs` initializes every field of this output structure.
    let mut stat: libc::statvfs = unsafe { mem::zeroed() };
    // SAFETY: `cstr` is null-terminated and `stat` is valid for the duration of the call.
    let ret = unsafe { libc::statvfs(cstr.as_ptr() as *const _, &mut stat) };
    if ret != 0 {
        Err(Error::last_os_error())
    } else {
        FsStats::from_block_counts(
            stat.f_frsize as u64,
            stat.f_bfree as u64,
            stat.f_bavail as u64,
            stat.f_blocks as u64,
        )
    }
}

#[cfg(test)]
mod test {
    use std::fs::{self, File};
    use std::os::unix::io::AsRawFd;

    use crate::{FileExt, lock_contended_error};
    use tempfile::tempdir;

    /// The duplicate method returns a file with a new file descriptor.
    #[test]
    fn duplicate_new_fd() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = file1.duplicate().unwrap();
        assert!(file1.as_raw_fd() != file2.as_raw_fd());
    }

    /// The duplicate method should preservesthe close on exec flag.
    #[test]
    fn duplicate_cloexec() {
        fn flags(file: &File) -> libc::c_int {
            unsafe {
                // SAFETY: `file` owns a valid descriptor for the duration of this call.
                libc::fcntl(file.as_raw_fd(), libc::F_GETFL, 0)
            }
        }

        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = file1.duplicate().unwrap();

        assert_eq!(flags(&file1), flags(&file2));
    }

    /// Tests that locking a file descriptor will replace any existing locks
    /// held on the file descriptor.
    #[test]
    fn lock_replace() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Creating a shared lock will drop an exclusive lock.
        file1.fs2_lock_exclusive().unwrap();
        file1.fs2_lock_shared().unwrap();
        file2.fs2_lock_shared().unwrap();

        // Attempting to replace a shared lock with an exclusive lock will fail
        // with multiple lock holders, and remove the original shared lock.
        assert_eq!(
            file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );
        file1.fs2_lock_shared().unwrap();
    }

    /// Tests that locks are shared among duplicated file descriptors.
    #[test]
    fn lock_duplicate() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = file1.duplicate().unwrap();
        let file3 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Create a lock through fd1, then replace it through fd2.
        file1.fs2_lock_shared().unwrap();
        file2.fs2_lock_exclusive().unwrap();
        assert_eq!(
            file3.fs2_try_lock_shared().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );

        // Either of the file descriptors should be able to unlock.
        file1.fs2_unlock().unwrap();
        file3.fs2_lock_shared().unwrap();
    }
}
