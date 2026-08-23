//! Solaris does not provide BSD-style `flock(2)`, so lock operations are
//! implemented via `fcntl` byte-range records instead. This keeps Solaris
//! behavior aligned with other platforms while handling non-blocking and unlock
//! semantics explicitly.

use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::io::AsRawFd;

pub(crate) fn flock(file: &File, flag: libc::c_int) -> Result<()> {
    let mut fl = libc::flock {
        l_whence: libc::SEEK_SET as _,
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
        -1 => {
            let error = Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EACCES) => Err(Error::from_raw_os_error(libc::EWOULDBLOCK)),
                _ => Err(error),
            }
        }
        _ => Ok(()),
    }
}
