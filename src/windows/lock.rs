use std::fs::File;
use std::io::{Error, Result};
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFile,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::windows::path::win32_bool_result;

#[inline(always)]
pub(crate) fn lock_shared(file: &File, nonblocking: bool) -> Result<()> {
    let flags = if nonblocking {
        LOCKFILE_FAIL_IMMEDIATELY
    } else {
        0
    };
    lock_file(file, flags)
}

#[inline(always)]
pub(crate) fn lock_exclusive(file: &File, nonblocking: bool) -> Result<()> {
    let flags = LOCKFILE_EXCLUSIVE_LOCK
        | if nonblocking {
            LOCKFILE_FAIL_IMMEDIATELY
        } else {
            0
        };
    lock_file(file, flags)
}

pub(crate) fn unlock(file: &File) -> Result<()> {
    let ret = unsafe {
        // SAFETY: `file` owns a valid handle for the duration of this call.
        UnlockFile(file.as_raw_handle(), 0, 0, u32::MAX, u32::MAX)
    };
    win32_bool_result(ret)
}

pub(crate) fn lock_error() -> Error {
    Error::from_raw_os_error(ERROR_LOCK_VIOLATION as i32)
}

fn lock_file(file: &File, flags: u32) -> Result<()> {
    let mut overlapped = OVERLAPPED::default();
    let ret = unsafe {
        // SAFETY: `file` owns a valid handle and `overlapped` is a valid zeroed structure.
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    win32_bool_result(ret)
}
