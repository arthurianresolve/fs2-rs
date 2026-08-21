use std::ffi::{CStr, CString};
use std::io::{Error, Result};
use std::mem::MaybeUninit;
use std::path::Path;

use crate::stats::{FilesystemCounters, SpaceKind, invalid_stats};

use super::path::with_c_path;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const INVALID_FRAGMENT_SIZE: &str = "filesystem returned a negative fragment size";
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
const INVALID_FRAGMENT_SIZE: &str = "filesystem returned an invalid fragment size";
const INVALID_FREE_BLOCKS: &str = "filesystem returned an invalid free-block count";
const INVALID_AVAILABLE_BLOCKS: &str = "filesystem returned an invalid available-block count";
const INVALID_TOTAL_BLOCKS: &str = "filesystem returned an invalid block count";

#[derive(Debug)]
pub(crate) struct StatsQuery {
    path: CString,
}

impl StatsQuery {
    pub(crate) const fn new(path: CString) -> Self {
        Self { path }
    }

    pub(crate) fn counters(&self) -> Result<FilesystemCounters> {
        statvfs_cstr(&self.path)
    }
}

pub(crate) fn statvfs(path: &Path) -> Result<FilesystemCounters> {
    with_c_path(path, statvfs_cstr)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
// libc fields are platform ABI-dependent (including signed widths), so we
// normalize to i64 before doing a checked nonnegative conversion.
#[allow(clippy::unnecessary_cast)]
fn statvfs_cstr(path: &CStr) -> Result<FilesystemCounters> {
    let stat = query_stat(MaybeUninit::<libc::statfs>::uninit(), |stat| unsafe {
        // SAFETY: `path` is null-terminated and `stat` points to writable storage
        // large enough for `libc::statfs`.
        libc::statfs(path.as_ptr(), stat)
    })?;
    unix_filesystem_counters_from_values(
        stat.f_frsize as i64,
        stat.f_bsize as i64,
        stat.f_bfree as i64,
        stat.f_bavail as i64,
        stat.f_blocks as i64,
    )
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn linux_allocation_granularity(fragment_size: u64, block_size: u64) -> u64 {
    if fragment_size == 0 {
        block_size
    } else {
        fragment_size
    }
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
// libc fields are platform ABI-dependent (including signed widths), so we
// normalize to i64 before doing a checked nonnegative conversion.
#[allow(clippy::unnecessary_cast)]
fn statvfs_cstr(path: &CStr) -> Result<FilesystemCounters> {
    let stat = query_stat(MaybeUninit::<libc::statvfs>::uninit(), |stat| unsafe {
        // SAFETY: `path` is null-terminated and `stat` points to writable storage.
        libc::statvfs(path.as_ptr() as *const _, stat)
    })?;
    unix_filesystem_counters_from_values(
        stat.f_frsize as i64,
        stat.f_bfree as i64,
        stat.f_bavail as i64,
        stat.f_blocks as i64,
    )
}

#[inline(always)]
fn query_stat<T>(mut stat: MaybeUninit<T>, query: impl FnOnce(*mut T) -> libc::c_int) -> Result<T> {
    let ret = query(stat.as_mut_ptr());
    if ret != 0 {
        Err(Error::last_os_error())
    } else {
        // SAFETY: a successful filesystem-stat syscall initialized the output.
        Ok(unsafe { stat.assume_init() })
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[inline(always)]
fn unix_filesystem_counters_from_values(
    fragment_size: i64,
    block_size: i64,
    free_blocks: i64,
    available_blocks: i64,
    total_blocks: i64,
) -> Result<FilesystemCounters> {
    let (fragment_size, free_blocks, available_blocks, total_blocks) =
        parse_unix_block_values(fragment_size, free_blocks, available_blocks, total_blocks)?;
    let block_size =
        nonnegative_filesystem_value(block_size, "filesystem returned a negative block size")?;
    Ok(FilesystemCounters::unix_blocks(
        linux_allocation_granularity(fragment_size, block_size),
        free_blocks,
        available_blocks,
        total_blocks,
    ))
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
#[inline(always)]
fn unix_filesystem_counters_from_values(
    fragment_size: i64,
    free_blocks: i64,
    available_blocks: i64,
    total_blocks: i64,
) -> Result<FilesystemCounters> {
    let (fragment_size, free_blocks, available_blocks, total_blocks) =
        parse_unix_block_values(fragment_size, free_blocks, available_blocks, total_blocks)?;
    Ok(FilesystemCounters::unix_blocks(
        fragment_size,
        free_blocks,
        available_blocks,
        total_blocks,
    ))
}

pub(crate) fn space(path: &Path, kind: SpaceKind) -> Result<u64> {
    statvfs(path)?.space(kind)
}

fn nonnegative_filesystem_value(value: i64, message: &'static str) -> Result<u64> {
    value.try_into().map_err(|_| invalid_stats(message))
}

#[inline(always)]
fn parse_unix_block_values(
    fragment_size: i64,
    free_blocks: i64,
    available_blocks: i64,
    total_blocks: i64,
) -> Result<(u64, u64, u64, u64)> {
    Ok((
        nonnegative_filesystem_value(fragment_size, INVALID_FRAGMENT_SIZE)?,
        nonnegative_filesystem_value(free_blocks, INVALID_FREE_BLOCKS)?,
        nonnegative_filesystem_value(available_blocks, INVALID_AVAILABLE_BLOCKS)?,
        nonnegative_filesystem_value(total_blocks, INVALID_TOTAL_BLOCKS)?,
    ))
}

#[cfg(test)]
mod test {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    use super::linux_allocation_granularity;
    use super::{nonnegative_filesystem_value, statvfs};
    use std::io::ErrorKind;
    use tempfile::tempdir;

    #[test]
    fn missing_stats_path_reports_not_found() {
        let tempdir = tempdir().unwrap();
        let error = statvfs(&tempdir.path().join("missing")).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn rejects_negative_native_sizes_and_statfs_values() {
        assert_eq!(
            nonnegative_filesystem_value(0, "negative value").unwrap(),
            0
        );
        assert_eq!(
            nonnegative_filesystem_value(4096i64, "negative value").unwrap(),
            4096
        );
        assert!(nonnegative_filesystem_value(-1i64, "negative value").is_err());
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn uses_filesystem_block_size_when_fragment_size_is_zero() {
        assert_eq!(linux_allocation_granularity(0, 4096), 4096);
        assert_eq!(linux_allocation_granularity(1024, 4096), 1024);
    }
}
