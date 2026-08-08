use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::sys;

/// A consistent filesystem statistics snapshot.
///
/// Obtain one snapshot with [`statvfs`] when more than one counter is needed.
/// The individual convenience functions each acquire their own snapshot.
/// On Windows, `total_space` reports physical volume capacity when the modern
/// provider is available; the legacy fallback may report a quota-limited total
/// for the calling user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FsStats {
    free_space: u64,
    available_space: u64,
    total_space: u64,
    allocation_granularity: u64,
}

impl FsStats {
    pub(crate) fn from_counters(counters: FilesystemCounters) -> Result<Self> {
        let allocation_granularity = validate_granularity(counters.allocation_granularity)?;
        #[cfg(unix)]
        let (free_space, available_space, total_space) = (
            checked_space(counters.allocation_granularity, counters.free_blocks)?,
            checked_space(counters.allocation_granularity, counters.available_blocks)?,
            checked_space(counters.allocation_granularity, counters.total_blocks)?,
        );
        #[cfg(windows)]
        // The legacy Windows API reports physical free space separately from
        // quota-limited total space, so these counters are not always ordered.
        let (free_space, available_space, total_space) = (
            counters.free_space,
            counters.available_space,
            counters.total_space,
        );

        validate_space_values(free_space, available_space, total_space)?;

        Ok(Self {
            free_space,
            available_space,
            total_space,
            allocation_granularity,
        })
    }

    /// Returns the number of free bytes in the file system containing the provided
    /// path.
    #[inline]
    pub fn free_space(&self) -> u64 {
        self.free_space
    }

    /// Returns the available space in bytes to non-privileged users in the file
    /// system containing the provided path.
    #[inline]
    pub fn available_space(&self) -> u64 {
        self.available_space
    }

    /// Returns the total space in bytes in the file system containing the provided
    /// path.
    ///
    /// On Windows, this is the physical volume capacity when the modern
    /// provider is available; the legacy fallback may be quota-limited.
    #[inline]
    pub fn total_space(&self) -> u64 {
        self.total_space
    }

    /// Returns the filesystem's disk space allocation granularity in bytes.
    /// The provided path may be for any file in the filesystem.
    ///
    /// On Posix, this is equivalent to the filesystem's block size.
    /// On Windows, this is equivalent to the filesystem's cluster size.
    #[inline]
    pub fn allocation_granularity(&self) -> u64 {
        self.allocation_granularity
    }

    pub(crate) fn value(&self, kind: SpaceKind) -> u64 {
        match kind {
            SpaceKind::Free => self.free_space,
            SpaceKind::Available => self.available_space,
            SpaceKind::Total => self.total_space,
            SpaceKind::AllocationGranularity => self.allocation_granularity,
        }
    }
}

pub(crate) fn validate_granularity(allocation_granularity: u64) -> Result<u64> {
    if allocation_granularity == 0 {
        Err(invalid_stats("filesystem allocation granularity is zero"))
    } else {
        Ok(allocation_granularity)
    }
}

pub(crate) fn validate_space_values(
    free_space: u64,
    available_space: u64,
    total_space: u64,
) -> Result<()> {
    if available_space > free_space {
        return Err(invalid_stats(
            "filesystem available space exceeds free space",
        ));
    }
    #[cfg(not(unix))]
    let _ = total_space;
    #[cfg(unix)]
    if free_space > total_space {
        return Err(invalid_stats("filesystem free space exceeds total space"));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn value_from_bytes(
    free_space: u64,
    available_space: u64,
    total_space: u64,
    kind: SpaceKind,
) -> Result<u64> {
    validate_space_values(free_space, available_space, total_space)?;
    match kind {
        SpaceKind::Free => Ok(free_space),
        SpaceKind::Available => Ok(available_space),
        SpaceKind::Total => Ok(total_space),
        SpaceKind::AllocationGranularity => Err(invalid_stats(
            "allocation granularity is not a byte-space value",
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpaceKind {
    Free,
    Available,
    Total,
    AllocationGranularity,
}

/// Platform-native filesystem counters before conversion to [`FsStats`].
///
/// On Windows, the legacy API can combine physical free space with
/// quota-limited total space; callers must not assume that `free_space <=
/// total_space` for that snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilesystemCounters {
    pub(crate) allocation_granularity: u64,
    #[cfg(unix)]
    pub(crate) free_blocks: u64,
    #[cfg(unix)]
    pub(crate) available_blocks: u64,
    #[cfg(unix)]
    pub(crate) total_blocks: u64,
    #[cfg(windows)]
    pub(crate) free_space: u64,
    #[cfg(windows)]
    pub(crate) available_space: u64,
    #[cfg(windows)]
    pub(crate) total_space: u64,
}

/// Gets one statistics snapshot for the filesystem containing `path`.
pub fn statvfs(path: impl AsRef<Path>) -> Result<FsStats> {
    sys::statvfs(path.as_ref()).and_then(FsStats::from_counters)
}

/// Returns free space from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::free_space`] when multiple counters
/// are needed.
pub fn free_space(path: impl AsRef<Path>) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::Free)
}

/// Returns available space from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::available_space`] when multiple
/// counters are needed.
pub fn available_space(path: impl AsRef<Path>) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::Available)
}

/// Returns total space from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::total_space`] when multiple counters
/// are needed.
pub fn total_space(path: impl AsRef<Path>) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::Total)
}

/// Returns allocation granularity from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::allocation_granularity`] when
/// multiple counters are needed.
pub fn allocation_granularity(path: impl AsRef<Path>) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::AllocationGranularity)
}

#[cfg(unix)]
fn checked_space(allocation_granularity: u64, blocks: u64) -> Result<u64> {
    allocation_granularity
        .checked_mul(blocks)
        .ok_or_else(|| invalid_stats("filesystem space calculation overflowed"))
}

fn invalid_stats(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use std::io::ErrorKind;

    use super::{FilesystemCounters, FsStats, statvfs};

    fn counters(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> FilesystemCounters {
        #[cfg(unix)]
        {
            FilesystemCounters {
                allocation_granularity,
                free_blocks: free_space,
                available_blocks: available_space,
                total_blocks: total_space,
            }
        }
        #[cfg(windows)]
        {
            FilesystemCounters {
                allocation_granularity,
                free_space,
                available_space,
                total_space,
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn constructs_stats_from_block_counts() {
        let stats = FsStats::from_counters(counters(4096, 8, 6, 10)).unwrap();

        assert_eq!(stats.free_space(), 32_768);
        assert_eq!(stats.available_space(), 24_576);
        assert_eq!(stats.total_space(), 40_960);
        assert_eq!(stats.allocation_granularity(), 4096);
    }

    #[cfg(windows)]
    #[test]
    fn constructs_stats_from_bytes() {
        let stats = FsStats::from_counters(counters(4096, 32_768, 24_576, 40_960)).unwrap();

        assert_eq!(stats.free_space(), 32_768);
        assert_eq!(stats.available_space(), 24_576);
        assert_eq!(stats.total_space(), 40_960);
        assert_eq!(stats.allocation_granularity(), 4096);
    }

    #[test]
    fn rejects_zero_granularity() {
        let error = FsStats::from_counters(counters(0, 1, 1, 1)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_block_count_zero_granularity() {
        let error = FsStats::from_counters(counters(0, 1, 1, 1)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_space_overflow() {
        let error = FsStats::from_counters(counters(u64::MAX, 2, 1, 2)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_inconsistent_space_counts() {
        let error = FsStats::from_counters(counters(4096, 32_768, 36_864, 40_960)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn filesystem_space() {
        let tempdir = tempdir().unwrap();
        let stats = statvfs(tempdir.path()).unwrap();

        assert!(stats.total_space() > 0);
        assert!(stats.available_space() <= stats.free_space());
        #[cfg(unix)]
        assert!(stats.total_space() > stats.free_space());
    }

    #[cfg(windows)]
    #[test]
    fn accepts_quota_limited_legacy_total_space() {
        let stats = FsStats::from_counters(counters(4096, 50_000, 10_000, 40_000)).unwrap();

        assert_eq!(stats.free_space(), 50_000);
        assert_eq!(stats.available_space(), 10_000);
        assert_eq!(stats.total_space(), 40_000);
    }
}
