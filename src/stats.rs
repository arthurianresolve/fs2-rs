use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::sys;

/// `FsStats` contains some common stats about a file system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FsStats {
    free_space: u64,
    available_space: u64,
    total_space: u64,
    allocation_granularity: u64,
}

impl FsStats {
    pub(crate) fn from_counters(counters: FilesystemCounters) -> Result<Self> {
        if counters.allocation_granularity == 0 {
            return Err(invalid_stats("filesystem allocation granularity is zero"));
        }

        if counters.available_space > counters.free_space {
            return Err(invalid_stats(
                "filesystem available space exceeds free space",
            ));
        }
        if counters.free_space > counters.total_space {
            return Err(invalid_stats("filesystem free space exceeds total space"));
        }

        Ok(Self {
            free_space: counters.free_space,
            available_space: counters.available_space,
            total_space: counters.total_space,
            allocation_granularity: counters.allocation_granularity,
        })
    }

    /// Returns the number of free bytes in the file system containing the provided
    /// path.
    pub fn free_space(&self) -> u64 {
        self.free_space
    }

    /// Returns the available space in bytes to non-privileged users in the file
    /// system containing the provided path.
    pub fn available_space(&self) -> u64 {
        self.available_space
    }

    /// Returns the total space in bytes in the file system containing the provided
    /// path.
    pub fn total_space(&self) -> u64 {
        self.total_space
    }

    /// Returns the filesystem's disk space allocation granularity in bytes.
    /// The provided path may be for any file in the filesystem.
    ///
    /// On Posix, this is equivalent to the filesystem's block size.
    /// On Windows, this is equivalent to the filesystem's cluster size.
    pub fn allocation_granularity(&self) -> u64 {
        self.allocation_granularity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilesystemCounters {
    pub(crate) allocation_granularity: u64,
    pub(crate) free_space: u64,
    pub(crate) available_space: u64,
    pub(crate) total_space: u64,
}

impl FilesystemCounters {
    #[cfg(unix)]
    pub(crate) fn from_block_counts(
        allocation_granularity: u64,
        free_blocks: u64,
        available_blocks: u64,
        total_blocks: u64,
    ) -> Result<Self> {
        Ok(Self {
            allocation_granularity,
            free_space: checked_space(allocation_granularity, free_blocks)?,
            available_space: checked_space(allocation_granularity, available_blocks)?,
            total_space: checked_space(allocation_granularity, total_blocks)?,
        })
    }
}

/// Get the stats of the file system containing the provided path.
pub fn statvfs<P>(path: P) -> Result<FsStats>
where
    P: AsRef<Path>,
{
    sys::statvfs(path.as_ref())
}

/// Returns the number of free bytes in the file system containing the provided
/// path.
pub fn free_space<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.free_space)
}

/// Returns the available space in bytes to non-privileged users in the file
/// system containing the provided path.
pub fn available_space<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.available_space)
}

/// Returns the total space in bytes in the file system containing the provided
/// path.
pub fn total_space<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    statvfs(path).map(|stat| stat.total_space)
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
    statvfs(path).map(|stat| stat.allocation_granularity)
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

    #[cfg(unix)]
    #[test]
    fn constructs_stats_from_block_counts() {
        let stats =
            FsStats::from_counters(FilesystemCounters::from_block_counts(4096, 8, 6, 10).unwrap())
                .unwrap();

        assert_eq!(stats.free_space(), 32_768);
        assert_eq!(stats.available_space(), 24_576);
        assert_eq!(stats.total_space(), 40_960);
        assert_eq!(stats.allocation_granularity(), 4096);
    }

    #[test]
    fn constructs_stats_from_bytes() {
        let stats = FsStats::from_counters(FilesystemCounters {
            allocation_granularity: 4096,
            free_space: 32_768,
            available_space: 24_576,
            total_space: 40_960,
        })
        .unwrap();

        assert_eq!(stats.free_space(), 32_768);
        assert_eq!(stats.available_space(), 24_576);
        assert_eq!(stats.total_space(), 40_960);
        assert_eq!(stats.allocation_granularity(), 4096);
    }

    #[test]
    fn rejects_zero_granularity() {
        let error = FsStats::from_counters(FilesystemCounters {
            allocation_granularity: 0,
            free_space: 1,
            available_space: 1,
            total_space: 1,
        })
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_block_count_zero_granularity() {
        let error =
            FsStats::from_counters(FilesystemCounters::from_block_counts(0, 1, 1, 1).unwrap())
                .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_space_overflow() {
        let error = FilesystemCounters::from_block_counts(u64::MAX, 2, 1, 2).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_inconsistent_space_counts() {
        let error = FsStats::from_counters(FilesystemCounters {
            allocation_granularity: 4096,
            free_space: 32_768,
            available_space: 36_864,
            total_space: 40_960,
        })
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn filesystem_space() {
        let tempdir = tempdir().unwrap();
        let stats = statvfs(tempdir.path()).unwrap();

        assert!(stats.total_space() > stats.free_space());
        assert!(stats.total_space() > stats.available_space());
        assert!(stats.available_space() <= stats.free_space());
    }
}
