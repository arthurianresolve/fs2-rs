use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::sys;

/// `FsStats` contains some common stats about a file system.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FsStats {
    free_space: u64,
    available_space: u64,
    total_space: u64,
    allocation_granularity: u64,
}

impl FsStats {
    pub(crate) fn from_block_counts(
        allocation_granularity: u64,
        free_blocks: u64,
        available_blocks: u64,
        total_blocks: u64,
    ) -> Result<Self> {
        if allocation_granularity == 0 {
            return Err(invalid_stats("filesystem allocation granularity is zero"));
        }

        let free_space = checked_space(allocation_granularity, free_blocks)?;
        let available_space = checked_space(allocation_granularity, available_blocks)?;
        let total_space = checked_space(allocation_granularity, total_blocks)?;

        if available_space > free_space {
            return Err(invalid_stats(
                "filesystem available space exceeds free space",
            ));
        }
        if free_space > total_space {
            return Err(invalid_stats("filesystem free space exceeds total space"));
        }

        Ok(Self {
            free_space,
            available_space,
            total_space,
            allocation_granularity,
        })
    }

    /// Returns the number of free bytes in the file system containing the provided
    /// path.
    pub fn free_space(&self) -> u64 {
        self.free_space
    }

    /// Returns the available space in bytes to non-priveleged users in the file
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

/// Returns the available space in bytes to non-priveleged users in the file
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

    use super::{FsStats, statvfs};

    #[test]
    fn constructs_stats_from_block_counts() {
        let stats = FsStats::from_block_counts(4096, 8, 6, 10).unwrap();

        assert_eq!(stats.free_space(), 32_768);
        assert_eq!(stats.available_space(), 24_576);
        assert_eq!(stats.total_space(), 40_960);
        assert_eq!(stats.allocation_granularity(), 4096);
    }

    #[test]
    fn rejects_zero_granularity() {
        let error = FsStats::from_block_counts(0, 1, 1, 1).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_space_overflow() {
        let error = FsStats::from_block_counts(u64::MAX, 2, 1, 2).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_inconsistent_space_counts() {
        let error = FsStats::from_block_counts(4096, 8, 9, 10).unwrap_err();

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
