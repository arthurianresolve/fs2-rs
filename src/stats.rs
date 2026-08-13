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

/// A prepared filesystem-statistics query for repeated snapshots.
///
/// Construction resolves and validates the platform path representation once.
/// Each call to [`FsStatsQuery::snapshot`] acquires fresh filesystem counters;
/// counter values are never cached. Recreate the query after changing the
/// process working directory or the path's mount, junction, or symbolic-link
/// mapping.
///
/// # Examples
///
/// ```
/// # fn main() -> std::io::Result<()> {
/// use fs2::FsStatsQuery;
///
/// let query = FsStatsQuery::new(".")?;
/// let first = query.snapshot()?;
/// let second = query.snapshot()?;
/// # let _ = (first, second);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct FsStatsQuery {
    inner: sys::StatsQuery,
}

impl FsStatsQuery {
    /// Prepares repeated statistics queries for the filesystem containing
    /// `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        Self::new_path(path.as_ref())
    }

    fn new_path(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path)?;
        sys::StatsQuery::new(&path).map(|inner| Self { inner })
    }

    /// Acquires a fresh statistics snapshot.
    pub fn snapshot(&self) -> Result<FsStats> {
        self.inner.counters().and_then(FsStats::from_counters)
    }
}

impl FsStats {
    pub(crate) fn from_counters(counters: FilesystemCounters) -> Result<Self> {
        #[cfg(unix)]
        let allocation_granularity = validate_unix_counters(counters)?;
        #[cfg(windows)]
        let allocation_granularity = validate_granularity(counters.allocation_granularity)?;
        #[cfg(unix)]
        let (free_space, available_space, total_space) = (
            allocation_granularity * counters.free_blocks,
            allocation_granularity * counters.available_blocks,
            allocation_granularity * counters.total_blocks,
        );
        #[cfg(windows)]
        // The legacy Windows API reports physical free space separately from
        // quota-limited total space, so these counters are not always ordered.
        let (free_space, available_space, total_space) = (
            counters.free_space,
            counters.available_space,
            counters.total_space,
        );

        #[cfg(windows)]
        match counters.source {
            WindowsCounterSource::Modern => {
                validate_modern_space_values(free_space, available_space, total_space)?;
            }
            WindowsCounterSource::Legacy => {
                validate_space_values(free_space, available_space, total_space)?;
            }
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

    #[cfg(windows)]
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
    #[cfg(windows)]
    {
        let _ = total_space;
        validate_available_space_values(free_space, available_space)?;
    }
    #[cfg(unix)]
    {
        if free_space > total_space {
            return Err(invalid_stats("filesystem free space exceeds total space"));
        }
        if available_space > total_space {
            return Err(invalid_stats(
                "filesystem available space exceeds total space",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_available_space_values(free_space: u64, available_space: u64) -> Result<()> {
    if available_space > free_space {
        return Err(invalid_stats(
            "filesystem available space exceeds free space",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_modern_space_values(
    free_space: u64,
    available_space: u64,
    total_space: u64,
) -> Result<()> {
    validate_available_space_values(free_space, available_space)?;
    if free_space > total_space {
        return Err(invalid_stats("filesystem free space exceeds total space"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpaceKind {
    Free,
    Available,
    Total,
    AllocationGranularity,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Identifies the quota domain used by a Windows statistics provider.
enum WindowsCounterSource {
    Modern,
    Legacy,
}

/// Platform-native filesystem counters before conversion to [`FsStats`].
///
/// On Windows, the legacy API can combine physical free space with
/// quota-limited total space; callers must not assume that `free_space <=
/// total_space` for that snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilesystemCounters {
    allocation_granularity: u64,
    #[cfg(unix)]
    free_blocks: u64,
    #[cfg(unix)]
    available_blocks: u64,
    #[cfg(unix)]
    total_blocks: u64,
    #[cfg(windows)]
    free_space: u64,
    #[cfg(windows)]
    available_space: u64,
    #[cfg(windows)]
    total_space: u64,
    #[cfg(windows)]
    /// Modern physical or legacy quota-aware Windows counters.
    source: WindowsCounterSource,
}

impl FilesystemCounters {
    #[cfg(unix)]
    #[inline(always)]
    pub(crate) const fn unix_blocks(
        allocation_granularity: u64,
        free_blocks: u64,
        available_blocks: u64,
        total_blocks: u64,
    ) -> Self {
        Self {
            allocation_granularity,
            free_blocks,
            available_blocks,
            total_blocks,
        }
    }

    #[cfg(windows)]
    #[inline(always)]
    pub(crate) const fn windows_modern_bytes(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> Self {
        Self {
            allocation_granularity,
            free_space,
            available_space,
            total_space,
            source: WindowsCounterSource::Modern,
        }
    }

    #[cfg(windows)]
    #[inline(always)]
    pub(crate) const fn windows_legacy_bytes(
        allocation_granularity: u64,
        actual_free_space: u64,
        caller_available_space: u64,
        caller_total_space: u64,
    ) -> Self {
        Self {
            allocation_granularity,
            free_space: actual_free_space,
            available_space: caller_available_space,
            total_space: caller_total_space,
            source: WindowsCounterSource::Legacy,
        }
    }
}

/// Gets one statistics snapshot for the filesystem containing `path`.
pub fn statvfs<P: AsRef<Path>>(path: P) -> Result<FsStats> {
    sys::statvfs(path.as_ref()).and_then(FsStats::from_counters)
}

/// Returns free space from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::free_space`] when multiple counters
/// are needed.
pub fn free_space<P: AsRef<Path>>(path: P) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::Free)
}

/// Returns available space from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::available_space`] when multiple
/// counters are needed.
pub fn available_space<P: AsRef<Path>>(path: P) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::Available)
}

/// Returns total space from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::total_space`] when multiple counters
/// are needed.
pub fn total_space<P: AsRef<Path>>(path: P) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::Total)
}

/// Returns allocation granularity from a newly acquired filesystem snapshot.
///
/// Call [`statvfs`] once and use [`FsStats::allocation_granularity`] when
/// multiple counters are needed.
pub fn allocation_granularity<P: AsRef<Path>>(path: P) -> Result<u64> {
    sys::space(path.as_ref(), SpaceKind::AllocationGranularity)
}

#[cfg(unix)]
fn validate_unix_counters(counters: FilesystemCounters) -> Result<u64> {
    let allocation_granularity = validate_granularity(counters.allocation_granularity)?;
    let maximum_blocks = counters
        .free_blocks
        .max(counters.available_blocks)
        .max(counters.total_blocks);
    checked_space(allocation_granularity, maximum_blocks)?;
    validate_space_values(
        counters.free_blocks,
        counters.available_blocks,
        counters.total_blocks,
    )?;
    Ok(allocation_granularity)
}

#[cfg(unix)]
pub(crate) fn space_from_counters(counters: FilesystemCounters, kind: SpaceKind) -> Result<u64> {
    let allocation_granularity = validate_unix_counters(counters)?;
    let blocks = match kind {
        SpaceKind::Free => counters.free_blocks,
        SpaceKind::Available => counters.available_blocks,
        SpaceKind::Total => counters.total_blocks,
        SpaceKind::AllocationGranularity => return Ok(allocation_granularity),
    };
    Ok(allocation_granularity * blocks)
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

    use super::{FilesystemCounters, FsStats, FsStatsQuery, statvfs};

    fn counters(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> FilesystemCounters {
        #[cfg(unix)]
        {
            FilesystemCounters::unix_blocks(
                allocation_granularity,
                free_space,
                available_space,
                total_space,
            )
        }
        #[cfg(windows)]
        {
            FilesystemCounters::windows_modern_bytes(
                allocation_granularity,
                free_space,
                available_space,
                total_space,
            )
        }
    }

    #[cfg(windows)]
    fn legacy_counters(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> FilesystemCounters {
        FilesystemCounters::windows_legacy_bytes(
            allocation_granularity,
            free_space,
            available_space,
            total_space,
        )
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

    #[cfg(windows)]
    #[test]
    fn rejects_available_space_above_free_space() {
        let error = FsStats::from_counters(counters(4096, 32_768, 36_864, 40_960)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn accepts_available_space_above_free_space() {
        let stats = FsStats::from_counters(counters(4096, 8, 9, 10)).unwrap();

        assert_eq!(stats.free_space(), 32_768);
        assert_eq!(stats.available_space(), 36_864);
        assert_eq!(stats.total_space(), 40_960);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_available_space_above_total_space() {
        let error = FsStats::from_counters(counters(4096, 8, 11, 10)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn filesystem_space() {
        let tempdir = tempdir().unwrap();
        let stats = statvfs(tempdir.path()).unwrap();

        assert!(stats.total_space() > 0);
        #[cfg(unix)]
        {
            assert!(stats.free_space() <= stats.total_space());
            assert!(stats.available_space() <= stats.total_space());
        }
        #[cfg(windows)]
        assert!(stats.available_space() <= stats.free_space());
    }

    #[test]
    fn prepared_query_returns_fresh_valid_snapshots() {
        let tempdir = tempdir().unwrap();
        let query = FsStatsQuery::new(tempdir.path()).unwrap();

        for stats in [query.snapshot().unwrap(), query.snapshot().unwrap()] {
            assert!(stats.total_space() > 0);
            assert!(stats.allocation_granularity() > 0);
            #[cfg(unix)]
            {
                assert!(stats.free_space() <= stats.total_space());
                assert!(stats.available_space() <= stats.total_space());
            }
            #[cfg(windows)]
            assert!(stats.available_space() <= stats.free_space());
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_modern_free_space_above_physical_total() {
        let error = FsStats::from_counters(counters(4096, 50_000, 10_000, 40_000)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(windows)]
    #[test]
    fn accepts_quota_limited_legacy_total_space() {
        let stats = FsStats::from_counters(legacy_counters(4096, 50_000, 10_000, 40_000)).unwrap();

        assert_eq!(stats.free_space(), 50_000);
        assert_eq!(stats.available_space(), 10_000);
        assert_eq!(stats.total_space(), 40_000);
    }
}
