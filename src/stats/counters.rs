use std::io::Result;

#[cfg(unix)]
use super::validation::validate_unix_counters;
#[cfg(windows)]
use super::validation::validate_windows_counters;
use super::{FsStats, SpaceKind};

/// Platform-native filesystem counters before validation and byte conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilesystemCounters {
    repr: CounterRepr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CounterRepr {
    #[cfg(unix)]
    Unix(UnixCounters),
    #[cfg(windows)]
    Windows(WindowsCounters),
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UnixCounters {
    pub(super) allocation_granularity: u64,
    pub(super) free_blocks: u64,
    pub(super) available_blocks: u64,
    pub(super) total_blocks: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WindowsCounters {
    pub(super) allocation_granularity: u64,
    pub(super) free_space: u64,
    pub(super) available_space: u64,
    pub(super) total_space: u64,
    pub(super) source: WindowsCounterSource,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WindowsCounterSource {
    Modern,
    Legacy,
}

impl FilesystemCounters {
    #[cfg(unix)]
    pub(crate) const fn unix_blocks(
        allocation_granularity: u64,
        free_blocks: u64,
        available_blocks: u64,
        total_blocks: u64,
    ) -> Self {
        Self {
            repr: CounterRepr::Unix(UnixCounters {
                allocation_granularity,
                free_blocks,
                available_blocks,
                total_blocks,
            }),
        }
    }

    #[cfg(windows)]
    pub(crate) const fn windows_modern_bytes(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> Self {
        Self::windows_bytes(
            allocation_granularity,
            free_space,
            available_space,
            total_space,
            WindowsCounterSource::Modern,
        )
    }

    #[cfg(windows)]
    pub(crate) const fn windows_legacy_bytes(
        allocation_granularity: u64,
        actual_free_space: u64,
        caller_available_space: u64,
        caller_total_space: u64,
    ) -> Self {
        Self::windows_bytes(
            allocation_granularity,
            actual_free_space,
            caller_available_space,
            caller_total_space,
            WindowsCounterSource::Legacy,
        )
    }

    #[cfg(windows)]
    const fn windows_bytes(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
        source: WindowsCounterSource,
    ) -> Self {
        Self {
            repr: CounterRepr::Windows(WindowsCounters {
                allocation_granularity,
                free_space,
                available_space,
                total_space,
                source,
            }),
        }
    }

    #[cfg(unix)]
    #[inline]
    pub(crate) fn into_stats(self) -> Result<FsStats> {
        match self.repr {
            CounterRepr::Unix(counters) => validate_unix_counters(counters).map(|c| c.into_stats()),
        }
    }

    #[cfg(windows)]
    #[inline]
    pub(crate) fn into_stats(self) -> Result<FsStats> {
        match self.repr {
            CounterRepr::Windows(counters) => {
                validate_windows_counters(counters).map(|c| c.into_stats())
            }
        }
    }

    #[cfg(unix)]
    #[inline]
    pub(crate) fn space(self, kind: SpaceKind) -> Result<u64> {
        match self.repr {
            CounterRepr::Unix(counters) => validate_unix_counters(counters).map(|c| c.space(kind)),
        }
    }

    #[cfg(windows)]
    #[inline]
    pub(crate) fn space(self, kind: SpaceKind) -> Result<u64> {
        match self.repr {
            CounterRepr::Windows(counters) => {
                validate_windows_counters(counters).map(|c| c.space(kind))
            }
        }
    }
}

#[cfg(test)]
impl FilesystemCounters {
    #[cfg(unix)]
    pub(crate) const fn test(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> Self {
        Self::unix_blocks(
            allocation_granularity,
            free_space,
            available_space,
            total_space,
        )
    }

    #[cfg(windows)]
    pub(crate) const fn test(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> Self {
        Self::windows_modern_bytes(
            allocation_granularity,
            free_space,
            available_space,
            total_space,
        )
    }

    #[cfg(windows)]
    pub(crate) const fn test_legacy(
        allocation_granularity: u64,
        free_space: u64,
        available_space: u64,
        total_space: u64,
    ) -> Self {
        Self::windows_legacy_bytes(
            allocation_granularity,
            free_space,
            available_space,
            total_space,
        )
    }
}
