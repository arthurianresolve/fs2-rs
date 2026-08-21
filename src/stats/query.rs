use std::borrow::Cow;
#[cfg(unix)]
use std::ffi::CString;
use std::io::Result;
#[cfg(unix)]
use std::io::{Error, ErrorKind};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::FsStats;

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
    inner: crate::sys::StatsQuery,
}

impl FsStatsQuery {
    /// Prepares repeated statistics queries for the filesystem containing
    /// `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        Self::new_path(path.as_ref())
    }

    #[cfg(unix)]
    fn new_path(path: &Path) -> Result<Self> {
        let path = if path.is_absolute() {
            Cow::Borrowed(path)
        } else {
            Cow::Owned(std::path::absolute(path)?)
        };
        let path = CString::new(path.as_ref().as_os_str().as_bytes())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path contained a null"))?;
        Ok(Self {
            inner: crate::sys::StatsQuery::new(path),
        })
    }

    #[cfg(not(unix))]
    fn new_path(path: &Path) -> Result<Self> {
        let path = if path.is_absolute() {
            Cow::Borrowed(path)
        } else {
            Cow::Owned(std::path::absolute(path)?)
        };
        crate::sys::StatsQuery::new(path.as_ref()).map(|inner| Self { inner })
    }

    /// Acquires a fresh statistics snapshot.
    pub fn snapshot(&self) -> Result<FsStats> {
        self.inner.counters().and_then(FsStats::from_counters)
    }
}
