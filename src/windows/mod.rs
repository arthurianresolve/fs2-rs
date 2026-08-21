mod allocation;
mod file;
mod lock;
mod path;
mod stats;

pub(crate) use allocation::{ALLOCATE_SPACE_EXTENDS_LENGTH, allocate_space, allocation_state};
pub(crate) use file::duplicate;
pub(crate) use lock::{lock_error, lock_exclusive, lock_shared, unlock};
pub(crate) use stats::{StatsQuery, space, statvfs};

#[cfg(test)]
#[path = "tests.rs"]
// Keep the platform module implementation in `mod.rs` and place the
// platform-specific tests in `windows/tests.rs` for readability.
mod test;
