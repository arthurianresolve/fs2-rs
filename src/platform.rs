use std::fs::File;
use std::io::{Error, Result};
use std::path::Path;

use crate::FsStats;
use crate::lock::LockOperation;

pub(crate) trait Platform {
    fn duplicate(file: &File) -> Result<File>;
    fn allocated_size(file: &File) -> Result<u64>;
    fn allocate_space(file: &File, len: u64) -> Result<()>;
    fn lock(file: &File, operation: LockOperation) -> Result<()>;
    fn lock_error() -> Error;
    fn statvfs(path: &Path) -> Result<FsStats>;
}
