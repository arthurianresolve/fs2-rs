use std::fs::File;
use std::io::Result;

use crate::sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AllocationCapability;

pub(crate) fn allocate(file: &File, len: u64) -> Result<()> {
    if sys::allocated_size(file)? < len {
        let _reservation = sys::allocate_space(file, len)?;
    }

    if file.metadata()?.len() < len {
        file.set_len(len)
    } else {
        Ok(())
    }
}
