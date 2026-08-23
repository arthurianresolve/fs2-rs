use std::fs::File;
use std::io::Result;

use crate::sys;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AllocationState {
    pub(crate) allocated_size: u64,
    pub(crate) file_size: u64,
}

#[inline]
pub(crate) fn allocated_size(file: &File) -> Result<u64> {
    sys::allocation_state(file).map(|state| state.allocated_size)
}

#[inline]
pub(crate) fn allocate(file: &File, len: u64) -> Result<()> {
    allocate_with_state(file, len, sys::allocation_state(file))
}

fn allocate_with_state(file: &File, len: u64, state: Result<AllocationState>) -> Result<()> {
    let state = state?;
    let reservation_needed = state.allocated_size < len;
    let reservation_can_set_length = reservation_needed && sys::ALLOCATE_SPACE_EXTENDS_LENGTH;

    if reservation_needed {
        // On platforms with ALLOCATE_SPACE_EXTENDS_LENGTH, reserving physical space
        // also guarantees the logical file length is at least `len` when needed.
        // Keep length-extension checks explicit to avoid implicit control-flow coupling.
        sys::allocate_space(file, state, len)?;
    }

    if !reservation_can_set_length && state.file_size < len {
        extend_file_length_after_snapshot(file, len)?;
    }

    Ok(())
}

fn extend_file_length_after_snapshot(file: &File, len: u64) -> Result<()> {
    if file.metadata()?.len() < len {
        file.set_len(len)
    } else {
        Ok(())
    }
}
