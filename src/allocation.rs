use std::fs::File;
use std::io::Result;

use crate::platform::Platform;

pub(crate) fn allocate<P: Platform>(file: &File, len: u64) -> Result<()> {
    if P::allocated_size(file)? < len {
        P::allocate_space(file, len)?;
    }

    if file.metadata()?.len() < len {
        file.set_len(len)
    } else {
        Ok(())
    }
}
