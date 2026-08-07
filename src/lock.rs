use std::fs::File;
use std::io::{Error, Result};

use crate::platform::Platform;

#[derive(Clone, Copy)]
pub(crate) enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy)]
pub(crate) enum LockOperation {
    Acquire { mode: LockMode, nonblocking: bool },
    Release,
}

pub(crate) fn lock_shared<P: Platform>(file: &File) -> Result<()> {
    apply::<P>(
        file,
        LockOperation::Acquire {
            mode: LockMode::Shared,
            nonblocking: false,
        },
    )
}

pub(crate) fn lock_exclusive<P: Platform>(file: &File) -> Result<()> {
    apply::<P>(
        file,
        LockOperation::Acquire {
            mode: LockMode::Exclusive,
            nonblocking: false,
        },
    )
}

pub(crate) fn try_lock_shared<P: Platform>(file: &File) -> Result<()> {
    apply::<P>(
        file,
        LockOperation::Acquire {
            mode: LockMode::Shared,
            nonblocking: true,
        },
    )
}

pub(crate) fn try_lock_exclusive<P: Platform>(file: &File) -> Result<()> {
    apply::<P>(
        file,
        LockOperation::Acquire {
            mode: LockMode::Exclusive,
            nonblocking: true,
        },
    )
}

pub(crate) fn unlock<P: Platform>(file: &File) -> Result<()> {
    apply::<P>(file, LockOperation::Release)
}

pub(crate) fn contended_error<P: Platform>() -> Error {
    P::lock_error()
}

fn apply<P: Platform>(file: &File, operation: LockOperation) -> Result<()> {
    P::lock(file, operation)
}
