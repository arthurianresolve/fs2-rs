use std::fs::File;
use std::io::Result;

use crate::sys;

#[derive(Clone, Copy, Debug)]
pub(crate) enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LockOperation {
    Acquire { mode: LockMode, nonblocking: bool },
    Release,
}

pub(crate) fn shared(file: &File) -> Result<()> {
    acquire(file, LockMode::Shared, false)
}

pub(crate) fn exclusive(file: &File) -> Result<()> {
    acquire(file, LockMode::Exclusive, false)
}

pub(crate) fn try_shared(file: &File) -> Result<()> {
    acquire(file, LockMode::Shared, true)
}

pub(crate) fn try_exclusive(file: &File) -> Result<()> {
    acquire(file, LockMode::Exclusive, true)
}

pub(crate) fn release(file: &File) -> Result<()> {
    sys::lock(file, LockOperation::Release)
}

fn acquire(file: &File, mode: LockMode, nonblocking: bool) -> Result<()> {
    sys::lock(file, LockOperation::Acquire { mode, nonblocking })
}
