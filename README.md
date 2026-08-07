# fs2

This is the maintained `fs2` fork at
[github.com/arthurianresolve/fs2-rs](https://github.com/arthurianresolve/fs2-rs),
focused on evolving the crate for Rust 2024 and current stable Rust releases.
The original implementation is from
[danburkert/fs2-rs](https://github.com/danburkert/fs2-rs).

Extended utilities for working with files and filesystems in Rust. `fs2`
requires Rust stable 1.97.1 or greater.

# Changes
1. Manifest modernization
    - Upgraded to SPDX license syntax
    - Added crate category and more accurate description
    - Removed deprecated Travis and AppVeyor metadata  
 * Dependency modernization
   - Replaced `winapi` with `windows-sys`
   - Replaced `tempdir` with `tempfile`
   - Updated to Rust 1.97.1 and Rust 2024 edition syntax
 * Updated to current `libc` library

[![Documentation](https://docs.rs/fs2/badge.svg)](https://docs.rs/fs2)
[![Crate](https://img.shields.io/crates/v/fs2.svg)](https://crates.io/crates/fs2)

## Features

- [x] file descriptor duplication.
- [x] file locks.
- [x] file (pre)allocation.
- [x] file allocation information.
- [x] filesystem space usage information.

## Platforms

`fs2` supports the Unix and Windows targets implemented by the platform
adapters in this repository. Unix support uses
[`libc`](https://github.com/rust-lang/libc); Windows support uses
[`windows-sys`](https://github.com/microsoft/windows-rs).

The CI matrix continuously tests the native `x86_64` targets on Linux, macOS,
and Windows with Rust 1.97.1 and stable. The historical 32-bit and GNU
Windows targets are not currently covered by the native test matrix. The
`armv7-unknown-linux-uclibceabihf` target is compile-checked separately with
nightly `build-std`; runtime tests require a target-specific emulator and
uClibc sysroot.

The target evidence and allocation capability claims are recorded in
[`support-matrix.json`](support-matrix.json). CI validates the matrix, runs
native runtime tests, and compile-checks the listed cross targets. Compile-only
evidence does not imply runtime support.

## Benchmarking

Stable Criterion benchmarks are provided for the public APIs. When benchmarking
files, account for the filesystem backing the temporary directory; `/tmp` is
often a `tmpfs` mount.

## License

`fs2` is primarily distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2015 Dan Burkert.
