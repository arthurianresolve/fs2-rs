## Purpose of this fork
This is a fork to evolve `fs2` into 2026, as original development of source has halted.

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

 
# fs2

Extended utilities for working with files and filesystems in Rust. `fs2`
requires Rust stable 1.97.1 or greater.

[![Documentation](https://docs.rs/fs2/badge.svg)](https://docs.rs/fs2)
[![Crate](https://img.shields.io/crates/v/fs2.svg)](https://crates.io/crates/fs2)

## Features

- [x] file descriptor duplication.
- [x] file locks.
- [x] file (pre)allocation.
- [x] file allocation information.
- [x] filesystem space usage information.

## Platforms

`fs2` should work on any platform supported by
[`libc`](https://github.com/rust-lang-nursery/libc#platforms-and-documentation).

The CI matrix continuously tests the native `x86_64` targets on Linux, macOS,
and Windows with Rust 1.97.1 and stable. The historical 32-bit and GNU
Windows targets are not currently covered by CI.

## Benchmarking

Stable Criterion benchmarks are provided for the public APIs. When benchmarking
files, account for the filesystem backing the temporary directory; `/tmp` is
often a `tmpfs` mount.

## License

`fs2` is primarily distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2015 Dan Burkert.
