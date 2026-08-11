# fs2

This is the maintained `fs2` fork at
[github.com/arthurianresolve/fs2-rs](https://github.com/arthurianresolve/fs2-rs),
focused on evolving the crate for Rust 2024 and current stable Rust releases.
The original implementation is from
[danburkert/fs2-rs](https://github.com/danburkert/fs2-rs).

Extended utilities for working with files and filesystems in Rust. `fs2`
requires Rust stable 1.88 or greater.

# Changes
1. Manifest modernization
    - Upgraded to SPDX license syntax
    - Added crate category and more accurate description
    - Removed deprecated Travis and AppVeyor metadata  
 * Dependency modernization
   - Replaced `winapi` with `windows-sys`
   - Replaced `tempdir` with `tempfile`
   - Updated to Rust 1.88 and Rust 2024 edition syntax
 * Updated to current `libc` library

[![Documentation](https://docs.rs/fs2/badge.svg)](https://docs.rs/fs2)
[![Crate](https://img.shields.io/crates/v/fs2.svg)](https://crates.io/crates/fs2)

## Features

- [x] file descriptor duplication.
- [x] file locks.
- [x] file (pre)allocation.
- [x] file allocation information.
- [x] filesystem space usage information.

On Unix, `FileExt::duplicate` retains the original crate's `dup(2)` semantics,
including an inheritable descriptor. Use `File::try_clone` when the duplicate
must be close-on-exec.

## Platforms

`fs2` supports the Unix and Windows targets implemented by the platform
adapters in this repository. Unix support uses
[`libc`](https://github.com/rust-lang/libc); Windows support uses
[`windows-sys`](https://github.com/microsoft/windows-rs).

On Windows, filesystem snapshots report physical total capacity when the
modern disk-space provider is available. On systems that require the legacy
fallback, the reported total may be limited by the calling user's disk quota.

The CI matrix continuously tests the native `x86_64` targets on Linux, macOS,
and Windows with Rust 1.88 and stable. The historical 32-bit and GNU
Windows targets are not currently covered by the native test matrix. The
`armv7-unknown-linux-uclibceabihf` target is compile-checked separately with
nightly `build-std`; runtime tests require a target-specific emulator and
uClibc sysroot.

The target evidence and allocation capability claims are recorded in the
repository's [`support-matrix.json`](https://github.com/arthurianresolve/fs2-rs/blob/v0.5/support-matrix.json).
CI validates the matrix and generates its native and cross-target job matrices
from the registry, then runs native runtime tests and compile-checks the listed
cross targets. Compile-only evidence does not imply runtime support.

## Benchmarking

Stable Criterion benchmarks are provided for the public APIs in the separate
`fs2-benchmarks` workspace member. From a repository checkout, run them with
`cargo bench --manifest-path benchmarks/Cargo.toml`. When benchmarking files,
account for the filesystem backing the temporary directory; `/tmp` is often a
`tmpfs` mount.

`statvfs` is the snapshot-first interface: it acquires and validates one
consistent set of filesystem counters. When several counters are needed, prefer
one `statvfs` snapshot and read its accessors rather than calling the individual
convenience functions, which each acquire a new snapshot.
When an application needs fresh snapshots repeatedly for the same filesystem,
construct `FsStatsQuery` once and call `snapshot`; it reuses platform path
preparation without caching counter values. The `stats_snapshot` and
`prepared_stats` benchmark groups measure both usage patterns. On Windows, the
`windows_root_stats` group also measures exact drive-root preparation and scalar
queries.

From a repository checkout, the compatibility oracle compiles one frozen v0.4
consumer against both fs2 0.4.3 and the current checkout across Rust editions
2015 through 2024, then runs the shared behavior fixture against both. Run it with
`python scripts/validate_compatibility.py`. Performance comparisons use the
same benchmark source for both subjects through
`python scripts/compare_performance.py --baseline <path> --candidate <path>`.
The default `fs2_legacy` workload uses only the v0.4-compatible API surface.
Use `--bench fs2` for v0.5-only APIs. The `fs_compat` workload covers the API
intersection with fs4; select it with `--bench fs_compat` and identify an fs4
subject with `--baseline-package fs4` or `--candidate-package fs4`. It excludes
file duplication because fs4 does not expose an equivalent operation. Same-lock
comparisons are required by default; use `--allow-different-locks` explicitly
when comparing releases with different dependency graphs, such as upstream
v0.4.3, v0.5, and fs4. The performance command defaults to 24 alternating pairs
across six independent build replicates and exits unsuccessfully unless every
selected workload proves non-regression. It freezes both subjects before the
first build so edits to a live checkout cannot contaminate later replicates; use
a benchmark-name filter to keep targeted comparisons practical. Pair counts
must be a multiple of eight so physical build placement and execution order
remain balanced. For private refactors, every comparison still requires paired
timing; object-file equality is not used as a substitute because public generic
code is generated in the consumer crate.

## License

`fs2` is primarily distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2015 Dan Burkert.
