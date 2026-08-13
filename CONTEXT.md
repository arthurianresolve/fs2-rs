# fs2-rs Domain Context

## File allocation

File allocation reserves physical filesystem space for a file and ensures the
file length reaches the requested size. `FileExt::allocate` owns the capacity
and length postcondition, and the allocation module owns the public allocated
size projection. Platform adapters provide the current allocation state and
reservation primitive through the allocation seam. A platform without a
reservation primitive must return `Unsupported` rather than claiming the
physical-space guarantee.

## File locks

File locks provide shared or exclusive advisory access, either blocking or
non-blocking, plus release. The private lock module owns operation construction
and compatibility routing; Unix and Windows adapters translate those
operations into operating-system locking calls while preserving
platform-specific behavior. Shared lock-contract tests exercise the
cross-platform interface; adapter tests retain OS-specific semantics.

## Filesystem statistics

Filesystem statistics report free, available, and total space plus allocation
granularity. The stats module owns the named `FilesystemCounters` seam, checked
counter conversion, invariants, the snapshot-first `FsStats` interface, and the
prepared `FsStatsQuery` interface for repeated fresh snapshots; Unix and Windows
adapters acquire the raw counters. Convenience queries remain compatibility
projections and each acquire a new snapshot. The Windows adapter uses a
one-query full snapshot when the operating system supports it, retains the
legacy fallback, uses the narrowest correct query for scalar projections, and
recognizes exact drive roots without repeating volume-root discovery. A guarded
metadata-only handle query accelerates free and available space for online
regular files. Paths that are ineligible for a narrow query retain canonical
volume-root resolution. On Windows, modern snapshots report physical total
space while the legacy fallback may report a quota-limited total for the calling
user; scalar queries preserve the physical-free and caller-available domains and
fall back to the canonical provider when an optimized query is unavailable or
invalid. Platform adapters construct private raw counters through
source-specific constructors; the stats module alone owns their representation,
projection, conversion, and validation.

## Support evidence

The support matrix owns target evidence levels, allocation capability claims,
and the CI job metadata that produces that evidence. Runtime evidence and
compile-only evidence remain distinct claims; the validator parses the workflow
and rejects drift between registry job references and the workflow's actual
matrix consumption. JSON is validated once into an immutable support registry;
workflow validation and matrix generation consume only that model.

The `coverage/` work package separately owns internal requirements-based
coverage mappings, explicit production/test surface classifications, source
decision inventory, tool-assessment boundaries, and a gap register. Stable
line/region reporting and pinned-nightly branch diagnostics are separate
profiles with exact commit, tree, lockfile, host, target, and toolchain
provenance. Dirty or failed runs remain non-promotable; diagnostic branch
coverage is not MC/DC, and the package does not establish certification,
qualification, independence, or authority credit.

## Compatibility and performance evidence

The compatibility oracle compiles one frozen v0.4 consumer against exact fs2
0.4.3 and the current checkout across supported Rust editions, then exercises
the shared legacy behavior contract through both adapters. Legacy source shape
and stable behavior come from the v0.4 reference; intentional v0.5 corrections
remain canonical. Performance comparisons use one byte-identical benchmark
workload and dependency lock for both checkouts, counterbalance execution order
and physical A/B build slots on the same host and filesystem, balance logical
left/right placement across independent build replicates, and reject candidates
whose exact, distribution-free one-sided 95% median bound exceeds the applied
non-inferiority margin. The default margin is zero; a nonzero slowdown allowance
must be supplied explicitly. Both subjects are frozen before replicate staging
so a long run cannot observe live checkout edits. Confidence is computed from
at least six build-replicate medians, not repeated runs of the same binaries. A
pure policy module owns pairing, replicate aggregation, exact confidence bounds,
applied policy context, and decision rules; orchestration owns staging and
Criterion execution. The oracle is tooling-only and does not enter the
production dependency graph or call path.
