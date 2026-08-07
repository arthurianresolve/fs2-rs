# fs2-rs Domain Context

## File allocation

File allocation reserves physical filesystem space for a file and ensures the
file length reaches the requested size. `FileExt::allocate` owns the capacity
and length postcondition; platform adapters provide only the reservation
primitive through the allocation seam. A platform without a reservation
primitive must return `Unsupported` rather than claiming the physical-space
guarantee.

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
counter conversion, invariants, and the snapshot-first `FsStats` interface;
Unix and Windows adapters acquire the raw counters. Convenience queries remain
compatibility projections and each acquire a new snapshot.

## Support evidence

The support matrix owns target evidence levels, allocation capability claims,
and the CI job metadata that produces that evidence. Runtime evidence and
compile-only evidence remain distinct claims; the validator parses the workflow
and rejects drift between registry job references and the workflow's actual
matrix consumption.
