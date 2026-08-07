# fs2-rs Domain Context

## File allocation

File allocation reserves physical filesystem space for a file and ensures the
file length reaches the requested size. `FileExt::allocate` owns the capacity
and length postcondition; platform adapters provide only the reservation
primitive through the `AllocationOutcome` seam. A platform without a
reservation primitive must return `Unsupported` rather than claiming the
physical-space guarantee.

## File locks

File locks provide shared or exclusive advisory access, either blocking or
non-blocking, plus release. Private lock-operation types at the crate root
define these operations; Unix and Windows adapters translate them into
operating-system locking calls while preserving platform-specific behavior.
Shared lock-contract tests exercise the cross-platform interface; adapter
tests retain OS-specific semantics.

## Filesystem statistics

Filesystem statistics report free, available, and total space plus allocation
granularity. The stats module owns the named `FilesystemCounters` seam, checked
counter conversion, invariants, and public query projections; Unix and Windows
adapters acquire the raw counters.
