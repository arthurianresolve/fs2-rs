# fs2-rs Domain Context

## File allocation

File allocation reserves physical filesystem space for a file and ensures the
file length reaches the requested size. Platform adapters provide the
reservation primitive; the shared allocation module owns the capacity and
length postcondition.

## File locks

File locks provide shared or exclusive advisory access, either blocking or
non-blocking, plus release. The shared lock-operation module defines these
operations; Unix and Windows adapters translate them into operating-system
locking calls while preserving platform-specific behavior.
