# DO-178C coverage work package

This directory is the local canonical owner for the `DO-178C` branch's
requirements-based test-coverage records.  It is an internal engineering
control package.  It does not establish certification credit, independence,
MC/DC acceptance, object-code coverage, tool qualification, or authority
acceptance.

The records are deliberately split by concern:

- `assurance-context.json` records the planning assumptions and open basis
  decisions.
- `requirements.json` maps derived internal requirements to verification
  procedures and expected results.
- `verification-inventory.json` freezes the test and doctest identities used by
  those mappings so renames fail validation instead of silently weakening the
  trace.
- `surface.json` records production and excluded/test surfaces without silently
  reducing a denominator.
- `decision-inventory.json` records source-level decisions and their mapped
  tests.  The inventory is an assessment input, not an MC/DC result.
- `mcdc.json` records manually reviewed source-level condition observations and
  independence pairs.  Its reported closure is internal engineering evidence
  for the registered source-pair scope only; it is not tool-generated MC/DC,
  object-code coverage, qualified-tool output, or certification credit.
- `policy.json` defines the internal gates and non-claims.
- `tool-assessment.json` records the intended functions, failure modes, and
  residual reliance for the coverage tools.
- `gap-register.json` preserves the historical focused-run measurements,
  records the clean local cross-host snapshot separately, and lists open
  closure actions.  An open gap is not silently converted into a pass.
- `run-manifest.schema.json` defines the provenance fields emitted by
  `scripts/collect_coverage.py`.
- `evidence-index.json` indexes the clean local snapshots for review, but keeps
  them explicitly disposable and unpromoted until the configured matrix is
  complete, independently reviewed, and placed in a controlled archive.

Windows manifests also retain `windows-provider.json`.  The
`records_provider_availability` test records whether `kernel32.dll` and
`GetDiskSpaceInformationW` are present and whether the provider returned an
available, unavailable, or error outcome.  The native failure tests inject
return values at reviewed result adapters; they do not claim kernel or OS
fault injection, independence, tool qualification, or certification credit.

## Local validation

Run the record validator from the repository root:

```text
python scripts/validate_coverage.py
```

Run a controlled local collection only from a clean, exact-commit checkout:

```text
python scripts/collect_coverage.py --profile stable --target x86_64-pc-windows-msvc --output-dir target/coverage-stable --expected-commit <full-commit> --locked
```

The `branch` profile is diagnostic branch reporting on the pinned nightly
toolchain.  It is not an MC/DC claim.  The `condition` profile repeats that
branch report with Rust's condition instrumentation flag; the pinned compiler
and `cargo-llvm-cov` combination currently emits no independent condition
total, so it is explicitly instrumentation-only rather than condition or
MC/DC coverage:

```text
python scripts/collect_coverage.py --profile branch --target x86_64-pc-windows-msvc --output-dir target/coverage-branch --expected-commit <full-commit> --locked
```

The latest available probe on `nightly-2026-08-13` also rejects
`-Z coverage-options=mcdc`; the accepted compiler values remain
`block|branch|condition`.  Until an approved basis and a capable, assessed
toolchain exist, the source-pair records remain internal, non-credit evidence.

The CI staging gate adds `--require-pass`; focused, failed, indeterminate, or
provenance-error manifests may be retained for analysis but cannot satisfy it.

Each run must retain the full commit, tree, lockfile hash, compiler host target,
requested target, host, toolchain, tool version, command, native exit status,
logs, raw report, and artifact hashes.  A pass manifest is valid only when the
compiler host target matches the requested target; cross-compilation is not
native runtime evidence.  The registered `Cargo.lock` digest uses canonical LF
text normalization so equivalent Windows and Unix checkouts compare
identically; artifact digests remain byte-for-byte hashes.  A report without
this provenance is not eligible for the internal gate.

## Review state

The current records are `draft` or `not_ready`.  The local snapshot closes the
emitted raw metrics and records provider availability for the Linux and
Windows hosts exercised, but the configured Apple-silicon matrix, approved
certification basis, assigned software level, qualified coverage-tool
determination, independence plan, native OS fault-injection disposition, and
external archive remain open.  Those items remain explicit decisions rather
than being inferred from passing tests or diagnostic branch percentages.
