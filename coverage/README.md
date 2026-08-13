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
- `policy.json` defines the internal gates and non-claims.
- `tool-assessment.json` records the intended functions, failure modes, and
  residual reliance for the coverage tools.
- `gap-register.json` records the current focused-run measurements and open
  closure actions.  An open gap is not silently converted into a pass.
- `run-manifest.schema.json` defines the provenance fields emitted by
  `scripts/collect_coverage.py`.
- `evidence-index.json` is an intentionally empty staging index until a clean,
  exact-commit run is produced and independently reviewed.

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

The CI staging gate adds `--require-pass`; focused, failed, indeterminate, or
provenance-error manifests may be retained for analysis but cannot satisfy it.

Each run must retain the full commit, tree, lockfile hash, host, target,
toolchain, tool version, command, native exit status, logs, raw report, and
artifact hashes.  A report without this provenance is not eligible for the
internal gate.

## Review state

The current records are `draft` or `not_ready`.  The repository does not yet
contain an approved certification basis, assigned software level, qualified
coverage tool determination, independence plan, or external archive.  Those
items remain explicit open decisions rather than being inferred from passing
tests or diagnostic branch percentages.
