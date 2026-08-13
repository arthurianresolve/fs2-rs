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
  records the current clean cross-host CI snapshot separately, and lists open
  closure actions.  An open gap is not silently converted into a pass.
- `run-manifest.schema.json` defines the provenance fields emitted by
  `scripts/collect_coverage.py`.
- `windows-native-faults.json` separates deterministic Win32-boundary error
  activation, optional user-mode Application Verifier depth, and the
  inapplicable kernel-driver verification path.
- `windows-native-fault-review.json` assigns the independent-review request,
  discloses identity and common-mode risks, binds the eventual clean candidate,
  records findings and checklist results, and prevents assignment from being
  treated as approval.  Its schema is
  `windows-native-fault-review.schema.json`.
- `windows-native-fault-run.schema.json` and
  `windows-appverifier-run.schema.json` define fail-closed evidence records for
  those two Windows procedures.
- `evidence-index.json` indexes the current clean exact-commit CI snapshots for
  review, but keeps them explicitly disposable and unpromoted until they are
  placed in a controlled archive.

Windows manifests also retain `windows-provider.json`.  The
`records_provider_availability` test records whether `kernel32.dll` and
`GetDiskSpaceInformationW` are present and whether the provider returned an
available, unavailable, or error outcome.  The native failure tests inject
return values at result adapters and separately activate real Windows-returned
errors for access rights, lock contention, unavailable volumes, and invalid
handles at the `DuplicateHandle`, allocation, lock, and unlock boundaries.
Those deterministic scenarios are OS-mediated internal evidence; they are not
kernel-mode Driver Verifier injection, independence, tool qualification, or
certification credit.

## Local validation

Run the record validator from the repository root:

```text
python scripts/validate_coverage.py
```

Collect the deterministic Windows native-fault matrix from a clean exact-commit
checkout, then validate its manifest:

```text
python scripts/collect_windows_native_faults.py --output-dir target/windows-native-faults --expected-commit <full-commit>
python scripts/validate_coverage.py --windows-native-fault-manifest target/windows-native-faults/windows-native-fault-manifest.json --expected-commit <full-commit> --require-pass
```

Application Verifier low-resource simulation is optional robustness depth for
the dedicated test process.  Its collector checks elevation before invoking
the tool, records an indeterminate preflight without opening UAC when the host
is not elevated, requires an observed baseline-to-injected `CreateFileW`
transition, and always attempts removal of the exact generated image settings:

```text
python scripts/collect_windows_appverifier.py --output-dir target/windows-appverifier --expected-commit <full-commit>
python scripts/validate_coverage.py --windows-appverifier-manifest target/windows-appverifier/windows-appverifier-manifest.json --expected-commit <full-commit> --require-pass
```

Run that optional procedure only on an elevated disposable Windows test host.
Do not enable Driver Verifier against operating-system or filesystem drivers:
this repository contains no kernel-mode driver for it to target, and such a run
would not isolate fs2 behavior.

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

## Independent review sequence

Commit and push the technical review candidate before performing the review.
That order gives the reviewer one immutable source commit and lets the
`windows-native-faults` CI job produce a clean exact-commit manifest.  Bind the
review record to that commit, tree, manifest reference, and manifest SHA-256
before changing its status to `in_review`.

The assigned reviewer is `github:arthurianresolve`.  Assignment does not prove
acceptance or independence.  The local publication identity is also
`arthurianresolve`, so the reviewer must explicitly assess implementation
authorship, organizational or process separation, technical independence,
independent expected results, common-mode dependencies, and the rationale for
the shared GitHub identity.  The validator required that declaration, all ten
checklist items passing, reciprocal and resolved findings, and a decision bound
to the exact candidate and native-fault manifest digest.  The previous
approval was bound to candidate `70cbe5e`; the current candidate `15da349`
changed the reviewed source and assurance records.  The current record is
bound to the clean Windows manifest for `15da349` (SHA-256
`8d22fea7c99a9181c4538fe82079207e453f67579fa260ed3341308df17cc464`) and
records the fresh approval for the registered internal review condition.  It
remains non-certification, non-qualification, and non-authority evidence.

If review findings change code, tests, collectors, validators, requirements,
or assurance records, create and push a new candidate, regenerate clean native
evidence, rebind the review record, and repeat affected checks.  Record the
completed review decision only after the final candidate is unchanged.

Each run must retain the full commit, tree, lockfile hash, compiler host target,
requested target, host, toolchain, tool version, command, native exit status,
logs, raw report, and artifact hashes.  A pass manifest is valid only when the
compiler host target matches the requested target; cross-compilation is not
native runtime evidence.  The registered `Cargo.lock` digest uses canonical LF
text normalization so equivalent Windows and Unix checkouts compare
identically; artifact digests remain byte-for-byte hashes.  A report without
this provenance is not eligible for the internal gate.

## Review state

The overall coverage package remains `draft` or `not_ready`.  The current CI
snapshot closes the emitted raw metrics for Linux, Windows, and the configured
Apple-silicon matrix, and records Windows provider availability.  The current
native-fault review condition is satisfied for candidate `15da349`; the
approved certification basis, assigned software level, qualified coverage-tool
determination, broader independence plan, and external archive remain open.
These items remain explicit decisions rather than being inferred from passing
tests or diagnostic branch percentages.
