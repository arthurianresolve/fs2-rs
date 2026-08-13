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
  procedures and expected results.  Its internal baseline is reviewed in
  `requirements-review.json`, which binds every requirement, source, and
  verification-inventory digest and retains the non-independent review
  boundary.
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
- `tool-assessment.json` records per-function intended and prohibited uses,
  I/O and topology, activity effects, failure escape/detection, fallbacks,
  common-mode risk, known problems, residual reliance, and revalidation
  triggers.  Its current decision is internal non-reliance: no function is
  qualified and no proposed or approved TQL is recorded.
- `configuration-management.json` assigns immutable internal baseline IDs,
  supersession links, change-impact and revalidation controls, and guarded
  promotion states.
- `archive-control.json` defines the exact ten-artifact internal staging
  package, SHA-256 and safe-path contract, 90-day GitHub Actions retention,
  retrieval procedure, and unresolved external-archive authorities.
- `archive-retrieval.json` binds the latest executed internal retrieval drill
  after the package has been downloaded and verified.
- `retrieval-results/` retains the canonical generated result for that drill;
  the static validator recomputes its normalized-LF SHA-256 and cross-checks
  every provenance and inventory field against the binding records.
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
- `evidence-index.json` distinguishes historical clean exact-commit CI
  snapshots from the current immutable internal staging package.  Neither is
  promoted until the external archive and release controls are satisfied.

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

## Internal archive staging and retrieval

On a push to `DO-178C`, the `assurance-package` CI job waits for the complete
nine-profile coverage matrix and the deterministic Windows native-fault job.
It downloads exactly those ten artifacts, rejects missing or extra artifact
directories, copies only regular files under canonical relative paths, and
writes an immutable manifest with an exact commit, tree, workflow run ID,
per-file byte count, and SHA-256 digest.  It also embeds the exact canonical
archive-control record used to construct the package, so later retrieval does
not depend on reconstructing changed policy bytes from the live branch.  The
job verifies that package before uploading `assurance-evidence-package` for 90
days.

After downloading the package without modification, repeat the retrieval
verification using its embedded control record and retain the generated result:

```text
python scripts/assurance_archive.py verify --package-dir <retrieved-package> --expected-commit <full-commit> --result target/assurance-retrieval-result.json
```

To compare against a live checkout as an additional control, pass
`--control-record` using `coverage/archive-control.json` from the package's
exact source commit.  A later binding commit changes the live record's latest
result and therefore must not be substituted for those source bytes.

The verifier rejects a wrong commit, stale control-record digest, changed or
missing file, unindexed file, unsafe path, symbolic link, case collision, or
noncanonical inventory.  This is an internal staging and retrieval rehearsal.
GitHub Actions is not designated as the controlled external archive, and the
repository does not invent an archive owner, backup policy, retention
authority, or disposition authority.

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
the shared GitHub identity.  The validator requires that declaration, all ten
checklist items passing, reciprocal and resolved findings, and a decision bound
to the exact candidate and native-fault manifest digest.  The approval for
candidate `15da349` remains immutable in Git history, but the current changes
affect reviewed requirements, tool assessment, validators, workflow, and
assurance records.  The review is therefore reopened until the new committed
candidate and clean Windows manifest are bound and reviewed.

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

The overall coverage package remains `draft`.  The internal
requirements baseline and detailed tool-function assessment are complete for
their explicitly non-certification scope.  CM-DO178C-0004 is bound to clean
candidate `1508aa1`, passing 36-job CI run `31731799593`, and a downloaded,
zero-discrepancy internal staging package.  The native-fault manifest for that
candidate is bound and ready, but its independent review decision remains
pending.  The approved certification basis, assigned
software level, any qualification/TQL determination, broader organizational
independence, controlled external archive, object-code analysis, release
approval, and authority acceptance remain open.  Passing tests, internal
review, or package integrity cannot infer those decisions.
