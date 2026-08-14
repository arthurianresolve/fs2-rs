# DO-178C coverage work package

This directory is the local canonical owner for the `DO-178C` branch's
requirements-based test-coverage records.  It is an internal engineering
control package.  The project owner has assigned DAL B and has declared an
internal human-review role independent from the implementation agent.  Those
internal decisions do not establish an approved certification basis,
authority-approved independence, MC/DC acceptance, source/object equivalence,
object-code coverage, tool qualification, certification credit, release
approval, or authority acceptance.

The records are deliberately split by concern:

- `assurance-context.json` records the internal assurance context, assigned
  DAL B level, linked controls, and open controlled-basis decisions.
- `software-level-assignment.json` records the project owner's explicit DAL B
  determination separately from the still-missing applicable certification
  basis and authority acceptance.
- `independence-plan.json` separates the Codex implementation role, the human
  organizational reviewer `IR-PERSON-001`, and the GitHub publication service
  account.  The service account has no decision authority.  Its review gate is
  bound to a canonical pre-commit change-set digest, avoiding an impossible
  self-reference to the commit that will contain the decision.
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
- `object-analysis.json` and `object-analysis-run.schema.json` define
  exact-commit native ELF, Mach-O, and COFF inventory collection.  Retained
  archives, members, symbols, sections, and disassembly support target review;
  `source-object-reconciliation.json` adds a reviewed module-level
  symbol-to-source inventory and an explicit compiler-generated-code
  non-credit disposition.  `semantic-source-object.json` defines a separate
  native companion run that retains MIR, LLVM IR/debug locations, and a
  debug-info object for reproducible semantic inspection.  It also compares
  direct production and debug-companion object bytes after LLVM debug sections
  are removed.  That bounded comparison does not establish full rlib/archive
  identity, complete source/object equivalence, or object-code coverage.
- `policy.json` defines the internal gates and non-claims.
- `tool-assessment.json` records per-function intended and prohibited uses,
  I/O and topology, activity effects, failure escape/detection, fallbacks,
  common-mode risk, known problems, residual reliance, and revalidation
  triggers.  Its current decision is internal non-reliance: no function is
  qualified and no proposed or approved TQL is recorded.
- `configuration-management.json` assigns immutable internal baseline IDs,
  supersession links, change-impact and revalidation controls, and guarded
  promotion states.
- `archive-control.json` defines the exact sixteen-artifact internal staging
  package, SHA-256 and safe-path contract, 90-day GitHub Actions retention,
  primary and independently implemented verification procedures, and
  unresolved external-archive authorities.
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
- `external-reference-registry.json` and
  `scripts/external_reference_resolver.py` provide a fail-closed typed,
  revision/configuration/digest-bound resolver for future authority-owned
  records.  The empty registry deliberately reports the missing records.
- `external-archive-endpoint.schema.json` and
  `scripts/archive_transport.py` provide immutable filesystem publish/retrieve
  mechanics for technical trials.  They cannot designate an archive or fill
  owner, access, backup, retention, disposition, or acceptance decisions.

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

The top-level validator includes the software-level, independence,
target-object, external-reference, endpoint-schema, archive, MC/DC, support
matrix, and cross-record controls.  Its negative tests must also pass; a static
validation pass alone does not prove that every fail-closed path was exercised.

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

Run a controlled local collection only from a clean, exact-commit checkout.
The stable evidence compiler is Rust 1.97.1 and reports LLVM 22.1.6; the
package MSRV remains Rust 1.88.0:

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

The exact `nightly-2026-08-14` probe rejects `-Z coverage-options=mcdc`; the
accepted compiler values remain `block|branch|condition`.  The stable
Rust 1.97.1 probe also rejects the unstable MC/DC option.  The executed
condition report contains empty `mcdc_records` and an LLVM `mcdc.count` of
zero.  Until an approved basis and a capable, assessed toolchain exist, the
source-pair records remain internal, non-credit evidence.

The LLVM 2022 presentation is retained as an advisory design input.  Its
frontend source mappings, per-decision bitmap test vectors, and
independence-pair analysis are useful semantic requirements for evaluating a
future Rust producer.  Current Clang implements MC/DC coverage, but LLVM
backend availability does not make rustc emit the required frontend mappings.
Accordingly, this work package adopts the paper's evidence and validation
concepts and defers any Rust MC/DC tool or credit claim.

Collect a native target-object inventory only from a clean checkout whose host
compiler target equals the requested target:

```text
python scripts/collect_object_analysis.py --target x86_64-pc-windows-msvc --output-dir target/object-analysis --expected-commit <full-commit>
python scripts/validate_object_analysis.py --manifest target/object-analysis/object-analysis-manifest.json --expected-commit <full-commit> --require-pass
```

Passing enhanced object runs also retain `source-object-map.json`.  The map is
derived from the exact defined-symbol inventory and records module-level
source associations only; it is not a statement, basic-block, semantic, or
object-code coverage map.

The semantic follow-on is collected separately so its debug-info companion
object cannot be confused with the production release object inventory:

```text
python scripts/collect_semantic_source_object.py --target x86_64-pc-windows-msvc --output-dir target/semantic-source-object --expected-commit <full-commit>
python scripts/validate_semantic_source_object.py --manifest target/semantic-source-object/semantic-source-object-manifest.json --expected-commit <full-commit> --require-pass
```

The map reconciles retained MIR functions, LLVM debug locations, and
diagnostic conditional sites to the current production source inventory.  The
collector additionally requires equal direct production/debug-companion object
bytes after `llvm-objcopy --strip-debug`.  The counts and byte comparison are
still diagnostic: they are not complete source/object equivalence, executed
object-code structural coverage, or an MC/DC result.

The analogous CI matrix uses `x86_64-unknown-linux-gnu` and
`aarch64-apple-darwin` on their native hosts.  A dirty local run may be retained
only as focused implementation evidence and cannot satisfy the clean-candidate
gate.

The CI staging gate adds `--require-pass`; focused, failed, indeterminate, or
provenance-error manifests may be retained for analysis but cannot satisfy it.

## Internal archive staging and retrieval

On a push to `DO-178C`, the `assurance-package` CI job waits for the complete
nine-profile coverage matrix, three native target-object inventories, three
semantic source-object companions, and the deterministic Windows native-fault
job.  It downloads exactly those sixteen
artifacts, rejects missing or extra artifact directories, copies only regular
files under canonical relative paths, and writes an immutable manifest with an
exact commit, tree, workflow run ID, per-file byte count, and SHA-256 digest.
It also embeds the exact canonical archive-control record used to construct
the package, so later retrieval does not depend on reconstructing changed
policy bytes from the live branch.  The job runs both the primary verifier and
the independently implemented verifier before uploading
`assurance-evidence-package` for 90 days.

After downloading the package without modification, repeat the retrieval
verification using its embedded control record and retain the generated result:

```text
python scripts/assurance_archive.py verify --package-dir <retrieved-package> --expected-commit <full-commit> --result target/assurance-retrieval-result.json
python scripts/independent_archive_verify.py --package-dir <retrieved-package> --expected-commit <full-commit> --result target/assurance-independent-result.json
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

Future authority-owned records can be resolved without weakening that
boundary:

```text
python scripts/external_reference_resolver.py --result target/external-reference-resolution.json
python scripts/external_reference_resolver.py --require-resolved
```

The first command records an honest pending result while the checked-in
registry is incomplete; the second fails until all required controlled records
are present and digest-bound.  After an archive provider and endpoint have
actually been designated by the appropriate authority, the technical adapter
can publish and retrieve without overwrite:

```text
python scripts/archive_transport.py publish --package-dir <verified-package> --endpoint <technical-trial-endpoint.json> --expected-commit <full-commit> --result <publish-result.json>
python scripts/archive_transport.py retrieve --package-id <package-id> --output-dir <new-output-dir> --endpoint <technical-trial-endpoint.json> --expected-commit <full-commit> --result <retrieve-result.json>
```

Even a successful transport receipt keeps `external_archive_verified` false;
the technical adapter cannot make the missing organizational decisions.

## Independent review sequence

The current implementation is reviewed before publication.  The human
reviewer receives the complete change set, local test evidence, residual
limitations, and post-push verification plan.  The canonical review-scope
digest binds every tracked modification and untracked candidate file relative
to preparation parent `d1054422079406ba9e4d59805016d9c97a6b01ed`; only the
mechanical insertion of the review decision and the corresponding review
markers for tool functions F-001, F-003, F-004, and F-005 is normalized out.
An approval permits one atomic commit and push.  It does not pre-accept the clean
exact-commit cross-host results that can exist only after publication.

The assigned organizational reviewer is the person `IR-PERSON-001`.  GitHub
login `arthurianresolve` is separately modeled as a publication service
account with no decision authority.  The reviewer has declared that the human
review and implementation agent are independent in their respective roles and
that sharing the publication identity creates no internal conflict under that
separation.  This is a self-attested internal independence arrangement, not an
authority-approved independence plan or external identity proof.

The historical approval for candidate `15da349` remains immutable in Git
history.  The Windows native-fault approval is independently bound to candidate
`1508aa1` and native-fault manifest SHA-256
`2c2f6a3af7fefcf210f56fa35d304c282c1289495a2e6f53ea7953970c0d4a04`, with
all ten objectives passing and no findings.  It satisfies only the registered
internal Windows native-fault review condition.

The current candidate hardens artifact-path handling in the native-fault and
Application Verifier validators.  CI run `31774523702` provides the clean
exact-commit Windows native-fault run, and the affected candidate-specific
review disposition is recorded in `IR-WINDOWS-NATIVE-FAULTS-001`.  The
validator gap remains open for future change-impact review and does not imply
qualification or authority acceptance.

If review findings change code, tests, collectors, validators, requirements,
or assurance records, recompute the candidate digest and repeat the
implementation review.  After approval and publication, regenerate and review
all affected clean exact-commit evidence.  A finding in that evidence requires
a successor change; it must not be hidden by rebinding the approved pre-commit
review.

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
their explicitly non-certification scope, and DAL B is assigned internally.
CM-DO178C-0004 remains the approved predecessor bound to clean candidate
`1508aa1`, passing 36-job CI run `31731799593`, and its downloaded,
zero-discrepancy internal staging package.  CM-DO178C-0005 is now bound to
exact candidate `f24c570bc9c302e4a5cb14cd580b7247f9888916`, tree
`46db086cfdd538c498de4e1993d6af1805af0686`, passing 39-job CI run
`31774523702`, and the object-inclusive internal package
`ASSURANCE-f24c570bc9c3-31774523702`.  The package contains the clean
three-target inventory matrix and was accepted as exact-commit internal DAL B
engineering evidence.  The target-specific inventory review is approved for
the registered internal scope.  The derived reconciliation records module-
  level symbol-to-source observations and explicitly treats compiler-generated
  code as non-credit; the semantic companion now retains bounded production
  non-debug object-byte equality evidence and remains open for target-specific
  review and any required complete source/object or object-code follow-on.

The applicable controlled certification basis and its DAL B binding, any
qualification/TQL determination, authority-approved independence, controlled
  external archive, production-byte semantic source/object mapping,
  compiler-generated-code reconciliation under an applicable basis,
  object-code structural coverage,
release approval, and authority acceptance remain open.  Passing tests,
internal human review, transport mechanics, or package integrity cannot infer
those decisions.
