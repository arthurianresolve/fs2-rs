#!/usr/bin/env python3
"""Run byte-identical Criterion workloads against two filesystem crates."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from measurement_policy import (
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_PAIRS,
    DEFAULT_SAMPLE_SIZE,
    DEFAULT_WARM_UP_TIME,
    MEASUREMENT_POLICY_PATH,
    MIN_GATING_PAIRS,
    PAIRS_PER_BUILD_REPLICATE,
    PAIR_ORDER,
)
from performance_harness import (
    BENCHMARKS,
    BENCHMARKS_BY_NAME,
    REPORT_SCHEMA_VERSION,
    ROOT,
    SUBJECT_PACKAGES,
    benchmark_workload,
    cargo,
    collect_estimates,
    criterion_output_root,
    default_report_path,
    ensure_no_transient_failures,
    freeze_benchmark_inputs,
    freeze_repositories,
    prepare_subject,
    repository_state,
    repository_tree_digest,
    run_benchmarks,
    stage_repository,
    subject_arguments,
    transient_failure_count,
    transient_failure_records,
    unescape_failure_label,
    write_json_report,
)
from performance_policy import (
    DEFAULT_NON_INFERIORITY_MARGIN,
    evaluate,
    pair_plan,
    summarize_replicate,
)




def balanced_pair_count(value: str) -> int:
    pairs = int(value)
    if pairs < MIN_GATING_PAIRS or pairs % (PAIRS_PER_BUILD_REPLICATE * 2) != 0:
        raise argparse.ArgumentTypeError(
            f"must be a multiple of 8 and at least {MIN_GATING_PAIRS} to provide "
            "at least six independent build replicates"
        )
    return pairs


def non_inferiority_margin(value: str) -> float:
    margin = float(value)
    if not 0 <= margin < 1:
        raise argparse.ArgumentTypeError("must be at least 0 and less than 1")
    return margin


def _compare(args: argparse.Namespace, report_path: Path) -> None:
    baseline, baseline_commit = repository_state(args.baseline, "baseline")
    candidate, candidate_commit = repository_state(args.candidate, "candidate")
    if baseline == candidate:
        fail("baseline and candidate must be different checkouts")

    policy_sha256 = hashlib.sha256(MEASUREMENT_POLICY_PATH.read_bytes()).hexdigest()

    baseline_arguments = subject_arguments(args.bench, args.baseline_package)
    candidate_arguments = subject_arguments(args.bench, args.candidate_package)
    print(
        f"subjects: baseline={args.baseline_package} "
        f"candidate={args.candidate_package}"
    )
    print(f"commits: baseline={baseline_commit} candidate={candidate_commit}")
    print(f"measurement policy sha256={policy_sha256}")

    with tempfile.TemporaryDirectory(prefix="fs2-performance-") as temporary:
        temporary_root = Path(temporary)
        benchmark_inputs, frozen_lockfile = freeze_benchmark_inputs(
            temporary_root / "frozen-inputs"
        )
        workload = benchmark_workload(args.bench, benchmark_inputs)
        digest = hashlib.sha256(workload.read_bytes()).hexdigest()
        print(f"benchmark workload sha256={digest}")
        if args.target_root is not None:
            target_root = args.target_root.resolve()
            target_root.mkdir(parents=True, exist_ok=True)
            print(f"shared target cache: {target_root}")
        else:
            target_root = temporary_root / "cargo-target"

        repositories = freeze_repositories(
            temporary_root / "frozen-subjects",
            {"baseline": baseline, "candidate": candidate},
        )
        tree_digests: dict[str, str] = {}
        for subject, source, expected_commit in (
            ("baseline", baseline, baseline_commit),
            ("candidate", candidate, candidate_commit),
        ):
            _, current_commit = repository_state(source, subject)
            if current_commit != expected_commit:
                fail(f"{subject} changed while benchmark inputs were being staged")
            source_digest = repository_tree_digest(source)
            frozen_digest = repository_tree_digest(repositories[subject])
            if source_digest != frozen_digest:
                fail(f"{subject} frozen checkout differs from its source tree")
            tree_digests[subject] = source_digest
            print(f"{subject} tree sha256={source_digest}")
        metadata: dict[str, object] = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "baseline_ref": str(args.baseline),
            "candidate_ref": str(args.candidate),
            "baseline_commit": baseline_commit,
            "candidate_commit": candidate_commit,
            "benchmark": args.bench,
            "filter": args.filter,
            "baseline_package": args.baseline_package,
            "candidate_package": args.candidate_package,
            "pairs": args.pairs,
            "sample_size": args.sample_size,
            "warm_up_time": args.warm_up_time,
            "measurement_time": args.measurement_time,
            "non_inferiority_margin": args.non_inferiority_margin,
            "measurement_policy_sha256": policy_sha256,
            "workload_sha256": digest,
            "tree_sha256": tree_digests,
            "dependency_lock_sha256": None,
        }
        packages = {
            "baseline": args.baseline_package,
            "candidate": args.candidate_package,
        }
        cargo_arguments = {
            "baseline": baseline_arguments,
            "candidate": candidate_arguments,
        }
        paired: list[tuple[dict[str, float], dict[str, float]]] = []
        observed_failures: list[dict[str, object]] = []
        reference_locks: tuple[bytes, bytes] | None = None
        build_replicates = args.pairs // PAIRS_PER_BUILD_REPLICATE
        print(f"independent build replicates: {build_replicates}")
        for replicate in range(build_replicates):
            replicate_root = temporary_root / f"replicate-{replicate:03d}"
            subjects_root = replicate_root / "subjects"
            side_subjects = (
                {"left": "baseline", "right": "candidate"}
                if replicate % 2 == 0
                else {"left": "candidate", "right": "baseline"}
            )
            subject_sides = {subject: side for side, subject in side_subjects.items()}
            print(
                f"build replicate {replicate + 1}/{build_replicates}: "
                f"left={side_subjects['left']} right={side_subjects['right']}",
                flush=True,
            )

            harnesses: dict[tuple[str, str], tuple[Path, Path, list[str]]] = {}
            for side, subject in side_subjects.items():
                for slot in ("a", "b"):
                    staged = stage_repository(
                        subjects_root,
                        f"subject-{slot}-{side}",
                        repositories[subject],
                    )
                    manifest, target = prepare_subject(
                        replicate_root,
                        f"harness-{slot}-{side}",
                        staged,
                        packages[subject],
                        target=target_root
                        / f"replicate-{replicate:03d}"
                        / f"{side}-{slot}",
                        benchmark_inputs=benchmark_inputs,
                        lockfile=frozen_lockfile,
                    )
                    harnesses[(subject, slot)] = (
                        manifest,
                        target,
                        cargo_arguments[subject],
                    )

            locks: dict[tuple[str, str], bytes] = {}
            for key, (manifest, _, _) in harnesses.items():
                cargo(
                    [
                        "generate-lockfile",
                        "--manifest-path",
                        str(manifest),
                        "--offline",
                    ]
                )
                locks[key] = (manifest.parent / "Cargo.lock").read_bytes()

            for subject in ("baseline", "candidate"):
                if locks[(subject, "a")] != locks[(subject, "b")]:
                    fail(f"{subject} slots resolved different dependency lockfiles")

            replicate_locks = (
                locks[("baseline", "a")],
                locks[("candidate", "a")],
            )
            if reference_locks is None:
                reference_locks = replicate_locks
                baseline_lock, candidate_lock = replicate_locks
                if baseline_lock != candidate_lock and not args.allow_different_locks:
                    fail("baseline and candidate resolved different dependency lockfiles")
                if baseline_lock == candidate_lock:
                    metadata["dependency_lock_sha256"] = hashlib.sha256(
                        baseline_lock
                    ).hexdigest()
                    print(
                        "dependency lock sha256="
                        f"{hashlib.sha256(baseline_lock).hexdigest()}"
                    )
                else:
                    metadata["dependency_lock_sha256"] = {
                        "baseline": hashlib.sha256(baseline_lock).hexdigest(),
                        "candidate": hashlib.sha256(candidate_lock).hexdigest(),
                    }
                    print(
                        "dependency lock differs (explicitly allowed): "
                        f"baseline={hashlib.sha256(baseline_lock).hexdigest()} "
                        f"candidate={hashlib.sha256(candidate_lock).hexdigest()}"
                    )
            elif replicate_locks != reference_locks:
                fail("dependency lockfiles changed between build replicates")

            for manifest, target, cargo_features in harnesses.values():
                cargo(
                    [
                        "bench",
                        "--manifest-path",
                        str(manifest),
                        "--bench",
                        args.bench,
                        "--no-run",
                        "--locked",
                        "--target-dir",
                        str(target),
                        *cargo_features,
                    ]
                )

            replicate_pairs: list[tuple[dict[str, float], dict[str, float]]] = []
            replicate_failed = False
            for local_pair in range(PAIRS_PER_BUILD_REPLICATE):
                pair = replicate * PAIRS_PER_BUILD_REPLICATE + local_pair
                plan = pair_plan(local_pair, PAIR_ORDER)
                slots = {
                    "baseline": plan.baseline_slot,
                    "candidate": plan.candidate_slot,
                }
                labels = [
                    f"{subject}[{slots[subject]}/{subject_sides[subject]}]"
                    for subject in plan.order
                ]
                print(
                    f"pair {pair + 1}/{args.pairs}: {' then '.join(labels)}",
                    flush=True,
                )
                results: dict[
                    str, tuple[dict[str, float], list[dict[str, int | str]]]
                ] = {}
                for subject in plan.order:
                    manifest, target, cargo_features = harnesses[(subject, slots[subject])]
                    results[subject] = run_benchmarks(
                        manifest,
                        target,
                        args.bench,
                        cargo_features,
                        args.filter,
                        args.sample_size,
                        args.warm_up_time,
                        args.measurement_time,
                    )
                baseline_estimates, baseline_failures = results["baseline"]
                candidate_estimates, candidate_failures = results["candidate"]
                for subject, failures in results.items():
                    for failure in failures:
                        replicate_failed = True
                        observed_failures.append(
                            {
                                "pair": pair + 1,
                                "subject": subject,
                                "benchmark": args.bench,
                                "filter": args.filter,
                                **failure,
                            }
                        )
                if baseline_failures or candidate_failures:
                    print("pair ratios=skipped due to transient benchmark failures")
                    continue
                if baseline_estimates.keys() != candidate_estimates.keys():
                    fail("baseline and candidate produced different benchmark sets")
                replicate_pairs.append((baseline_estimates, candidate_estimates))
                print(
                    "pair estimates="
                    + json.dumps(
                        {
                            "pair": pair + 1,
                            "baseline": baseline_estimates,
                            "candidate": candidate_estimates,
                            "transient_failures": {
                                "baseline": baseline_failures,
                                "candidate": candidate_failures,
                            },
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    flush=True,
                )

            if replicate_failed:
                print("replicate ratios=skipped due to transient benchmark failures")
                continue
            replicate_summary = summarize_replicate(replicate_pairs)
            paired.append(replicate_summary)
            print(
                "replicate ratios="
                + json.dumps(
                    {
                        "replicate": replicate + 1,
                        "candidate_over_baseline": replicate_summary[1],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )

    if observed_failures:
        print(
            "transient benchmark failures="
            + json.dumps(observed_failures, sort_keys=True, separators=(",", ":"))
        )
        write_json_report(
            report_path,
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "status": "invalid-transient-failure",
                "valid": False,
                "metadata": metadata,
                "completed_replicates": len(paired),
                "transient_failures": observed_failures,
            },
        )
        print(f"failure report={report_path}")
        try:
            ensure_no_transient_failures(observed_failures)
        except ValueError as error:
            fail(str(error))

    try:
        report = evaluate(
            paired,
            args.non_inferiority_margin,
        )
    except ValueError as error:
        write_json_report(
            report_path,
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "status": "invalid-analysis",
                "valid": False,
                "metadata": metadata,
                "completed_replicates": len(paired),
                "error": str(error),
            },
        )
        fail(str(error))

    write_json_report(
        report_path,
        {
            "schema_version": REPORT_SCHEMA_VERSION,
            "status": "completed",
            "valid": True,
            "decision_passed": report.passed,
            "metadata": metadata,
            "paired_results": paired,
            "decisions": [
                {
                    "benchmark": decision.benchmark,
                    "median_ratio": decision.median_ratio,
                    "lower_bound": decision.lower_bound,
                    "upper_bound": decision.upper_bound,
                    "decision": decision.decision,
                }
                for decision in report.decisions
            ],
            "replicate_count": report.replicate_count,
        },
    )
    print(f"report={report_path}")

    print(
        "non-inferiority margin="
        f"{report.non_inferiority_margin:.2%} "
        f"(upper-bound limit={report.non_inferiority_limit:.6f}; "
        f"confidence={report.confidence_level:.0%}; "
        f"replicates={report.replicate_count})"
    )
    print(
        "benchmark\tmedian candidate/baseline\texact one-sided "
        f"{report.confidence_level:.0%} lower\texact one-sided "
        f"{report.confidence_level:.0%} upper\tdecision"
    )
    for decision in report.decisions:
        print(
            f"{decision.benchmark}\t{decision.median_ratio:.6f}\t"
            f"{decision.lower_bound:.6f}\t{decision.upper_bound:.6f}\t"
            f"{decision.decision}"
        )

    if not report.passed:
        fail("at least one workload did not prove non-inferiority")


def compare(args: argparse.Namespace) -> None:
    report_path = args.report.resolve() if args.report else default_report_path()
    if report_path.exists():
        report_path.unlink()
    try:
        _compare(args, report_path)
    except (Exception, SystemExit) as error:
        if not report_path.exists():
            write_json_report(
                report_path,
                {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "status": "invalid-execution",
                    "valid": False,
                    "error": str(error),
                },
            )
            print(f"failure report={report_path}")
        raise


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument(
        "--baseline-package",
        choices=SUBJECT_PACKAGES,
        default="fs2",
    )
    parser.add_argument(
        "--candidate-package",
        choices=SUBJECT_PACKAGES,
        default="fs2",
    )
    parser.add_argument(
        "--bench",
        choices=tuple(BENCHMARKS_BY_NAME),
        default="fs2_legacy",
        help="benchmark workload; fs_compat also supports fs4 subjects",
    )
    parser.add_argument(
        "--allow-different-locks",
        action="store_true",
        help="allow subject dependency locks to differ for cross-version comparisons",
    )
    parser.add_argument("--filter")
    parser.add_argument(
        "--target-root",
        type=Path,
        help="reuse Cargo build artifacts under this directory across comparisons",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="path for the retained invalid-run report when failures are observed",
    )
    parser.add_argument("--pairs", type=balanced_pair_count, default=DEFAULT_PAIRS)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--warm-up-time", type=float, default=DEFAULT_WARM_UP_TIME)
    parser.add_argument("--measurement-time", type=float, default=DEFAULT_MEASUREMENT_TIME)
    parser.add_argument(
        "--non-inferiority-margin",
        type=non_inferiority_margin,
        default=DEFAULT_NON_INFERIORITY_MARGIN,
        help=(
            "largest acceptable candidate slowdown as a fraction; "
            "0 requires the upper bound to stay at or below parity "
            "(default: %(default)s)"
        ),
    )
    args = parser.parse_args(arguments)

    if args.sample_size < 10:
        parser.error("--sample-size must be at least 10")
    if args.warm_up_time <= 0 or args.measurement_time <= 0:
        parser.error("benchmark times must be positive")
    return args


def main() -> None:
    compare(parse_arguments())


if __name__ == "__main__":
    main()
