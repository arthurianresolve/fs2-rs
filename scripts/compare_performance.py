#!/usr/bin/env python3
"""Run byte-identical Criterion workloads against two filesystem crates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from performance_policy import evaluate, pair_plan, summarize_replicate


ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
LOCKFILE = ROOT / "Cargo.lock"
CARGO = os.environ.get("CARGO", "cargo")
BENCHMARKS_BY_NAME = {
    "fs2": BENCHMARKS / "benches" / "fs2.rs",
    "fs2_legacy": BENCHMARKS / "benches" / "fs2_legacy.rs",
    "fs_compat": BENCHMARKS / "benches" / "fs_compat.rs",
}
SUBJECT_PACKAGES = ("fs2", "fs4")


def fail(message: str) -> None:
    raise SystemExit(f"performance comparison failed: {message}")


def balanced_pair_count(value: str) -> int:
    pairs = int(value)
    if pairs < 8 or pairs % 8 != 0:
        raise argparse.ArgumentTypeError(
            "must be a multiple of 8 and at least 8 to balance build placement"
        )
    return pairs


def benchmark_workload(name: str) -> Path:
    try:
        return BENCHMARKS_BY_NAME[name]
    except KeyError:
        fail(f"unknown benchmark: {name}")


def checked_repository(path: Path, label: str) -> Path:
    path = path.resolve()
    if not (path / "Cargo.toml").is_file():
        fail(f"{label} is not a crate checkout: {path}")
    return path


def stage_repository(root: Path, name: str, repository: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    destination = root / name
    shutil.copytree(
        repository,
        destination,
        ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
    )
    return destination


def freeze_repositories(
    root: Path, repositories: dict[str, Path]
) -> dict[str, Path]:
    return {
        subject: stage_repository(root, subject, repository)
        for subject, repository in repositories.items()
    }


def prepare_subject(
    root: Path,
    name: str,
    repository: Path,
    package_name: str = "fs2",
    target: Path | None = None,
) -> tuple[Path, Path]:
    package = root / name
    shutil.copytree(
        BENCHMARKS,
        package,
        ignore=shutil.ignore_patterns("target", "__pycache__", "*.pyc"),
    )
    shutil.copy2(LOCKFILE, package / "Cargo.lock")

    manifest = package / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    dependency = 'fs2 = { path = ".." }'
    if text.count(dependency) != 1:
        fail("benchmark manifest no longer has the expected fs2 path dependency")
    repository_path = json.dumps(repository.as_posix())
    if package_name == "fs2":
        replacement = f"fs2 = {{ path = {repository_path} }}"
    elif package_name == "fs4":
        replacement = (
            'fs2 = { package = "fs4", '
            f"path = {repository_path}, default-features = false, features = [\"sync\"] }}"
        )
    else:
        fail(f"unsupported subject package: {package_name}")
    manifest.write_text(
        text.replace(dependency, replacement) + "\n[workspace]\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest, target if target is not None else package / "target"


def subject_arguments(benchmark: str, package_name: str) -> list[str]:
    if benchmark == "fs_compat":
        return ["--no-default-features", "--features", f"subject-{package_name}"]
    if package_name != "fs2":
        fail(f"benchmark {benchmark} does not support package {package_name}")
    return []


def cargo(arguments: list[str], environment: dict[str, str] | None = None) -> str:
    command = [CARGO, *arguments]
    process_environment = None
    if environment is not None:
        process_environment = os.environ.copy()
        process_environment.update(environment)
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        env=process_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout)
        fail(f"command exited with {result.returncode}: {' '.join(command)}")
    return result.stdout or ""


def collect_estimates(criterion_root: Path) -> dict[str, float]:
    estimates: dict[str, float] = {}
    for path in criterion_root.rglob("estimates.json"):
        if path.parent.name != "new":
            continue
        relative = path.relative_to(criterion_root)
        benchmark = "/".join(relative.parts[:-2])
        data = json.loads(path.read_text(encoding="utf-8"))
        estimates[benchmark] = float(data["median"]["point_estimate"])
    if not estimates:
        fail(f"Criterion produced no estimates under {criterion_root}")
    return estimates


def criterion_output_root(manifest: Path) -> Path:
    return manifest.parent / "target" / "criterion"


def run_benchmarks(
    manifest: Path,
    target: Path,
    benchmark: str,
    cargo_features: list[str],
    benchmark_filter: str | None,
    sample_size: int,
    warm_up_time: float,
    measurement_time: float,
) -> dict[str, float]:
    criterion_root = criterion_output_root(manifest)
    if criterion_root.exists():
        criterion_root.resolve().relative_to(manifest.parent.resolve())
        shutil.rmtree(criterion_root)

    arguments = [
        "bench",
        "--manifest-path",
        str(manifest),
        "--bench",
        benchmark,
        "--locked",
        "--target-dir",
        str(target),
        *cargo_features,
        "--",
    ]
    if benchmark_filter:
        arguments.append(benchmark_filter)
    arguments.extend(
        [
            "--sample-size",
            str(sample_size),
            "--warm-up-time",
            str(warm_up_time),
            "--measurement-time",
            str(measurement_time),
        ]
    )
    cargo(arguments, {"CRITERION_HOME": str(criterion_root)})
    return collect_estimates(criterion_root)


def compare(args: argparse.Namespace) -> None:
    baseline = checked_repository(args.baseline, "baseline")
    candidate = checked_repository(args.candidate, "candidate")
    if baseline == candidate:
        fail("baseline and candidate must be different checkouts")

    workload = benchmark_workload(args.bench)
    baseline_arguments = subject_arguments(args.bench, args.baseline_package)
    candidate_arguments = subject_arguments(args.bench, args.candidate_package)
    digest = hashlib.sha256(workload.read_bytes()).hexdigest()
    print(f"benchmark workload sha256={digest}")
    print(
        f"subjects: baseline={args.baseline_package} "
        f"candidate={args.candidate_package}"
    )

    with tempfile.TemporaryDirectory(prefix="fs2-performance-") as temporary:
        temporary_root = Path(temporary)
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
        packages = {
            "baseline": args.baseline_package,
            "candidate": args.candidate_package,
        }
        cargo_arguments = {
            "baseline": baseline_arguments,
            "candidate": candidate_arguments,
        }
        paired: list[tuple[dict[str, float], dict[str, float]]] = []
        reference_locks: tuple[bytes, bytes] | None = None
        build_replicates = args.pairs // 4
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
                        target_root
                        / f"replicate-{replicate:03d}"
                        / f"{side}-{slot}",
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
                    print(
                        "dependency lock sha256="
                        f"{hashlib.sha256(baseline_lock).hexdigest()}"
                    )
                else:
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
            for local_pair in range(4):
                pair = replicate * 4 + local_pair
                plan = pair_plan(local_pair)
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
                results: dict[str, dict[str, float]] = {}
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
                if results["baseline"].keys() != results["candidate"].keys():
                    fail("baseline and candidate produced different benchmark sets")
                replicate_pairs.append((results["baseline"], results["candidate"]))

            paired.append(summarize_replicate(replicate_pairs))

    try:
        report = evaluate(paired, args.bootstrap_resamples)
    except ValueError as error:
        fail(str(error))

    print(
        "benchmark\tmedian candidate/baseline\tone-sided 95% lower\t"
        "one-sided 95% upper\tdecision"
    )
    for decision in report.decisions:
        print(
            f"{decision.benchmark}\t{decision.median_ratio:.6f}\t"
            f"{decision.lower_bound:.6f}\t{decision.upper_bound:.6f}\t"
            f"{decision.decision}"
        )

    if not report.passed:
        fail("at least one workload did not prove non-regression")


def main() -> None:
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
    parser.add_argument("--pairs", type=balanced_pair_count, default=24)
    parser.add_argument("--sample-size", type=int, default=10)
    parser.add_argument("--warm-up-time", type=float, default=0.5)
    parser.add_argument("--measurement-time", type=float, default=1.0)
    parser.add_argument("--bootstrap-resamples", type=int, default=10_000)
    args = parser.parse_args()

    if args.sample_size < 10:
        parser.error("--sample-size must be at least 10")
    if args.warm_up_time <= 0 or args.measurement_time <= 0:
        parser.error("benchmark times must be positive")
    if args.bootstrap_resamples < 1_000:
        parser.error("--bootstrap-resamples must be at least 1000")

    compare(args)


if __name__ == "__main__":
    main()
