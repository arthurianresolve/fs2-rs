#!/usr/bin/env python3
"""Run byte-identical Criterion workloads against two filesystem crates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path


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


def prepare_subject(
    root: Path,
    name: str,
    repository: Path,
    package_name: str = "fs2",
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
    return manifest, package / "target"


def subject_arguments(benchmark: str, package_name: str) -> list[str]:
    if benchmark == "fs_compat":
        return ["--no-default-features", "--features", f"subject-{package_name}"]
    if package_name != "fs2":
        fail(f"benchmark {benchmark} does not support package {package_name}")
    return []


def cargo(arguments: list[str], *, capture: bool = False) -> str:
    command = [CARGO, *arguments]
    if not capture:
        print("+", " ".join(command), flush=True)
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
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
    criterion_root = manifest.parent / "target" / "criterion"
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
    cargo(arguments, capture=True)
    return collect_estimates(criterion_root)


def bootstrap_upper_bound(ratios: list[float], resamples: int) -> float:
    rng = random.Random(0)
    count = len(ratios)
    medians = [
        statistics.median(ratios[rng.randrange(count)] for _ in range(count))
        for _ in range(resamples)
    ]
    medians.sort()
    return medians[min(len(medians) - 1, int(0.95 * len(medians)))]


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
        baseline_manifest, baseline_target = prepare_subject(
            temporary_root, "baseline", baseline, args.baseline_package
        )
        candidate_manifest, candidate_target = prepare_subject(
            temporary_root, "candidate", candidate, args.candidate_package
        )

        for manifest in (baseline_manifest, candidate_manifest):
            cargo(
                [
                    "generate-lockfile",
                    "--manifest-path",
                    str(manifest),
                    "--offline",
                ]
            )
        baseline_lock = (baseline_manifest.parent / "Cargo.lock").read_bytes()
        candidate_lock = (candidate_manifest.parent / "Cargo.lock").read_bytes()
        if baseline_lock != candidate_lock and not args.allow_different_locks:
            fail("baseline and candidate resolved different dependency lockfiles")
        if baseline_lock == candidate_lock:
            print(f"dependency lock sha256={hashlib.sha256(baseline_lock).hexdigest()}")
        else:
            print(
                "dependency lock differs (explicitly allowed): "
                f"baseline={hashlib.sha256(baseline_lock).hexdigest()} "
                f"candidate={hashlib.sha256(candidate_lock).hexdigest()}"
            )

        for manifest, target, cargo_features in (
            (baseline_manifest, baseline_target, baseline_arguments),
            (candidate_manifest, candidate_target, candidate_arguments),
        ):
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

        paired: list[tuple[dict[str, float], dict[str, float]]] = []
        for pair in range(args.pairs):
            order = ("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")
            print(f"pair {pair + 1}/{args.pairs}: {' then '.join(order)}", flush=True)
            results: dict[str, dict[str, float]] = {}
            for subject in order:
                if subject == "baseline":
                    manifest, target, cargo_features = (
                        baseline_manifest,
                        baseline_target,
                        baseline_arguments,
                    )
                else:
                    manifest, target, cargo_features = (
                        candidate_manifest,
                        candidate_target,
                        candidate_arguments,
                    )
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
            paired.append((results["baseline"], results["candidate"]))

    failed = False
    print("benchmark\tmedian candidate/baseline\tone-sided 95% upper\tdecision")
    for benchmark in sorted(paired[0][0]):
        ratios = [candidate[benchmark] / baseline[benchmark] for baseline, candidate in paired]
        median_ratio = statistics.median(ratios)
        upper = bootstrap_upper_bound(ratios, args.bootstrap_resamples)
        decision = "pass" if upper <= 1.0 else "inconclusive-or-slower"
        failed |= decision != "pass"
        print(f"{benchmark}\t{median_ratio:.6f}\t{upper:.6f}\t{decision}")

    if failed:
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
    parser.add_argument("--pairs", type=int, default=20)
    parser.add_argument("--sample-size", type=int, default=10)
    parser.add_argument("--warm-up-time", type=float, default=0.5)
    parser.add_argument("--measurement-time", type=float, default=1.0)
    parser.add_argument("--bootstrap-resamples", type=int, default=10_000)
    args = parser.parse_args()

    if args.pairs < 2:
        parser.error("--pairs must be at least 2")
    if args.sample_size < 10:
        parser.error("--sample-size must be at least 10")
    if args.warm_up_time <= 0 or args.measurement_time <= 0:
        parser.error("benchmark times must be positive")
    if args.bootstrap_resamples < 1_000:
        parser.error("--bootstrap-resamples must be at least 1000")

    compare(args)


if __name__ == "__main__":
    main()
