#!/usr/bin/env python3
"""Compare two fs2 revisions with same-process paired filesystem-stat calls."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "benchmarks" / "paired-stats-policy.json"
HARNESS_SOURCE = ROOT / "benchmarks" / "paired_stats.rs"
METRICS = {
    "free_space",
    "available_space",
    "total_space",
    "stats_snapshot/one_snapshot",
    "prepared_stats/one_prepared_snapshot",
}
FIELDS = [
    "metric",
    "baseline_ns",
    "candidate_ns",
    "ratio",
    "ratio_mad",
    "iterations",
    "outliers",
    "failures",
]


class BenchmarkError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture(command: Sequence[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise BenchmarkError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result.stdout.strip()


def run_logged(command: Sequence[str], cwd: Path, stdout_path: Path, stderr_path: Path) -> int:
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, check=False)
    return result.returncode


def resolve_ref(repo: Path, revision: str) -> str:
    return capture(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        repo,
    )


def create_isolated_source(repo: Path, destination: Path, revision: str) -> None:
    capture(["git", "init", "--bare", str(destination)], repo)
    capture(
        [
            "git",
            "--git-dir",
            str(destination),
            "fetch",
            "--no-tags",
            str(repo),
            f"+{revision}:refs/heads/benchmark",
        ],
        repo,
    )


def load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "non_regression_margin",
        "confidence",
        "process_replicates",
        "sample_size",
        "warm_up_seconds",
        "measurement_seconds",
        "cooldown_seconds",
        "aa_control",
    }
    if set(policy) != expected or policy["schema_version"] != 1:
        raise BenchmarkError("paired-stat policy has an unsupported schema")
    for name in ("non_regression_margin", "warm_up_seconds", "measurement_seconds"):
        if not isinstance(policy[name], (int, float)) or policy[name] <= 0:
            raise BenchmarkError(f"policy {name} must be positive")
    if not isinstance(policy["cooldown_seconds"], (int, float)) or policy["cooldown_seconds"] < 0:
        raise BenchmarkError("policy cooldown_seconds must be nonnegative")
    if not 0.5 < policy["confidence"] < 1.0:
        raise BenchmarkError("policy confidence must be between 0.5 and 1")
    for name in ("process_replicates", "sample_size"):
        if isinstance(policy[name], bool) or not isinstance(policy[name], int) or policy[name] <= 0:
            raise BenchmarkError(f"policy {name} must be a positive integer")
    if not isinstance(policy["aa_control"], bool):
        raise BenchmarkError("policy aa_control must be boolean")
    if exact_median_rank(policy["process_replicates"], policy["confidence"]) is None:
        raise BenchmarkError("policy has too few process replicates for its confidence")
    return policy


def exact_median_rank(sample_count: int, confidence: float) -> tuple[int, float] | None:
    denominator = 2**sample_count
    for rank in range(1, sample_count + 1):
        upper_tail = sum(math.comb(sample_count, value) for value in range(rank, sample_count + 1))
        achieved = 1.0 - upper_tail / denominator
        if achieved >= confidence:
            return rank, achieved
    return None


def exact_median_bounds(values: Sequence[float], confidence: float) -> tuple[float, float, float]:
    rank_result = exact_median_rank(len(values), confidence)
    if rank_result is None:
        raise BenchmarkError("too few values for the requested exact median confidence")
    rank, achieved = rank_result
    ordered = sorted(values)
    return ordered[len(ordered) - rank], ordered[rank - 1], achieved


def parse_measurements(text: str, run: str, mode: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames != FIELDS:
        raise BenchmarkError(f"{run} emitted an unexpected header: {reader.fieldnames!r}")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in reader:
        metric = row["metric"]
        if metric not in METRICS or metric in seen:
            raise BenchmarkError(f"{run} emitted an unexpected or duplicate metric: {metric!r}")
        seen.add(metric)
        try:
            record = {
                "run": run,
                "mode": mode,
                "metric": metric,
                "baseline_ns": float(row["baseline_ns"]),
                "candidate_ns": float(row["candidate_ns"]),
                "ratio": float(row["ratio"]),
                "ratio_mad": float(row["ratio_mad"]),
                "iterations": int(row["iterations"]),
                "outliers": int(row["outliers"]),
                "failures": int(row["failures"]),
            }
        except (TypeError, ValueError) as error:
            raise BenchmarkError(f"{run} emitted a malformed measurement") from error
        finite_values = (
            record["baseline_ns"],
            record["candidate_ns"],
            record["ratio"],
            record["ratio_mad"],
        )
        if not all(math.isfinite(value) for value in finite_values):
            raise BenchmarkError(f"{run} emitted a non-finite measurement")
        if min(record["baseline_ns"], record["candidate_ns"], record["ratio"]) <= 0:
            raise BenchmarkError(f"{run} emitted a non-positive timing")
        if min(record["ratio_mad"], record["outliers"], record["failures"]) < 0:
            raise BenchmarkError(f"{run} emitted a negative diagnostic")
        if record["iterations"] <= 0:
            raise BenchmarkError(f"{run} emitted a non-positive iteration count")
        records.append(record)
    if seen != METRICS:
        raise BenchmarkError(f"{run} did not emit every filesystem-stat metric")
    return records


def median_absolute_deviation(values: Sequence[float]) -> float:
    center = statistics.median(values)
    return statistics.median(abs(value - center) for value in values)


def summarize(
    records: Sequence[dict[str, Any]],
    mode: str,
    process_replicates: int,
    confidence: float,
    margin: float,
) -> tuple[list[dict[str, Any]], bool]:
    limit = 1.0 + margin
    lower_limit = 1.0 / limit
    summary = []
    passed = True
    for metric in sorted(METRICS):
        selected = [record for record in records if record["mode"] == mode and record["metric"] == metric]
        ratios = [record["ratio"] for record in selected]
        if len(ratios) != process_replicates:
            raise BenchmarkError(
                f"{mode} {metric} has {len(ratios)} replicates; expected {process_replicates}"
            )
        lower, upper, achieved = exact_median_bounds(ratios, confidence)
        if mode == "aa":
            metric_passed = lower >= lower_limit and upper <= limit
            disposition = "balanced" if metric_passed else "biased"
        else:
            metric_passed = upper <= limit
            disposition = "non-inferior" if metric_passed else "regression"
        passed = passed and metric_passed
        summary.append(
            {
                "metric": metric,
                "ratios": ratios,
                "median_ratio": statistics.median(ratios),
                "process_ratio_mad": median_absolute_deviation(ratios),
                "exact_lower_ratio": lower,
                "exact_upper_ratio": upper,
                "confidence_requested": confidence,
                "confidence_achieved": achieved,
                "disposition": disposition,
            }
        )
    return summary, passed


def write_manifest(
    project: Path,
    baseline_source: Path,
    candidate_source: Path,
    baseline_revision: str,
    candidate_revision: str,
) -> None:
    project.mkdir(parents=True)
    source_dir = project / "src"
    source_dir.mkdir()
    shutil.copyfile(HARNESS_SOURCE, source_dir / "main.rs")
    manifest = f'''[package]
name = "fs2-paired-stats"
version = "0.0.0"
edition = "2021"

[dependencies]
fs2_baseline = {{ package = "fs2", git = {json.dumps(baseline_source.as_uri())}, rev = {json.dumps(baseline_revision)} }}
fs2_candidate = {{ package = "fs2", git = {json.dumps(candidate_source.as_uri())}, rev = {json.dumps(candidate_revision)} }}

[workspace]
'''
    (project / "Cargo.toml").write_text(manifest, encoding="ascii")


def effective_settings(args: argparse.Namespace, policy: dict[str, Any]) -> dict[str, Any]:
    settings = {
        "non_regression_margin": policy["non_regression_margin"],
        "confidence": policy["confidence"],
        "process_replicates": args.replicates or policy["process_replicates"],
        "sample_size": args.sample_size or policy["sample_size"],
        "warm_up_seconds": args.warm_up_seconds or policy["warm_up_seconds"],
        "measurement_seconds": args.measurement_seconds or policy["measurement_seconds"],
        "cooldown_seconds": (
            policy["cooldown_seconds"] if args.cooldown_seconds is None else args.cooldown_seconds
        ),
        "aa_control": policy["aa_control"] and not args.skip_aa_control,
    }
    if exact_median_rank(settings["process_replicates"], settings["confidence"]) is None:
        raise BenchmarkError("too few process replicates for the requested confidence")
    return settings


def is_strict_configuration(settings: dict[str, Any], policy: dict[str, Any]) -> bool:
    return all(settings[name] == policy[name] for name in settings)


def milliseconds(seconds: float) -> int:
    value = round(seconds * 1000)
    if value <= 0:
        raise BenchmarkError("warm-up and measurement durations must be at least one millisecond")
    return value


def run_comparison(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    fixture = Path(args.fixture).resolve()
    output = Path(args.output).resolve()
    policy_path = Path(args.policy).resolve()
    if output.exists():
        raise BenchmarkError(f"output directory already exists: {output}")
    output.mkdir(parents=True)
    logs = output / "logs"
    logs.mkdir()
    started = datetime.now(timezone.utc).isoformat()

    policy = load_policy(policy_path)
    settings = effective_settings(args, policy)
    strict_configuration = is_strict_configuration(settings, policy)
    if not repo.is_dir() or not fixture.exists():
        raise BenchmarkError("repository or fixture path is missing")

    baseline_revision = resolve_ref(repo, args.baseline)
    candidate_revision = resolve_ref(repo, args.candidate)
    sources = output / "sources"
    sources.mkdir()
    baseline_source = sources / "baseline.git"
    candidate_source = sources / "candidate.git"
    create_isolated_source(repo, baseline_source, baseline_revision)
    create_isolated_source(repo, candidate_source, candidate_revision)

    project = output / "paired-project"
    write_manifest(
        project,
        baseline_source,
        candidate_source,
        baseline_revision,
        candidate_revision,
    )
    target = output / "target"
    manifest = project / "Cargo.toml"
    lock_stdout = logs / "cargo-lock.stdout.txt"
    lock_stderr = logs / "cargo-lock.stderr.txt"
    lock_command = ["cargo", "generate-lockfile", "--manifest-path", str(manifest)]
    lock_exit = run_logged(lock_command, repo, lock_stdout, lock_stderr)
    build_stdout = logs / "cargo-build.stdout.txt"
    build_stderr = logs / "cargo-build.stderr.txt"
    build_command = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        str(manifest),
        "--target-dir",
        str(target),
    ]
    build_exit = (
        run_logged(build_command, repo, build_stdout, build_stderr) if lock_exit == 0 else None
    )
    binary = target / "release" / ("fs2-paired-stats.exe" if os.name == "nt" else "fs2-paired-stats")
    if lock_exit != 0 or build_exit != 0 or not binary.is_file():
        report = {
            "schema_version": 1,
            "valid": False,
            "decision": "setup-failure",
            "baseline_source": baseline_revision,
            "candidate_source": candidate_revision,
            "native_exits": {"cargo_generate_lockfile": lock_exit, "cargo_build": build_exit},
            "logs": {
                "cargo_lock_stdout": str(lock_stdout),
                "cargo_lock_stderr": str(lock_stderr),
                "cargo_build_stdout": str(build_stdout),
                "cargo_build_stderr": str(build_stderr),
            },
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 2

    records: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    anomalies: list[str] = []
    jobs: list[tuple[str, int]] = []
    for replicate in range(settings["process_replicates"]):
        modes = ["ab"]
        if settings["aa_control"]:
            modes = ["ab", "aa"] if replicate % 2 == 0 else ["aa", "ab"]
        jobs.extend((mode, replicate) for mode in modes)

    warm_up_ms = milliseconds(settings["warm_up_seconds"])
    measurement_ms = milliseconds(settings["measurement_seconds"])
    for job_index, (mode, replicate) in enumerate(jobs):
        run_name = f"{mode}-run{replicate + 1:02d}"
        stdout_path = logs / f"{run_name}.stdout.tsv"
        stderr_path = logs / f"{run_name}.stderr.txt"
        command = [
            str(binary),
            str(fixture),
            mode,
            str(settings["sample_size"]),
            str(warm_up_ms),
            str(measurement_ms),
            str(replicate % len(METRICS)),
        ]
        native_exit = run_logged(command, repo, stdout_path, stderr_path)
        run_record = {
            "run": run_name,
            "mode": mode,
            "replicate": replicate + 1,
            "rotation": replicate % len(METRICS),
            "native_exit": native_exit,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
        runs.append(run_record)
        try:
            parsed = parse_measurements(
                stdout_path.read_text(encoding="utf-8", errors="replace"), run_name, mode
            )
            records.extend(parsed)
            failures = sum(record["failures"] for record in parsed)
            if failures:
                anomalies.append(f"{run_name} reported {failures} operation failures")
        except BenchmarkError as error:
            anomalies.append(str(error))
        if native_exit != 0:
            anomalies.append(f"{run_name} exited with {native_exit}")
        if job_index + 1 < len(jobs) and settings["cooldown_seconds"]:
            time.sleep(settings["cooldown_seconds"])

    ab_summary: list[dict[str, Any]] = []
    aa_summary: list[dict[str, Any]] = []
    ab_passed = False
    aa_passed = not settings["aa_control"]
    if not anomalies:
        try:
            ab_summary, ab_passed = summarize(
                records,
                "ab",
                settings["process_replicates"],
                settings["confidence"],
                settings["non_regression_margin"],
            )
            if settings["aa_control"]:
                aa_summary, aa_passed = summarize(
                    records,
                    "aa",
                    settings["process_replicates"],
                    settings["confidence"],
                    settings["non_regression_margin"],
                )
        except BenchmarkError as error:
            anomalies.append(str(error))

    valid = not anomalies and aa_passed
    if anomalies:
        decision = "invalid"
    elif not aa_passed:
        decision = "invalid-aa-control"
    elif not strict_configuration:
        decision = "exploratory-non-inferior" if ab_passed else "exploratory-regression"
    else:
        decision = "strict-non-regression-pass" if ab_passed else "regression"

    report = {
        "schema_version": 1,
        "valid": valid,
        "decision": decision,
        "strict_configuration": strict_configuration,
        "baseline_source": baseline_revision,
        "candidate_source": candidate_revision,
        "fixture": str(fixture),
        "method": {
            "name": "same-process alternating paired filesystem-stat measurement",
            "reason": "separate-process ABBA cannot cancel abrupt between-process Windows filesystem state changes",
            **settings,
            "inference": "exact distribution-free one-sided median bounds across process replicates",
            "sample_outliers": "reported using three MAD; never removed",
            "workload_order": "rotated by process replicate",
        },
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
            "cargo": capture(["cargo", "--version"], repo),
            "rustc": capture(["rustc", "-vV"], repo),
            "git": capture(["git", "--version"], repo),
        },
        "artifacts": {
            "report": str(output / "report.json"),
            "harness_source": str(HARNESS_SOURCE),
            "harness_source_sha256": sha256(HARNESS_SOURCE),
            "orchestrator_sha256": sha256(Path(__file__).resolve()),
            "policy": str(policy_path),
            "policy_sha256": sha256(policy_path),
            "cargo_lock_sha256": sha256(project / "Cargo.lock"),
            "binary_sha256": sha256(binary),
            "logs": str(logs),
        },
        "native_exits": {
            "cargo_generate_lockfile": lock_exit,
            "cargo_build": build_exit,
            "benchmark_runs": runs,
        },
        "anomalies": anomalies,
        "ab": {"passed": ab_passed, "summary": ab_summary},
        "aa_control": {
            "enabled": settings["aa_control"],
            "passed": aa_passed,
            "summary": aa_summary,
        },
        "records": records,
        "started_utc": started,
        "completed_utc": datetime.now(timezone.utc).isoformat(),
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"report: {output / 'report.json'}")
    print(f"decision: {decision}")
    for result in ab_summary:
        print(
            f"{result['metric']}: median={result['median_ratio']:.6f} "
            f"upper={result['exact_upper_ratio']:.6f} {result['disposition']}"
        )
    if not valid:
        return 2
    return 0 if ab_passed else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("baseline", help="baseline Git revision")
    result.add_argument("candidate", help="candidate Git revision")
    result.add_argument("--repo", default=str(ROOT), help="fs2 Git repository")
    result.add_argument("--fixture", default=str(ROOT), help="existing path to query")
    result.add_argument("--output", required=True, help="new artifact directory")
    result.add_argument("--policy", default=str(DEFAULT_POLICY), help="paired benchmark policy")
    result.add_argument("--replicates", type=int, help="exploratory process replicate override")
    result.add_argument("--sample-size", type=int, help="exploratory sample-size override")
    result.add_argument("--warm-up-seconds", type=float, help="exploratory warm-up override")
    result.add_argument("--measurement-seconds", type=float, help="exploratory measurement override")
    result.add_argument("--cooldown-seconds", type=float, help="exploratory cooldown override")
    result.add_argument(
        "--skip-aa-control",
        action="store_true",
        help="skip the A/A harness control and mark the report exploratory",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return run_comparison(args)
    except (BenchmarkError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
