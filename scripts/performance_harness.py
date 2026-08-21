"""Filesystem benchmark staging, execution, and artifact helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
LOCKFILE = ROOT / "Cargo.lock"
CARGO = os.environ.get("CARGO", "cargo")
_LINKER_ERROR_MARKER = "LNK1318"
_RETRY_LINKER_FLAGS = "-C debuginfo=0"
_RETRY_LINKER_ENV = {
    "CARGO_INCREMENTAL": "0",
    "CARGO_BUILD_JOBS": "1",
}
BENCHMARKS_BY_NAME = {
    "fs2": BENCHMARKS / "benches" / "fs2.rs",
    "fs2_legacy": BENCHMARKS / "benches" / "fs2_legacy.rs",
    "fs_compat": BENCHMARKS / "benches" / "fs_compat.rs",
}
SUBJECT_PACKAGES = ("fs2", "fs4")
_FAILURE_RECORD_PATTERN = re.compile(
    r"^\[fs2-bench\] FS2_BENCH_FAILURE\t([^\t\r\n]+)\t([1-9]\d*)$",
    re.MULTILINE,
)
REPORT_SCHEMA_VERSION = 1


def run_logged_process(
    command: list[str],
    working_directory: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    if not command:
        raise ValueError("logged process command must not be empty")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            result = subprocess.run(
                command,
                cwd=working_directory,
                check=False,
                stdout=stdout,
                stderr=stderr,
            )
    except OSError as error:
        with stderr_path.open("ab") as stderr:
            stderr.write(f"unable to start {command[0]}: {error}\n".encode())
        return 127
    return result.returncode


def fail(message: str) -> None:
    raise SystemExit(f"performance comparison failed: {message}")


def transient_failure_records(output: str) -> list[dict[str, int | str]]:
    return [
        {"label": unescape_failure_label(label), "count": int(count)}
        for label, count in _FAILURE_RECORD_PATTERN.findall(output)
    ]


def unescape_failure_label(value: str) -> str:
    result: list[str] = []
    index = 0
    escapes = {"\\": "\\", "t": "\t", "r": "\r", "n": "\n"}
    while index < len(value):
        character = value[index]
        if character == "\\" and index + 1 < len(value):
            escaped = escapes.get(value[index + 1])
            if escaped is not None:
                result.append(escaped)
                index += 2
                continue
        result.append(character)
        index += 1
    return "".join(result)


def transient_failure_count(output: str) -> int:
    return sum(int(record["count"]) for record in transient_failure_records(output))


def ensure_no_transient_failures(records: list[dict[str, object]]) -> None:
    if records:
        raise ValueError(
            "transient benchmark failures were observed; no performance decision is valid"
        )


def default_report_path() -> Path:
    return (
        ROOT
        / "target"
        / "measurement-runs"
        / f"cross-crate-{time.time_ns()}.json"
    )


def write_json_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def benchmark_workload(name: str, benchmarks: Path = BENCHMARKS) -> Path:
    try:
        relative = BENCHMARKS_BY_NAME[name].relative_to(BENCHMARKS)
        return benchmarks / relative
    except KeyError:
        fail(f"unknown benchmark: {name}")


def repository_state(path: Path, label: str) -> tuple[Path, str]:
    path = path.resolve()
    if not (path / "Cargo.toml").is_file():
        fail(f"{label} is not a crate checkout: {path}")
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        fail(f"{label} is not a Git checkout: {path}")
    status = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if status.returncode != 0:
        fail(f"unable to inspect {label} status: {path}")
    if status.stdout.strip():
        fail(f"{label} checkout is dirty: {path}")
    return path, result.stdout.strip()


def repository_tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    excluded = {".git", "target", "__pycache__"}
    for file in sorted(path.rglob("*")):
        relative = file.relative_to(path)
        if (
            not file.is_file()
            or any(part in excluded for part in relative.parts)
            or file.suffix == ".pyc"
        ):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


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


def freeze_benchmark_inputs(
    root: Path,
    benchmarks: Path = BENCHMARKS,
    lockfile: Path = LOCKFILE,
) -> tuple[Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    frozen_benchmarks = root / "benchmarks"
    shutil.copytree(
        benchmarks,
        frozen_benchmarks,
        ignore=shutil.ignore_patterns("target", "__pycache__", "*.pyc"),
    )
    frozen_lockfile = root / "Cargo.lock"
    shutil.copy2(lockfile, frozen_lockfile)
    return frozen_benchmarks, frozen_lockfile


def prepare_subject(
    root: Path,
    name: str,
    repository: Path,
    package_name: str = "fs2",
    target: Path | None = None,
    benchmark_inputs: Path = BENCHMARKS,
    lockfile: Path = LOCKFILE,
) -> tuple[Path, Path]:
    package = root / name
    shutil.copytree(
        benchmark_inputs,
        package,
        ignore=shutil.ignore_patterns("target", "__pycache__", "*.pyc"),
    )
    shutil.copy2(lockfile, package / "Cargo.lock")

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
    base_environment = os.environ.copy()
    if environment is not None:
        base_environment.update(environment)

    def _target_dir_for_command() -> Path | None:
        for index, value in enumerate(arguments):
            if value == "--target-dir" and index + 1 < len(arguments):
                return Path(arguments[index + 1]).resolve()
        return None

    def _merge_rustflags(environment: dict[str, str]) -> None:
        rustflags = environment.get("RUSTFLAGS", "")
        if _RETRY_LINKER_FLAGS not in rustflags.split():
            environment["RUSTFLAGS"] = f"{rustflags} {_RETRY_LINKER_FLAGS}".strip()

    def _retry_with_linker_workaround() -> str:
        retry_environment = base_environment.copy()
        retry_environment.update(_RETRY_LINKER_ENV)
        _merge_rustflags(retry_environment)

        target = _target_dir_for_command()
        if target is None:
            print("LNK1318 observed; retrying without linker workaround support")
        else:
            print(f"LNK1318 observed; cleaning debug artifacts under {target} and retrying")
            for pattern in ("*.pdb", "*.ilk"):
                for path in target.rglob(pattern):
                    try:
                        path.unlink()
                    except OSError:
                        pass

        retry = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            env=retry_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if retry.returncode != 0:
            if retry.stdout:
                print(retry.stdout)
            fail(f"command exited with {retry.returncode}: {' '.join(command)}")
        return retry.stdout or ""

    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        env=base_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        if result.stdout and _LINKER_ERROR_MARKER in result.stdout:
            return _retry_with_linker_workaround()
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
        raise ValueError(f"Criterion produced no estimates under {criterion_root}")
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
) -> tuple[dict[str, float], list[dict[str, object]]]:
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
    try:
        output = cargo(
            arguments,
            {
                "CRITERION_HOME": str(criterion_root),
                "FS2_BENCH_REPORT_ERRORS": "0",
            },
        )
    except SystemExit as error:
        return {}, [{"label": "benchmark_command", "count": 1, "error": str(error)}]

    failures: list[dict[str, object]] = transient_failure_records(output)
    try:
        estimates = collect_estimates(criterion_root)
    except Exception as error:
        failures.append(
            {"label": "criterion_estimates", "count": 1, "error": str(error)}
        )
        return {}, failures
    return estimates, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    logged = subparsers.add_parser("run-logged")
    logged.add_argument("--working-directory", required=True, type=Path)
    logged.add_argument("--stdout", required=True, type=Path)
    logged.add_argument("--stderr", required=True, type=Path)
    logged.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("run-logged requires a command after --")
    return run_logged_process(
        command,
        args.working_directory,
        args.stdout,
        args.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())


