#!/usr/bin/env python3
"""Collect provenance-bound internal coverage reports for the fs2 package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "arthurianresolve/fs2-rs"
BRANCH = "DO-178C"
BRANCH_TOOLCHAIN = "nightly-2026-07-23"
TARGET_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

PROFILES: dict[str, dict[str, Any]] = {
    "stable": {
        "toolchain": "1.88",
        "metrics": ["line", "region"],
        "extra": [],
    },
    "branch": {
        "toolchain": BRANCH_TOOLCHAIN,
        "metrics": ["branch"],
        "extra": ["--branch"],
        "environment": {},
    },
    "condition": {
        "toolchain": BRANCH_TOOLCHAIN,
        "metrics": ["condition_diagnostic"],
        "extra": ["--branch"],
        "environment": {"RUSTFLAGS": "-Z coverage-options=condition"},
    },
}


class CollectionError(Exception):
    """A preflight or collection error that must be recorded."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_text_sha256(path: Path) -> str:
    """Hash text inputs with a host-independent LF line-ending contract."""
    contents = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(contents).hexdigest()


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectionError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.strip()


def command_output(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectionError(f"{' '.join(command)} failed: {detail}")
    return (result.stdout.strip() or result.stderr.strip())


def rustc_host_target(verbose_version: str) -> str:
    """Extract the compiler host triple used to execute the coverage run."""
    target = next(
        (
            line.split(":", 1)[1].strip()
            for line in verbose_version.splitlines()
            if line.startswith("host:")
        ),
        None,
    )
    if not target:
        raise CollectionError("rustc --version --verbose did not report a host target")
    return target


def resolve_output_dir(value: Path) -> Path:
    output_dir = value if value.is_absolute() else ROOT / value
    output_dir = output_dir.resolve()
    try:
        output_dir.relative_to(ROOT)
    except ValueError as error:
        raise CollectionError("--output-dir must be inside the repository") from error
    if output_dir == ROOT or output_dir == (ROOT / "coverage").resolve():
        raise CollectionError("--output-dir must be a fresh staging directory")
    if output_dir.exists():
        raise CollectionError(f"--output-dir already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    return output_dir


def artifact_records(run_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(run_root.iterdir()):
        if path.name == "run-manifest.json" or not path.is_file():
            continue
        records.append(
            {
                "path": path.name,
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
        )
    return records


def base_manifest(
    *,
    run_id: str,
    target: str,
    profile: str,
    expected_commit: str,
    branch: str,
    tree: str,
    dirty: bool,
    lock_hash: str,
    requested_toolchain: str,
    resolved_toolchain: str,
    host_target: str,
    cargo_llvm_cov: str,
    command: list[str],
    environment: dict[str, str],
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "repository": REPOSITORY,
        "branch": branch,
        "commit": expected_commit,
        "tree": tree,
        "dirty": dirty,
        "cargo_lock_sha256": lock_hash,
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "target": host_target,
        },
        "target": target,
        "profile": profile,
        "requested_toolchain": requested_toolchain,
        "resolved_toolchain": resolved_toolchain,
        "cargo_llvm_cov": cargo_llvm_cov,
        "command": command,
        "environment": environment,
        "native_exit": None,
        "status": "provenance_error",
        "artifacts": [],
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }


def write_manifest(run_root: Path, manifest: dict[str, Any]) -> None:
    manifest["artifacts"] = artifact_records(run_root)
    path = run_root / "run-manifest.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def preflight(
    *, expected_commit: str, allow_dirty: bool, target: str
) -> tuple[str, str, bool, str]:
    if not COMMIT_RE.fullmatch(expected_commit):
        raise CollectionError("expected commit must be a full 40-character hexadecimal commit")
    if not TARGET_RE.fullmatch(target):
        raise CollectionError(f"invalid target triple: {target!r}")
    branch = git("branch", "--show-current")
    if not branch:
        branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME") or ""
    if branch != BRANCH:
        raise CollectionError(f"collector requires branch {BRANCH!r}, found {branch!r}")
    commit = git("rev-parse", "HEAD")
    if commit != expected_commit:
        raise CollectionError(f"HEAD {commit} does not match expected commit {expected_commit}")
    tree = git("rev-parse", "HEAD^{tree}")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    if dirty and not allow_dirty:
        raise CollectionError("working tree is dirty; use a clean checkout for evidence")
    lockfile = ROOT / "Cargo.lock"
    if not lockfile.is_file():
        raise CollectionError("Cargo.lock is missing")
    return branch, tree, dirty, canonical_text_sha256(lockfile)


def profile_command(profile: str, target: str, output_dir: Path) -> list[str]:
    configuration = PROFILES[profile]
    requested_toolchain = configuration["toolchain"]
    return [
        "cargo",
        f"+{requested_toolchain}",
        "llvm-cov",
        *configuration["extra"],
        "--package",
        "fs2",
        "--lib",
        "--tests",
        "--target",
        target,
        "--locked",
        "--json",
        "--output-path",
        (output_dir / "coverage.json").relative_to(ROOT).as_posix(),
        "--",
        "--test-threads=1",
    ]


def run_profile(
    *, profile: str, target: str, output_dir: Path, timeout_seconds: int
) -> tuple[list[str], int | None, str, str]:
    configuration = PROFILES[profile]
    requested_toolchain = configuration["toolchain"]
    command = profile_command(profile, target, output_dir)
    environment = os.environ.copy()
    cargo_target_dir = output_dir / "cargo-target"
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_TARGET_DIR"] = str(cargo_target_dir)
    environment["RUST_BACKTRACE"] = "1"
    environment.pop("RUSTFLAGS", None)
    environment.update(configuration.get("environment", {}))
    stdout_path = output_dir / "stdout.log"
    stderr_path = output_dir / "stderr.log"
    with stdout_path.open("w", encoding="utf-8", newline="\n") as stdout, stderr_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as stderr:
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return command, None, requested_toolchain, "indeterminate"
    status = "pass" if completed.returncode == 0 and (output_dir / "coverage.json").is_file() else "fail"
    return command, completed.returncode, requested_toolchain, status


def collect(args: argparse.Namespace) -> int:
    if args.profile not in PROFILES:
        raise CollectionError(f"unknown profile: {args.profile}")
    expected_commit = args.expected_commit or os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD")
    output_dir = resolve_output_dir(args.output_dir)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    requested_toolchain = PROFILES[args.profile]["toolchain"]
    command = profile_command(args.profile, args.target, output_dir)
    branch = ""
    actual_commit = expected_commit
    tree = "0" * 40
    dirty = False
    lock_hash = "0" * 64
    resolved_toolchain = "unresolved"
    host_target = "unresolved"
    cargo_llvm_cov = "unresolved"
    try:
        branch, tree, dirty, lock_hash = preflight(
            expected_commit=expected_commit, allow_dirty=args.allow_dirty, target=args.target
        )
        resolved_toolchain = command_output(
            ["rustc", f"+{requested_toolchain}", "--version", "--verbose"]
        )
        host_target = rustc_host_target(resolved_toolchain)
        if host_target != args.target:
            raise CollectionError(
                f"native coverage requires compiler host {args.target!r}; found {host_target!r}"
            )
        cargo_llvm_cov = command_output(
            ["cargo", f"+{requested_toolchain}", "llvm-cov", "--version"]
        )
        command, native_exit, _, status = run_profile(
            profile=args.profile,
            target=args.target,
            output_dir=output_dir,
            timeout_seconds=args.timeout_seconds,
        )
        if args.allow_dirty and status == "pass":
            status = "focused_only"
        if status == "indeterminate":
            (output_dir / "timeout.txt").write_text(
                f"coverage command exceeded {args.timeout_seconds} seconds\n",
                encoding="utf-8",
                newline="\n",
            )
    except CollectionError as error:
        try:
            branch = git("branch", "--show-current")
            if not branch:
                branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME") or "unknown"
        except CollectionError:
            branch = "unknown"
        try:
            actual_commit = git("rev-parse", "HEAD")
        except CollectionError:
            actual_commit = expected_commit
        try:
            tree = git("rev-parse", "HEAD^{tree}")
        except CollectionError:
            tree = "0" * 40
        try:
            dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
        except CollectionError:
            dirty = True
        lockfile = ROOT / "Cargo.lock"
        if lockfile.is_file():
            lock_hash = canonical_text_sha256(lockfile)
        (output_dir / "preflight-error.txt").write_text(
            f"{error}\n", encoding="utf-8", newline="\n"
        )
        native_exit = None
        status = "provenance_error"

    environment = {
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(output_dir / "cargo-target"),
        "RUST_BACKTRACE": "1",
        "collector": "scripts/collect_coverage.py",
    }
    environment.update(PROFILES[args.profile].get("environment", {}))
    manifest = base_manifest(
        run_id=run_id,
        target=args.target,
        profile=args.profile,
        expected_commit=actual_commit,
        branch=branch,
        tree=tree,
        dirty=dirty,
        lock_hash=lock_hash,
        requested_toolchain=requested_toolchain,
        resolved_toolchain=resolved_toolchain,
        host_target=host_target,
        cargo_llvm_cov=cargo_llvm_cov,
        command=command,
        environment=environment,
    )
    manifest["native_exit"] = native_exit
    manifest["status"] = status
    write_manifest(output_dir, manifest)

    # Import lazily so the collector remains usable for a recorded preflight
    # failure even when validation is being debugged.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validate_coverage import validate_manifest

    validate_manifest(
        output_dir / "run-manifest.json",
        expected_commit if actual_commit == expected_commit else None,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if status in {"pass", "focused_only"} else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--locked", action="store_true", help="retained for explicit command intent; collection is always locked")
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    try:
        return collect(args)
    except (CollectionError, OSError, ValueError) as error:
        print(f"coverage collection failed before a run manifest could be written: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
