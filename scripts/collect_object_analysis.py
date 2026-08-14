#!/usr/bin/env python3
"""Collect native target-object inventories for internal DAL B review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validate_object_analysis import (
    COMMIT_RE,
    NON_CLAIMS,
    ROOT,
    TARGETS,
    expected_source_inventory,
    validate_manifest,
)


REPOSITORY = "arthurianresolve/fs2-rs"
BRANCH = "DO-178C"
TOOLCHAIN = "1.88"


class CollectionError(Exception):
    """Object collection could not produce passing internal evidence."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_text_sha256(path: Path) -> str:
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
    return result.stdout.strip() or result.stderr.strip()


def rustc_host_target(verbose_version: str) -> str:
    for line in verbose_version.splitlines():
        if line.startswith("host:"):
            target = line.split(":", 1)[1].strip()
            if target:
                return target
    raise CollectionError("rustc --version --verbose did not report a host target")


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


def artifact_records(output_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(output_dir.iterdir(), key=lambda item: item.name):
        if path.name == "object-analysis-manifest.json" or not path.is_file():
            continue
        records.append(
            {"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
        )
    return records


def write_manifest(output_dir: Path, manifest: dict[str, Any]) -> Path:
    manifest["artifacts"] = artifact_records(output_dir)
    path = output_dir / "object-analysis-manifest.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def llvm_tool_paths(sysroot: str, host_target: str) -> dict[str, Path]:
    suffix = ".exe" if os.name == "nt" else ""
    directory = Path(sysroot) / "lib" / "rustlib" / host_target / "bin"
    tools = {
        "llvm_ar": directory / f"llvm-ar{suffix}",
        "llvm_nm": directory / f"llvm-nm{suffix}",
        "llvm_readobj": directory / f"llvm-readobj{suffix}",
        "llvm_objdump": directory / f"llvm-objdump{suffix}",
    }
    missing = [name for name, path in tools.items() if not path.is_file()]
    if missing:
        raise CollectionError(
            "llvm-tools-preview is incomplete; missing " + ", ".join(sorted(missing))
        )
    return tools


def build_command(target: str, target_dir: Path) -> list[str]:
    return [
        "cargo",
        f"+{TOOLCHAIN}",
        "rustc",
        "--package",
        "fs2",
        "--lib",
        "--release",
        "--target",
        target,
        "--locked",
        "--target-dir",
        str(target_dir),
        "--message-format=json-render-diagnostics",
        "--",
        "--emit=link",
    ]


def find_rlib(cargo_stdout: Path) -> Path:
    candidates: list[Path] = []
    for line_number, line in enumerate(cargo_stdout.read_text(encoding="utf-8").splitlines(), 1):
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise CollectionError(
                f"cargo JSON output is invalid at line {line_number}: {error}"
            ) from error
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        if not isinstance(target, dict) or target.get("name") != "fs2":
            continue
        filenames = message.get("filenames")
        if not isinstance(filenames, list):
            continue
        candidates.extend(
            Path(filename) for filename in filenames if str(filename).endswith(".rlib")
        )
    candidates = [path for path in candidates if path.is_file()]
    if len(candidates) != 1:
        raise CollectionError(
            f"cargo did not report exactly one fs2 rlib; found {len(candidates)}"
        )
    return candidates[0]


def run_tool(
    command: list[str], output_path: Path, shared_stderr: Path
) -> int:
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )
    output_path.write_text(result.stdout, encoding="utf-8", newline="\n")
    if result.stderr:
        with shared_stderr.open("a", encoding="utf-8", newline="\n") as sink:
            sink.write(f"\n--- {' '.join(command[:2])} stderr ---\n")
            sink.write(result.stderr)
            if not result.stderr.endswith("\n"):
                sink.write("\n")
    return result.returncode


def initial_manifest(
    *, run_id: str, target: str, commit: str, tree: str, dirty: bool,
    lock_hash: str, host_target: str, command: list[str]
) -> dict[str, Any]:
    return {
        "record_type": "object_analysis_run",
        "schema_version": 1,
        "run_id": run_id,
        "repository": REPOSITORY,
        "branch": BRANCH,
        "commit": commit,
        "tree": tree,
        "dirty": dirty,
        "cargo_lock_sha256": lock_hash,
        "host": {
            "system": platform.system() or "unknown",
            "release": platform.release() or "unknown",
            "version": platform.version() or "unknown",
            "machine": platform.machine() or "unknown",
            "python": platform.python_version(),
            "target": host_target,
        },
        "target": target,
        "object_format": TARGETS[target]["object_format"],
        "profile": "release",
        "source_inventory": {
            "record_ref": "coverage/surface.json",
            "records": expected_source_inventory(target),
        },
        "toolchain": {
            "requested": TOOLCHAIN,
            "rustc": "unresolved",
            "cargo": "unresolved",
            "llvm_ar": "unresolved",
            "llvm_nm": "unresolved",
            "llvm_readobj": "unresolved",
            "llvm_objdump": "unresolved",
        },
        "command": command,
        "native_exits": {
            "cargo": None,
            "llvm_ar": None,
            "llvm_nm": None,
            "llvm_readobj": None,
            "llvm_objdump": None,
        },
        "status": "provenance_error",
        "analysis": {
            "archive_member_count": 0,
            "object_member_count": 0,
            "defined_symbol_count": 0,
            "fs2_symbol_observed": False,
            "source_object_mapping_status": "not_established_inventory_only",
            "generated_code_disposition": "pending_target_review",
        },
        "artifacts": [],
        "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "limitations": [
            "The retained rlib and LLVM reports are compiler-output inventories only.",
            "Compiler-generated, monomorphized, inlined, and library code require target-specific human disposition.",
            "No independent compiler, disassembler, or source/object semantic comparison is performed.",
        ],
        "non_claims": NON_CLAIMS,
    }


def collect(args: argparse.Namespace) -> int:
    if args.target not in TARGETS:
        raise CollectionError(f"unregistered target: {args.target!r}")
    expected_commit = args.expected_commit or os.environ.get("GITHUB_SHA") or git(
        "rev-parse", "HEAD"
    )
    if not COMMIT_RE.fullmatch(expected_commit):
        raise CollectionError("expected commit must be a full lowercase Git object ID")
    output_dir = resolve_output_dir(args.output_dir)
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-object-"
        + uuid.uuid4().hex[:12]
    )
    actual_commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    lockfile = ROOT / "Cargo.lock"
    lock_hash = canonical_text_sha256(lockfile) if lockfile.is_file() else "0" * 64
    host_target = "unresolved"
    target_root = ROOT / "target"
    target_root.mkdir(exist_ok=True)
    placeholder_build = target_root / "object-analysis-build"
    command = build_command(args.target, placeholder_build)
    manifest = initial_manifest(
        run_id=run_id,
        target=args.target,
        commit=actual_commit,
        tree=tree,
        dirty=dirty,
        lock_hash=lock_hash,
        host_target=host_target,
        command=command,
    )
    status = "provenance_error"
    try:
        branch = git("branch", "--show-current") or os.environ.get("GITHUB_REF_NAME", "")
        if branch != BRANCH:
            raise CollectionError(f"collector requires branch {BRANCH!r}, found {branch!r}")
        if actual_commit != expected_commit:
            raise CollectionError(
                f"HEAD {actual_commit} does not match expected commit {expected_commit}"
            )
        if dirty and not args.allow_dirty:
            raise CollectionError("working tree is dirty; use a clean checkout for evidence")
        if not lockfile.is_file():
            raise CollectionError("Cargo.lock is missing")
        rustc_version = command_output(
            ["rustc", f"+{TOOLCHAIN}", "--version", "--verbose"]
        )
        host_target = rustc_host_target(rustc_version)
        manifest["host"]["target"] = host_target
        if host_target != args.target:
            raise CollectionError(
                f"native object analysis requires host {args.target!r}; found {host_target!r}"
            )
        sysroot = command_output(["rustc", f"+{TOOLCHAIN}", "--print", "sysroot"])
        llvm_tools = llvm_tool_paths(sysroot, host_target)
        manifest["toolchain"] = {
            "requested": TOOLCHAIN,
            "rustc": rustc_version,
            "cargo": command_output(["cargo", f"+{TOOLCHAIN}", "--version"]),
            **{
                name: command_output([str(path), "--version"])
                for name, path in llvm_tools.items()
            },
        }
        with tempfile.TemporaryDirectory(
            prefix="object-analysis-", dir=target_root
        ) as temporary:
            build_root = Path(temporary)
            command = build_command(args.target, build_root)
            manifest["command"] = command
            stdout_path = output_dir / "cargo.stdout.jsonl"
            stderr_path = output_dir / "cargo.stderr.log"
            with stdout_path.open("w", encoding="utf-8", newline="\n") as stdout, stderr_path.open(
                "w", encoding="utf-8", newline="\n"
            ) as stderr:
                try:
                    result = subprocess.run(
                        command,
                        cwd=ROOT,
                        stdout=stdout,
                        stderr=stderr,
                        check=False,
                        timeout=args.timeout_seconds,
                        env={**os.environ, "CARGO_INCREMENTAL": "0"},
                    )
                except subprocess.TimeoutExpired:
                    result = None
            if result is None:
                status = "indeterminate"
                (output_dir / "timeout.txt").write_text(
                    f"object build exceeded {args.timeout_seconds} seconds\n",
                    encoding="utf-8",
                    newline="\n",
                )
            else:
                manifest["native_exits"]["cargo"] = result.returncode
                if result.returncode != 0:
                    status = "fail"
                else:
                    rlib = find_rlib(stdout_path)
                    retained_rlib = output_dir / "fs2.rlib"
                    shutil.copyfile(rlib, retained_rlib)
                    tool_commands = {
                        "llvm_ar": (
                            [str(llvm_tools["llvm_ar"]), "t", str(retained_rlib)],
                            output_dir / "archive-members.txt",
                        ),
                        "llvm_nm": (
                            [
                                str(llvm_tools["llvm_nm"]),
                                "--defined-only",
                                "--demangle",
                                str(retained_rlib),
                            ],
                            output_dir / "defined-symbols.txt",
                        ),
                        "llvm_readobj": (
                            [
                                str(llvm_tools["llvm_readobj"]),
                                "--file-headers",
                                "--sections",
                                "--symbols",
                                str(retained_rlib),
                            ],
                            output_dir / "object-structure.txt",
                        ),
                        "llvm_objdump": (
                            [
                                str(llvm_tools["llvm_objdump"]),
                                "--disassemble",
                                "--demangle",
                                str(retained_rlib),
                            ],
                            output_dir / "disassembly.txt",
                        ),
                    }
                    for name, (tool_command, output_path) in tool_commands.items():
                        manifest["native_exits"][name] = run_tool(
                            tool_command, output_path, stderr_path
                        )
                    members = (output_dir / "archive-members.txt").read_text(
                        encoding="utf-8"
                    ).splitlines()
                    symbols = (output_dir / "defined-symbols.txt").read_text(
                        encoding="utf-8"
                    ).splitlines()
                    members = [line.strip() for line in members if line.strip()]
                    defined = [line for line in symbols if line.strip()]
                    manifest["analysis"] = {
                        "archive_member_count": len(members),
                        "object_member_count": sum(
                            member.endswith((".o", ".obj")) for member in members
                        ),
                        "defined_symbol_count": len(defined),
                        "fs2_symbol_observed": any("fs2::" in line for line in defined),
                        "source_object_mapping_status": "not_established_inventory_only",
                        "generated_code_disposition": "pending_target_review",
                    }
                    status = (
                        "pass"
                        if all(value == 0 for value in manifest["native_exits"].values())
                        and manifest["analysis"]["object_member_count"] > 0
                        and manifest["analysis"]["defined_symbol_count"] > 0
                        and manifest["analysis"]["fs2_symbol_observed"]
                        else "fail"
                    )
                    if status == "pass" and dirty:
                        status = "focused_only"
    except CollectionError as error:
        (output_dir / "preflight-error.txt").write_text(
            f"{error}\n", encoding="utf-8", newline="\n"
        )
        status = "provenance_error"
    manifest["status"] = status
    manifest_path = write_manifest(output_dir, manifest)
    validate_manifest(
        manifest_path,
        expected_commit=expected_commit if actual_commit == expected_commit else None,
        require_pass=False,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if status in {"pass", "focused_only"} else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--locked",
        action="store_true",
        help="retained for explicit command intent; collection is always locked",
    )
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    try:
        return collect(args)
    except (CollectionError, OSError, ValueError) as error:
        print(
            f"object analysis failed before a valid manifest could be written: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
