#!/usr/bin/env python3
"""Collect provenance-bound Windows native-fault evidence for fs2."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collect_coverage import (
    BRANCH,
    REPOSITORY,
    CollectionError,
    artifact_records,
    command_output,
    git,
    preflight,
    resolve_output_dir,
    rustc_host_target,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-pc-windows-msvc"
TOOLCHAIN = "1.97.1"
TEST_ID = "windows::test::records_os_mediated_native_failures"
EVIDENCE_FILE = "windows-native-faults.json"
MANIFEST_FILE = "windows-native-fault-manifest.json"
EXPECTED_SCENARIOS: dict[str, tuple[str, str, int | None]] = {
    "WIN-NATIVE-ALLOC-READONLY": (
        "SetFileInformationByHandle",
        "read_only_file_handle",
        5,
    ),
    "WIN-NATIVE-LOCK-CONTENTION": (
        "LockFileEx",
        "exclusive_lock_owned_by_peer_handle",
        33,
    ),
    "WIN-NATIVE-VOLUME-UNAVAILABLE": (
        "Windows volume and space providers",
        "unavailable_volume_root",
        None,
    ),
    "WIN-WIN32-DUPLICATE-INVALID-HANDLE": (
        "DuplicateHandle",
        "null_source_handle",
        6,
    ),
    "WIN-WIN32-ALLOCATION-QUERY-INVALID-HANDLE": (
        "GetFileInformationByHandleEx",
        "null_file_handle",
        6,
    ),
    "WIN-WIN32-ALLOCATION-WRITE-INVALID-HANDLE": (
        "SetFileInformationByHandle",
        "null_file_handle",
        6,
    ),
    "WIN-WIN32-LOCK-INVALID-HANDLE": (
        "LockFileEx",
        "null_file_handle",
        6,
    ),
    "WIN-WIN32-UNLOCK-INVALID-HANDLE": (
        "UnlockFile",
        "null_file_handle",
        6,
    ),
}


def default_fault_record(status: str = "not_run") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_class": "internal_engineering",
        "fault_model": "os_mediated_error_activation",
        "status": status,
        "scenarios": [],
        "limitations": [],
    }


def load_fault_record(path: Path) -> dict[str, Any]:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CollectionError(f"invalid Windows native-fault evidence: {error}") from error
    if not isinstance(record, dict):
        raise CollectionError("Windows native-fault evidence must be a JSON object")
    required = {
        "schema_version",
        "evidence_class",
        "fault_model",
        "status",
        "scenarios",
        "limitations",
    }
    if set(record) != required:
        raise CollectionError("Windows native-fault evidence fields do not match the schema")
    if (
        record["schema_version"] != 1
        or record["evidence_class"] != "internal_engineering"
        or record["fault_model"] != "os_mediated_error_activation"
        or record["status"] != "pass"
    ):
        raise CollectionError("Windows native-fault evidence identity or status is invalid")
    scenarios = record["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(EXPECTED_SCENARIOS):
        raise CollectionError("Windows native-fault evidence has an incomplete scenario matrix")
    observed: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != {
            "id",
            "api_boundary",
            "activation",
            "expected_raw_os",
            "actual_raw_os",
        }:
            raise CollectionError("Windows native-fault scenario fields do not match the schema")
        scenario_id = scenario["id"]
        if scenario_id not in EXPECTED_SCENARIOS or scenario_id in observed:
            raise CollectionError(f"unexpected or duplicate Windows native-fault scenario: {scenario_id!r}")
        observed.add(scenario_id)
        api, activation, expected_error = EXPECTED_SCENARIOS[scenario_id]
        if (
            scenario["api_boundary"] != api
            or scenario["activation"] != activation
            or scenario["expected_raw_os"] != expected_error
        ):
            raise CollectionError(f"Windows native-fault scenario contract drifted: {scenario_id}")
        actual_error = scenario["actual_raw_os"]
        if not isinstance(actual_error, int) or isinstance(actual_error, bool) or actual_error <= 0:
            raise CollectionError(f"Windows native-fault scenario has no native error: {scenario_id}")
        if expected_error is not None and actual_error != expected_error:
            raise CollectionError(f"Windows native-fault scenario returned the wrong error: {scenario_id}")
    if observed != set(EXPECTED_SCENARIOS):
        raise CollectionError("Windows native-fault scenario identities are incomplete")
    limitations = record["limitations"]
    if not isinstance(limitations, list) or len(limitations) < 3 or not all(
        isinstance(item, str) and item for item in limitations
    ):
        raise CollectionError("Windows native-fault limitations are incomplete")
    return record


def native_artifacts(run_root: Path) -> list[dict[str, Any]]:
    return [
        artifact
        for artifact in artifact_records(run_root)
        if artifact["path"] != MANIFEST_FILE
    ]


def write_manifest(run_root: Path, manifest: dict[str, Any]) -> None:
    manifest["artifacts"] = native_artifacts(run_root)
    (run_root / MANIFEST_FILE).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def collect(args: argparse.Namespace) -> int:
    expected_commit = args.expected_commit or os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD")
    output_dir = resolve_output_dir(args.output_dir)
    evidence_path = output_dir / EVIDENCE_FILE
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "test",
        "--package",
        "fs2",
        "--lib",
        "--target",
        TARGET,
        "--locked",
        TEST_ID,
        "--",
        "--exact",
        "--test-threads=1",
        "--nocapture",
    ]
    manifest: dict[str, Any] = {
        "record_type": "windows_native_fault_run",
        "schema_version": 1,
        "run_id": run_id,
        "repository": REPOSITORY,
        "branch": "",
        "commit": expected_commit,
        "tree": "0" * 40,
        "dirty": False,
        "cargo_lock_sha256": "0" * 64,
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "target": "unresolved",
        },
        "target": TARGET,
        "requested_toolchain": TOOLCHAIN,
        "resolved_toolchain": "unresolved",
        "test_id": TEST_ID,
        "command": command,
        "environment": {
            "CARGO_INCREMENTAL": "0",
            "RUST_BACKTRACE": "1",
            "FS2_WINDOWS_NATIVE_FAULT_EVIDENCE": str(evidence_path),
        },
        "native_exit": None,
        "native_faults": default_fault_record(),
        "review_status": "independent_review_pending",
        "status": "provenance_error",
        "artifacts": [],
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }

    try:
        branch, tree, dirty, lock_hash = preflight(
            expected_commit=expected_commit,
            allow_dirty=args.allow_dirty,
            target=TARGET,
        )
        resolved_toolchain = command_output(
            ["rustc", f"+{TOOLCHAIN}", "--version", "--verbose"]
        )
        host_target = rustc_host_target(resolved_toolchain)
        if host_target != TARGET:
            raise CollectionError(
                f"native fault evidence requires compiler host {TARGET!r}; found {host_target!r}"
            )
        manifest.update(
            {
                "branch": branch,
                "tree": tree,
                "dirty": dirty,
                "cargo_lock_sha256": lock_hash,
                "resolved_toolchain": resolved_toolchain,
            }
        )
        manifest["host"]["target"] = host_target

        environment = os.environ.copy()
        environment["CARGO_INCREMENTAL"] = "0"
        environment["RUST_BACKTRACE"] = "1"
        environment["FS2_WINDOWS_NATIVE_FAULT_EVIDENCE"] = str(evidence_path)
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
                    timeout=args.timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                manifest["status"] = "indeterminate"
                (output_dir / "timeout.txt").write_text(
                    f"native-fault command exceeded {args.timeout_seconds} seconds\n",
                    encoding="utf-8",
                    newline="\n",
                )
            else:
                manifest["native_exit"] = completed.returncode
                if completed.returncode == 0 and evidence_path.is_file():
                    manifest["native_faults"] = load_fault_record(evidence_path)
                    manifest["status"] = "focused_only" if dirty else "pass"
                else:
                    manifest["status"] = "fail"
    except CollectionError as error:
        (output_dir / "collection-error.txt").write_text(
            f"{error}\n", encoding="utf-8", newline="\n"
        )
        manifest["status"] = "fail" if manifest["branch"] == BRANCH else "provenance_error"
    finally:
        write_manifest(output_dir, manifest)

    print(output_dir / MANIFEST_FILE)
    return 0 if manifest["status"] in {"pass", "focused_only"} else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    try:
        return collect(args)
    except (CollectionError, OSError) as error:
        print(f"Windows native-fault collection failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
