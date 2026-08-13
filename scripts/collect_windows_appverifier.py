#!/usr/bin/env python3
"""Run the optional targeted Application Verifier robustness probe."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
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
    sha256,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-pc-windows-msvc"
TOOLCHAIN = "1.88"
TEST_TARGET = "windows_appverifier"
TEST_ID = "appverifier_file_fault_is_observed"
MARKER = "FS2_APPVERIFIER_PROBE_JSON="
MANIFEST_FILE = "windows-appverifier-manifest.json"
TARGET_IMAGE = "fs2-windows-appverifier-probe.exe"
APPVERIFIER = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "appverif.exe"


class AppVerifierUnavailable(Exception):
    """The optional verifier cannot run without changing the host security context."""


def is_administrator() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def executable_version(path: Path) -> str:
    literal_path = str(path).replace("'", "''")
    return command_output(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"(Get-Item -LiteralPath '{literal_path}').VersionInfo.FileVersion",
        ]
    )


def native_artifacts(run_root: Path) -> list[dict[str, Any]]:
    return [artifact for artifact in artifact_records(run_root) if artifact["path"] != MANIFEST_FILE]


def write_manifest(run_root: Path, manifest: dict[str, Any]) -> None:
    manifest["artifacts"] = native_artifacts(run_root)
    (run_root / MANIFEST_FILE).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def run_logged(
    command: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    environment: dict[str, str] | None = None,
    timeout_seconds: int,
) -> int:
    with stdout_path.open("w", encoding="utf-8", newline="\n") as stdout, stderr_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as stderr:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            check=False,
            timeout=timeout_seconds,
        )
    return completed.returncode


def parse_probe(path: Path, expected_fault: bool) -> dict[str, Any]:
    markers = [
        line.split(MARKER, 1)[1]
        for line in path.read_text(encoding="utf-8").splitlines()
        if MARKER in line
    ]
    if len(markers) != 1:
        raise CollectionError(f"{path.name} must contain exactly one probe marker")
    try:
        record = json.loads(markers[0])
    except json.JSONDecodeError as error:
        raise CollectionError(f"{path.name} contains invalid probe JSON: {error}") from error
    required = {
        "schema_version",
        "fault_expected",
        "control_create_file",
        "control_raw_os_error",
        "fs2_outcome",
        "fs2_raw_os_error",
    }
    if not isinstance(record, dict) or set(record) != required or record["schema_version"] != 1:
        raise CollectionError(f"{path.name} probe fields do not match the schema")
    if record["fault_expected"] is not expected_fault:
        raise CollectionError(f"{path.name} has the wrong fault expectation")
    if expected_fault:
        if record["control_create_file"] != "error" or not isinstance(record["control_raw_os_error"], int):
            raise CollectionError("Application Verifier activation control did not observe a native failure")
    elif record["control_create_file"] != "success" or record["control_raw_os_error"] is not None:
        raise CollectionError("Application Verifier baseline control did not succeed")
    if record["fs2_outcome"] not in {"success", "error"}:
        raise CollectionError("fs2 probe outcome is invalid")
    if record["fs2_outcome"] == "error" and not isinstance(record["fs2_raw_os_error"], int):
        raise CollectionError("fs2 probe error did not preserve a native error")
    return record


def parse_appverifier_query(path: Path) -> dict[str, Any]:
    contents = path.read_bytes()
    if contents.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = contents.decode("utf-16")
    elif contents and contents[1::2].count(0) > len(contents) // 4:
        text = contents.decode("utf-16-le")
    else:
        text = contents.decode("utf-8", errors="replace")

    def property_value(name: str) -> int | None:
        matches = re.findall(
            rf"(?im)^\s*{re.escape(name)}\s*=\s*(\d+)\b",
            text,
        )
        if len(matches) > 1:
            raise CollectionError(f"{path.name} contains duplicate {name} settings")
        return int(matches[0]) if matches else None

    return {
        "lowres_enabled": bool(
            re.search(r"(?im)^\s*Test\s+\[lowres\]\s+enabled\.?\s*$", text)
        ),
        "file_probability": property_value("FILE"),
        "timeout_ms": property_value("TimeOut"),
    }


def query_is_absent(observation: dict[str, Any]) -> bool:
    return observation == {
        "lowres_enabled": False,
        "file_probability": None,
        "timeout_ms": None,
    }


def find_test_executable(build_output: Path) -> Path:
    candidates: list[Path] = []
    for line in build_output.read_text(encoding="utf-8").splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == TEST_TARGET
            and message.get("executable")
        ):
            candidates.append(Path(message["executable"]))
    if len(candidates) != 1 or not candidates[0].is_file():
        raise CollectionError("Cargo did not identify exactly one Application Verifier test executable")
    return candidates[0]


def run_appverifier_command(
    command: list[str], output_dir: Path, stem: str, timeout_seconds: int
) -> int:
    return run_logged(
        command,
        stdout_path=output_dir / f"{stem}-stdout.log",
        stderr_path=output_dir / f"{stem}-stderr.log",
        timeout_seconds=min(timeout_seconds, 60),
    )


def collect(args: argparse.Namespace) -> int:
    expected_commit = args.expected_commit or os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD")
    output_dir = resolve_output_dir(args.output_dir)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    administrator = is_administrator()
    build_command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "test",
        "--package",
        "fs2",
        "--target",
        TARGET,
        "--locked",
        "--test",
        TEST_TARGET,
        "--no-run",
        "--message-format=json",
    ]
    probe_executable = output_dir / TARGET_IMAGE
    probe_command = [str(probe_executable), "--exact", TEST_ID, "--nocapture"]
    delete_command = [str(APPVERIFIER), "-delete", "settings", "-for", TARGET_IMAGE]
    configure_command = [
        str(APPVERIFIER),
        "-enable",
        "lowres",
        "-for",
        TARGET_IMAGE,
        "-with",
        "file=1000000",
        "timeout=0",
    ]
    query_command = [str(APPVERIFIER), "-query", "lowres", "-for", TARGET_IMAGE]
    baseline_overrides = {"FS2_APPVERIFIER_PROBE_PATH": str(ROOT / "Cargo.toml")}
    injected_overrides = {
        **baseline_overrides,
        "FS2_EXPECT_APPVERIFIER_FILE_FAULT": "1",
    }
    manifest: dict[str, Any] = {
        "record_type": "windows_appverifier_run",
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
            "administrator": administrator,
        },
        "target": TARGET,
        "requested_toolchain": TOOLCHAIN,
        "resolved_toolchain": "unresolved",
        "application_verifier": {
            "path": str(APPVERIFIER),
            "version": "unresolved",
            "sha256": "0" * 64,
        },
        "probe": {
            "test_target": TEST_TARGET,
            "test_id": TEST_ID,
            "binary": None,
            "sha256": None,
        },
        "configuration": {
            "layer": "lowres",
            "file_probability": 1000000,
            "timeout_ms": 0,
            "target_image": TARGET_IMAGE,
        },
        "commands": {
            "build": build_command,
            "probe": probe_command,
            "initial_delete": delete_command,
            "initial_query": query_command,
            "configure": configure_command,
            "query": query_command,
            "cleanup_delete": delete_command,
            "cleanup_query": query_command,
        },
        "controlled_environment": {
            "baseline": baseline_overrides,
            "injected": injected_overrides,
        },
        "initial_state": {
            "delete_native_exit": None,
            "query_native_exit": None,
            "query_observation": None,
            "verified_absent": False,
        },
        "baseline": {"native_exit": None, "observation": None},
        "configured_state": {
            "enable_native_exit": None,
            "query_native_exit": None,
            "query_observation": None,
            "verified": False,
        },
        "injected": {"native_exit": None, "observation": None},
        "cleanup": {
            "delete_native_exit": None,
            "query_native_exit": None,
            "query_observation": None,
            "verified_absent": False,
        },
        "review_status": "independent_review_pending",
        "status": "provenance_error",
        "artifacts": [],
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }

    configured = False
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
                f"Application Verifier evidence requires compiler host {TARGET!r}; found {host_target!r}"
            )
        if not APPVERIFIER.is_file():
            raise CollectionError(f"Application Verifier is not installed at {APPVERIFIER}")
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
        manifest["application_verifier"].update(
            {"version": executable_version(APPVERIFIER), "sha256": sha256(APPVERIFIER)}
        )
        if not administrator:
            raise AppVerifierUnavailable(
                "Application Verifier configuration requires an elevated disposable Windows test host; no configuration was attempted."
            )

        build_exit = run_logged(
            build_command,
            stdout_path=output_dir / "build-stdout.jsonl",
            stderr_path=output_dir / "build-stderr.log",
            timeout_seconds=args.timeout_seconds,
        )
        if build_exit != 0:
            raise CollectionError(f"Application Verifier probe build failed with exit {build_exit}")
        source_executable = find_test_executable(output_dir / "build-stdout.jsonl")
        shutil.copy2(source_executable, probe_executable)
        manifest["probe"].update(
            {"binary": TARGET_IMAGE, "sha256": sha256(probe_executable)}
        )

        initial_cleanup = run_appverifier_command(
            delete_command, output_dir, "initial-delete", args.timeout_seconds
        )
        manifest["initial_state"]["delete_native_exit"] = initial_cleanup
        if initial_cleanup != 0:
            raise CollectionError(f"Application Verifier pre-clean failed with exit {initial_cleanup}")
        initial_query_exit = run_appverifier_command(
            query_command, output_dir, "initial-query", args.timeout_seconds
        )
        manifest["initial_state"]["query_native_exit"] = initial_query_exit
        if initial_query_exit != 0:
            raise CollectionError(
                f"Application Verifier pre-clean query failed with exit {initial_query_exit}"
            )
        initial_observation = parse_appverifier_query(
            output_dir / "initial-query-stdout.log"
        )
        manifest["initial_state"]["query_observation"] = initial_observation
        manifest["initial_state"]["verified_absent"] = query_is_absent(
            initial_observation
        )
        if not manifest["initial_state"]["verified_absent"]:
            raise CollectionError("Application Verifier pre-clean did not remove lowres settings")

        baseline_environment = os.environ.copy()
        baseline_environment.update(baseline_overrides)
        baseline_exit = run_logged(
            probe_command,
            stdout_path=output_dir / "baseline-stdout.log",
            stderr_path=output_dir / "baseline-stderr.log",
            environment=baseline_environment,
            timeout_seconds=args.timeout_seconds,
        )
        manifest["baseline"]["native_exit"] = baseline_exit
        if baseline_exit != 0:
            raise CollectionError(f"Application Verifier baseline failed with exit {baseline_exit}")
        manifest["baseline"]["observation"] = parse_probe(
            output_dir / "baseline-stdout.log", False
        )

        configure_exit = run_appverifier_command(
            configure_command, output_dir, "configure", args.timeout_seconds
        )
        manifest["configured_state"]["enable_native_exit"] = configure_exit
        if configure_exit != 0:
            raise CollectionError(f"Application Verifier configuration failed with exit {configure_exit}")
        configured = True
        query_exit = run_appverifier_command(
            query_command,
            output_dir,
            "query",
            args.timeout_seconds,
        )
        manifest["configured_state"]["query_native_exit"] = query_exit
        if query_exit != 0:
            raise CollectionError(f"Application Verifier query failed with exit {query_exit}")
        configured_observation = parse_appverifier_query(output_dir / "query-stdout.log")
        manifest["configured_state"]["query_observation"] = configured_observation
        manifest["configured_state"]["verified"] = configured_observation == {
            "lowres_enabled": True,
            "file_probability": 1000000,
            "timeout_ms": 0,
        }
        if not manifest["configured_state"]["verified"]:
            raise CollectionError(
                "Application Verifier query did not confirm the configured lowres settings"
            )

        injected_environment = baseline_environment.copy()
        injected_environment.update(injected_overrides)
        injected_exit = run_logged(
            probe_command,
            stdout_path=output_dir / "injected-stdout.log",
            stderr_path=output_dir / "injected-stderr.log",
            environment=injected_environment,
            timeout_seconds=args.timeout_seconds,
        )
        manifest["injected"]["native_exit"] = injected_exit
        if injected_exit != 0:
            raise CollectionError(f"Application Verifier injected probe failed with exit {injected_exit}")
        manifest["injected"]["observation"] = parse_probe(
            output_dir / "injected-stdout.log", True
        )
        manifest["status"] = "focused_only" if dirty else "pass"
    except subprocess.TimeoutExpired:
        manifest["status"] = "indeterminate"
        (output_dir / "timeout.txt").write_text(
            f"Application Verifier command exceeded {args.timeout_seconds} seconds\n",
            encoding="utf-8",
            newline="\n",
        )
    except AppVerifierUnavailable as error:
        manifest["status"] = "indeterminate"
        (output_dir / "preflight-error.txt").write_text(
            f"{error}\n", encoding="utf-8", newline="\n"
        )
    except CollectionError as error:
        manifest["status"] = "fail" if manifest["branch"] == BRANCH else "provenance_error"
        (output_dir / "collection-error.txt").write_text(
            f"{error}\n", encoding="utf-8", newline="\n"
        )
    finally:
        if administrator and (configured or manifest["probe"]["binary"] is not None):
            cleanup_error: str | None = None
            try:
                cleanup_exit = run_appverifier_command(
                    delete_command, output_dir, "cleanup-delete", args.timeout_seconds
                )
            except subprocess.TimeoutExpired:
                cleanup_exit = None
                cleanup_error = "Application Verifier cleanup delete timed out"
            except OSError as error:
                cleanup_exit = None
                cleanup_error = f"Application Verifier cleanup delete failed: {error}"
            manifest["cleanup"]["delete_native_exit"] = cleanup_exit
            if cleanup_exit == 0:
                try:
                    cleanup_query_exit = run_appverifier_command(
                        query_command,
                        output_dir,
                        "cleanup-query",
                        args.timeout_seconds,
                    )
                except subprocess.TimeoutExpired:
                    cleanup_query_exit = None
                    cleanup_error = "Application Verifier cleanup query timed out"
                except OSError as error:
                    cleanup_query_exit = None
                    cleanup_error = f"Application Verifier cleanup query failed: {error}"
                manifest["cleanup"]["query_native_exit"] = cleanup_query_exit
                if cleanup_query_exit == 0:
                    try:
                        cleanup_observation = parse_appverifier_query(
                            output_dir / "cleanup-query-stdout.log"
                        )
                    except (CollectionError, OSError) as error:
                        cleanup_error = f"Application Verifier cleanup query was invalid: {error}"
                    else:
                        manifest["cleanup"]["query_observation"] = cleanup_observation
                        manifest["cleanup"]["verified_absent"] = query_is_absent(
                            cleanup_observation
                        )
            if cleanup_error is not None:
                (output_dir / "cleanup-error.txt").write_text(
                    f"{cleanup_error}\n", encoding="utf-8", newline="\n"
                )
            if (
                not manifest["cleanup"]["verified_absent"]
                and manifest["status"] in {"pass", "focused_only"}
            ):
                manifest["status"] = "fail"
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
        print(f"Application Verifier collection failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
