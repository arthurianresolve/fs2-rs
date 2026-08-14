#!/usr/bin/env python3
"""Validate target-object inventory controls and exact-run manifests.

The records produced by this module are internal engineering evidence.  They
inventory compiler output and LLVM observations; they do not establish
source/object equivalence, object-code coverage, MC/DC, or certification credit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTROL_PATH = ROOT / "coverage" / "object-analysis.json"
SCHEMA_PATH = ROOT / "coverage" / "object-analysis-run.schema.json"
SURFACE_PATH = ROOT / "coverage" / "surface.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_STATUSES = {"pass", "fail", "indeterminate", "provenance_error", "focused_only"}
TARGETS = {
    "x86_64-unknown-linux-gnu": {
        "runner": "ubuntu-latest",
        "platform_family": "unix",
        "object_format": "ELF",
    },
    "aarch64-apple-darwin": {
        "runner": "macos-latest",
        "platform_family": "unix",
        "object_format": "Mach-O",
    },
    "x86_64-pc-windows-msvc": {
        "runner": "windows-latest",
        "platform_family": "windows",
        "object_format": "COFF",
    },
}
PASS_ARTIFACTS = {
    "archive-members.txt",
    "cargo.stderr.log",
    "cargo.stdout.jsonl",
    "defined-symbols.txt",
    "disassembly.txt",
    "fs2.rlib",
    "object-structure.txt",
}
NON_CLAIMS = [
    "The inventory does not establish source-to-object traceability or source/object equivalence.",
    "Disassembly and symbol presence do not establish object-code structural coverage or MC/DC.",
    "The compiler and LLVM tools are not qualified, and this record grants no certification credit or authority acceptance.",
]


class ObjectAnalysisError(Exception):
    """A target-object control or run manifest is invalid."""


def fail(message: str) -> None:
    raise ObjectAnalysisError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_text_sha256(path: Path) -> str:
    contents = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(contents).hexdigest()


def safe_relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "//" in value:
        fail(f"{label} must be a canonical POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        fail(f"{label} must not be absolute or contain traversal components")
    return path


def validate_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str):
        fail(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label} must include a timezone")


def expected_source_inventory(target: str) -> list[dict[str, Any]]:
    target_spec = TARGETS.get(target)
    if target_spec is None:
        fail(f"unregistered object-analysis target: {target!r}")
    surface = load_json(SURFACE_PATH)
    records = surface.get("records")
    if not isinstance(records, list):
        fail("coverage/surface.json has no records")
    expected: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or record.get("classification") != "production":
            continue
        applicability = record.get("applicability")
        if not isinstance(applicability, list) or target_spec["platform_family"] not in applicability:
            continue
        path = record.get("path")
        if not isinstance(path, str) or path in seen_paths:
            fail("production source inventory contains an invalid or duplicate path")
        source = ROOT / path
        if not source.is_file() or canonical_text_sha256(source) != record.get("sha256"):
            fail(f"production source digest is stale: {path}")
        spans = record.get("line_spans")
        if not isinstance(spans, list) or not spans:
            fail(f"production source has no line spans: {path}")
        expected.append(
            {
                "id": record.get("id"),
                "path": path,
                "sha256": record.get("sha256"),
                "line_spans": spans,
            }
        )
        seen_paths.add(path)
    if not expected:
        fail(f"no production source records apply to {target}")
    return sorted(expected, key=lambda record: record["path"])


def validate_control(control: dict[str, Any]) -> None:
    fields = {
        "record_type",
        "schema_version",
        "status",
        "owner",
        "assurance_context",
        "software_level",
        "credit",
        "strategy",
        "review",
        "open_items",
        "non_claims",
    }
    if set(control) != fields:
        fail("coverage/object-analysis.json fields do not match the registered contract")
    if (
        control["record_type"] != "target_object_analysis_control"
        or control["schema_version"] != 1
        or control["status"] != "assessment_open"
        or control["owner"] != "fs2 DO-178C coverage workstream"
        or control["assurance_context"] != "internal_assurance"
        or control["software_level"] != "DAL_B"
        or control["credit"] != "none"
    ):
        fail("coverage/object-analysis.json identity or assurance state is invalid")
    strategy = control["strategy"]
    strategy_fields = {
        "status",
        "selection_basis",
        "crate",
        "profile",
        "requested_toolchain",
        "source_inventory_ref",
        "targets",
        "retained_outputs",
        "source_object_mapping_status",
        "generated_code_disposition",
    }
    if not isinstance(strategy, dict) or set(strategy) != strategy_fields:
        fail("coverage/object-analysis.json strategy is invalid")
    if (
        strategy["status"] != "implementation_ready_awaiting_clean_candidate"
        or strategy["selection_basis"] != "native_runtime_coverage_matrix"
        or strategy["crate"] != "fs2"
        or strategy["profile"] != "release"
        or strategy["requested_toolchain"] != "1.88"
        or strategy["source_inventory_ref"] != "coverage/surface.json"
        or strategy["retained_outputs"]
        != ["rlib", "archive_members", "defined_symbols", "sections_and_symbols", "disassembly"]
        or strategy["source_object_mapping_status"] != "not_established_inventory_only"
        or strategy["generated_code_disposition"] != "pending_target_review"
    ):
        fail("coverage/object-analysis.json strategy overstates or changes the registered scope")
    targets = strategy["targets"]
    if not isinstance(targets, list) or len(targets) != len(TARGETS):
        fail("coverage/object-analysis.json must define the three native evidence targets")
    observed: dict[str, dict[str, Any]] = {}
    for record in targets:
        if not isinstance(record, dict) or set(record) != {
            "target",
            "runner",
            "platform_family",
            "object_format",
        }:
            fail("coverage/object-analysis.json contains an invalid target record")
        target = record["target"]
        if target in observed or TARGETS.get(target) != {
            key: record[key] for key in ("runner", "platform_family", "object_format")
        }:
            fail("coverage/object-analysis.json target mapping is invalid")
        observed[target] = record
    if list(observed) != list(TARGETS):
        fail("coverage/object-analysis.json target order is not canonical")
    review = control["review"]
    if review != {
        "status": "pending_user_review",
        "reviewer": None,
        "reviewed_commit": None,
        "evidence_refs": [],
    }:
        fail("coverage/object-analysis.json must remain pending before review")
    for field in ("open_items", "non_claims"):
        values = control[field]
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value.strip() for value in values
        ):
            fail(f"coverage/object-analysis.json {field} is incomplete")
    if not all(claim in control["non_claims"] for claim in NON_CLAIMS):
        fail("coverage/object-analysis.json omits a required non-claim")


def validate_schema(schema: dict[str, Any]) -> None:
    required = [
        "record_type",
        "schema_version",
        "run_id",
        "repository",
        "branch",
        "commit",
        "tree",
        "dirty",
        "cargo_lock_sha256",
        "host",
        "target",
        "object_format",
        "profile",
        "source_inventory",
        "toolchain",
        "command",
        "native_exits",
        "status",
        "analysis",
        "artifacts",
        "created_utc",
        "limitations",
        "non_claims",
    ]
    if (
        schema.get("record_type") != "object_analysis_run_schema"
        or schema.get("schema_version") != 1
        or schema.get("required") != required
        or schema.get("enums")
        != {
            "status": ["pass", "fail", "indeterminate", "provenance_error", "focused_only"],
            "profile": ["release"],
            "source_object_mapping_status": ["not_established_inventory_only"],
        }
        or schema.get("promotion_rule")
        != "Only a pass manifest from a clean exact-commit native target run may enter internal review; no run establishes source/object equivalence, object-code coverage, qualification, certification credit, or authority acceptance."
    ):
        fail("coverage/object-analysis-run.schema.json is invalid")


def validate_artifacts(manifest: dict[str, Any], manifest_path: Path, require_pass: bool) -> None:
    records = manifest["artifacts"]
    if not isinstance(records, list):
        fail("object-analysis artifacts must be a list")
    observed: list[str] = []
    for index, record in enumerate(records):
        label = f"object-analysis artifacts[{index}]"
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            fail(f"{label} has invalid fields")
        relative = safe_relative_path(record["path"], f"{label}.path")
        if len(relative.parts) != 1 or relative.as_posix() in observed:
            fail(f"{label}.path must be a unique top-level file")
        if not SHA256_RE.fullmatch(str(record["sha256"])):
            fail(f"{label}.sha256 is invalid")
        if not isinstance(record["bytes"], int) or isinstance(record["bytes"], bool) or record["bytes"] < 0:
            fail(f"{label}.bytes is invalid")
        path = manifest_path.parent / relative.as_posix()
        if not path.is_file() or path.is_symlink():
            fail(f"object-analysis artifact is missing or unsafe: {relative}")
        if path.stat().st_size != record["bytes"] or sha256(path) != record["sha256"]:
            fail(f"object-analysis artifact changed: {relative}")
        observed.append(relative.as_posix())
    if observed != sorted(observed):
        fail("object-analysis artifact inventory is not canonically sorted")
    entries = list(manifest_path.parent.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        fail("object-analysis directory contains a non-regular or nested entry")
    actual = sorted(
        path.name for path in entries if path.name != manifest_path.name
    )
    if observed != actual:
        fail("object-analysis directory inventory differs from the manifest")
    if require_pass or manifest["status"] == "pass":
        if set(observed) != PASS_ARTIFACTS:
            fail("passing object-analysis run lacks the exact retained output set")


def validate_manifest(
    manifest_path: Path,
    *,
    expected_commit: str | None = None,
    require_pass: bool = False,
) -> dict[str, Any]:
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("object-analysis manifest is missing or unsafe")
    manifest_path = manifest_path.resolve()
    manifest = load_json(manifest_path)
    fields = {
        "record_type",
        "schema_version",
        "run_id",
        "repository",
        "branch",
        "commit",
        "tree",
        "dirty",
        "cargo_lock_sha256",
        "host",
        "target",
        "object_format",
        "profile",
        "source_inventory",
        "toolchain",
        "command",
        "native_exits",
        "status",
        "analysis",
        "artifacts",
        "created_utc",
        "limitations",
        "non_claims",
    }
    if set(manifest) != fields:
        fail("object-analysis manifest fields do not match the registered contract")
    target = manifest["target"]
    target_spec = TARGETS.get(target)
    if (
        manifest["record_type"] != "object_analysis_run"
        or manifest["schema_version"] != 1
        or manifest["repository"] != "arthurianresolve/fs2-rs"
        or manifest["branch"] != "DO-178C"
        or target_spec is None
        or manifest["object_format"] != target_spec["object_format"]
        or manifest["profile"] != "release"
        or manifest["status"] not in RUN_STATUSES
    ):
        fail("object-analysis manifest identity or status is invalid")
    if not isinstance(manifest["run_id"], str) or not manifest["run_id"]:
        fail("object-analysis run_id is invalid")
    if not COMMIT_RE.fullmatch(str(manifest["commit"])) or not COMMIT_RE.fullmatch(str(manifest["tree"])):
        fail("object-analysis manifest has invalid Git provenance")
    if expected_commit is not None:
        if not COMMIT_RE.fullmatch(expected_commit) or manifest["commit"] != expected_commit:
            fail("object-analysis manifest does not match the expected commit")
    if not isinstance(manifest["dirty"], bool) or not SHA256_RE.fullmatch(str(manifest["cargo_lock_sha256"])):
        fail("object-analysis cleanliness or lockfile provenance is invalid")
    host = manifest["host"]
    if not isinstance(host, dict) or set(host) != {
        "system",
        "release",
        "version",
        "machine",
        "python",
        "target",
    } or not all(isinstance(value, str) and value for value in host.values()):
        fail("object-analysis host identity is invalid")
    if manifest["status"] == "pass" and (manifest["dirty"] or host["target"] != target):
        fail("passing object-analysis evidence must be clean and native")
    if manifest["status"] == "focused_only" and not manifest["dirty"]:
        fail("focused-only object analysis must disclose a dirty tree")
    if require_pass and manifest["status"] != "pass":
        fail("object-analysis manifest is not passing")
    source_inventory = manifest["source_inventory"]
    if not isinstance(source_inventory, dict) or set(source_inventory) != {"record_ref", "records"}:
        fail("object-analysis source inventory is invalid")
    if source_inventory["record_ref"] != "coverage/surface.json" or source_inventory["records"] != expected_source_inventory(target):
        fail("object-analysis source inventory is stale or inapplicable")
    toolchain = manifest["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "requested",
        "rustc",
        "cargo",
        "llvm_ar",
        "llvm_nm",
        "llvm_readobj",
        "llvm_objdump",
    } or toolchain["requested"] != "1.88" or not all(
        isinstance(toolchain[field], str) and toolchain[field].strip()
        for field in set(toolchain) - {"requested"}
    ):
        fail("object-analysis toolchain provenance is invalid")
    command = manifest["command"]
    if not isinstance(command, list) or not all(isinstance(value, str) and value for value in command):
        fail("object-analysis build command is invalid")
    command_text = " ".join(command)
    for required in ("cargo", "+1.88", "rustc", "--package", "fs2", "--lib", "--release", "--target", target, "--locked"):
        if required not in command_text:
            fail("object-analysis build command is incomplete")
    exits = manifest["native_exits"]
    exit_names = {"cargo", "llvm_ar", "llvm_nm", "llvm_readobj", "llvm_objdump"}
    if not isinstance(exits, dict) or set(exits) != exit_names or not all(
        value is None or (isinstance(value, int) and not isinstance(value, bool))
        for value in exits.values()
    ):
        fail("object-analysis native exits are invalid")
    if manifest["status"] == "pass" and any(value != 0 for value in exits.values()):
        fail("passing object-analysis evidence has a nonzero native exit")
    analysis = manifest["analysis"]
    if not isinstance(analysis, dict) or set(analysis) != {
        "archive_member_count",
        "object_member_count",
        "defined_symbol_count",
        "fs2_symbol_observed",
        "source_object_mapping_status",
        "generated_code_disposition",
    }:
        fail("object-analysis result summary is invalid")
    if (
        analysis["source_object_mapping_status"] != "not_established_inventory_only"
        or analysis["generated_code_disposition"] != "pending_target_review"
        or not all(
            isinstance(analysis[field], int)
            and not isinstance(analysis[field], bool)
            and analysis[field] >= 0
            for field in ("archive_member_count", "object_member_count", "defined_symbol_count")
        )
        or not isinstance(analysis["fs2_symbol_observed"], bool)
    ):
        fail("object-analysis result summary overstates or corrupts the analysis")
    if manifest["status"] == "pass" and (
        analysis["archive_member_count"] < 1
        or analysis["object_member_count"] < 1
        or analysis["defined_symbol_count"] < 1
        or analysis["fs2_symbol_observed"] is not True
    ):
        fail("passing object-analysis evidence lacks observable object content")
    for field in ("limitations", "non_claims"):
        values = manifest[field]
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value.strip() for value in values
        ):
            fail(f"object-analysis {field} is incomplete")
    if manifest["non_claims"] != NON_CLAIMS:
        fail("object-analysis non-claims differ from the registered contract")
    validate_timestamp(manifest["created_utc"], "object-analysis created_utc")
    validate_artifacts(manifest, manifest_path, require_pass)
    return manifest


def validate_static() -> None:
    validate_control(load_json(CONTROL_PATH))
    validate_schema(load_json(SCHEMA_PATH))
    for target in TARGETS:
        expected_source_inventory(target)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()
    try:
        validate_static()
        if args.manifest is not None:
            validate_manifest(
                args.manifest,
                expected_commit=args.expected_commit,
                require_pass=args.require_pass,
            )
    except (ObjectAnalysisError, OSError) as error:
        print(f"object analysis is invalid: {error}", file=sys.stderr)
        return 1
    print("object analysis controls are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
