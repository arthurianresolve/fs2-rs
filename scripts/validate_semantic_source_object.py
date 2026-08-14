#!/usr/bin/env python3
"""Validate the target-specific semantic source/object companion contract.

The companion is intentionally separate from the production rlib inventory.
It retains a release-profile rustc build with MIR, LLVM IR, debug locations, and
the generated debug-info object so that a reviewer can inspect the compiler's
intermediate representation and its source-location bridge.  A separate
debuginfo=0 semantic build is compared with the production object after
llvm-objcopy removes symbols and relocations.  That bounded comparison does not
establish full archive identity, source/object equivalence, object-code
coverage, MC/DC, qualification, or certification credit.
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

from validate_object_analysis import (
    COMMIT_RE,
    ROOT,
    TARGETS,
    canonical_text_sha256,
    expected_source_inventory,
)


CONTROL_PATH = ROOT / "coverage" / "semantic-source-object.json"
SCHEMA_PATH = ROOT / "coverage" / "semantic-source-object-run.schema.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOOLCHAIN = "1.97.1"
LLVM_VERSION = "22.1.6"
RUN_STATUSES = {"pass", "fail", "indeterminate", "provenance_error", "focused_only"}
MAPPING_METHOD = "rustc_mir_llvm_debug_location_source_inventory_bridge_v1"
MAPPING_SCOPE = "debuginfo_source_bridge_with_separate_non_debug_production_object_equivalence"
PRODUCTION_BINDING_STATUS = "production_non_debug_object_payload_equal"
PRODUCTION_COMPARISON = "same-target-release-object-section-payloads-equal-after-llvm-objcopy-strip-all"
SECTION_COMPARISON = "llvm-readobj-section-payload-fingerprint-after-llvm-objcopy-strip-all"
SOURCE_RECORD_STATUS = {
    "observed": "companion_source_locations_observed",
    "absent": "no_companion_source_locations_observed",
}
GENERATION_REVIEW = {
    "status": "reviewed_internal_non_credit",
    "project_generated_sources": {
        "status": "not_observed",
        "build_scripts": [],
        "proc_macro_sources": [],
        "included_generated_sources": [],
    },
    "compiler_generated_code": {
        "status": "present_not_credited",
        "reason": "Rust monomorphization, inlining, compiler support, and target runtime code may be present in the companion outputs without a complete semantic source mapping.",
    },
}
NON_CLAIMS = [
    "The byte comparison is limited to direct release object section payloads after llvm-objcopy --strip-all; symbols, relocations, and format metadata are excluded, so it does not establish full object, rlib/archive, symbol/relocation identity, or source/object equivalence.",
    "The debuginfo companion is a separate diagnostic build; debug-info settings may alter object code. The byte binding uses a separate debuginfo=0 semantic build with the same release inputs.",
    "MIR, LLVM debug locations, and disassembly are diagnostic evidence; they do not establish complete source/object equivalence or statement/basic-block correspondence.",
    "The companion does not provide executed object-code structural coverage or MC/DC, and it grants no tool qualification, certification credit, or authority acceptance.",
]
OBJECT_COVERAGE = {
    "status": "not_collected",
    "reason": "No target-specific executed object-code structural coverage artifact is retained; the companion only retains compiler and object inspection inputs.",
}
PRODUCTION_BINDING = {
    "status": PRODUCTION_BINDING_STATUS,
    "production_inventory_ref": "object-analysis-manifest.json",
    "comparison": PRODUCTION_COMPARISON,
    "reason": "The production and separate debuginfo=0 semantic builds use the same target, release profile, source tree, lockfile, and Rust/LLVM toolchain; their non-debug section payloads are equal after llvm-objcopy --strip-all removes symbols and relocations and the comparison excludes format metadata. The debuginfo=2 source-location companion remains diagnostic. This is bounded object-byte evidence, not full object/archive identity or source/object equivalence.",
}


class SemanticSourceObjectError(Exception):
    """A semantic source/object control or run manifest is invalid."""


def fail(message: str) -> None:
    raise SemanticSourceObjectError(message)


def validate_toolchain_versions(toolchain: dict[str, Any]) -> None:
    if (
        f"release: {TOOLCHAIN}" not in toolchain["rustc"]
        or not re.search(rf"LLVM version:?\s+{re.escape(LLVM_VERSION)}", toolchain["rustc"])
        or not toolchain["cargo"].startswith(f"cargo {TOOLCHAIN} ")
        or any(not re.search(rf"LLVM version:?\s+{re.escape(LLVM_VERSION)}", toolchain[field]) for field in (
            "llvm_objcopy", "llvm_readobj", "llvm_objdump"
        ))
    ):
        fail("semantic source/object toolchain versions are not Rust 1.97.1 / LLVM 22.1.6")


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


def source_candidate(raw: str, expected_paths: set[str]) -> str | None:
    normalized = raw.replace("\\", "/")
    if normalized.startswith("src/") and normalized in expected_paths:
        return normalized
    if "/src/" in normalized:
        candidate = "src/" + normalized.rsplit("/src/", 1)[1]
        if candidate in expected_paths:
            return candidate
    return None


def mir_source_path(line: str, expected_paths: set[str]) -> str | None:
    match = re.search(r"\bsrc[\\/](?P<path>[^:]+\.rs):", line)
    return source_candidate("src/" + match.group("path"), expected_paths) if match else None


def parse_mir(text: str, expected_paths: set[str]) -> dict[str, Any]:
    function_counts = {path: 0 for path in expected_paths}
    switch_counts = {path: 0 for path in expected_paths}
    function_count = 0
    switch_count = 0
    current_path: str | None = None
    for line in text.splitlines():
        if line.startswith("fn "):
            current_path = mir_source_path(line, expected_paths)
            if current_path is not None:
                function_count += 1
                function_counts[current_path] += 1
        if re.search(r"\bswitchInt\s*\(", line):
            switch_count += 1
            if current_path is not None:
                switch_counts[current_path] += 1
    return {
        "function_count": function_count,
        "switch_count": switch_count,
        "function_counts": function_counts,
        "switch_counts": switch_counts,
    }


def llvm_quoted_value(value: str) -> str:
    match = re.search(r'"((?:\\.|[^"])*)"', value)
    if match is None:
        return ""
    return match.group(1).replace(r"\"", '"').replace(r"\\", "\\")


def parse_llvm(text: str, expected_paths: set[str]) -> dict[str, Any]:
    lines = text.splitlines()
    nodes: dict[int, str] = {}
    for line in lines:
        match = re.match(r"^!(\d+)\s*=\s*(.*)$", line)
        if match:
            nodes[int(match.group(1))] = match.group(2)

    file_ids: dict[int, str] = {}
    for identifier, node in nodes.items():
        if not node.startswith("!DIFile"):
            continue
        filename_match = re.search(r"filename:\s*(\"(?:\\.|[^\"])*\")", node)
        directory_match = re.search(r"directory:\s*(\"(?:\\.|[^\"])*\")", node)
        if filename_match is None:
            continue
        filename = llvm_quoted_value(filename_match.group(1)).replace("\\", "/")
        directory = (
            llvm_quoted_value(directory_match.group(1)).replace("\\", "/")
            if directory_match
            else ""
        )
        candidate = source_candidate(
            f"{directory}/{filename}" if directory else filename, expected_paths
        )
        if candidate is not None:
            file_ids[identifier] = candidate

    def scope_file(identifier: int, seen: set[int] | None = None) -> str | None:
        visited = set() if seen is None else seen
        if identifier in visited:
            return None
        visited.add(identifier)
        node = nodes.get(identifier, "")
        file_match = re.search(r"\bfile:\s*!(\d+)", node)
        if file_match:
            return file_ids.get(int(file_match.group(1)))
        scope_match = re.search(r"\bscope:\s*!(\d+)", node)
        if scope_match:
            return scope_file(int(scope_match.group(1)), visited)
        return None

    location_ids: dict[int, tuple[str, int]] = {}
    for identifier, node in nodes.items():
        if not node.startswith("!DILocation"):
            continue
        line_match = re.search(r"\bline:\s*(\d+)", node)
        scope_match = re.search(r"\bscope:\s*!(\d+)", node)
        if line_match is None or scope_match is None or int(line_match.group(1)) == 0:
            continue
        path = scope_file(int(scope_match.group(1)))
        if path is not None:
            location_ids[identifier] = (path, int(line_match.group(1)))

    debug_counts = {path: 0 for path in expected_paths}
    conditional_counts = {path: 0 for path in expected_paths}
    function_counts = {path: 0 for path in expected_paths}
    debug_location_count = 0
    conditional_site_count = 0
    function_count = 0
    for line in lines:
        debug_match = re.search(r"!dbg\s*!(\d+)", line)
        location = location_ids.get(int(debug_match.group(1))) if debug_match else None
        function_path = (
            scope_file(int(debug_match.group(1)))
            if debug_match and line.startswith("define ")
            else None
        )
        if location is not None:
            path, _line_number = location
            debug_location_count += 1
            debug_counts[path] += 1
        if line.startswith("define ") and function_path is not None:
            function_count += 1
            function_counts[function_path] += 1
        if location is not None and re.search(r"\b(?:br i1|switch|select)\b", line):
            conditional_site_count += 1
            conditional_counts[location[0]] += 1
    return {
        "function_count": function_count,
        "debug_location_count": debug_location_count,
        "conditional_site_count": conditional_site_count,
        "function_counts": function_counts,
        "debug_counts": debug_counts,
        "conditional_counts": conditional_counts,
    }


def parse_object_structure(text: str) -> dict[str, Any]:
    section_names = [
        match.group(1)
        for match in re.finditer(r"^\s*Name:\s*([^\s(]+)", text, re.MULTILINE)
        if "debug" in match.group(1).lower()
    ]
    return {
        "debug_section_count": len(section_names),
        "debug_section_names": sorted(set(section_names)),
    }


def source_records(
    inventory: list[dict[str, Any]], mir: dict[str, Any], llvm: dict[str, Any]
) -> list[dict[str, Any]]:
    records = []
    for source in inventory:
        path = source["path"]
        observed = any(
            (
                mir["function_counts"][path],
                mir["switch_counts"][path],
                llvm["function_counts"][path],
                llvm["debug_counts"][path],
                llvm["conditional_counts"][path],
            )
        )
        records.append(
            {
                "path": path,
                "source_sha256": source["sha256"],
                "mir_function_count": mir["function_counts"][path],
                "mir_switch_count": mir["switch_counts"][path],
                "llvm_function_count": llvm["function_counts"][path],
                "llvm_debug_location_count": llvm["debug_counts"][path],
                "llvm_conditional_site_count": llvm["conditional_counts"][path],
                "status": SOURCE_RECORD_STATUS["observed" if observed else "absent"],
            }
        )
    return records


def build_semantic_source_object_map(
    *,
    target: str,
    commit: str,
    tree: str,
    inventory: list[dict[str, Any]],
    mir_path: Path,
    llvm_path: Path,
    object_path: Path,
    object_structure_path: Path,
    disassembly_path: Path,
) -> dict[str, Any]:
    if target not in TARGETS:
        fail(f"unregistered target: {target!r}")
    expected_paths = {record["path"] for record in inventory}
    mir = parse_mir(mir_path.read_text(encoding="utf-8"), expected_paths)
    llvm = parse_llvm(llvm_path.read_text(encoding="utf-8"), expected_paths)
    object_structure = parse_object_structure(object_structure_path.read_text(encoding="utf-8"))
    return {
        "record_type": "semantic_source_object_map",
        "schema_version": 1,
        "target": target,
        "object_format": TARGETS[target]["object_format"],
        "commit": commit,
        "tree": tree,
        "source_inventory": {
            "record_ref": "coverage/surface.json",
            "records": inventory,
        },
        "mapping_method": MAPPING_METHOD,
        "mapping_scope": MAPPING_SCOPE,
        "evidence_artifacts": [
            {
                "path": path.name,
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in (
                mir_path,
                llvm_path,
                object_path,
                object_structure_path,
                disassembly_path,
            )
        ],
        "mir": {
            "function_count": mir["function_count"],
            "switch_count": mir["switch_count"],
        },
        "llvm": {
            "function_count": llvm["function_count"],
            "debug_location_count": llvm["debug_location_count"],
            "conditional_site_count": llvm["conditional_site_count"],
        },
        "object": object_structure,
        "source_records": source_records(inventory, mir, llvm),
        "production_object_binding": PRODUCTION_BINDING,
        "generation_review": GENERATION_REVIEW,
        "object_code_coverage": OBJECT_COVERAGE,
        "non_claims": NON_CLAIMS,
    }


def validate_map(
    record: dict[str, Any],
    *,
    root: Path,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> None:
    fields = {
        "record_type",
        "schema_version",
        "target",
        "object_format",
        "commit",
        "tree",
        "source_inventory",
        "mapping_method",
        "mapping_scope",
        "evidence_artifacts",
        "mir",
        "llvm",
        "object",
        "source_records",
        "production_object_binding",
        "generation_review",
        "object_code_coverage",
        "non_claims",
    }
    if set(record) != fields:
        fail("semantic source-object map fields do not match the registered contract")
    target = record["target"]
    if target not in TARGETS or record["object_format"] != TARGETS[target]["object_format"]:
        fail("semantic source-object map target or object format is invalid")
    if record["record_type"] != "semantic_source_object_map" or record["schema_version"] != 1:
        fail("semantic source-object map identity is invalid")
    for field in ("commit", "tree"):
        if not isinstance(record[field], str) or not COMMIT_RE.fullmatch(record[field]):
            fail(f"semantic source-object map {field} is invalid")
    if expected_commit is not None and record["commit"] != expected_commit:
        fail("semantic source-object map does not match the expected commit")
    if expected_tree is not None and record["tree"] != expected_tree:
        fail("semantic source-object map does not match the expected tree")
    inventory_record = record["source_inventory"]
    if not isinstance(inventory_record, dict) or set(inventory_record) != {"record_ref", "records"}:
        fail("semantic source-object map source inventory is invalid")
    if inventory_record["record_ref"] != "coverage/surface.json":
        fail("semantic source-object map source inventory reference is invalid")
    inventory = expected_source_inventory(target)
    if inventory_record["records"] != inventory:
        fail("semantic source-object map source inventory is stale or inapplicable")
    if record["mapping_method"] != MAPPING_METHOD or record["mapping_scope"] != MAPPING_SCOPE:
        fail("semantic source-object map method or scope is invalid")

    evidence = record["evidence_artifacts"]
    if not isinstance(evidence, list) or [item.get("path") for item in evidence] != [
        "fs2.semantic.mir",
        "fs2.semantic.ll",
        "fs2.semantic.debug.o",
        "object-structure.txt",
        "disassembly.txt",
    ]:
        fail("semantic source-object map evidence artifact order is invalid")
    evidence_paths: dict[str, Path] = {}
    for index, item in enumerate(evidence):
        label = f"semantic source-object map evidence_artifacts[{index}]"
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}:
            fail(f"{label} has an invalid shape")
        relative = safe_relative_path(item["path"], f"{label}.path")
        if not SHA256_RE.fullmatch(str(item["sha256"])):
            fail(f"{label}.sha256 is invalid")
        if not isinstance(item["bytes"], int) or isinstance(item["bytes"], bool) or item["bytes"] < 1:
            fail(f"{label}.bytes is invalid")
        path = root / relative.as_posix()
        if not path.is_file() or path.is_symlink():
            fail(f"{label} is missing or unsafe")
        if path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"]:
            fail(f"{label} changed after map generation")
        evidence_paths[relative.as_posix()] = path

    mir = parse_mir(evidence_paths["fs2.semantic.mir"].read_text(encoding="utf-8"), {item["path"] for item in inventory})
    llvm = parse_llvm(evidence_paths["fs2.semantic.ll"].read_text(encoding="utf-8"), {item["path"] for item in inventory})
    if record["mir"] != {"function_count": mir["function_count"], "switch_count": mir["switch_count"]}:
        fail("semantic source-object map MIR counts are not reproducible")
    if record["llvm"] != {
        "function_count": llvm["function_count"],
        "debug_location_count": llvm["debug_location_count"],
        "conditional_site_count": llvm["conditional_site_count"],
    }:
        fail("semantic source-object map LLVM counts are not reproducible")
    object_structure = parse_object_structure(
        evidence_paths["object-structure.txt"].read_text(encoding="utf-8")
    )
    if record["object"] != object_structure:
        fail("semantic source-object map object debug-section inventory is not reproducible")
    records = record["source_records"]
    expected_paths = {item["path"] for item in inventory}
    if not isinstance(records, list) or [item.get("path") for item in records] != [item["path"] for item in inventory]:
        fail("semantic source-object map source records are incomplete or unordered")
    for index, (item, expected) in enumerate(zip(records, inventory)):
        label = f"semantic source-object map source_records[{index}]"
        required = {
            "path",
            "source_sha256",
            "mir_function_count",
            "mir_switch_count",
            "llvm_function_count",
            "llvm_debug_location_count",
            "llvm_conditional_site_count",
            "status",
        }
        if not isinstance(item, dict) or set(item) != required:
            fail(f"{label} has an invalid shape")
        if item["path"] != expected["path"] or item["source_sha256"] != expected["sha256"]:
            fail(f"{label} has stale source identity")
        source = ROOT / item["path"]
        if not source.is_file() or canonical_text_sha256(source) != item["source_sha256"]:
            fail(f"{label} has a stale source digest")
        expected_counts = {
            "mir_function_count": mir["function_counts"][item["path"]],
            "mir_switch_count": mir["switch_counts"][item["path"]],
            "llvm_function_count": llvm["function_counts"][item["path"]],
            "llvm_debug_location_count": llvm["debug_counts"][item["path"]],
            "llvm_conditional_site_count": llvm["conditional_counts"][item["path"]],
        }
        if {field: item[field] for field in expected_counts} != expected_counts:
            fail(f"{label} counts are not reproducible")
        observed = any(expected_counts.values())
        if item["status"] != SOURCE_RECORD_STATUS["observed" if observed else "absent"]:
            fail(f"{label}.status is invalid")
    if record["production_object_binding"] != PRODUCTION_BINDING:
        fail("semantic source-object map production binding is invalid")
    if record["generation_review"] != GENERATION_REVIEW:
        fail("semantic source-object map generated-code disposition is invalid")
    if record["object_code_coverage"] != OBJECT_COVERAGE:
        fail("semantic source-object map object-code coverage disposition is invalid")
    if record["non_claims"] != NON_CLAIMS:
        fail("semantic source-object map non-claims differ from the registered contract")


PRODUCTION_BYTE_STATUSES = {
    "not_established",
    "non_debug_object_payload_equal",
    "non_debug_object_payload_differ",
}
ANALYSIS_BINDING_STATUSES = PRODUCTION_BYTE_STATUSES | {PRODUCTION_BINDING_STATUS}


def validate_byte_file(
    record: Any, *, label: str, root: Path
) -> tuple[str, str, int]:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        fail(f"{label} has an invalid shape")
    relative = safe_relative_path(record["path"], f"{label}.path")
    if len(relative.parts) != 1:
        fail(f"{label}.path must name a top-level artifact")
    digest = str(record["sha256"])
    if not SHA256_RE.fullmatch(digest):
        fail(f"{label}.sha256 is invalid")
    size = record["bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        fail(f"{label}.bytes is invalid")
    path = root / relative.as_posix()
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or unsafe")
    if path.stat().st_size != size or sha256(path) != digest:
        fail(f"{label} changed after production-byte comparison")
    return relative.as_posix(), digest, size


def validate_byte_equivalence(
    record: Any, *, root: Path, require_equal: bool
) -> None:
    required = {
        "status",
        "comparison",
        "production_object",
        "semantic_object",
        "production_stripped_object",
        "semantic_stripped_object",
        "payload_comparison",
    }
    if not isinstance(record, dict) or set(record) != required:
        fail("semantic source/object production-byte comparison has invalid fields")
    status = record["status"]
    if status not in PRODUCTION_BYTE_STATUSES:
        fail("semantic source/object production-byte comparison status is invalid")
    if record["comparison"] != PRODUCTION_COMPARISON:
        fail("semantic source/object production-byte comparison method is invalid")
    file_fields = (
        "production_object",
        "semantic_object",
        "production_stripped_object",
        "semantic_stripped_object",
    )
    if status == "not_established":
        if any(record[field] is not None for field in file_fields):
            fail("unestablished production-byte comparison must not contain artifacts")
        if record["payload_comparison"] is not None:
            fail("unestablished production-byte comparison must not contain payload evidence")
        if require_equal:
            fail("passing semantic source/object evidence lacks production-byte comparison")
        return
    observed: dict[str, tuple[str, str, int]] = {}
    for field in file_fields:
        observed[field] = validate_byte_file(
            record[field], label=f"production-byte comparison {field}", root=root
        )
    payload = record["payload_comparison"]
    if not isinstance(payload, dict) or set(payload) != {
        "method", "format", "status", "production", "semantic"
    }:
        fail("production-byte payload comparison has invalid fields")
    if payload["method"] != SECTION_COMPARISON or payload["format"] not in {"ELF", "Mach-O", "COFF"}:
        fail("production-byte payload comparison method or format is invalid")
    if payload["status"] not in {"equal", "differ"}:
        fail("production-byte payload comparison status is invalid")
    canonical_sections: dict[str, list[dict[str, Any]]] = {}
    for side in ("production", "semantic"):
        summary = payload[side]
        if not isinstance(summary, dict) or set(summary) != {"fingerprint", "section_count", "sections"}:
            fail(f"production-byte payload comparison {side} summary is invalid")
        if not SHA256_RE.fullmatch(str(summary["fingerprint"])):
            fail(f"production-byte payload comparison {side} fingerprint is invalid")
        if not isinstance(summary["section_count"], int) or isinstance(summary["section_count"], bool) or summary["section_count"] < 1:
            fail(f"production-byte payload comparison {side} section count is invalid")
        sections = summary["sections"]
        if not isinstance(sections, list) or len(sections) != summary["section_count"]:
            fail(f"production-byte payload comparison {side} sections are invalid")
        canonical_sections[side] = []
        for index, section in enumerate(sections):
            if not isinstance(section, dict) or set(section) != {"index", "type", "segment", "flags", "size", "sha256"}:
                fail(f"production-byte payload comparison {side} section fields are invalid")
            if section["index"] != index or not isinstance(section["type"], str) or not isinstance(section["segment"], str):
                fail(f"production-byte payload comparison {side} section identity is invalid")
            if not isinstance(section["flags"], int) or isinstance(section["flags"], bool) or section["flags"] < 0:
                fail(f"production-byte payload comparison {side} section flags are invalid")
            if not isinstance(section["size"], int) or isinstance(section["size"], bool) or section["size"] < 0:
                fail(f"production-byte payload comparison {side} section size is invalid")
            if not SHA256_RE.fullmatch(str(section["sha256"])):
                fail(f"production-byte payload comparison {side} section digest is invalid")
            canonical_sections[side].append(section)
    equal_sections = canonical_sections["production"] == canonical_sections["semantic"]
    equal_fingerprints = payload["production"]["fingerprint"] == payload["semantic"]["fingerprint"]
    if payload["status"] == "equal" and (not equal_sections or not equal_fingerprints):
        fail("production-byte payload comparison claims equality but section payloads differ")
    if payload["status"] == "differ" and equal_sections and equal_fingerprints:
        fail("production-byte payload comparison claims a difference but section payloads match")
    expected_equal = status == "non_debug_object_payload_equal"
    if expected_equal != (payload["status"] == "equal"):
        fail("production-byte comparison status disagrees with payload comparison")
    if require_equal and status != "non_debug_object_payload_equal":
        fail("passing semantic source/object evidence lacks equal production non-debug section payloads")


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
        fail("coverage/semantic-source-object.json fields do not match the registered contract")
    if (
        control["record_type"] != "semantic_source_object_control"
        or control["schema_version"] != 1
        or control["status"] != "assessment_open"
        or control["owner"] != "fs2 DO-178C coverage workstream"
        or control["assurance_context"] != "internal_assurance"
        or control["software_level"] != "DAL_B"
        or control["credit"] != "none"
    ):
        fail("semantic source/object control identity or assurance state is invalid")
    strategy = control["strategy"]
    if not isinstance(strategy, dict) or set(strategy) != {
        "status",
        "selection_basis",
        "crate",
        "profile",
        "requested_toolchain",
        "source_inventory_ref",
        "mapping_method",
        "mapping_scope",
        "targets",
        "retained_outputs",
        "production_object_binding",
        "generated_code_disposition",
    }:
        fail("semantic source/object strategy is invalid")
    if (
        strategy["status"] != "implemented_internal_companion_with_production_non_debug_equivalence"
        or strategy["selection_basis"] != "target_object_analysis_follow_on"
        or strategy["crate"] != "fs2"
        or strategy["profile"] != "release"
        or strategy["requested_toolchain"] != TOOLCHAIN
        or strategy["source_inventory_ref"] != "coverage/surface.json"
        or strategy["mapping_method"] != MAPPING_METHOD
        or strategy["mapping_scope"] != MAPPING_SCOPE
        or strategy["retained_outputs"] != [
            "production_object",
            "production_non_debug_object",
            "mir",
            "llvm_ir",
            "debug_info_object",
            "semantic_non_debug_object",
            "object_structure",
            "disassembly",
            "semantic_source_object_map",
            "production_byte_equivalence",
        ]
        or strategy["production_object_binding"] != PRODUCTION_BINDING_STATUS
        or strategy["generated_code_disposition"] != "reviewed_internal_compiler_generated_not_credited"
    ):
        fail("semantic source/object strategy overstates or changes the registered scope")
    targets = strategy["targets"]
    if not isinstance(targets, list) or [item.get("target") for item in targets] != list(TARGETS):
        fail("semantic source/object target order is invalid")
    for item in targets:
        if not isinstance(item, dict) or set(item) != {"target", "runner", "platform_family", "object_format"}:
            fail("semantic source/object target mapping is invalid")
        target = item["target"]
        if target not in TARGETS or {key: item[key] for key in ("runner", "platform_family", "object_format")} != {
            key: TARGETS[target][key] for key in ("runner", "platform_family", "object_format")
        }:
            fail("semantic source/object target mapping is invalid")
    review = control["review"]
    if not isinstance(review, dict) or set(review) != {"status", "reviewer", "reviewed_commit", "evidence_refs"}:
        fail("semantic source/object review has invalid fields")
    if review["status"] == "pending_user_review":
        if review != {"status": "pending_user_review", "reviewer": None, "reviewed_commit": None, "evidence_refs": []}:
            fail("pending semantic source/object review must not contain approval data")
    elif review["status"] == "reviewed_internal":
        if not isinstance(review["reviewer"], str) or not review["reviewer"].strip() or not COMMIT_RE.fullmatch(str(review["reviewed_commit"])):
            fail("reviewed semantic source/object review is incomplete")
        if not isinstance(review["evidence_refs"], list) or not review["evidence_refs"]:
            fail("reviewed semantic source/object review lacks evidence references")
    else:
        fail("semantic source/object review has an unsupported status")
    for field in ("open_items", "non_claims"):
        values = control[field]
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value.strip() for value in values):
            fail(f"semantic source/object {field} is incomplete")
    if control["non_claims"] != NON_CLAIMS:
        fail("semantic source/object control non-claims differ from the registered contract")


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
        "production_command",
        "object_command",
        "native_exits",
        "status",
        "analysis",
        "production_byte_equivalence",
        "artifacts",
        "created_utc",
        "limitations",
        "non_claims",
    ]
    if (
        schema.get("record_type") != "semantic_source_object_run_schema"
        or schema.get("schema_version") != 1
        or schema.get("required") != required
        or schema.get("enums") != {
            "status": ["pass", "fail", "indeterminate", "provenance_error", "focused_only"],
            "profile": ["release"],
            "source_object_mapping_status": ["debug_location_bridge_retained_not_equivalence"],
            "production_object_binding_status": ["production_non_debug_object_payload_equal", "non_debug_object_payload_differ", "not_established"],
            "generated_code_disposition": ["reviewed_internal_compiler_generated_not_credited"],
            "object_code_coverage_status": ["not_collected"],
        }
        or schema.get("promotion_rule")
        != "Only a pass manifest from a clean exact-commit native target run may enter internal review; bounded symbol/relocation-stripped non-debug object section-payload equality is diagnostic traceability evidence and does not establish complete source/object equivalence, object-code coverage, MC/DC, qualification, certification credit, or authority acceptance."
    ):
        fail("coverage/semantic-source-object-run.schema.json is invalid")


PASS_ARTIFACTS = {
    "cargo.stderr.log",
    "cargo.stdout.jsonl",
    "disassembly.txt",
    "fs2.production.nondebug.o",
    "fs2.production.o",
    "fs2.semantic.ll",
    "fs2.semantic.mir",
    "fs2.semantic.debug.o",
    "fs2.semantic.nondebug.o",
    "fs2.semantic.o",
    "object-structure.txt",
    "object.stderr.log",
    "object.stdout.jsonl",
    "production.stderr.log",
    "production.stdout.jsonl",
    "semantic-source-object-map.json",
}


def validate_artifacts(manifest: dict[str, Any], manifest_path: Path, require_pass: bool) -> None:
    records = manifest["artifacts"]
    if not isinstance(records, list):
        fail("semantic source/object artifacts must be a list")
    observed: list[str] = []
    for index, record in enumerate(records):
        label = f"semantic source/object artifacts[{index}]"
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
            fail(f"semantic source/object artifact is missing or unsafe: {relative}")
        if path.stat().st_size != record["bytes"] or sha256(path) != record["sha256"]:
            fail(f"semantic source/object artifact changed: {relative}")
        observed.append(relative.as_posix())
    if observed != sorted(observed):
        fail("semantic source/object artifact inventory is not canonically sorted")
    entries = list(manifest_path.parent.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        fail("semantic source/object directory contains a non-regular or nested entry")
    actual = sorted(path.name for path in entries if path.name != manifest_path.name)
    if observed != actual:
        fail("semantic source/object directory inventory differs from the manifest")
    if require_pass or manifest["status"] == "pass":
        if set(observed) != PASS_ARTIFACTS:
            fail("passing semantic source/object run lacks the exact retained output set")


def validate_manifest(
    manifest_path: Path,
    *,
    expected_commit: str | None = None,
    require_pass: bool = False,
) -> dict[str, Any]:
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("semantic source/object manifest is missing or unsafe")
    manifest_path = manifest_path.resolve()
    manifest = load_json(manifest_path)
    fields = {
        "record_type", "schema_version", "run_id", "repository", "branch", "commit", "tree",
        "dirty", "cargo_lock_sha256", "host", "target", "object_format", "profile", "source_inventory",
        "toolchain", "command", "production_command", "object_command", "native_exits", "status", "analysis", "production_byte_equivalence", "artifacts", "created_utc",
        "limitations", "non_claims",
    }
    if set(manifest) != fields:
        fail("semantic source/object manifest fields do not match the registered contract")
    target = manifest["target"]
    if (
        manifest["record_type"] != "semantic_source_object_run"
        or manifest["schema_version"] != 1
        or manifest["repository"] != "arthurianresolve/fs2-rs"
        or manifest["branch"] != "DO-178C"
        or target not in TARGETS
        or manifest["object_format"] != TARGETS[target]["object_format"]
        or manifest["profile"] != "release"
        or manifest["status"] not in RUN_STATUSES
    ):
        fail("semantic source/object manifest identity or status is invalid")
    if not isinstance(manifest["run_id"], str) or not manifest["run_id"]:
        fail("semantic source/object run_id is invalid")
    if not COMMIT_RE.fullmatch(str(manifest["commit"])) or not COMMIT_RE.fullmatch(str(manifest["tree"])):
        fail("semantic source/object manifest has invalid Git provenance")
    if expected_commit is not None:
        if not COMMIT_RE.fullmatch(expected_commit) or manifest["commit"] != expected_commit:
            fail("semantic source/object manifest does not match the expected commit")
    if not isinstance(manifest["dirty"], bool) or not SHA256_RE.fullmatch(str(manifest["cargo_lock_sha256"])):
        fail("semantic source/object cleanliness or lockfile provenance is invalid")
    host = manifest["host"]
    if not isinstance(host, dict) or set(host) != {"system", "release", "version", "machine", "python", "target"} or not all(isinstance(value, str) and value for value in host.values()):
        fail("semantic source/object host identity is invalid")
    if manifest["status"] == "pass" and (manifest["dirty"] or host["target"] != target):
        fail("passing semantic source/object evidence must be clean and native")
    if manifest["status"] == "focused_only" and not manifest["dirty"]:
        fail("focused-only semantic source/object evidence must disclose a dirty tree")
    if require_pass and manifest["status"] != "pass":
        fail("semantic source/object manifest is not passing")
    source_inventory = manifest["source_inventory"]
    if not isinstance(source_inventory, dict) or set(source_inventory) != {"record_ref", "records"} or source_inventory["record_ref"] != "coverage/surface.json" or source_inventory["records"] != expected_source_inventory(target):
        fail("semantic source/object source inventory is stale or inapplicable")
    toolchain = manifest["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {"requested", "rustc", "cargo", "llvm_objcopy", "llvm_readobj", "llvm_objdump"} or toolchain["requested"] != TOOLCHAIN or not all(isinstance(toolchain[field], str) and toolchain[field].strip() for field in set(toolchain) - {"requested"}):
        fail("semantic source/object toolchain provenance is invalid")
    validate_toolchain_versions(toolchain)
    command = manifest["command"]
    if not isinstance(command, list) or not all(isinstance(value, str) and value for value in command):
        fail("semantic source/object build command is invalid")
    command_text = " ".join(command)
    for required in ("cargo", f"+{TOOLCHAIN}", "rustc", "--package", "fs2", "--lib", "--release", "--target", target, "--locked", "--emit=link,mir,llvm-ir,obj", "-C", "debuginfo=2"):
        if required not in command_text:
            fail("semantic source/object build command is incomplete")
    production_command = manifest["production_command"]
    if not isinstance(production_command, list) or not all(isinstance(value, str) and value for value in production_command):
        fail("semantic source/object production build command is invalid")
    production_command_text = " ".join(production_command)
    for required in ("cargo", f"+{TOOLCHAIN}", "rustc", "--package", "fs2", "--lib", "--release", "--target", target, "--locked", "--emit=link,obj", "-C", "debuginfo=0"):
        if required not in production_command_text:
            fail("semantic source/object production build command is incomplete")
    object_command = manifest["object_command"]
    if not isinstance(object_command, list) or not all(isinstance(value, str) and value for value in object_command):
        fail("semantic source/object companion object command is invalid")
    object_command_text = " ".join(object_command)
    for required in ("cargo", f"+{TOOLCHAIN}", "rustc", "--package", "fs2", "--lib", "--release", "--target", target, "--locked", "--emit=link,mir,llvm-ir,obj", "-C", "debuginfo=0"):
        if required not in object_command_text:
            fail("semantic source/object non-debug semantic command is incomplete")
    exits = manifest["native_exits"]
    if not isinstance(exits, dict) or set(exits) != {"production_cargo", "object_cargo", "cargo", "llvm_objcopy_production", "llvm_objcopy_companion", "llvm_payload_compare", "llvm_readobj", "llvm_objdump"} or not all(value is None or (isinstance(value, int) and not isinstance(value, bool)) for value in exits.values()):
        fail("semantic source/object native exits are invalid")
    if manifest["status"] in {"pass", "focused_only"} and any(value != 0 for value in exits.values()):
        fail("passing semantic source/object evidence has a nonzero native exit")
    analysis = manifest["analysis"]
    required_analysis = {
        "mir_function_count", "mir_switch_count", "llvm_function_count", "llvm_debug_location_count",
        "llvm_conditional_site_count", "object_debug_section_count", "source_object_mapping_status",
        "production_object_binding_status",
        "generated_code_disposition", "object_code_coverage_status",
    }
    if not isinstance(analysis, dict) or set(analysis) != required_analysis:
        fail("semantic source/object result summary is invalid")
    if (
        analysis["source_object_mapping_status"] != "debug_location_bridge_retained_not_equivalence"
        or analysis["production_object_binding_status"] not in ANALYSIS_BINDING_STATUSES
        or analysis["generated_code_disposition"] != "reviewed_internal_compiler_generated_not_credited"
        or analysis["object_code_coverage_status"] != "not_collected"
        or not all(isinstance(analysis[field], int) and not isinstance(analysis[field], bool) and analysis[field] >= 0 for field in (
            "mir_function_count", "mir_switch_count", "llvm_function_count", "llvm_debug_location_count",
            "llvm_conditional_site_count", "object_debug_section_count"
        ))
    ):
        fail("semantic source/object result summary overstates or corrupts the analysis")
    if manifest["status"] == "pass" and not all(analysis[field] > 0 for field in (
        "mir_function_count", "llvm_function_count", "llvm_debug_location_count", "object_debug_section_count"
    )):
        fail("passing semantic source/object evidence lacks compiler semantic observations")
    validate_byte_equivalence(
        manifest["production_byte_equivalence"],
        root=manifest_path.parent,
        require_equal=manifest["status"] in {"pass", "focused_only"},
    )
    if manifest["status"] in {"pass", "focused_only"} and analysis["production_object_binding_status"] != PRODUCTION_BINDING_STATUS:
        fail("passing semantic source/object evidence lacks the registered production-byte binding")
    for field in ("limitations", "non_claims"):
        values = manifest[field]
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value.strip() for value in values):
            fail(f"semantic source/object {field} is incomplete")
    if manifest["non_claims"] != NON_CLAIMS:
        fail("semantic source/object non-claims differ from the registered contract")
    validate_timestamp(manifest["created_utc"], "semantic source/object created_utc")
    validate_artifacts(manifest, manifest_path, require_pass)
    if manifest["status"] in {"pass", "focused_only"}:
        map_record = load_json(manifest_path.parent / "semantic-source-object-map.json")
        validate_map(map_record, root=manifest_path.parent, expected_commit=manifest["commit"], expected_tree=manifest["tree"])
        if (
            analysis["mir_function_count"] != map_record["mir"]["function_count"]
            or analysis["mir_switch_count"] != map_record["mir"]["switch_count"]
            or analysis["llvm_function_count"] != map_record["llvm"]["function_count"]
            or analysis["llvm_debug_location_count"] != map_record["llvm"]["debug_location_count"]
            or analysis["llvm_conditional_site_count"] != map_record["llvm"]["conditional_site_count"]
            or analysis["object_debug_section_count"] != map_record["object"]["debug_section_count"]
        ):
            fail("semantic source/object manifest counts disagree with the retained map")
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
    except (SemanticSourceObjectError, OSError) as error:
        print(f"semantic source/object evidence is invalid: {error}", file=sys.stderr)
        return 1
    print("semantic source/object controls are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
