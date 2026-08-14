#!/usr/bin/env python3
"""Validate the internal module-level source/object reconciliation contract.

The reconciliation is deliberately narrower than source/object equivalence. It
maps demangled fs2 symbols retained in a target rlib to the source module that
owns the symbol. It does not establish statement, basic-block, semantic, or
object-code coverage correspondence.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_INVENTORY_REF = "coverage/surface.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

TARGETS = {
    "x86_64-unknown-linux-gnu": {"object_format": "ELF", "platform_family": "unix"},
    "aarch64-apple-darwin": {"object_format": "Mach-O", "platform_family": "unix"},
    "x86_64-pc-windows-msvc": {"object_format": "COFF", "platform_family": "windows"},
}

ACCEPTED_TARGET_SUMMARIES = {
    "x86_64-unknown-linux-gnu": {
        "run_id": "20260814T055531Z-object-f7191780e5d5",
        "object_manifest_sha256": "1138dace229d4accb4c98ef2c6aaf2008be96bcc5001bf29121cad8a2ef37aae",
        "defined_symbols_sha256": "c5bf2ed7aa17f5cefa8d08fd520b58979c8644d3c0b7745b1b1bb57da66388f8",
        "archive_member_count": 2,
        "object_member_count": 1,
        "defined_symbol_count": 17,
        "fs2_symbol_count": 12,
        "direct_symbol_counts": {
            "src/allocation.rs": 0,
            "src/lib.rs": 7,
            "src/lock.rs": 0,
            "src/stats.rs": 3,
            "src/unix.rs": 2,
        },
    },
    "aarch64-apple-darwin": {
        "run_id": "20260814T055529Z-object-cda3c2be15b9",
        "object_manifest_sha256": "9b59467af5ae00b5d343f2ef3abf6df8cb71f38d526442f23bf8cf1251077abe",
        "defined_symbols_sha256": "5641a0febe084d4d3f84fe70a81cff341f9f2bb4597122b2a5aeaacb7c224ed0",
        "archive_member_count": 2,
        "object_member_count": 1,
        "defined_symbol_count": 32,
        "fs2_symbol_count": 12,
        "direct_symbol_counts": {
            "src/allocation.rs": 0,
            "src/lib.rs": 7,
            "src/lock.rs": 0,
            "src/stats.rs": 3,
            "src/unix.rs": 2,
        },
    },
    "x86_64-pc-windows-msvc": {
        "run_id": "20260814T055542Z-object-6360d9ea744c",
        "object_manifest_sha256": "9011286229be1f82698482068aa7a00ce448f99a7c11504a74ab3eb718612264",
        "defined_symbols_sha256": "1e9c239d72229c35b31e719823c1dc4459a4eba8a5adc5966750680a69582b0a",
        "archive_member_count": 3,
        "object_member_count": 2,
        "defined_symbol_count": 95,
        "fs2_symbol_count": 24,
        "direct_symbol_counts": {
            "src/allocation.rs": 0,
            "src/lib.rs": 7,
            "src/lock.rs": 0,
            "src/stats.rs": 4,
            "src/windows.rs": 13,
        },
    },
}

MAPPING_METHOD = "demangled_fs2_symbol_module_prefix_v1"
MAPPING_SCOPE = "defined_fs2_symbols_in_retained_rlib_module_level_only"
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
        "reason": "Rust monomorphization, inlining, compiler support, and target runtime code may be present in retained object output without semantic source mapping.",
    },
}
RECONCILIATION_NON_CLAIMS = [
    "The map is module-level symbol inventory evidence; it does not establish source/object equivalence or statement/basic-block mapping.",
    "Compiler-generated, monomorphized, inlined, runtime, and foreign-library code remains outside the reviewed source mapping.",
    "The record does not establish object-code structural coverage, MC/DC, tool qualification, certification credit, or authority acceptance.",
]


class ReconciliationError(Exception):
    """A source/object reconciliation record or artifact is invalid."""


def fail(message: str) -> None:
    raise ReconciliationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def canonical_text_sha256(path: Path) -> str:
    contents = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(contents).hexdigest()


def expected_source_inventory(target: str) -> list[dict[str, Any]]:
    from validate_object_analysis import expected_source_inventory as load_inventory

    return load_inventory(target)


def parse_defined_symbols(text: str) -> list[str]:
    symbols: list[str] = []
    for line in text.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) != 3:
            continue
        symbol = fields[2].strip()
        if symbol.startswith("fs2::") or "fs2..FileExt" in symbol:
            symbols.append(symbol)
    return sorted(set(symbols))


def symbol_source_path(symbol: str) -> str:
    if symbol.startswith("fs2::allocation::"):
        return "src/allocation.rs"
    if symbol.startswith("fs2::lock::"):
        return "src/lock.rs"
    if symbol.startswith("fs2::stats::"):
        return "src/stats.rs"
    if symbol.startswith("fs2::unix::"):
        return "src/unix.rs"
    if symbol.startswith("fs2::windows::"):
        return "src/windows.rs"
    if "fs2..FileExt" in symbol or symbol.startswith("fs2::"):
        return "src/lib.rs"
    fail(f"cannot map fs2 symbol to a source module: {symbol}")


def source_records(
    target: str, inventory: list[dict[str, Any]], symbols: list[str]
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for symbol in symbols:
        path = symbol_source_path(symbol)
        counts[path] = counts.get(path, 0) + 1
    return [
        {
            "path": record["path"],
            "source_sha256": record["sha256"],
            "direct_symbol_count": counts.get(record["path"], 0),
            "status": (
                "direct_symbol_observed"
                if counts.get(record["path"], 0)
                else "no_direct_symbol_observed_in_retained_rlib"
            ),
        }
        for record in inventory
    ]


def build_source_object_map(
    *,
    target: str,
    commit: str,
    tree: str,
    inventory: list[dict[str, Any]],
    defined_symbols_text: str,
) -> dict[str, Any]:
    if target not in TARGETS:
        fail(f"unregistered target: {target!r}")
    symbols = parse_defined_symbols(defined_symbols_text)
    return {
        "record_type": "source_object_map",
        "schema_version": 1,
        "target": target,
        "object_format": TARGETS[target]["object_format"],
        "commit": commit,
        "tree": tree,
        "source_inventory": {
            "record_ref": SOURCE_INVENTORY_REF,
            "records": inventory,
        },
        "mapping_method": MAPPING_METHOD,
        "mapping_scope": MAPPING_SCOPE,
        "symbols": [
            {"symbol": symbol, "source_path": symbol_source_path(symbol)}
            for symbol in symbols
        ],
        "source_records": source_records(target, inventory, symbols),
        "generation_review": GENERATION_REVIEW,
        "object_code_coverage": {
            "status": "not_collected",
            "reason": "The retained rlib inventory and module-level map do not provide executed object-code structural coverage.",
        },
        "non_claims": RECONCILIATION_NON_CLAIMS,
    }


def validate_source_object_map(
    record: dict[str, Any],
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    defined_symbols_text: str | None = None,
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
        "symbols",
        "source_records",
        "generation_review",
        "object_code_coverage",
        "non_claims",
    }
    if set(record) != fields:
        fail("source-object map fields do not match the registered contract")
    target = record["target"]
    if target not in TARGETS or record["object_format"] != TARGETS[target]["object_format"]:
        fail("source-object map target or object format is invalid")
    for field, value in (("commit", record["commit"]), ("tree", record["tree"])):
        if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
            fail(f"source-object map {field} is invalid")
    if expected_commit is not None and record["commit"] != expected_commit:
        fail("source-object map does not match the expected commit")
    if expected_tree is not None and record["tree"] != expected_tree:
        fail("source-object map does not match the expected tree")
    inventory = record["source_inventory"]
    if not isinstance(inventory, dict) or set(inventory) != {"record_ref", "records"}:
        fail("source-object map source inventory is invalid")
    if inventory["record_ref"] != SOURCE_INVENTORY_REF:
        fail("source-object map source inventory reference is invalid")
    expected_inventory = expected_source_inventory(target)
    if inventory["records"] != expected_inventory:
        fail("source-object map source inventory is stale or inapplicable")
    if record["mapping_method"] != MAPPING_METHOD or record["mapping_scope"] != MAPPING_SCOPE:
        fail("source-object map method or scope is invalid")

    symbols = record["symbols"]
    if not isinstance(symbols, list) or any(not isinstance(item, dict) for item in symbols):
        fail("source-object map symbols must be objects")
    if symbols != sorted(symbols, key=lambda item: item.get("symbol", "")):
        fail("source-object map symbols are not canonically ordered")
    observed_symbols: list[str] = []
    expected_paths = {item["path"] for item in expected_inventory}
    for index, item in enumerate(symbols):
        label = f"source-object map symbols[{index}]"
        if not isinstance(item, dict) or set(item) != {"symbol", "source_path"}:
            fail(f"{label} has an invalid shape")
        symbol = item["symbol"]
        path = item["source_path"]
        if not isinstance(symbol, str) or not symbol or symbol in observed_symbols:
            fail(f"{label}.symbol is invalid or duplicated")
        if not isinstance(path, str) or path != symbol_source_path(symbol) or path not in expected_paths:
            fail(f"{label}.source_path is not a valid module mapping")
        observed_symbols.append(symbol)
    if defined_symbols_text is not None and observed_symbols != parse_defined_symbols(defined_symbols_text):
        fail("source-object map does not match the retained defined-symbol inventory")

    records = record["source_records"]
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        fail("source-object map source records must be objects")
    if [item.get("path") for item in records] != [item["path"] for item in expected_inventory]:
        fail("source-object map source records are incomplete or unordered")
    counts: dict[str, int] = {}
    for symbol in observed_symbols:
        path = symbol_source_path(symbol)
        counts[path] = counts.get(path, 0) + 1
    for index, (item, expected) in enumerate(zip(records, expected_inventory)):
        label = f"source-object map source_records[{index}]"
        if not isinstance(item, dict) or set(item) != {"path", "source_sha256", "direct_symbol_count", "status"}:
            fail(f"{label} has an invalid shape")
        if item["path"] != expected["path"] or item["source_sha256"] != expected["sha256"]:
            fail(f"{label} has stale source identity")
        source = ROOT / item["path"]
        if not source.is_file() or canonical_text_sha256(source) != item["source_sha256"]:
            fail(f"{label} has a stale source digest")
        count = counts.get(item["path"], 0)
        if item["direct_symbol_count"] != count:
            fail(f"{label} has an incorrect direct symbol count")
        expected_status = "direct_symbol_observed" if count else "no_direct_symbol_observed_in_retained_rlib"
        if item["status"] != expected_status:
            fail(f"{label} has an invalid symbol observation status")

    if record["generation_review"] != GENERATION_REVIEW:
        fail("source-object map generated-code disposition is invalid")
    coverage = record["object_code_coverage"]
    if not isinstance(coverage, dict) or set(coverage) != {"status", "reason"} or coverage["status"] != "not_collected" or not isinstance(coverage["reason"], str) or not coverage["reason"].strip():
        fail("source-object map object-code coverage disposition is invalid")
    if record["non_claims"] != RECONCILIATION_NON_CLAIMS:
        fail("source-object map non-claims differ from the registered contract")


def validate_record(record: dict[str, Any]) -> None:
    fields = {
        "record_type",
        "schema_version",
        "status",
        "owner",
        "assurance_context",
        "software_level",
        "credit",
        "baseline",
        "source_inventory_ref",
        "mapping_method",
        "mapping_scope",
        "targets",
        "generation_review",
        "object_code_coverage",
        "open_items",
        "non_claims",
    }
    if set(record) != fields:
        fail("coverage/source-object-reconciliation.json fields do not match the registered contract")
    if (
        record["record_type"] != "source_object_reconciliation"
        or record["schema_version"] != 1
        or record["status"] != "reviewed_internal_inventory_only"
        or record["owner"] != "fs2 DO-178C coverage workstream"
        or record["assurance_context"] != "internal_assurance"
        or record["software_level"] != "DAL_B"
        or record["credit"] != "none"
        or record["source_inventory_ref"] != SOURCE_INVENTORY_REF
        or record["mapping_method"] != MAPPING_METHOD
        or record["mapping_scope"] != MAPPING_SCOPE
    ):
        fail("source-object reconciliation identity or assurance state is invalid")
    baseline = record["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != {
        "commit",
        "tree",
        "package_id",
        "workflow_run_id",
        "package_manifest_sha256",
        "review_ref",
    }:
        fail("source-object reconciliation baseline is invalid")
    if (
        baseline["commit"] != "f24c570bc9c302e4a5cb14cd580b7247f9888916"
        or baseline["tree"] != "46db086cfdd538c498de4e1993d6af1805af0686"
        or baseline["package_id"] != "ASSURANCE-f24c570bc9c3-31774523702"
        or baseline["workflow_run_id"] != "31774523702"
        or baseline["package_manifest_sha256"] != "1981909ab7ff23cf9cd4790ea59569d1c6e2aa52ad5267989cae9071291bfc0d"
        or baseline["review_ref"] != "independent-review:IR-OBJECT-ANALYSIS-001"
    ):
        fail("source-object reconciliation baseline is not bound to the accepted package")
    if not SHA256_RE.fullmatch(baseline["package_manifest_sha256"]):
        fail("source-object reconciliation package digest is invalid")

    targets = record["targets"]
    if not isinstance(targets, list) or any(not isinstance(item, dict) for item in targets):
        fail("source-object reconciliation targets must be objects")
    if [item.get("target") for item in targets] != list(TARGETS):
        fail("source-object reconciliation target order is invalid")
    for index, target_record in enumerate(targets):
        label = f"source-object reconciliation targets[{index}]"
        required = {
            "target",
            "object_format",
            "run_id",
            "object_manifest_ref",
            "object_manifest_sha256",
            "defined_symbols_ref",
            "defined_symbols_sha256",
            "archive_member_count",
            "object_member_count",
            "defined_symbol_count",
            "fs2_symbol_count",
            "source_records",
        }
        if not isinstance(target_record, dict) or set(target_record) != required:
            fail(f"{label} has an invalid shape")
        target = target_record["target"]
        if target not in TARGETS or target_record["object_format"] != TARGETS[target]["object_format"]:
            fail(f"{label} has an invalid target")
        expected_summary = ACCEPTED_TARGET_SUMMARIES[target]
        if target_record["run_id"] != expected_summary["run_id"]:
            fail(f"{label}.run_id is not bound to the accepted target run")
        if not isinstance(target_record["object_manifest_ref"], str) or not target_record["object_manifest_ref"].startswith("package:ASSURANCE-f24c570bc9c3-31774523702/"):
            fail(f"{label}.object_manifest_ref is invalid")
        if target_record["object_manifest_sha256"] != expected_summary["object_manifest_sha256"]:
            fail(f"{label}.object_manifest_sha256 is not bound to the accepted target manifest")
        if not isinstance(target_record["defined_symbols_ref"], str) or not target_record["defined_symbols_ref"].startswith("package:ASSURANCE-f24c570bc9c3-31774523702/"):
            fail(f"{label}.defined_symbols_ref is invalid")
        if target_record["defined_symbols_sha256"] != expected_summary["defined_symbols_sha256"]:
            fail(f"{label}.defined_symbols_sha256 is not bound to the accepted symbol inventory")
        if not SHA256_RE.fullmatch(str(target_record["object_manifest_sha256"])) or not SHA256_RE.fullmatch(str(target_record["defined_symbols_sha256"])):
            fail(f"{label} contains an invalid artifact digest")
        if not all(isinstance(target_record[field], int) and target_record[field] >= 0 for field in ("archive_member_count", "object_member_count", "defined_symbol_count")):
            fail(f"{label} has invalid object counts")
        for field in ("archive_member_count", "object_member_count", "defined_symbol_count", "fs2_symbol_count"):
            if target_record[field] != expected_summary[field]:
                fail(f"{label}.{field} disagrees with the accepted target run")
        source_record_values = target_record["source_records"]
        if not isinstance(source_record_values, list):
            fail(f"{label}.source_records must be a list")
        expected_inventory = expected_source_inventory(target)
        expected_paths = [item["path"] for item in expected_inventory]
        if [item.get("path") for item in source_record_values] != expected_paths:
            fail(f"{label}.source_records are incomplete or unordered")
        for source_index, (source_record, expected_source) in enumerate(zip(source_record_values, expected_inventory)):
            source_label = f"{label}.source_records[{source_index}]"
            if not isinstance(source_record, dict) or set(source_record) != {"path", "source_sha256", "direct_symbol_count", "status"}:
                fail(f"{source_label} has an invalid shape")
            if source_record["path"] != expected_source["path"] or source_record["source_sha256"] != expected_source["sha256"]:
                fail(f"{source_label} has stale source identity")
            expected_count = expected_summary["direct_symbol_counts"][source_record["path"]]
            if source_record["direct_symbol_count"] != expected_count:
                fail(f"{source_label}.direct_symbol_count disagrees with the accepted symbol inventory")
            expected_status = "direct_symbol_observed" if expected_count else "no_direct_symbol_observed_in_retained_rlib"
            if source_record["status"] != expected_status:
                fail(f"{source_label}.status is invalid")
    if record["generation_review"] != GENERATION_REVIEW:
        fail("source-object reconciliation generated-code disposition is invalid")
    if record["object_code_coverage"] != {
        "status": "not_collected",
        "reason": "No target-specific executed object-code structural coverage artifact is retained; source-level MC/DC remains a separate internal record.",
    }:
        fail("source-object reconciliation object-code coverage disposition is invalid")
    for field in ("open_items", "non_claims"):
        values = record[field]
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value.strip() for value in values):
            fail(f"source-object reconciliation {field} is incomplete")
    if record["non_claims"] != RECONCILIATION_NON_CLAIMS:
        fail("source-object reconciliation non-claims differ from the registered contract")


if __name__ == "__main__":
    validate_record(load_json(ROOT / "coverage" / "source-object-reconciliation.json"))
    print("source-object reconciliation is valid")
