#!/usr/bin/env python3
"""Validate the internal DO-178C coverage records and run manifests.

The validator is intentionally conservative.  It checks record structure,
source hashes, explicit denominator classifications, requirements mappings,
and run provenance.  It does not calculate or accept certification coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "coverage"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SPAN_RE = re.compile(r"^(\d+)-(\d+)$")
REQUIRED_RECORDS = (
    "assurance-context.json",
    "requirements.json",
    "surface.json",
    "decision-inventory.json",
    "policy.json",
    "tool-assessment.json",
    "run-manifest.schema.json",
    "evidence-index.json",
    "gap-register.json",
    "verification-inventory.json",
    "mcdc.json",
)
VALID_RECORD_STATUSES = {"draft", "assessment_open", "not_ready"}
VALID_MANIFEST_STATUSES = {
    "pass",
    "fail",
    "indeterminate",
    "provenance_error",
    "focused_only",
}
VALID_CLASSIFICATIONS = {
    "production",
    "test_only",
    "test_support",
    "generated",
    "vendored",
}


class ValidationError(Exception):
    """A record-validation failure."""


def fail(message: str) -> None:
    raise ValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path.relative_to(ROOT)} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def required_fields(value: dict[str, Any], fields: set[str], label: str) -> None:
    missing = fields - value.keys()
    if missing:
        fail(f"{label} is missing fields: {sorted(missing)}")


def check_status(value: dict[str, Any], label: str) -> None:
    status = value.get("status")
    if status not in VALID_RECORD_STATUSES:
        fail(f"{label} has invalid record status: {status!r}")


def source_path(reference: str, label: str) -> Path:
    if not isinstance(reference, str) or not reference:
        fail(f"{label} must be a non-empty source reference")
    relative = reference.split(":", 1)[0].replace("\\", "/")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        fail(f"{label} escapes the repository: {reference!r}")
    if not path.is_file():
        fail(f"{label} references missing source file: {reference!r}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_source_sha256(path: Path) -> str:
    """Hash text source with a host-independent LF line-ending contract."""
    contents = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(contents).hexdigest()


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def validate_context(context: dict[str, Any]) -> None:
    label = "coverage/assurance-context.json"
    required_fields(
        context,
        {
            "record_type",
            "schema_version",
            "status",
            "owner",
            "repository",
            "branch",
            "baseline",
            "planning_target_level",
            "assigned_software_level",
            "certification_credit",
            "approved_basis_refs",
            "requirements_status",
            "mcdc_status",
            "tool_credit",
            "independence_status",
            "open_items",
        },
        label,
    )
    check_status(context, label)
    if context["record_type"] != "assurance_context" or context["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if context["repository"] != "arthurianresolve/fs2-rs" or context["branch"] != "DO-178C":
        fail(f"{label} is bound to the wrong repository or branch")
    if context["planning_target_level"] != "DAL_B":
        fail(f"{label} must retain the approved planning target DAL_B")
    if context["assigned_software_level"] is not None:
        fail(f"{label} must not imply an assigned software level")
    if context["certification_credit"] != "none":
        fail(f"{label} must declare no certification credit")
    if context["approved_basis_refs"] != []:
        fail(f"{label} contains an unapproved basis reference")
    if context["mcdc_status"] != "not_assessed" or context["tool_credit"] != "internal_only":
        fail(f"{label} contains an unsupported assurance claim")
    baseline = context["baseline"]
    if not isinstance(baseline, dict):
        fail(f"{label}.baseline must be an object")
    required_fields(
        baseline,
        {"reference", "reference_kind", "working_tree_state", "exact_commit_required_for_evidence"},
        f"{label}.baseline",
    )
    if not isinstance(baseline["reference"], str) or not COMMIT_RE.fullmatch(baseline["reference"]):
        fail(f"{label}.baseline.reference must be a full commit")
    if baseline["exact_commit_required_for_evidence"] is not True:
        fail(f"{label} must require exact commit provenance")
    if not isinstance(context["open_items"], list) or not context["open_items"]:
        fail(f"{label}.open_items must retain unresolved assurance decisions")


def validate_requirements(requirements: dict[str, Any], verification_ids: set[str] | None = None) -> set[str]:
    label = "coverage/requirements.json"
    required_fields(requirements, {"record_type", "schema_version", "status", "owner", "basis", "requirements"}, label)
    check_status(requirements, label)
    if requirements["record_type"] != "derived_requirements" or requirements["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    records = requirements["requirements"]
    if not isinstance(records, list) or not records:
        fail(f"{label}.requirements must be a non-empty list")
    identifiers: set[str] = set()
    for index, record in enumerate(records):
        item_label = f"{label}.requirements[{index}]"
        if not isinstance(record, dict):
            fail(f"{item_label} must be an object")
        required_fields(
            record,
            {"id", "statement", "source_refs", "platforms", "verification_ids", "expected_result", "status", "review"},
            item_label,
        )
        identifier = record["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"REQ-[A-Z0-9-]+", identifier) or identifier in identifiers:
            fail(f"{item_label}.id must be a unique REQ identifier")
        identifiers.add(identifier)
        for field in ("statement", "expected_result"):
            if not isinstance(record[field], str) or not record[field].strip():
                fail(f"{item_label}.{field} must be non-empty")
        for field in ("source_refs", "platforms", "verification_ids"):
            values = record[field]
            if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
                fail(f"{item_label}.{field} must be a non-empty string list")
        for reference in record["source_refs"]:
            source_path(reference, f"{item_label}.source_refs")
        if verification_ids is not None:
            missing_verifications = set(record["verification_ids"]) - verification_ids
            if missing_verifications:
                fail(f"{item_label} references unknown verifications: {sorted(missing_verifications)}")
        if record["status"] not in {"mapped", "open", "deferred"}:
            fail(f"{item_label}.status is invalid")
        review = record["review"]
        if not isinstance(review, dict) or review.get("status") not in {"internal_review_open", "accepted", "rejected"}:
            fail(f"{item_label}.review must retain a controlled review status")
    return identifiers


def validate_surface(surface: dict[str, Any], requirement_ids: set[str]) -> set[str]:
    label = "coverage/surface.json"
    required_fields(surface, {"record_type", "schema_version", "status", "owner", "source_revision", "records", "explicit_exclusions"}, label)
    check_status(surface, label)
    if surface["record_type"] != "coverage_surface" or surface["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    records = surface["records"]
    if not isinstance(records, list) or not records:
        fail(f"{label}.records must be a non-empty list")
    identifiers: set[str] = set()
    represented: set[str] = set()
    span_owners: dict[str, dict[int, str]] = {}
    for index, record in enumerate(records):
        item_label = f"{label}.records[{index}]"
        if not isinstance(record, dict):
            fail(f"{item_label} must be an object")
        required_fields(
            record,
            {"id", "path", "sha256", "line_spans", "classification", "applicability", "denominator", "requirement_ids", "decision_ids"},
            item_label,
        )
        identifier = record["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"SURF-[A-Z0-9-]+", identifier) or identifier in identifiers:
            fail(f"{item_label}.id must be a unique SURF identifier")
        identifiers.add(identifier)
        path = source_path(record["path"], f"{item_label}.path")
        represented.add(record["path"].replace("/", "\\"))
        digest = record["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail(f"{item_label}.sha256 must be a lowercase SHA-256 digest")
        if digest != canonical_source_sha256(path):
            fail(f"{item_label}.sha256 does not match {record['path']}")
        spans = record["line_spans"]
        if not isinstance(spans, list) or not spans:
            fail(f"{item_label}.line_spans must be non-empty")
        maximum = line_count(path)
        for span in spans:
            match = SPAN_RE.fullmatch(span) if isinstance(span, str) else None
            if match is None or int(match.group(1)) < 1 or int(match.group(2)) < int(match.group(1)) or int(match.group(2)) > maximum:
                fail(f"{item_label}.line_spans contains an invalid span: {span!r}")
            owners = span_owners.setdefault(record["path"].replace("\\", "/"), {})
            for line_number in range(int(match.group(1)), int(match.group(2)) + 1):
                previous = owners.get(line_number)
                if previous is not None:
                    fail(
                        f"{item_label}.line_spans overlaps {previous} at "
                        f"{record['path']}:{line_number}"
                    )
                owners[line_number] = record["classification"]
        if record["classification"] not in VALID_CLASSIFICATIONS:
            fail(f"{item_label}.classification is invalid")
        if record["denominator"] not in {"in_scope", "excluded_with_classification"}:
            fail(f"{item_label}.denominator is invalid")
        if record["classification"] == "production" and record["denominator"] != "in_scope":
            fail(f"{item_label} production records must be in_scope")
        if record["classification"] != "production" and record["denominator"] != "excluded_with_classification":
            fail(f"{item_label} non-production records require an explicit exclusion")
        for field in ("applicability", "requirement_ids", "decision_ids"):
            if not isinstance(record[field], list) or not all(isinstance(value, str) for value in record[field]):
                fail(f"{item_label}.{field} must be a string list")
        unknown_requirements = set(record["requirement_ids"]) - requirement_ids
        if unknown_requirements:
            fail(f"{item_label} references unknown requirements: {sorted(unknown_requirements)}")

    expected_paths = {
        *[path.relative_to(ROOT).as_posix().replace("/", "\\") for path in (ROOT / "src").rglob("*.rs")],
        *[path.relative_to(ROOT).as_posix().replace("/", "\\") for path in (ROOT / "tests").rglob("*.rs")],
    }
    missing_paths = expected_paths - represented
    if missing_paths:
        fail(f"{label} omits source/test files: {sorted(missing_paths)}")
    for relative in expected_paths:
        path = ROOT / relative.replace("\\", "/")
        owners = span_owners.get(relative.replace("\\", "/"), {})
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip() != "#[cfg(test)]":
                continue
            classification = owners.get(line_number)
            if classification is None:
                fail(f"{label} does not classify test module declaration {relative}:{line_number}")
            if classification == "production":
                fail(f"{label} classifies test module declaration as production: {relative}:{line_number}")
    exclusions = surface["explicit_exclusions"]
    if not isinstance(exclusions, list) or not exclusions:
        fail(f"{label}.explicit_exclusions must be non-empty")
    for index, exclusion in enumerate(exclusions):
        if not isinstance(exclusion, dict) or not all(key in exclusion for key in ("path", "reason", "review_status")):
            fail(f"{label}.explicit_exclusions[{index}] is incomplete")
    return identifiers


def validate_decisions(
    inventory: dict[str, Any],
    requirement_ids: set[str],
    verification_ids: set[str] | None = None,
    mcdc_ids: set[str] | None = None,
) -> set[str]:
    label = "coverage/decision-inventory.json"
    required_fields(inventory, {"record_type", "schema_version", "status", "owner", "decision_basis", "decisions", "open_dispositions"}, label)
    check_status(inventory, label)
    if inventory["record_type"] != "source_decision_inventory" or inventory["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    decisions = inventory["decisions"]
    if not isinstance(decisions, list) or not decisions:
        fail(f"{label}.decisions must be a non-empty list")
    identifiers: set[str] = set()
    for index, decision in enumerate(decisions):
        item_label = f"{label}.decisions[{index}]"
        if not isinstance(decision, dict):
            fail(f"{item_label} must be an object")
        required_fields(decision, {"id", "source", "symbol", "requirement_ids", "applicability", "outcomes", "verification_ids", "status"}, item_label)
        identifier = decision["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"DEC-[A-Z0-9-]+", identifier) or identifier in identifiers:
            fail(f"{item_label}.id must be a unique DEC identifier")
        identifiers.add(identifier)
        source_path(decision["source"], f"{item_label}.source")
        if not isinstance(decision["symbol"], str) or not decision["symbol"]:
            fail(f"{item_label}.symbol must be non-empty")
        unknown = set(decision["requirement_ids"]) - requirement_ids
        if unknown:
            fail(f"{item_label} references unknown requirements: {sorted(unknown)}")
        for field in ("requirement_ids", "applicability", "outcomes", "verification_ids"):
            if not isinstance(decision[field], list) or not decision[field] or not all(isinstance(value, str) and value for value in decision[field]):
                fail(f"{item_label}.{field} must be a non-empty string list")
        if verification_ids is not None:
            missing_verifications = set(decision["verification_ids"]) - verification_ids
            if missing_verifications:
                fail(f"{item_label} references unknown verifications: {sorted(missing_verifications)}")
        if len(decision["outcomes"]) < 2:
            fail(f"{item_label} must record at least two outcomes")
        if decision["status"] not in {"mapped", "open", "deferred"}:
            fail(f"{item_label}.status is invalid")
        if "mcdc_record_ids" in decision:
            records = decision["mcdc_record_ids"]
            if not isinstance(records, list) or not all(isinstance(value, str) and value for value in records):
                fail(f"{item_label}.mcdc_record_ids must be a string list")
            if mcdc_ids is not None:
                unknown_mcdc = set(records) - mcdc_ids
                if unknown_mcdc:
                    fail(f"{item_label} references unknown MC/DC records: {sorted(unknown_mcdc)}")
    return identifiers


def validate_policy(policy: dict[str, Any]) -> None:
    label = "coverage/policy.json"
    required_fields(policy, {"record_type", "schema_version", "status", "owner", "claim_class", "required_controls", "metrics", "denominator_rules", "release_blockers", "non_claims"}, label)
    check_status(policy, label)
    if policy["record_type"] != "coverage_policy" or policy["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if policy["claim_class"] != "internal_engineering_evidence":
        fail(f"{label} must be internal-only")
    metrics = policy["metrics"]
    if not isinstance(metrics, dict) or set(metrics) != {"line", "region", "branch", "condition_diagnostic", "function", "mcdc"}:
        fail(f"{label}.metrics must separate line, region, branch, condition diagnostics, function, and mcdc")
    if metrics["branch"].get("mcdc_claim") is not False or metrics["mcdc"].get("status") != "not_assessed":
        fail(f"{label} must not convert branch coverage into MC/DC")
    for field in ("required_controls", "denominator_rules", "release_blockers", "non_claims"):
        if not isinstance(policy[field], list) or not policy[field] or not all(isinstance(value, str) and value for value in policy[field]):
            fail(f"{label}.{field} must be a non-empty string list")


def validate_tool_assessment(tool: dict[str, Any]) -> None:
    label = "coverage/tool-assessment.json"
    required_fields(tool, {"record_type", "schema_version", "status", "owner", "toolchain", "qualification_status", "credit_status", "functions", "open_decisions"}, label)
    check_status(tool, label)
    if tool["record_type"] != "tool_assessment" or tool["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if tool["qualification_status"] != "not_qualified" or tool["credit_status"] != "internal_only":
        fail(f"{label} contains an unsupported tool claim")
    functions = tool["functions"]
    if not isinstance(functions, list) or not functions:
        fail(f"{label}.functions must be non-empty")
    identifiers: set[str] = set()
    for index, function in enumerate(functions):
        item_label = f"{label}.functions[{index}]"
        if not isinstance(function, dict):
            fail(f"{item_label} must be an object")
        required_fields(function, {"id", "function", "status", "failure_modes", "fallback", "residual_reliance"}, item_label)
        if function["id"] in identifiers or not isinstance(function["id"], str):
            fail(f"{item_label}.id must be unique")
        identifiers.add(function["id"])
        if function["status"] not in {"assessment_open", "internal_only", "not_implemented"}:
            fail(f"{item_label}.status is invalid")
        for field in ("failure_modes", "fallback", "residual_reliance"):
            value = function[field]
            if isinstance(value, list):
                if not value or not all(isinstance(item, str) and item for item in value):
                    fail(f"{item_label}.{field} is invalid")
            elif not isinstance(value, str) or not value:
                fail(f"{item_label}.{field} is invalid")


def validate_evidence_index(index: dict[str, Any]) -> None:
    label = "coverage/evidence-index.json"
    required_fields(index, {"record_type", "schema_version", "status", "owner", "archive_status", "external_archive_uri", "runs", "open_items", "non_claims"}, label)
    check_status(index, label)
    if index["record_type"] != "evidence_index" or index["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if index["archive_status"] != "not_archived" or index["external_archive_uri"] is not None:
        fail(f"{label} must not imply an external archive")
    runs = index["runs"]
    if not isinstance(runs, list) or not runs:
        fail(f"{label}.runs must be a list")
    identifiers: set[str] = set()
    provenance: set[tuple[str, str]] = set()
    for index_number, run in enumerate(runs):
        run_label = f"{label}.runs[{index_number}]"
        if not isinstance(run, dict):
            fail(f"{run_label} must be an object")
        required_fields(
            run,
            {"run_id", "profile", "target", "commit", "tree", "status", "disposition"},
            run_label,
        )
        run_id = run["run_id"]
        if not isinstance(run_id, str) or not run_id or run_id in identifiers:
            fail(f"{run_label}.run_id must be unique and non-empty")
        identifiers.add(run_id)
        if run["profile"] not in {"stable", "branch", "condition"}:
            fail(f"{run_label}.profile is invalid")
        if not isinstance(run["target"], str) or not run["target"]:
            fail(f"{run_label}.target must be non-empty")
        if not COMMIT_RE.fullmatch(str(run["commit"])) or not COMMIT_RE.fullmatch(str(run["tree"])):
            fail(f"{run_label} must contain full commit and tree values")
        if run["status"] != "pass" or run["disposition"] != "local_disposable_not_promoted":
            fail(f"{run_label} contains an unsupported promotion disposition")
        provenance.add((run["commit"], run["tree"]))
    if len(provenance) != 1:
        fail(f"{label}.runs must share one exact commit and tree snapshot")


def validate_verification_inventory(inventory: dict[str, Any]) -> set[str]:
    label = "coverage/verification-inventory.json"
    required_fields(inventory, {"record_type", "schema_version", "status", "owner", "source_revision", "inventory_basis", "verifications"}, label)
    check_status(inventory, label)
    if inventory["record_type"] != "verification_inventory" or inventory["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    records = inventory["verifications"]
    if not isinstance(records, list) or not records:
        fail(f"{label}.verifications must be non-empty")
    identifiers: set[str] = set()
    for index, record in enumerate(records):
        item_label = f"{label}.verifications[{index}]"
        if not isinstance(record, dict):
            fail(f"{item_label} must be an object")
        required_fields(record, {"id", "kind", "platforms"}, item_label)
        identifier = record["id"]
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            fail(f"{item_label}.id must be unique and non-empty")
        identifiers.add(identifier)
        if record["kind"] not in {"unit", "integration", "doctest"}:
            fail(f"{item_label}.kind is invalid")
        if not isinstance(record["platforms"], list) or not record["platforms"] or not all(isinstance(value, str) for value in record["platforms"]):
            fail(f"{item_label}.platforms must be a non-empty string list")
        if "targets" in record:
            if not isinstance(record["targets"], list) or not record["targets"] or not all(
                isinstance(value, str) and value for value in record["targets"]
            ):
                fail(f"{item_label}.targets must be a non-empty string list")
    return identifiers


def parse_cargo_test_list(output: str, default_kind: str | None = None) -> dict[str, set[str]]:
    """Parse Cargo's grouped test listing into stable verification IDs."""
    discovered = {"unit": set(), "integration": set(), "doctest": set()}
    kind: str | None = default_kind
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "Running unittests " in line:
            kind = "unit"
        elif "Running tests/" in line or "Running tests\\" in line:
            kind = "integration"
        elif line.startswith("Doc-tests "):
            kind = "doctest"
        if kind is None or not line.endswith(": test"):
            continue
        identifier = line[: -len(": test")].replace("\\", "/")
        if kind == "doctest":
            match = re.fullmatch(r"(.+?) - (.+) \(line (\d+)\)", identifier)
            if match is None:
                fail(f"unable to normalize Cargo doctest identity: {identifier!r}")
            identifier = f"{match.group(1)}:{match.group(2).removeprefix('stats::')} (line {match.group(3)})"
        discovered[kind].add(identifier)
    return discovered


def validate_test_inventory() -> None:
    """Compare the catalog with the tests discoverable on the current runtime host."""
    commands = {
        "unit": ["cargo", "test", "--package", "fs2", "--lib", "--locked", "--", "--list"],
        "integration": [
            "cargo", "test", "--package", "fs2", "--test", "upstream_compat", "--locked", "--", "--list"
        ],
        "doctest": ["cargo", "test", "--package", "fs2", "--doc", "--locked", "--", "--list"],
    }
    rustc = subprocess.run(
        ["rustc", "-vV"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if rustc.returncode != 0:
        detail = rustc.stderr.strip() or rustc.stdout.strip()
        fail(f"rustc -vV failed: {detail}")
    target = next(
        (line.split(":", 1)[1].strip() for line in rustc.stdout.splitlines() if line.startswith("host:")),
        None,
    )
    if not target:
        fail("rustc -vV did not report a host target")
    discovered = {kind: set() for kind in commands}
    for kind, command in commands.items():
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            fail(f"{' '.join(command)} failed: {detail}")
        discovered[kind] = parse_cargo_test_list(
            result.stdout + "\n" + result.stderr, default_kind=kind
        )[kind]
    inventory = load_json(COVERAGE / "verification-inventory.json")["verifications"]
    runtime = "windows" if os.name == "nt" else "unix"
    expected = {
        kind: {
            item["id"]
            for item in inventory
            if item["kind"] == kind
            and runtime in item["platforms"]
            and ("targets" not in item or target in item["targets"])
        }
        for kind in discovered
    }
    for kind in discovered:
        missing = discovered[kind] - expected[kind]
        stale = expected[kind] - discovered[kind]
        if missing or stale:
            fail(
                f"verification inventory drift for {runtime}/{kind}: "
                f"missing={sorted(missing)}, stale={sorted(stale)}"
            )


def validate_gap_register(gaps: dict[str, Any]) -> None:
    label = "coverage/gap-register.json"
    required_fields(gaps, {"record_type", "schema_version", "status", "owner", "baseline", "observed_metrics", "historical_internal_metrics", "clean_local_snapshot", "gaps", "closure_rules", "non_claims"}, label)
    check_status(gaps, label)
    if gaps["record_type"] != "coverage_gap_register" or gaps["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    baseline = gaps["baseline"]
    if not isinstance(baseline, dict) or not COMMIT_RE.fullmatch(str(baseline.get("commit", ""))) or not COMMIT_RE.fullmatch(str(baseline.get("tree", ""))):
        fail(f"{label}.baseline must contain full commit and tree values")
    if baseline.get("measurement_status") != "focused_only" or baseline.get("dirty") is not True:
        fail(f"{label} must identify focused dirty measurements as non-promotable")
    metrics = gaps["observed_metrics"]
    if not isinstance(metrics, dict) or not all(name in metrics for name in ("stable_line", "stable_region", "branch_diagnostic", "mcdc")):
        fail(f"{label}.observed_metrics must separate stable, branch, and MC/DC status")
    if metrics["mcdc"].get("status") != "not_assessed":
        fail(f"{label} must retain MC/DC as not assessed")
    snapshot = gaps["clean_local_snapshot"]
    if not isinstance(snapshot, dict):
        fail(f"{label}.clean_local_snapshot must be an object")
    required_fields(
        snapshot,
        {"commit", "tree", "dirty", "source_scope", "targets", "profiles", "run_ids", "status"},
        f"{label}.clean_local_snapshot",
    )
    if not COMMIT_RE.fullmatch(str(snapshot["commit"])) or not COMMIT_RE.fullmatch(str(snapshot["tree"])):
        fail(f"{label}.clean_local_snapshot must contain full commit and tree values")
    if snapshot["dirty"] is not False or snapshot["status"] != "clean_exact_commit_local_disposable; not release evidence":
        fail(f"{label}.clean_local_snapshot must remain clean and non-promotable")
    if not isinstance(snapshot["targets"], list) or len(snapshot["targets"]) < 2 or not all(
        isinstance(target, str) and target for target in snapshot["targets"]
    ):
        fail(f"{label}.clean_local_snapshot.targets must identify multiple targets")
    run_ids = snapshot["run_ids"]
    if not isinstance(run_ids, list) or len(run_ids) != 6 or len(set(run_ids)) != len(run_ids) or not all(
        isinstance(run_id, str) and run_id for run_id in run_ids
    ):
        fail(f"{label}.clean_local_snapshot.run_ids must identify six unique runs")
    profiles = snapshot["profiles"]
    expected_profiles = {
        "linux_stable",
        "linux_branch",
        "linux_condition_instrumentation",
        "windows_stable",
        "windows_branch",
        "windows_condition_instrumentation",
    }
    if not isinstance(profiles, dict) or set(profiles) != expected_profiles:
        fail(f"{label}.clean_local_snapshot.profiles must contain the six local profile snapshots")
    for profile_name, profile in profiles.items():
        if not isinstance(profile, dict):
            fail(f"{label}.clean_local_snapshot.profiles.{profile_name} must be an object")
        for metric_name, metric in profile.items():
            if metric_name == "independent_condition_total":
                if metric is not False:
                    fail(f"{label}.clean_local_snapshot.profiles.{profile_name} cannot claim an independent condition total")
                continue
            if not isinstance(metric, dict) or set(metric) != {"covered", "total", "percent"}:
                fail(f"{label}.clean_local_snapshot.profiles.{profile_name}.{metric_name} is invalid")
            if metric["total"] <= 0 or metric["covered"] != metric["total"] or metric["percent"] != 100.0:
                fail(f"{label}.clean_local_snapshot.profiles.{profile_name}.{metric_name} is not closed")
    if not isinstance(gaps["historical_internal_metrics"], dict) or gaps["historical_internal_metrics"].get("status") != "superseded_focused_only_dirty_working_tree; not release evidence":
        fail(f"{label}.historical_internal_metrics must be explicitly superseded")
    records = gaps["gaps"]
    if not isinstance(records, list) or not records:
        fail(f"{label}.gaps must be non-empty")
    identifiers: set[str] = set()
    for index, record in enumerate(records):
        item_label = f"{label}.gaps[{index}]"
        if not isinstance(record, dict):
            fail(f"{item_label} must be an object")
        required_fields(record, {"id", "source_refs", "classification", "observed_condition", "required_action", "status", "credit"}, item_label)
        identifier = record["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"GAP-[A-Z0-9-]+", identifier) or identifier in identifiers:
            fail(f"{item_label}.id must be a unique GAP identifier")
        identifiers.add(identifier)
        if record["status"] not in {"open", "closed", "deferred"} or record["credit"] != "none":
            fail(f"{item_label} contains an unsupported gap status or credit")
        if record["status"] == "closed" and (
            not isinstance(record.get("closure_basis"), str) or not record["closure_basis"].strip()
        ):
            fail(f"{item_label} must record a closure basis")
        for reference in record["source_refs"]:
            source_path(reference, f"{item_label}.source_refs")
        for field in ("classification", "observed_condition", "required_action"):
            if not isinstance(record[field], str) or not record[field].strip():
                fail(f"{item_label}.{field} must be non-empty")
    for field in ("closure_rules", "non_claims"):
        if not isinstance(gaps[field], list) or not gaps[field] or not all(isinstance(value, str) and value for value in gaps[field]):
            fail(f"{label}.{field} must be a non-empty string list")


def validate_static_records() -> None:
    records = {}
    for filename in REQUIRED_RECORDS:
        path = COVERAGE / filename
        if not path.is_file():
            fail(f"required record is missing: coverage/{filename}")
        records[filename] = load_json(path)
    context = records["assurance-context.json"]
    requirements = records["requirements.json"]
    surface = records["surface.json"]
    decisions = records["decision-inventory.json"]
    verifications = validate_verification_inventory(records["verification-inventory.json"])
    from validate_mcdc import validate_record as validate_mcdc_record

    mcdc_ids = validate_mcdc_record(records["mcdc.json"], verifications)
    validate_context(context)
    requirement_ids = validate_requirements(requirements, verifications)
    validate_surface(surface, requirement_ids)
    decision_ids = validate_decisions(decisions, requirement_ids, verifications, mcdc_ids)
    surface_decisions = {
        decision_id
        for record in surface["records"]
        for decision_id in record["decision_ids"]
    }
    unknown_surface_decisions = surface_decisions - decision_ids
    if unknown_surface_decisions:
        fail(f"coverage/surface.json references unknown decisions: {sorted(unknown_surface_decisions)}")
    validate_policy(records["policy.json"])
    validate_tool_assessment(records["tool-assessment.json"])
    validate_evidence_index(records["evidence-index.json"])
    validate_gap_register(records["gap-register.json"])


def validate_manifest(path: Path, expected_commit: str | None = None) -> None:
    manifest = load_json(path)
    label = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
    required_fields(
        manifest,
        {
            "run_id", "repository", "branch", "commit", "tree", "dirty", "cargo_lock_sha256",
            "host", "target", "profile", "requested_toolchain", "resolved_toolchain",
            "cargo_llvm_cov", "command", "environment", "native_exit", "status", "artifacts",
        },
        label,
    )
    if manifest["repository"] != "arthurianresolve/fs2-rs":
        fail(f"{label} has the wrong repository")
    if manifest["branch"] != "DO-178C" and manifest["status"] != "provenance_error":
        fail(f"{label}.branch must be DO-178C")
    for field, pattern in (("commit", COMMIT_RE), ("tree", COMMIT_RE), ("cargo_lock_sha256", SHA256_RE)):
        if not isinstance(manifest[field], str) or not pattern.fullmatch(manifest[field]):
            fail(f"{label}.{field} has invalid provenance")
    if expected_commit is not None and manifest["commit"] != expected_commit:
        fail(f"{label}.commit does not match expected commit {expected_commit}")
    if not isinstance(manifest["dirty"], bool):
        fail(f"{label}.dirty must be boolean")
    if manifest["profile"] not in {"stable", "branch", "condition"}:
        fail(f"{label}.profile is invalid")
    if not isinstance(manifest["target"], str) or not manifest["target"]:
        fail(f"{label}.target must be non-empty")
    if not isinstance(manifest["command"], list) or not manifest["command"] or not all(isinstance(item, str) and item for item in manifest["command"]):
        fail(f"{label}.command must be a non-empty string list")
    if not isinstance(manifest["environment"], dict):
        fail(f"{label}.environment must be an object")
    native_exit = manifest["native_exit"]
    if native_exit is not None and (not isinstance(native_exit, int) or isinstance(native_exit, bool)):
        fail(f"{label}.native_exit must be an integer or null")
    if manifest["status"] not in VALID_MANIFEST_STATUSES:
        fail(f"{label}.status is invalid")
    if manifest["status"] == "pass" and (manifest["dirty"] or native_exit != 0):
        fail(f"{label} cannot be pass with dirty provenance or non-zero exit")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{label}.artifacts must be non-empty")
    run_root = path.parent.resolve()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not all(key in artifact for key in ("path", "sha256", "bytes")):
            fail(f"{label} contains an incomplete artifact")
        artifact_path = (run_root / artifact["path"]).resolve()
        try:
            artifact_path.relative_to(run_root)
        except ValueError:
            fail(f"{label} contains an artifact outside its run directory")
        if not artifact_path.is_file():
            fail(f"{label} references missing artifact: {artifact['path']}")
        if not isinstance(artifact["sha256"], str) or not SHA256_RE.fullmatch(artifact["sha256"]):
            fail(f"{label} contains an invalid artifact digest")
        if artifact["sha256"] != sha256(artifact_path) or artifact["bytes"] != artifact_path.stat().st_size:
            fail(f"{label} contains a stale artifact digest or size")


def validate_runs(runs_dir: Path, expected_commit: str | None, require_pass: bool) -> int:
    manifests = sorted(runs_dir.rglob("run-manifest.json"))
    if not manifests:
        fail(f"no run-manifest.json files found under {runs_dir}")
    for manifest in manifests:
        validate_manifest(manifest, expected_commit)
        if require_pass and load_json(manifest)["status"] != "pass":
            fail(f"{manifest} is not promotable: status must be pass")
    return len(manifests)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument(
        "--verify-test-inventory",
        action="store_true",
        help="compare verification-inventory.json with Cargo's current test listing",
    )
    args = parser.parse_args()
    try:
        validate_static_records()
        if args.verify_test_inventory:
            validate_test_inventory()
        expected_commit = args.expected_commit or os.environ.get("GITHUB_SHA")
        if expected_commit is not None and not COMMIT_RE.fullmatch(expected_commit):
            fail("expected commit must be a full 40-character hexadecimal commit")
        if args.runs_dir and args.manifest:
            fail("--runs-dir and --manifest are mutually exclusive")
        if args.runs_dir:
            count = validate_runs(args.runs_dir.resolve(), expected_commit, args.require_pass)
            print(f"coverage records and {count} run manifest(s) are valid")
        elif args.manifest:
            validate_manifest(args.manifest.resolve(), expected_commit)
            print("coverage records and run manifest are valid")
        else:
            print("coverage records are valid; no run manifests were requested")
    except (ValidationError, OSError) as error:
        print(f"coverage validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
