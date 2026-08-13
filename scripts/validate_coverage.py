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
from datetime import datetime
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
    "requirements-review.json",
    "surface.json",
    "decision-inventory.json",
    "policy.json",
    "tool-assessment.json",
    "run-manifest.schema.json",
    "evidence-index.json",
    "configuration-management.json",
    "archive-control.json",
    "archive-retrieval.json",
    "gap-register.json",
    "verification-inventory.json",
    "mcdc.json",
    "windows-native-faults.json",
    "windows-native-fault-review.json",
    "windows-native-fault-review.schema.json",
    "windows-native-fault-run.schema.json",
    "windows-appverifier-run.schema.json",
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
MCDC_DISPOSITIONS = {
    "assessed_internal_source_pairs",
    "assessment_open_no_record",
    "not_applicable_non_boolean_dispatch",
    "not_applicable_enum_dispatch",
    "not_applicable_sequential_query",
    "not_applicable_error_propagation",
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


def canonical_json_sha256(value: Any) -> str:
    """Hash a logical JSON value independently of whitespace and object-key order."""
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_source_reference(reference: str, label: str) -> None:
    path = source_path(reference, label)
    if ":" not in reference:
        fail(f"{label} must include a source line or line span")
    location = reference.split(":", 1)[1]
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", location)
    if match is None:
        fail(f"{label} has an invalid source span: {reference!r}")
    first = int(match.group(1))
    last = int(match.group(2) or first)
    maximum = line_count(path)
    if first < 1 or last < first or last > maximum:
        fail(f"{label} references lines outside {path.relative_to(ROOT)}")


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
            "configuration_management_ref",
            "archive_control_ref",
            "requirements_review_ref",
        },
        label,
    )
    check_status(context, label)
    if context["record_type"] != "assurance_context" or context["schema_version"] != 2:
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
    if (
        context["mcdc_status"] != "not_assessed"
        or context["tool_credit"] != "internal_only"
        or context["independence_status"] != "not_assessed"
    ):
        fail(f"{label} contains an unsupported assurance claim")
    if context["requirements_status"] != "approved_internal":
        fail(f"{label} must retain only the approved internal requirements state")
    if (
        context["configuration_management_ref"]
        != "coverage/configuration-management.json"
        or context["archive_control_ref"] != "coverage/archive-control.json"
        or context["requirements_review_ref"]
        != "coverage/requirements-review.json"
    ):
        fail(f"{label} has invalid internal control references")
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
    required_fields(requirements, {"record_type", "schema_version", "status", "owner", "baseline_id", "review_record", "basis", "requirements"}, label)
    check_status(requirements, label)
    if requirements["record_type"] != "derived_requirements" or requirements["schema_version"] != 2:
        fail(f"{label} has the wrong record type or schema version")
    if (
        requirements["baseline_id"] != "REQ-BASELINE-DO178C-001"
        or requirements["review_record"] != "REQ-REVIEW-DO178C-001"
    ):
        fail(f"{label} has the wrong internal baseline or review identity")
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
            validate_source_reference(reference, f"{item_label}.source_refs")
        if verification_ids is not None:
            missing_verifications = set(record["verification_ids"]) - verification_ids
            if missing_verifications:
                fail(f"{item_label} references unknown verifications: {sorted(missing_verifications)}")
        if record["status"] not in {"mapped", "open", "deferred"}:
            fail(f"{item_label}.status is invalid")
        review = record["review"]
        if not isinstance(review, dict) or review.get("status") not in {"internal_review_open", "accepted", "rejected"}:
            fail(f"{item_label}.review must retain a controlled review status")
        if review.get("status") != "accepted" or review.get("review_ref") != requirements["review_record"]:
            fail(f"{item_label}.review is not bound to the approved internal review")
        if not isinstance(review.get("reviewer"), str) or not review["reviewer"].strip():
            fail(f"{item_label}.review must name the internal reviewer")
    return identifiers


def validate_requirements_review(
    review: dict[str, Any],
    requirements: dict[str, Any],
    verification_inventory: dict[str, Any],
    requirement_ids: set[str],
) -> None:
    label = "coverage/requirements-review.json"
    required_fields(
        review,
        {
            "record_type",
            "schema_version",
            "status",
            "id",
            "baseline_id",
            "owner",
            "assurance_context",
            "credit",
            "reviewer",
            "reviewed_artifacts",
            "review_method",
            "requirements",
            "findings",
            "approval",
            "open_items",
            "non_claims",
        },
        label,
    )
    check_status(review, label)
    if (
        review["record_type"] != "requirements_baseline_review"
        or review["schema_version"] != 1
        or review["id"] != requirements["review_record"]
        or review["baseline_id"] != requirements["baseline_id"]
        or review["assurance_context"] != "internal_assurance"
        or review["credit"] != "none"
    ):
        fail(f"{label} has the wrong identity or assurance state")
    reviewer = review["reviewer"]
    if (
        not isinstance(reviewer, dict)
        or set(reviewer) != {"identity", "role", "independent"}
        or not isinstance(reviewer["identity"], str)
        or not reviewer["identity"].strip()
        or not isinstance(reviewer["role"], str)
        or not reviewer["role"].strip()
        or reviewer["independent"] is not False
    ):
        fail(f"{label}.reviewer must retain the non-independent internal boundary")

    artifacts = review["reviewed_artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "logical_json_hash_contract",
        "source_hash_contract",
        "requirements",
        "verification_inventory",
        "sources",
    }:
        fail(f"{label}.reviewed_artifacts is invalid")
    expected_logical_contract = (
        "UTF-8 JSON sorted by object key with no insignificant whitespace"
    )
    expected_source_contract = (
        "SHA-256 over source bytes after CRLF and CR normalization to LF"
    )
    if (
        artifacts["logical_json_hash_contract"] != expected_logical_contract
        or artifacts["source_hash_contract"] != expected_source_contract
    ):
        fail(f"{label} has an unsupported digest contract")
    for name, expected_path, expected_version, value in (
        ("requirements", "coverage/requirements.json", 2, requirements),
        (
            "verification_inventory",
            "coverage/verification-inventory.json",
            1,
            verification_inventory,
        ),
    ):
        record = artifacts[name]
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "schema_version", "sha256"}
            or record["path"] != expected_path
            or record["schema_version"] != expected_version
            or record["sha256"] != canonical_json_sha256(value)
        ):
            fail(f"{label}.reviewed_artifacts.{name} is stale or invalid")

    expected_sources = {
        reference.split(":", 1)[0]
        for requirement in requirements["requirements"]
        for reference in requirement["source_refs"]
    }
    sources = artifacts["sources"]
    if not isinstance(sources, list) or not sources:
        fail(f"{label}.reviewed_artifacts.sources must be non-empty")
    observed_sources: set[str] = set()
    for index, record in enumerate(sources):
        item_label = f"{label}.reviewed_artifacts.sources[{index}]"
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            fail(f"{item_label} is invalid")
        path_value = record["path"]
        path = source_path(path_value, f"{item_label}.path")
        if path_value in observed_sources or record["sha256"] != canonical_source_sha256(path):
            fail(f"{item_label} is duplicated or stale")
        observed_sources.add(path_value)
    if observed_sources != expected_sources:
        fail(f"{label}.reviewed_artifacts.sources does not match requirement traces")

    method = review["review_method"]
    if (
        not isinstance(method, list)
        or len(method) < 5
        or not all(isinstance(item, str) and item.strip() for item in method)
    ):
        fail(f"{label}.review_method is incomplete")
    records = review["requirements"]
    if not isinstance(records, list) or len(records) != len(requirement_ids):
        fail(f"{label}.requirements does not match the requirement inventory")
    expected_checks = {
        "statement_clear",
        "source_trace_valid",
        "verification_trace_resolved",
        "expected_result_observable",
        "platform_scope_reviewed",
    }
    finding_ids = {
        finding.get("id")
        for finding in review["findings"]
        if isinstance(finding, dict)
    }
    observed_ids: set[str] = set()
    referenced_findings: set[str] = set()
    requirement_records = {
        record["id"]: record for record in requirements["requirements"]
    }
    for index, record in enumerate(records):
        item_label = f"{label}.requirements[{index}]"
        if not isinstance(record, dict) or set(record) != {
            "id",
            "disposition",
            "checks",
            "finding_refs",
        }:
            fail(f"{item_label} is invalid")
        identifier = record["id"]
        if identifier not in requirement_ids or identifier in observed_ids:
            fail(f"{item_label}.id is unknown or duplicated")
        observed_ids.add(identifier)
        if record["disposition"] != "accepted_internal":
            fail(f"{item_label} must retain the internal-only disposition")
        if requirement_records[identifier]["review"].get("reviewer") != reviewer["identity"]:
            fail(f"{item_label} reviewer does not match the reviewed requirement")
        checks = record["checks"]
        if not isinstance(checks, dict) or set(checks) != expected_checks or not all(
            value is True for value in checks.values()
        ):
            fail(f"{item_label}.checks is incomplete")
        refs = record["finding_refs"]
        if (
            not isinstance(refs, list)
            or len(refs) != len(set(refs))
            or not set(refs).issubset(finding_ids)
        ):
            fail(f"{item_label}.finding_refs is invalid")
        referenced_findings.update(refs)
    if observed_ids != requirement_ids:
        fail(f"{label}.requirements is incomplete")

    findings = review["findings"]
    if not isinstance(findings, list):
        fail(f"{label}.findings must be a list")
    observed_findings: set[str] = set()
    for index, finding in enumerate(findings):
        item_label = f"{label}.findings[{index}]"
        fields = {
            "id",
            "status",
            "severity",
            "requirement_ids",
            "description",
            "resolution",
            "resolution_ref",
        }
        if not isinstance(finding, dict) or set(finding) != fields:
            fail(f"{item_label} is invalid")
        identifier = finding["id"]
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"REQ-REVIEW-FINDING-\d{3}", identifier)
            or identifier in observed_findings
            or finding["status"] != "resolved"
            or finding["severity"] not in {"minor", "major", "critical"}
        ):
            fail(f"{item_label} has an invalid identity or disposition")
        observed_findings.add(identifier)
        affected = finding["requirement_ids"]
        if not isinstance(affected, list) or not affected or not set(affected).issubset(requirement_ids):
            fail(f"{item_label}.requirement_ids is invalid")
        for field in ("description", "resolution", "resolution_ref"):
            if not isinstance(finding[field], str) or not finding[field].strip():
                fail(f"{item_label}.{field} must be non-empty")
    if referenced_findings != observed_findings:
        fail(f"{label}.findings and requirement references are not reciprocal")

    approval = review["approval"]
    if (
        not isinstance(approval, dict)
        or set(approval)
        != {
            "status",
            "approver",
            "approver_role",
            "approval_scope",
            "approval_basis",
            "approval_ref",
            "approved_at",
        }
        or approval["status"] != "approved_internal"
        or approval["approver"] != "github:arthurianresolve"
        or approval["approval_scope"]
        != "internal requirements and verification baseline only"
    ):
        fail(f"{label}.approval is invalid or overclaims its scope")
    for field in ("approver_role", "approval_basis", "approval_ref"):
        if not isinstance(approval[field], str) or not approval[field].strip():
            fail(f"{label}.approval.{field} must be non-empty")
    if not isinstance(approval["approved_at"], str):
        fail(f"{label}.approval.approved_at must be an ISO-8601 timestamp")
    try:
        approved_at = datetime.fromisoformat(approval["approved_at"])
    except ValueError:
        fail(f"{label}.approval.approved_at must be an ISO-8601 timestamp")
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        fail(f"{label}.approval.approved_at must include a timezone offset")
    for field in ("open_items", "non_claims"):
        if (
            not isinstance(review[field], list)
            or not review[field]
            or not all(isinstance(item, str) and item.strip() for item in review[field])
        ):
            fail(f"{label}.{field} is incomplete")


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
        required_fields(decision, {"id", "source", "symbol", "requirement_ids", "applicability", "outcomes", "verification_ids", "mcdc_disposition", "status"}, item_label)
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
        if decision["mcdc_disposition"] not in MCDC_DISPOSITIONS:
            fail(f"{item_label}.mcdc_disposition is invalid")
        if "mcdc_record_ids" in decision:
            records = decision["mcdc_record_ids"]
            if not isinstance(records, list) or not all(isinstance(value, str) and value for value in records):
                fail(f"{item_label}.mcdc_record_ids must be a string list")
            if mcdc_ids is not None:
                unknown_mcdc = set(records) - mcdc_ids
                if unknown_mcdc:
                    fail(f"{item_label} references unknown MC/DC records: {sorted(unknown_mcdc)}")
        elif decision["mcdc_disposition"] == "assessed_internal_source_pairs":
            fail(f"{item_label} claims assessed internal pairs without mcdc_record_ids")
        if "mcdc_record_ids" in decision and decision["mcdc_disposition"] != "assessed_internal_source_pairs":
            fail(f"{item_label} has MC/DC records but a non-assessed disposition")
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
    required_fields(tool, {"record_type", "schema_version", "status", "owner", "assurance_context", "toolchain", "qualification_status", "credit_status", "current_use_decision", "topology", "functions", "known_problems", "open_decisions", "non_claims"}, label)
    check_status(tool, label)
    if tool["record_type"] != "tool_assessment" or tool["schema_version"] != 2:
        fail(f"{label} has the wrong record type or schema version")
    if (
        tool["assurance_context"] != "internal_assurance"
        or tool["qualification_status"] != "not_qualified"
        or tool["credit_status"] != "internal_only"
    ):
        fail(f"{label} contains an unsupported tool claim")
    decision = tool["current_use_decision"]
    if (
        not isinstance(decision, dict)
        or set(decision)
        != {
            "status",
            "certification_use",
            "activity_elimination_credited",
            "decision_basis",
            "decision_owner",
        }
        or decision["status"] != "approved_internal_non_reliance"
        or decision["certification_use"] is not False
        or decision["activity_elimination_credited"] is not False
        or not isinstance(decision["decision_basis"], str)
        or not decision["decision_basis"].strip()
        or not isinstance(decision["decision_owner"], str)
        or not decision["decision_owner"].strip()
    ):
        fail(f"{label}.current_use_decision is invalid or overclaims reliance")
    functions = tool["functions"]
    if not isinstance(functions, list) or len(functions) != 6:
        fail(f"{label}.functions must contain the six registered functions")
    expected_function_ids = {f"TOOL-F-{number:03d}" for number in range(1, 7)}
    identifiers: set[str] = set()
    known_problem_refs: set[str] = set()
    for index, function in enumerate(functions):
        item_label = f"{label}.functions[{index}]"
        if not isinstance(function, dict):
            fail(f"{item_label} must be an object")
        required_fields(
            function,
            {
                "id",
                "function",
                "status",
                "intended_uses",
                "prohibited_uses",
                "inputs",
                "outputs",
                "upstream_ids",
                "downstream_ids",
                "affected_process",
                "activity_effect",
                "failure_modes",
                "fallback",
                "residual_reliance",
                "qualification_criterion",
                "qualification_state",
                "proposed_tql",
                "approved_tql",
                "limitations",
                "known_problem_ids",
                "owner",
                "review",
                "revalidation_triggers",
            },
            item_label,
        )
        if function["id"] not in expected_function_ids or function["id"] in identifiers:
            fail(f"{item_label}.id must be unique")
        identifiers.add(function["id"])
        if function["status"] not in {"non_reliance_internal", "implemented_internal"}:
            fail(f"{item_label}.status is invalid")
        for field in (
            "intended_uses",
            "prohibited_uses",
            "inputs",
            "outputs",
            "limitations",
            "known_problem_ids",
            "revalidation_triggers",
        ):
            value = function[field]
            if not isinstance(value, list) or not value or not all(
                isinstance(item, str) and item.strip() for item in value
            ):
                fail(f"{item_label}.{field} is invalid")
        for field in ("upstream_ids", "downstream_ids"):
            value = function[field]
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item in expected_function_ids for item in value
            ) or len(value) != len(set(value)):
                fail(f"{item_label}.{field} is invalid")
        for field in ("function", "affected_process", "residual_reliance", "owner"):
            if not isinstance(function[field], str) or not function[field].strip():
                fail(f"{item_label}.{field} must be non-empty")
        effect = function["activity_effect"]
        if (
            not isinstance(effect, dict)
            or set(effect) != {"kind", "detail"}
            or effect["kind"] not in {"automates_internal", "reduces_internal"}
            or not isinstance(effect["detail"], str)
            or not effect["detail"].strip()
        ):
            fail(f"{item_label}.activity_effect is invalid")
        failure_modes = function["failure_modes"]
        if not isinstance(failure_modes, list) or len(failure_modes) < 3:
            fail(f"{item_label}.failure_modes is incomplete")
        failure_ids: set[str] = set()
        for mode_index, mode in enumerate(failure_modes):
            mode_label = f"{item_label}.failure_modes[{mode_index}]"
            if (
                not isinstance(mode, dict)
                or set(mode)
                != {"id", "description", "can_escape", "detection_controls"}
                or not isinstance(mode["id"], str)
                or mode["id"] in failure_ids
                or mode["can_escape"] is not True
                or not isinstance(mode["description"], str)
                or not mode["description"].strip()
                or not isinstance(mode["detection_controls"], list)
                or not mode["detection_controls"]
                or not all(
                    isinstance(control, str) and control.strip()
                    for control in mode["detection_controls"]
                )
            ):
                fail(f"{mode_label} is invalid")
            failure_ids.add(mode["id"])
        fallback = function["fallback"]
        if (
            not isinstance(fallback, dict)
            or set(fallback)
            != {
                "id",
                "procedure",
                "scope",
                "completeness",
                "independent",
                "common_mode_dependencies",
            }
            or fallback["id"] != f"FALLBACK-{function['id']}"
            or fallback["independent"] is not False
            or not isinstance(fallback["common_mode_dependencies"], list)
            or not fallback["common_mode_dependencies"]
        ):
            fail(f"{item_label}.fallback is invalid")
        for field in ("procedure", "scope", "completeness"):
            if not isinstance(fallback[field], str) or not fallback[field].strip():
                fail(f"{item_label}.fallback.{field} must be non-empty")
        criterion = function["qualification_criterion"]
        if criterion != {
            "state": "assessment_open_basis_missing",
            "controlled_basis_ref": None,
            "software_level_ref": None,
        }:
            fail(f"{item_label}.qualification_criterion overstates the basis")
        if (
            function["qualification_state"] != "non_reliance"
            or function["proposed_tql"] is not None
            or function["approved_tql"] is not None
        ):
            fail(f"{item_label} contains an unsupported qualification claim")
        review = function["review"]
        if (
            not isinstance(review, dict)
            or set(review) != {"status", "reviewer", "evidence_refs"}
            or review["status"] != "reviewed_internal"
            or not isinstance(review["reviewer"], str)
            or not review["reviewer"].strip()
            or not isinstance(review["evidence_refs"], list)
            or not review["evidence_refs"]
        ):
            fail(f"{item_label}.review is incomplete")
        for reference in review["evidence_refs"]:
            source_path(reference, f"{item_label}.review.evidence_refs")
        known_problem_refs.update(function["known_problem_ids"])
    if identifiers != expected_function_ids:
        fail(f"{label}.functions does not match the registered inventory")

    topology = tool["topology"]
    if not isinstance(topology, list) or not topology:
        fail(f"{label}.topology must be non-empty")
    observed_edges: set[tuple[str, str]] = set()
    for index, edge in enumerate(topology):
        edge_label = f"{label}.topology[{index}]"
        if (
            not isinstance(edge, dict)
            or set(edge) != {"upstream_id", "downstream_id", "interface", "interference"}
            or edge["upstream_id"] not in identifiers
            or edge["downstream_id"] not in identifiers
            or edge["upstream_id"] == edge["downstream_id"]
            or (edge["upstream_id"], edge["downstream_id"]) in observed_edges
        ):
            fail(f"{edge_label} is invalid")
        observed_edges.add((edge["upstream_id"], edge["downstream_id"]))
        for field in ("interface", "interference"):
            if not isinstance(edge[field], str) or not edge[field].strip():
                fail(f"{edge_label}.{field} must be non-empty")
    declared_edges = {
        (function["id"], downstream)
        for function in functions
        for downstream in function["downstream_ids"]
    }
    reverse_edges = {
        (upstream, function["id"])
        for function in functions
        for upstream in function["upstream_ids"]
    }
    if observed_edges != declared_edges or observed_edges != reverse_edges:
        fail(f"{label}.topology is not reciprocal with function links")

    known_problems = tool["known_problems"]
    if not isinstance(known_problems, list) or not known_problems:
        fail(f"{label}.known_problems must be non-empty")
    problem_ids: set[str] = set()
    for index, problem in enumerate(known_problems):
        item_label = f"{label}.known_problems[{index}]"
        if (
            not isinstance(problem, dict)
            or set(problem) != {"id", "status", "function_ids", "description", "control"}
            or not isinstance(problem["id"], str)
            or problem["id"] in problem_ids
            or problem["status"] != "open_controlled"
            or not isinstance(problem["function_ids"], list)
            or not problem["function_ids"]
            or not set(problem["function_ids"]).issubset(identifiers)
        ):
            fail(f"{item_label} is invalid")
        problem_ids.add(problem["id"])
        for field in ("description", "control"):
            if not isinstance(problem[field], str) or not problem[field].strip():
                fail(f"{item_label}.{field} must be non-empty")
    if known_problem_refs != problem_ids:
        fail(f"{label}.known_problems and function references are not reciprocal")
    for field in ("open_decisions", "non_claims"):
        if (
            not isinstance(tool[field], list)
            or not tool[field]
            or not all(isinstance(item, str) and item.strip() for item in tool[field])
        ):
            fail(f"{label}.{field} is incomplete")


def validate_evidence_index(
    index: dict[str, Any], independent_review_approved: bool = False
) -> None:
    label = "coverage/evidence-index.json"
    required_fields(index, {"record_type", "schema_version", "status", "owner", "technical_baseline_id", "archive_status", "external_archive_uri", "assurance_package", "runs", "open_items", "non_claims"}, label)
    check_status(index, label)
    if index["record_type"] != "evidence_index" or index["schema_version"] != 2:
        fail(f"{label} has the wrong record type or schema version")
    if (
        index["technical_baseline_id"] != "CM-DO178C-0002"
        or index["archive_status"]
        not in {"internal_staging_pending", "internal_staging_verified"}
        or index["external_archive_uri"] is not None
    ):
        fail(f"{label} must not imply an external archive")
    package = index["assurance_package"]
    package_fields = {
        "status",
        "artifact_name",
        "retention_days",
        "workflow_run_id",
        "commit",
        "tree",
        "manifest_sha256",
        "retrieval_result_sha256",
        "retrieval_record_ref",
    }
    if (
        not isinstance(package, dict)
        or set(package) != package_fields
        or package["artifact_name"] != "assurance-evidence-package"
        or package["retention_days"] != 90
        or package["retrieval_record_ref"] != "coverage/archive-retrieval.json"
        or package["status"] not in {"pending_current_ci", "verified_internal_staging"}
    ):
        fail(f"{label}.assurance_package is invalid")
    package_bound_fields = (
        "workflow_run_id",
        "commit",
        "tree",
        "manifest_sha256",
        "retrieval_result_sha256",
    )
    if package["status"] == "pending_current_ci":
        if any(package[field] is not None for field in package_bound_fields):
            fail(f"{label}.assurance_package cannot contain partial pending evidence")
        if index["archive_status"] != "internal_staging_pending":
            fail(f"{label}.archive_status is inconsistent with the pending package")
    elif (
        not isinstance(package["workflow_run_id"], str)
        or not package["workflow_run_id"].isdigit()
        or not COMMIT_RE.fullmatch(str(package["commit"]))
        or not COMMIT_RE.fullmatch(str(package["tree"]))
        or not SHA256_RE.fullmatch(str(package["manifest_sha256"]))
        or not SHA256_RE.fullmatch(str(package["retrieval_result_sha256"]))
        or index["archive_status"] != "internal_staging_verified"
    ):
        fail(f"{label}.assurance_package lacks verified exact provenance")
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
    open_items = index["open_items"]
    if not isinstance(open_items, list) or not open_items or not all(
        isinstance(item, str) and item.strip() for item in open_items
    ):
        fail(f"{label}.open_items must be a non-empty string list")
    has_native_review_item = any(
        "native-fault" in item.lower() and "review" in item.lower()
        for item in open_items
    )
    if independent_review_approved == has_native_review_item:
        fail(f"{label}.open_items is inconsistent with the native-fault review state")


def validate_configuration_management(record: dict[str, Any]) -> None:
    label = "coverage/configuration-management.json"
    required_fields(
        record,
        {
            "record_type",
            "schema_version",
            "status",
            "owner",
            "repository",
            "branch",
            "baseline_id_format",
            "baselines",
            "current_internal_baseline_id",
            "candidate",
            "pending_change",
            "change_control",
            "release_control",
            "open_items",
            "non_claims",
        },
        label,
    )
    check_status(record, label)
    if (
        record["record_type"] != "assurance_configuration_management"
        or record["schema_version"] != 1
        or record["repository"] != "arthurianresolve/fs2-rs"
        or record["branch"] != "DO-178C"
        or record["baseline_id_format"] != "CM-DO178C-[0-9]{4}"
    ):
        fail(f"{label} has the wrong identity")
    baselines = record["baselines"]
    if not isinstance(baselines, list) or not baselines:
        fail(f"{label}.baselines must be non-empty")
    identifiers: list[str] = []
    previous: str | None = None
    for index, baseline in enumerate(baselines):
        item_label = f"{label}.baselines[{index}]"
        if (
            not isinstance(baseline, dict)
            or set(baseline)
            != {"id", "role", "commit", "tree", "state", "supersedes", "evidence_ref"}
            or not isinstance(baseline["id"], str)
            or not re.fullmatch(r"CM-DO178C-\d{4}", baseline["id"])
            or baseline["id"] in identifiers
            or not COMMIT_RE.fullmatch(str(baseline["commit"]))
            or not COMMIT_RE.fullmatch(str(baseline["tree"]))
            or not isinstance(baseline["role"], str)
            or not baseline["role"].strip()
            or not isinstance(baseline["state"], str)
            or not baseline["state"].strip()
        ):
            fail(f"{item_label} is invalid")
        if baseline["supersedes"] != previous:
            fail(f"{item_label}.supersedes does not form a linear baseline chain")
        if baseline["evidence_ref"] is not None and (
            not isinstance(baseline["evidence_ref"], str)
            or not baseline["evidence_ref"].strip()
        ):
            fail(f"{item_label}.evidence_ref is invalid")
        identifiers.append(baseline["id"])
        previous = baseline["id"]
    if identifiers != sorted(identifiers) or record["current_internal_baseline_id"] != identifiers[-1]:
        fail(f"{label}.baselines are not monotonic or current")

    candidate = record["candidate"]
    candidate_fields = {
        "id",
        "state",
        "preparation_parent_commit",
        "commit",
        "tree",
        "ci_run_id",
        "assurance_package_manifest_sha256",
        "retrieval_result_sha256",
    }
    if (
        not isinstance(candidate, dict)
        or set(candidate) != candidate_fields
        or candidate["id"] in identifiers
        or not re.fullmatch(r"CM-DO178C-\d{4}", str(candidate["id"]))
        or candidate["id"] <= identifiers[-1]
        or not COMMIT_RE.fullmatch(str(candidate["preparation_parent_commit"]))
        or candidate["state"] not in {
            "awaiting_clean_exact_commit",
            "clean_exact_commit_internal_staging_verified",
        }
    ):
        fail(f"{label}.candidate is invalid")
    bound_fields = (
        "commit",
        "tree",
        "ci_run_id",
        "assurance_package_manifest_sha256",
        "retrieval_result_sha256",
    )
    if candidate["state"] == "awaiting_clean_exact_commit":
        if any(candidate[field] is not None for field in bound_fields):
            fail(f"{label}.candidate cannot be partially bound")
    elif (
        not COMMIT_RE.fullmatch(str(candidate["commit"]))
        or not COMMIT_RE.fullmatch(str(candidate["tree"]))
        or not isinstance(candidate["ci_run_id"], str)
        or not candidate["ci_run_id"].isdigit()
        or not SHA256_RE.fullmatch(str(candidate["assurance_package_manifest_sha256"]))
        or not SHA256_RE.fullmatch(str(candidate["retrieval_result_sha256"]))
    ):
        fail(f"{label}.candidate lacks exact verified provenance")

    change = record["pending_change"]
    if (
        not isinstance(change, dict)
        or set(change)
        != {
            "id",
            "categories",
            "product_code_changed",
            "verification_code_changed",
            "assurance_tool_changed",
            "native_fault_review_affected",
            "required_reverification",
            "state",
        }
        or change["product_code_changed"] is not False
        or change["verification_code_changed"] is not True
        or change["assurance_tool_changed"] is not True
        or change["native_fault_review_affected"] is not True
        or change["state"] not in {"implementation_in_progress", "evidence_bound_review_pending"}
    ):
        fail(f"{label}.pending_change is invalid")
    for field in ("categories", "required_reverification"):
        if (
            not isinstance(change[field], list)
            or not change[field]
            or not all(isinstance(item, str) and item.strip() for item in change[field])
        ):
            fail(f"{label}.pending_change.{field} is incomplete")

    control = record["change_control"]
    if not isinstance(control, dict) or set(control) != {
        "immutable_identity",
        "change_impact_required",
        "supersession_rule",
        "revalidation_triggers",
        "promotion_rule",
    } or control["change_impact_required"] is not True:
        fail(f"{label}.change_control is invalid")
    for field in ("immutable_identity", "supersession_rule", "promotion_rule"):
        if not isinstance(control[field], str) or not control[field].strip():
            fail(f"{label}.change_control.{field} must be non-empty")
    if not isinstance(control["revalidation_triggers"], list) or not control["revalidation_triggers"]:
        fail(f"{label}.change_control.revalidation_triggers is incomplete")

    release = record["release_control"]
    allowed_states = [
        "internal_candidate",
        "internal_staging_verified",
        "release_candidate",
        "authority_candidate",
        "accepted",
        "superseded",
    ]
    if (
        not isinstance(release, dict)
        or set(release)
        != {
            "current_state",
            "release_tag",
            "controlled_external_archive_required",
            "authority_acceptance_required",
            "allowed_states",
        }
        or release["current_state"] not in {"internal_candidate", "internal_staging_verified"}
        or release["release_tag"] is not None
        or release["controlled_external_archive_required"] is not True
        or release["authority_acceptance_required"] is not True
        or release["allowed_states"] != allowed_states
    ):
        fail(f"{label}.release_control contains an unsupported promotion state")
    for field in ("open_items", "non_claims"):
        if not isinstance(record[field], list) or not record[field]:
            fail(f"{label}.{field} is incomplete")


def validate_archive_control(record: dict[str, Any]) -> None:
    label = "coverage/archive-control.json"
    required_fields(
        record,
        {
            "record_type",
            "schema_version",
            "status",
            "owner",
            "repository",
            "branch",
            "internal_staging",
            "retrieval",
            "external_archive",
            "open_items",
            "non_claims",
        },
        label,
    )
    check_status(record, label)
    if (
        record["record_type"] != "assurance_archive_control"
        or record["schema_version"] != 1
        or record["repository"] != "arthurianresolve/fs2-rs"
        or record["branch"] != "DO-178C"
    ):
        fail(f"{label} has the wrong identity")
    staging = record["internal_staging"]
    if not isinstance(staging, dict) or set(staging) != {
        "status",
        "provider",
        "workflow_path",
        "job_id",
        "artifact_name",
        "retention_days",
        "required_artifacts",
        "package_contract",
        "access_boundary",
        "backup_status",
        "retention_authority",
        "disposition_authority",
    }:
        fail(f"{label}.internal_staging is invalid")
    if (
        staging["status"] != "implemented"
        or staging["provider"] != "github_actions"
        or staging["workflow_path"] != ".github/workflows/ci.yml"
        or staging["job_id"] != "assurance-package"
        or staging["artifact_name"] != "assurance-evidence-package"
        or staging["retention_days"] != 90
        or staging["backup_status"] != "not_controlled"
        or staging["retention_authority"] is not None
        or staging["disposition_authority"] is not None
    ):
        fail(f"{label}.internal_staging contains an unsupported control claim")
    expected_artifacts = {
        "coverage-aarch64-apple-darwin": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "stable", "target": "aarch64-apple-darwin"},
        "coverage-branch-aarch64-apple-darwin": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "branch", "target": "aarch64-apple-darwin"},
        "coverage-branch-x86_64-pc-windows-msvc": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "branch", "target": "x86_64-pc-windows-msvc"},
        "coverage-branch-x86_64-unknown-linux-gnu": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "branch", "target": "x86_64-unknown-linux-gnu"},
        "coverage-condition-aarch64-apple-darwin": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "condition", "target": "aarch64-apple-darwin"},
        "coverage-condition-x86_64-pc-windows-msvc": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "condition", "target": "x86_64-pc-windows-msvc"},
        "coverage-condition-x86_64-unknown-linux-gnu": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "condition", "target": "x86_64-unknown-linux-gnu"},
        "coverage-x86_64-pc-windows-msvc": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "stable", "target": "x86_64-pc-windows-msvc"},
        "coverage-x86_64-unknown-linux-gnu": {"manifest": "run-manifest.json", "kind": "coverage", "profile": "stable", "target": "x86_64-unknown-linux-gnu"},
        "windows-native-faults": {"manifest": "windows-native-fault-manifest.json", "kind": "windows_native_fault", "profile": None, "target": "x86_64-pc-windows-msvc"},
    }
    artifacts = staging["required_artifacts"]
    if not isinstance(artifacts, dict) or artifacts != expected_artifacts:
        fail(f"{label}.internal_staging.required_artifacts has the wrong inventory")
    for name, spec in artifacts.items():
        path = spec["manifest"]
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or path.startswith("/")
            or ".." in Path(path).parts
        ):
            fail(f"{label} has an unsafe manifest path for {name}")
    contract = staging["package_contract"]
    if (
        not isinstance(contract, dict)
        or set(contract)
        != {
            "manifest_name",
            "hash_algorithm",
            "path_contract",
            "inventory_rule",
            "control_record_rule",
            "source_state",
            "create_command",
            "verify_command",
        }
        or contract["manifest_name"] != "assurance-archive-manifest.json"
        or contract["hash_algorithm"] != "sha256"
        or contract["control_record_rule"]
        != "package_contains_digest_bound_canonical_control_record"
        or contract["source_state"] != "clean_exact_commit_tracked_tree"
    ):
        fail(f"{label}.internal_staging.package_contract is invalid")
    source_path(staging["workflow_path"], f"{label}.internal_staging.workflow_path")

    retrieval = record["retrieval"]
    if not isinstance(retrieval, dict) or set(retrieval) != {
        "procedure",
        "latest_result",
        "failure_disposition",
    }:
        fail(f"{label}.retrieval is invalid")
    latest = retrieval["latest_result"]
    latest_fields = {
        "status",
        "workflow_run_id",
        "source_commit",
        "manifest_sha256",
        "result_sha256",
        "verified_at",
        "result_ref",
    }
    if not isinstance(latest, dict) or set(latest) != latest_fields or latest["status"] not in {
        "pending_first_current_package",
        "pass_internal_staging",
    }:
        fail(f"{label}.retrieval.latest_result is invalid")
    bound_fields = latest_fields - {"status"}
    if latest["status"] == "pending_first_current_package":
        if any(latest[field] is not None for field in bound_fields):
            fail(f"{label}.retrieval.latest_result cannot be partially bound")
    elif (
        not isinstance(latest["workflow_run_id"], str)
        or not latest["workflow_run_id"].isdigit()
        or not COMMIT_RE.fullmatch(str(latest["source_commit"]))
        or not SHA256_RE.fullmatch(str(latest["manifest_sha256"]))
        or not SHA256_RE.fullmatch(str(latest["result_sha256"]))
        or not isinstance(latest["result_ref"], str)
        or not latest["result_ref"].strip()
    ):
        fail(f"{label}.retrieval.latest_result lacks verified provenance")
    if not isinstance(retrieval["procedure"], str) or not retrieval["procedure"].strip():
        fail(f"{label}.retrieval.procedure is incomplete")
    if not isinstance(retrieval["failure_disposition"], str) or not retrieval["failure_disposition"].strip():
        fail(f"{label}.retrieval.failure_disposition is incomplete")

    external = record["external_archive"]
    if not isinstance(external, dict) or external != {
        "status": "not_archived",
        "uri": None,
        "archive_owner": None,
        "access_control_approval": None,
        "backup_policy": None,
        "retention_period": None,
        "retention_authority": None,
        "disposition_authority": None,
        "retrieval_acceptance": None,
    }:
        fail(f"{label}.external_archive must remain unresolved")
    for field in ("open_items", "non_claims"):
        if not isinstance(record[field], list) or not record[field]:
            fail(f"{label}.{field} is incomplete")


def validate_archive_retrieval(record: dict[str, Any]) -> None:
    label = "coverage/archive-retrieval.json"
    fields = {
        "record_type",
        "schema_version",
        "status",
        "owner",
        "scope",
        "result",
        "package_id",
        "source_commit",
        "source_tree",
        "workflow_run_id",
        "artifact_name",
        "manifest_sha256",
        "retrieval_result_sha256",
        "file_count",
        "total_bytes",
        "retrieved_at",
        "verified_by",
        "discrepancies",
        "external_archive_verified",
        "open_items",
        "non_claims",
    }
    if set(record) != fields:
        fail(f"{label} fields do not match the registered contract")
    check_status(record, label)
    if (
        record["record_type"] != "assurance_archive_retrieval_record"
        or record["schema_version"] != 1
        or record["scope"] != "internal_github_actions_staging"
        or record["result"] not in {"pending", "pass"}
        or record["artifact_name"] != "assurance-evidence-package"
        or record["external_archive_verified"] is not False
        or not isinstance(record["discrepancies"], list)
    ):
        fail(f"{label} has an invalid identity or assurance state")
    bound_fields = (
        "package_id",
        "source_commit",
        "source_tree",
        "workflow_run_id",
        "manifest_sha256",
        "retrieval_result_sha256",
        "file_count",
        "total_bytes",
        "retrieved_at",
        "verified_by",
    )
    if record["result"] == "pending":
        if record["status"] != "not_ready" or any(
            record[field] is not None for field in bound_fields
        ) or record["discrepancies"]:
            fail(f"{label} contains partial pending retrieval evidence")
    else:
        if (
            record["status"] != "draft"
            or not isinstance(record["package_id"], str)
            or not record["package_id"].strip()
            or not COMMIT_RE.fullmatch(str(record["source_commit"]))
            or not COMMIT_RE.fullmatch(str(record["source_tree"]))
            or not isinstance(record["workflow_run_id"], str)
            or not record["workflow_run_id"].isdigit()
            or not SHA256_RE.fullmatch(str(record["manifest_sha256"]))
            or not SHA256_RE.fullmatch(str(record["retrieval_result_sha256"]))
            or not isinstance(record["file_count"], int)
            or record["file_count"] <= 0
            or not isinstance(record["total_bytes"], int)
            or record["total_bytes"] <= 0
            or not isinstance(record["verified_by"], str)
            or not record["verified_by"].strip()
            or record["discrepancies"]
        ):
            fail(f"{label} lacks a complete passing retrieval result")
        validate_created_utc(record["retrieved_at"], f"{label}.retrieved_at")
    for field in ("open_items", "non_claims"):
        if not isinstance(record[field], list) or not record[field]:
            fail(f"{label}.{field} is incomplete")


def validate_assurance_control_links(
    context: dict[str, Any],
    configuration: dict[str, Any],
    archive_control: dict[str, Any],
    retrieval: dict[str, Any],
    evidence_index: dict[str, Any],
) -> None:
    label = "assurance configuration/archive cross-record controls"
    baselines = {baseline["id"]: baseline for baseline in configuration["baselines"]}
    current = baselines[configuration["current_internal_baseline_id"]]
    if context["baseline"]["reference"] != current["commit"]:
        fail(f"{label}: assurance context does not name the current CM baseline")
    if evidence_index["technical_baseline_id"] not in baselines:
        fail(f"{label}: evidence index references an unknown technical baseline")
    staging = archive_control["internal_staging"]
    package = evidence_index["assurance_package"]
    if (
        package["artifact_name"] != staging["artifact_name"]
        or package["retention_days"] != staging["retention_days"]
        or retrieval["artifact_name"] != staging["artifact_name"]
    ):
        fail(f"{label}: package identity or retention is inconsistent")

    candidate = configuration["candidate"]
    latest = archive_control["retrieval"]["latest_result"]
    pending_states = (
        candidate["state"] == "awaiting_clean_exact_commit",
        configuration["pending_change"]["state"] == "implementation_in_progress",
        configuration["release_control"]["current_state"] == "internal_candidate",
        latest["status"] == "pending_first_current_package",
        retrieval["result"] == "pending",
        package["status"] == "pending_current_ci",
        evidence_index["archive_status"] == "internal_staging_pending",
    )
    if any(pending_states):
        if not all(pending_states):
            fail(f"{label}: pending candidate states are inconsistent")
        return

    bound_states = (
        candidate["state"] == "clean_exact_commit_internal_staging_verified",
        configuration["pending_change"]["state"] == "evidence_bound_review_pending",
        configuration["release_control"]["current_state"] == "internal_staging_verified",
        latest["status"] == "pass_internal_staging",
        retrieval["result"] == "pass",
        package["status"] == "verified_internal_staging",
        evidence_index["archive_status"] == "internal_staging_verified",
    )
    if not all(bound_states):
        fail(f"{label}: bound candidate states are inconsistent")
    if not (
        candidate["commit"]
        == latest["source_commit"]
        == retrieval["source_commit"]
        == package["commit"]
        and candidate["tree"] == retrieval["source_tree"] == package["tree"]
        and candidate["ci_run_id"]
        == latest["workflow_run_id"]
        == retrieval["workflow_run_id"]
        == package["workflow_run_id"]
        and candidate["assurance_package_manifest_sha256"]
        == latest["manifest_sha256"]
        == retrieval["manifest_sha256"]
        == package["manifest_sha256"]
        and candidate["retrieval_result_sha256"]
        == latest["result_sha256"]
        == retrieval["retrieval_result_sha256"]
        == package["retrieval_result_sha256"]
    ):
        fail(f"{label}: bound candidate provenance or digests disagree")


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
            "cargo",
            "test",
            "--package",
            "fs2",
            "--test",
            "upstream_compat",
            "--test",
            "windows_appverifier",
            "--locked",
            "--",
            "--list",
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


def validate_gap_register(
    gaps: dict[str, Any], independent_review_approved: bool = False
) -> None:
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
    if snapshot["dirty"] is not False or snapshot["status"] not in {
        "clean_exact_commit_local_disposable; not release evidence",
        "clean_exact_commit_ci_disposable; not release evidence",
    }:
        fail(f"{label}.clean_local_snapshot must remain clean and non-promotable")
    if not isinstance(snapshot["targets"], list) or len(snapshot["targets"]) < 2 or not all(
        isinstance(target, str) and target for target in snapshot["targets"]
    ):
        fail(f"{label}.clean_local_snapshot.targets must identify multiple targets")
    run_ids = snapshot["run_ids"]
    if not isinstance(run_ids, list) or len(run_ids) != 9 or len(set(run_ids)) != len(run_ids) or not all(
        isinstance(run_id, str) and run_id for run_id in run_ids
    ):
        fail(f"{label}.clean_local_snapshot.run_ids must identify nine unique runs")
    profiles = snapshot["profiles"]
    expected_profiles = {
        "linux_stable",
        "linux_branch",
        "linux_condition_instrumentation",
        "windows_stable",
        "windows_branch",
        "windows_condition_instrumentation",
        "macos_stable",
        "macos_branch",
        "macos_condition_instrumentation",
    }
    if not isinstance(profiles, dict) or set(profiles) != expected_profiles:
        fail(f"{label}.clean_local_snapshot.profiles must contain the nine matrix profile snapshots")
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
    native_gap = next(
        (record for record in records if record["id"] == "GAP-WINDOWS-NATIVE-ERRORS"),
        None,
    )
    if native_gap is None:
        fail(f"{label} must retain the Windows native-error gap")
    if independent_review_approved:
        if (
            native_gap["status"] != "closed"
            or "IR-WINDOWS-NATIVE-FAULTS-001" not in native_gap.get("closure_basis", "")
        ):
            fail(f"{label} approved native-error closure lacks its review basis")
    elif (
        native_gap["status"] != "open"
        or "independent" not in native_gap["required_action"].lower()
    ):
        fail(f"{label} must retain the Windows native-error gap until independent review")


NATIVE_FAULT_SCENARIOS = {
    "WIN-NATIVE-ALLOC-READONLY": ("SetFileInformationByHandle", "os_mediated_error_activation", "ERROR_ACCESS_DENIED"),
    "WIN-NATIVE-LOCK-CONTENTION": ("LockFileEx", "os_mediated_error_activation", "ERROR_LOCK_VIOLATION"),
    "WIN-NATIVE-VOLUME-UNAVAILABLE": ("Windows volume and space providers", "os_mediated_error_activation", "nonzero native error"),
    "WIN-WIN32-DUPLICATE-INVALID-HANDLE": ("DuplicateHandle", "win32_boundary_invalid_handle_activation", "ERROR_INVALID_HANDLE"),
    "WIN-WIN32-ALLOCATION-QUERY-INVALID-HANDLE": ("GetFileInformationByHandleEx", "win32_boundary_invalid_handle_activation", "ERROR_INVALID_HANDLE"),
    "WIN-WIN32-ALLOCATION-WRITE-INVALID-HANDLE": ("SetFileInformationByHandle", "win32_boundary_invalid_handle_activation", "ERROR_INVALID_HANDLE"),
    "WIN-WIN32-LOCK-INVALID-HANDLE": ("LockFileEx", "win32_boundary_invalid_handle_activation", "ERROR_INVALID_HANDLE"),
    "WIN-WIN32-UNLOCK-INVALID-HANDLE": ("UnlockFile", "win32_boundary_invalid_handle_activation", "ERROR_INVALID_HANDLE"),
    "WIN-APPVERIFIER-FILE-LOW-RESOURCE": ("CreateFileW and fs2 file-space query", "application_verifier_low_resource_simulation", "baseline control succeeds; configured control fails with a native error; fs2 exits normally"),
}

NATIVE_FAULT_PAYLOAD_SCENARIOS = {
    "WIN-NATIVE-ALLOC-READONLY": ("SetFileInformationByHandle", "read_only_file_handle", 5),
    "WIN-NATIVE-LOCK-CONTENTION": ("LockFileEx", "exclusive_lock_owned_by_peer_handle", 33),
    "WIN-NATIVE-VOLUME-UNAVAILABLE": ("Windows volume and space providers", "unavailable_volume_root", None),
    "WIN-WIN32-DUPLICATE-INVALID-HANDLE": ("DuplicateHandle", "null_source_handle", 6),
    "WIN-WIN32-ALLOCATION-QUERY-INVALID-HANDLE": ("GetFileInformationByHandleEx", "null_file_handle", 6),
    "WIN-WIN32-ALLOCATION-WRITE-INVALID-HANDLE": ("SetFileInformationByHandle", "null_file_handle", 6),
    "WIN-WIN32-LOCK-INVALID-HANDLE": ("LockFileEx", "null_file_handle", 6),
    "WIN-WIN32-UNLOCK-INVALID-HANDLE": ("UnlockFile", "null_file_handle", 6),
}

WINDOWS_FAULT_REFERENCE_URLS = {
    "MICROSOFT-APPLICATION-VERIFIER": "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier",
    "MICROSOFT-DRIVER-VERIFIER": "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/verifier",
    "MICROSOFT-SYSTEMATIC-LOW-RESOURCE-SIMULATION": "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/systematic-low-resource-simulation",
    "MICROSOFT-SYSTEM-ERROR-CODES-0-499": "https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-",
}

WINDOWS_FAULT_REFERENCE_ROLES = {
    identifier: (
        "advisory_expected_result_input_not_approved_certification_basis"
        if identifier == "MICROSOFT-SYSTEM-ERROR-CODES-0-499"
        else "advisory_tool_scope_not_approved_certification_basis"
    )
    for identifier in WINDOWS_FAULT_REFERENCE_URLS
}

WINDOWS_NATIVE_FAULT_REVIEW_FIELDS = {
    "record_type",
    "schema_version",
    "id",
    "status",
    "owner",
    "assurance_context",
    "credit",
    "assignment",
    "independence",
    "candidate_baseline",
    "review_scope",
    "review_inputs",
    "procedure_revision",
    "checklist",
    "findings",
    "decision",
    "closure_effect",
    "created_at",
    "updated_at",
    "non_claims",
}

WINDOWS_NATIVE_FAULT_REVIEW_STATUSES = {
    "assigned_awaiting_clean_baseline",
    "assigned_ready_for_review",
    "in_review",
    "changes_requested",
    "approved",
    "rejected",
}

WINDOWS_NATIVE_FAULT_REVIEW_INPUTS = {
    "coverage/windows-native-faults.json": "scenario and verifier applicability owner",
    "coverage/requirements.json": "requirements trace owner",
    "coverage/verification-inventory.json": "verification identity owner",
    "coverage/decision-inventory.json": "decision trace owner",
    "coverage/tool-assessment.json": "tool function and fallback owner",
    "coverage/gap-register.json": "gap and closure owner",
    "src/windows/tests.rs": "deterministic and OS-mediated native-fault procedure",
    "tests/windows_appverifier.rs": "optional Application Verifier probe",
    "scripts/collect_windows_native_faults.py": "native-fault evidence collector",
    "scripts/collect_windows_appverifier.py": "optional verifier lifecycle collector",
    "scripts/validate_coverage.py": "fail-closed record and evidence validator",
    ".github/workflows/ci.yml": "clean branch-head evidence execution",
}

WINDOWS_NATIVE_FAULT_REVIEW_CHECKS = {
    f"IR-WNF-{number:03d}" for number in range(1, 11)
}

NATIVE_FAULT_MANIFEST_FIELDS = {
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
    "requested_toolchain",
    "resolved_toolchain",
    "test_id",
    "command",
    "environment",
    "native_exit",
    "native_faults",
    "review_status",
    "status",
    "artifacts",
    "created_utc",
}

APPVERIFIER_MANIFEST_FIELDS = {
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
    "requested_toolchain",
    "resolved_toolchain",
    "application_verifier",
    "probe",
    "configuration",
    "commands",
    "controlled_environment",
    "initial_state",
    "baseline",
    "configured_state",
    "injected",
    "cleanup",
    "review_status",
    "status",
    "artifacts",
    "created_utc",
}

NATIVE_FAULT_COMMAND = [
    "cargo",
    "+1.88",
    "test",
    "--package",
    "fs2",
    "--lib",
    "--target",
    "x86_64-pc-windows-msvc",
    "--locked",
    "windows::test::records_os_mediated_native_failures",
    "--",
    "--exact",
    "--test-threads=1",
    "--nocapture",
]


def validate_created_utc(value: Any, label: str) -> None:
    if not isinstance(value, str):
        fail(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        fail(f"{label} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label} must include a timezone offset")


def portable_path_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def validate_appverifier_observation(
    observation: Any, *, expected_fault: bool, label: str
) -> None:
    fields = {
        "schema_version",
        "fault_expected",
        "control_create_file",
        "control_raw_os_error",
        "fs2_outcome",
        "fs2_raw_os_error",
    }
    if not isinstance(observation, dict) or set(observation) != fields:
        fail(f"{label} has invalid probe fields")
    if observation["schema_version"] != 1 or observation["fault_expected"] is not expected_fault:
        fail(f"{label} has the wrong probe identity or fault expectation")
    control_error = observation["control_raw_os_error"]
    if expected_fault:
        if (
            observation["control_create_file"] != "error"
            or not isinstance(control_error, int)
            or isinstance(control_error, bool)
            or control_error <= 0
        ):
            fail(f"{label} did not observe a positive native control failure")
    elif observation["control_create_file"] != "success" or control_error is not None:
        fail(f"{label} did not retain a successful unconfigured control")
    fs2_outcome = observation["fs2_outcome"]
    fs2_error = observation["fs2_raw_os_error"]
    if fs2_outcome == "success":
        if fs2_error is not None:
            fail(f"{label} records a native error for a successful fs2 outcome")
    elif fs2_outcome == "error":
        if (
            not isinstance(fs2_error, int)
            or isinstance(fs2_error, bool)
            or fs2_error <= 0
        ):
            fail(f"{label} does not retain a positive fs2 native error")
    else:
        fail(f"{label}.fs2_outcome is invalid")
    if not expected_fault and fs2_outcome != "success":
        fail(f"{label} baseline fs2 call did not succeed")


def validate_appverifier_query_observation(observation: Any, label: str) -> None:
    if observation is None:
        return
    if not isinstance(observation, dict) or set(observation) != {
        "lowres_enabled",
        "file_probability",
        "timeout_ms",
    }:
        fail(f"{label} has invalid query fields")
    if not isinstance(observation["lowres_enabled"], bool):
        fail(f"{label}.lowres_enabled must be boolean")
    for field in ("file_probability", "timeout_ms"):
        value = observation[field]
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            fail(f"{label}.{field} must be a non-negative integer or null")


def validate_windows_native_fault_review(review: dict[str, Any]) -> str:
    label = "coverage/windows-native-fault-review.json"
    if set(review) != WINDOWS_NATIVE_FAULT_REVIEW_FIELDS:
        fail(f"{label} fields do not match the registered review contract")
    if (
        review["record_type"] != "windows_native_fault_independent_review"
        or review["schema_version"] != 1
        or review["id"] != "IR-WINDOWS-NATIVE-FAULTS-001"
    ):
        fail(f"{label} has the wrong identity")
    if review["status"] not in WINDOWS_NATIVE_FAULT_REVIEW_STATUSES:
        fail(f"{label}.status is invalid")
    if (
        review["owner"] != "fs2 DO-178C coverage workstream"
        or review["assurance_context"] != "internal_assurance"
        or review["credit"] != "none"
    ):
        fail(f"{label} contains an unsupported assurance claim")
    validate_created_utc(review["created_at"], f"{label}.created_at")
    validate_created_utc(review["updated_at"], f"{label}.updated_at")
    if datetime.fromisoformat(review["updated_at"]) < datetime.fromisoformat(review["created_at"]):
        fail(f"{label}.updated_at precedes created_at")

    assignment = review["assignment"]
    if not isinstance(assignment, dict) or set(assignment) != {
        "reviewer",
        "assignment_status",
        "reviewer_acceptance",
        "assigned_at",
        "assignment_basis",
    }:
        fail(f"{label}.assignment is invalid")
    reviewer = assignment["reviewer"]
    if reviewer != {
        "identity_provider": "github",
        "login": "arthurianresolve",
        "account_id": 268402532,
        "node_id": "U_kgDOD_9_ZA",
        "profile_url": "https://github.com/arthurianresolve",
    }:
        fail(f"{label}.assignment.reviewer is not the resolved GitHub identity")
    if assignment["assignment_status"] != "assigned":
        fail(f"{label} must retain the explicit reviewer assignment")
    if assignment["reviewer_acceptance"] not in {"pending", "accepted", "declined"}:
        fail(f"{label}.assignment.reviewer_acceptance is invalid")
    if assignment["assignment_basis"] != "explicit_user_direction":
        fail(f"{label}.assignment.assignment_basis is invalid")
    validate_created_utc(assignment["assigned_at"], f"{label}.assignment.assigned_at")

    independence = review["independence"]
    independence_fields = {
        "status",
        "identity_observation",
        "implementation_authorship",
        "organizational_independence",
        "technical_independence",
        "expected_results_independently_established",
        "common_mode_independence",
        "conflicts_of_interest",
        "same_identity_rationale",
        "declaration_ref",
        "declared_at",
    }
    if not isinstance(independence, dict) or set(independence) != independence_fields:
        fail(f"{label}.independence is invalid")
    if independence["status"] not in {"declaration_pending", "accepted", "rejected"}:
        fail(f"{label}.independence.status is invalid")
    if (
        not isinstance(independence["identity_observation"], str)
        or "matches the local Git commit identity" not in independence["identity_observation"]
    ):
        fail(f"{label}.independence must disclose the same-identity observation")
    independence_dimensions = (
        "implementation_authorship",
        "organizational_independence",
        "technical_independence",
        "expected_results_independently_established",
        "common_mode_independence",
    )
    valid_independence_values = {"not_assessed", "confirmed", "not_independent"}
    if any(independence[field] not in valid_independence_values for field in independence_dimensions):
        fail(f"{label}.independence contains an invalid dimension result")
    conflicts = independence["conflicts_of_interest"]
    if not isinstance(conflicts, list) or not all(
        isinstance(conflict, str) and conflict.strip() for conflict in conflicts
    ):
        fail(f"{label}.independence.conflicts_of_interest is invalid")
    if independence["status"] == "declaration_pending":
        if any(independence[field] != "not_assessed" for field in independence_dimensions):
            fail(f"{label} cannot record independence conclusions before a declaration")
        if any(
            independence[field] is not None
            for field in ("same_identity_rationale", "declaration_ref", "declared_at")
        ):
            fail(f"{label} pending independence must not contain an attestation")
    else:
        if not isinstance(independence["same_identity_rationale"], str) or not independence["same_identity_rationale"].strip():
            fail(f"{label}.independence must resolve the same-identity risk")
        if not isinstance(independence["declaration_ref"], str) or not independence["declaration_ref"].strip():
            fail(f"{label}.independence.declaration_ref must be non-empty")
        validate_created_utc(independence["declared_at"], f"{label}.independence.declared_at")
        if independence["status"] == "accepted" and (
            any(independence[field] != "confirmed" for field in independence_dimensions)
            or conflicts
        ):
            fail(f"{label} cannot accept incomplete or conflicted independence")
        if independence["status"] == "rejected" and not any(
            independence[field] == "not_independent" for field in independence_dimensions
        ):
            fail(f"{label} rejected independence must identify a failed dimension")

    baseline = review["candidate_baseline"]
    baseline_fields = {
        "repository",
        "branch",
        "preparation_parent_commit",
        "reviewed_commit",
        "reviewed_tree",
        "clean_native_fault_manifest_ref",
        "clean_native_fault_manifest_sha256",
        "application_verifier_manifest_ref",
        "application_verifier_required_for_approval",
        "state",
    }
    if not isinstance(baseline, dict) or set(baseline) != baseline_fields:
        fail(f"{label}.candidate_baseline is invalid")
    if (
        baseline["repository"] != "arthurianresolve/fs2-rs"
        or baseline["branch"] != "DO-178C"
        or not COMMIT_RE.fullmatch(str(baseline["preparation_parent_commit"]))
        or baseline["application_verifier_required_for_approval"] is not False
    ):
        fail(f"{label}.candidate_baseline has invalid repository or planning provenance")
    baseline_bound = baseline["state"] == "clean_candidate_bound"
    if baseline["state"] not in {
        "awaiting_committed_candidate_and_clean_ci_evidence",
        "clean_candidate_bound",
    }:
        fail(f"{label}.candidate_baseline.state is invalid")
    if baseline_bound:
        if (
            not COMMIT_RE.fullmatch(str(baseline["reviewed_commit"]))
            or not COMMIT_RE.fullmatch(str(baseline["reviewed_tree"]))
            or baseline["reviewed_commit"] == "0" * 40
            or baseline["reviewed_tree"] == "0" * 40
            or not isinstance(baseline["clean_native_fault_manifest_ref"], str)
            or not baseline["clean_native_fault_manifest_ref"].strip()
            or not SHA256_RE.fullmatch(str(baseline["clean_native_fault_manifest_sha256"]))
        ):
            fail(f"{label}.candidate_baseline does not bind clean native-fault evidence")
        appverifier_ref = baseline["application_verifier_manifest_ref"]
        if appverifier_ref is not None and (
            not isinstance(appverifier_ref, str) or not appverifier_ref.strip()
        ):
            fail(f"{label}.candidate_baseline.application_verifier_manifest_ref is invalid")
    elif any(
        baseline[field] is not None
        for field in (
            "reviewed_commit",
            "reviewed_tree",
            "clean_native_fault_manifest_ref",
            "clean_native_fault_manifest_sha256",
            "application_verifier_manifest_ref",
        )
    ):
        fail(f"{label} cannot bind partial candidate evidence")

    scope = review["review_scope"]
    if not isinstance(scope, list) or len(scope) != 9 or len(set(scope)) != len(scope) or not all(
        isinstance(item, str) and item.strip() for item in scope
    ):
        fail(f"{label}.review_scope must contain nine unique objectives")
    inputs = review["review_inputs"]
    if not isinstance(inputs, list) or len(inputs) != len(WINDOWS_NATIVE_FAULT_REVIEW_INPUTS):
        fail(f"{label}.review_inputs is incomplete")
    observed_inputs: dict[str, str] = {}
    for index, item in enumerate(inputs):
        item_label = f"{label}.review_inputs[{index}]"
        if not isinstance(item, dict) or set(item) != {"path", "role"}:
            fail(f"{item_label} is invalid")
        path = item["path"]
        if path in observed_inputs or WINDOWS_NATIVE_FAULT_REVIEW_INPUTS.get(path) != item["role"]:
            fail(f"{item_label} has an unexpected or duplicate input")
        source_path(path, f"{item_label}.path")
        observed_inputs[path] = item["role"]
    if observed_inputs != WINDOWS_NATIVE_FAULT_REVIEW_INPUTS:
        fail(f"{label}.review_inputs does not match the registered review surface")
    if review["procedure_revision"] != 1:
        fail(f"{label}.procedure_revision is invalid")

    findings = review["findings"]
    if not isinstance(findings, list):
        fail(f"{label}.findings must be a list")
    finding_ids: set[str] = set()
    open_findings: set[str] = set()
    for index, finding in enumerate(findings):
        finding_label = f"{label}.findings[{index}]"
        if not isinstance(finding, dict) or set(finding) != {
            "id",
            "severity",
            "status",
            "check_ids",
            "description",
            "resolution",
            "resolution_ref",
        }:
            fail(f"{finding_label} is invalid")
        identifier = finding["id"]
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"IR-WNF-FINDING-\d{3}", identifier)
            or identifier in finding_ids
        ):
            fail(f"{finding_label}.id is invalid or duplicated")
        finding_ids.add(identifier)
        if finding["severity"] not in {"minor", "major", "critical"}:
            fail(f"{finding_label}.severity is invalid")
        if finding["status"] not in {"open", "resolved"}:
            fail(f"{finding_label}.status is invalid")
        check_ids = finding["check_ids"]
        if (
            not isinstance(check_ids, list)
            or not check_ids
            or len(set(check_ids)) != len(check_ids)
            or not set(check_ids).issubset(WINDOWS_NATIVE_FAULT_REVIEW_CHECKS)
        ):
            fail(f"{finding_label}.check_ids is invalid")
        if not isinstance(finding["description"], str) or not finding["description"].strip():
            fail(f"{finding_label}.description must be non-empty")
        if finding["status"] == "open":
            open_findings.add(identifier)
            if finding["resolution"] is not None or finding["resolution_ref"] is not None:
                fail(f"{finding_label} open finding cannot claim resolution")
        elif (
            not isinstance(finding["resolution"], str)
            or not finding["resolution"].strip()
            or not isinstance(finding["resolution_ref"], str)
            or not finding["resolution_ref"].strip()
        ):
            fail(f"{finding_label} resolved finding must retain resolution evidence")

    checklist = review["checklist"]
    if not isinstance(checklist, list) or len(checklist) != len(WINDOWS_NATIVE_FAULT_REVIEW_CHECKS):
        fail(f"{label}.checklist is incomplete")
    observed_checks: set[str] = set()
    check_statuses: dict[str, str] = {}
    referenced_findings: set[str] = set()
    for index, check in enumerate(checklist):
        check_label = f"{label}.checklist[{index}]"
        if not isinstance(check, dict) or set(check) != {
            "id",
            "objective",
            "status",
            "finding_refs",
        }:
            fail(f"{check_label} is invalid")
        identifier = check["id"]
        if identifier not in WINDOWS_NATIVE_FAULT_REVIEW_CHECKS or identifier in observed_checks:
            fail(f"{check_label}.id is unexpected or duplicated")
        observed_checks.add(identifier)
        if not isinstance(check["objective"], str) or not check["objective"].strip():
            fail(f"{check_label}.objective must be non-empty")
        if check["status"] not in {"not_reviewed", "pass", "fail"}:
            fail(f"{check_label}.status is invalid")
        refs = check["finding_refs"]
        if not isinstance(refs, list) or len(set(refs)) != len(refs) or not set(refs).issubset(finding_ids):
            fail(f"{check_label}.finding_refs is invalid")
        if check["status"] == "fail" and not refs:
            fail(f"{check_label} failed check must reference a finding")
        referenced_findings.update(refs)
        check_statuses[identifier] = check["status"]
    if observed_checks != WINDOWS_NATIVE_FAULT_REVIEW_CHECKS:
        fail(f"{label}.checklist does not match the registered objectives")
    if referenced_findings != finding_ids:
        fail(f"{label}.findings and checklist references are not reciprocal")

    decision = review["decision"]
    decision_fields = {
        "status",
        "outcome",
        "reviewer_login",
        "reviewed_commit",
        "native_fault_manifest_sha256",
        "attestation",
        "decision_ref",
        "decided_at",
    }
    if not isinstance(decision, dict) or set(decision) != decision_fields:
        fail(f"{label}.decision is invalid")
    if decision["status"] not in {"pending", "recorded"}:
        fail(f"{label}.decision.status is invalid")
    if decision["status"] == "pending":
        if any(decision[field] is not None for field in decision_fields - {"status"}):
            fail(f"{label} pending decision must not contain decision data")
    else:
        if decision["outcome"] not in {"approve", "reject", "changes_requested"}:
            fail(f"{label}.decision.outcome is invalid")
        if decision["reviewer_login"] != reviewer["login"]:
            fail(f"{label}.decision reviewer does not match the assignment")
        if (
            not baseline_bound
            or decision["reviewed_commit"] != baseline["reviewed_commit"]
            or decision["native_fault_manifest_sha256"]
            != baseline["clean_native_fault_manifest_sha256"]
        ):
            fail(f"{label}.decision is not bound to the candidate evidence")
        for field in ("attestation", "decision_ref"):
            if not isinstance(decision[field], str) or not decision[field].strip():
                fail(f"{label}.decision.{field} must be non-empty")
        validate_created_utc(decision["decided_at"], f"{label}.decision.decided_at")

    closure = review["closure_effect"]
    if not isinstance(closure, dict) or set(closure) != {
        "gap_id",
        "current_effect",
        "independent_review_condition_satisfied",
        "gap_closure_permitted",
        "remaining_conditions",
    }:
        fail(f"{label}.closure_effect is invalid")
    if closure["gap_id"] != "GAP-WINDOWS-NATIVE-ERRORS":
        fail(f"{label}.closure_effect has the wrong gap")
    if not isinstance(closure["remaining_conditions"], list) or not all(
        isinstance(item, str) and item.strip() for item in closure["remaining_conditions"]
    ):
        fail(f"{label}.closure_effect.remaining_conditions is invalid")
    for field in ("independent_review_condition_satisfied", "gap_closure_permitted"):
        if not isinstance(closure[field], bool):
            fail(f"{label}.closure_effect.{field} must be boolean")

    status = review["status"]
    if status == "assigned_awaiting_clean_baseline":
        if (
            baseline_bound
            or assignment["reviewer_acceptance"] == "declined"
            or independence["status"] != "declaration_pending"
            or decision["status"] != "pending"
            or any(value != "not_reviewed" for value in check_statuses.values())
            or findings
        ):
            fail(f"{label} assigned state contains premature review results")
    elif status == "assigned_ready_for_review":
        if (
            not baseline_bound
            or assignment["reviewer_acceptance"] == "declined"
            or independence["status"] != "declaration_pending"
            or decision["status"] != "pending"
            or any(value != "not_reviewed" for value in check_statuses.values())
            or findings
        ):
            fail(f"{label} ready state requires clean evidence without review results")
    elif status == "in_review":
        if (
            not baseline_bound
            or assignment["reviewer_acceptance"] != "accepted"
            or independence["status"] != "accepted"
            or decision["status"] != "pending"
        ):
            fail(f"{label} cannot enter review without accepted assignment, independence, and clean evidence")
    elif status == "changes_requested":
        if (
            not baseline_bound
            or assignment["reviewer_acceptance"] != "accepted"
            or independence["status"] != "accepted"
            or decision["status"] != "recorded"
            or decision["outcome"] != "changes_requested"
            or not (open_findings or "fail" in check_statuses.values())
        ):
            fail(f"{label} changes-requested state lacks a bound adverse review decision")
    elif status == "rejected":
        if decision["status"] != "recorded" or decision["outcome"] != "reject":
            fail(f"{label} rejected state lacks a recorded rejection")
    elif status == "approved":
        if (
            not baseline_bound
            or assignment["reviewer_acceptance"] != "accepted"
            or independence["status"] != "accepted"
            or decision["status"] != "recorded"
            or decision["outcome"] != "approve"
            or any(value != "pass" for value in check_statuses.values())
            or findings and (open_findings or len(findings) != len(finding_ids))
        ):
            fail(f"{label} cannot approve incomplete or unresolved review work")

    approved = status == "approved"
    if approved:
        if closure != {
            "gap_id": "GAP-WINDOWS-NATIVE-ERRORS",
            "current_effect": "independent_review_condition_satisfied",
            "independent_review_condition_satisfied": True,
            "gap_closure_permitted": True,
            "remaining_conditions": [],
        }:
            fail(f"{label}.closure_effect does not match the approved review")
    elif (
        closure["current_effect"] not in {"none_assignment_only", "none_review_incomplete"}
        or closure["independent_review_condition_satisfied"]
        or closure["gap_closure_permitted"]
        or not closure["remaining_conditions"]
    ):
        fail(f"{label} cannot imply closure before approval")
    non_claims = review["non_claims"]
    if not isinstance(non_claims, list) or len(non_claims) < 4 or not all(
        isinstance(item, str) and item.strip() for item in non_claims
    ):
        fail(f"{label}.non_claims is incomplete")
    if not any("assignment is not" in item.lower() for item in non_claims):
        fail(f"{label}.non_claims must separate assignment from approval")

    if status == "approved":
        return "independent_review_approved"
    if status == "rejected":
        return "independent_review_rejected"
    return "independent_review_pending"


def validate_windows_native_fault_assessment(
    assessment: dict[str, Any],
    verification_ids: set[str],
    expected_review_status: str = "independent_review_pending",
) -> None:
    label = "coverage/windows-native-faults.json"
    required_fields(
        assessment,
        {
            "record_type",
            "schema_version",
            "status",
            "owner",
            "claim_class",
            "credit",
            "review_status",
            "external_references",
            "tool_disposition",
            "scenarios",
            "closure_conditions",
            "non_claims",
        },
        label,
    )
    check_status(assessment, label)
    if assessment["record_type"] != "windows_native_fault_assessment" or assessment["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if assessment["claim_class"] != "internal_engineering_evidence" or assessment["credit"] != "none":
        fail(f"{label} contains an unsupported assurance claim")
    if assessment["review_status"] != expected_review_status:
        fail(f"{label}.review_status is inconsistent with the review record")
    references = assessment["external_references"]
    if not isinstance(references, list) or len(references) != len(WINDOWS_FAULT_REFERENCE_URLS):
        fail(f"{label}.external_references must retain the registered Microsoft sources")
    observed_references: set[str] = set()
    for index, reference in enumerate(references):
        item_label = f"{label}.external_references[{index}]"
        if not isinstance(reference, dict):
            fail(f"{item_label} must be an object")
        required_fields(reference, {"id", "title", "url", "source_role"}, item_label)
        identifier = reference["id"]
        if identifier not in WINDOWS_FAULT_REFERENCE_URLS or identifier in observed_references:
            fail(f"{item_label}.id is unexpected or duplicated")
        observed_references.add(identifier)
        if reference["url"] != WINDOWS_FAULT_REFERENCE_URLS[identifier]:
            fail(f"{item_label}.url has drifted from the registered official source")
        if reference["source_role"] != WINDOWS_FAULT_REFERENCE_ROLES[identifier]:
            fail(f"{item_label} must not claim an approved certification basis")
        if not isinstance(reference["title"], str) or not reference["title"].strip():
            fail(f"{item_label}.title must be a non-empty string")
    if observed_references != set(WINDOWS_FAULT_REFERENCE_URLS):
        fail(f"{label}.external_references is incomplete")
    tools = assessment["tool_disposition"]
    if not isinstance(tools, dict) or set(tools) != {"application_verifier", "driver_verifier"}:
        fail(f"{label}.tool_disposition must classify both Windows verifier facilities")
    appverifier = tools["application_verifier"]
    driver_verifier = tools["driver_verifier"]
    if not isinstance(appverifier, dict) or appverifier.get("applicability") != "optional_user_mode_robustness":
        fail(f"{label} must keep Application Verifier optional and user-mode scoped")
    if (
        not isinstance(driver_verifier, dict)
        or driver_verifier.get("applicability") != "not_applicable_no_kernel_driver"
        or driver_verifier.get("target") is not None
    ):
        fail(f"{label} must not claim Driver Verifier coverage without a kernel driver")
    records = assessment["scenarios"]
    if not isinstance(records, list) or len(records) != len(NATIVE_FAULT_SCENARIOS):
        fail(f"{label}.scenarios must contain the complete native-fault matrix")
    observed: set[str] = set()
    for index, record in enumerate(records):
        item_label = f"{label}.scenarios[{index}]"
        if not isinstance(record, dict):
            fail(f"{item_label} must be an object")
        required_fields(record, {"id", "verification_id", "mechanism", "api_boundary", "oracle"}, item_label)
        identifier = record["id"]
        if identifier not in NATIVE_FAULT_SCENARIOS or identifier in observed:
            fail(f"{item_label}.id is unexpected or duplicated")
        observed.add(identifier)
        api, mechanism, oracle = NATIVE_FAULT_SCENARIOS[identifier]
        if record["api_boundary"] != api or record["mechanism"] != mechanism or record["oracle"] != oracle:
            fail(f"{item_label} has drifted from the registered scenario contract")
        if record["verification_id"] not in verification_ids:
            fail(f"{item_label} references an unknown verification")
    if observed != set(NATIVE_FAULT_SCENARIOS):
        fail(f"{label}.scenarios is incomplete")
    for field in ("closure_conditions", "non_claims"):
        values = assessment[field]
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
            fail(f"{label}.{field} must be a non-empty string list")
    if not any("independent reviewer" in value.lower() for value in assessment["closure_conditions"]):
        fail(f"{label}.closure_conditions must retain independent review")


def validate_native_fault_payload(payload: dict[str, Any], label: str, require_pass: bool) -> None:
    required_fields(
        payload,
        {"schema_version", "evidence_class", "fault_model", "status", "scenarios", "limitations"},
        label,
    )
    if (
        payload["schema_version"] != 1
        or payload["evidence_class"] != "internal_engineering"
        or payload["fault_model"] != "os_mediated_error_activation"
    ):
        fail(f"{label} has an invalid identity")
    if require_pass and payload["status"] != "pass":
        fail(f"{label} must be pass for a promotable run")
    scenarios = payload["scenarios"]
    expected = NATIVE_FAULT_PAYLOAD_SCENARIOS
    if require_pass and (not isinstance(scenarios, list) or len(scenarios) != len(expected)):
        fail(f"{label}.scenarios is incomplete")
    observed: set[str] = set()
    for index, scenario in enumerate(scenarios):
        item_label = f"{label}.scenarios[{index}]"
        if not isinstance(scenario, dict):
            fail(f"{item_label} must be an object")
        required_fields(
            scenario,
            {"id", "api_boundary", "activation", "expected_raw_os", "actual_raw_os"},
            item_label,
        )
        identifier = scenario["id"]
        if identifier not in expected or identifier in observed:
            fail(f"{item_label} has an unexpected identity or API boundary")
        observed.add(identifier)
        api_boundary, activation, registered_error = expected[identifier]
        if (
            scenario["api_boundary"] != api_boundary
            or scenario["activation"] != activation
            or scenario["expected_raw_os"] != registered_error
        ):
            fail(f"{item_label} has drifted from the registered activation contract")
        actual = scenario["actual_raw_os"]
        expected_error = registered_error
        if not isinstance(actual, int) or isinstance(actual, bool) or actual <= 0:
            fail(f"{item_label}.actual_raw_os must be a positive native error")
        if expected_error is not None and actual != expected_error:
            fail(f"{item_label} did not return its expected native error")
    if require_pass and observed != set(expected):
        fail(f"{label}.scenarios does not contain the registered matrix")
    limitations = payload["limitations"]
    if not isinstance(limitations, list) or (require_pass and len(limitations) < 3):
        fail(f"{label}.limitations is incomplete")


def validate_windows_native_fault_manifest(
    path: Path, expected_commit: str | None = None
) -> None:
    manifest = load_json(path)
    label = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
    required_fields(manifest, NATIVE_FAULT_MANIFEST_FIELDS, label)
    if manifest["record_type"] != "windows_native_fault_run" or manifest["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if manifest["repository"] != "arthurianresolve/fs2-rs":
        fail(f"{label} has the wrong repository")
    if manifest["branch"] != "DO-178C" and manifest["status"] != "provenance_error":
        fail(f"{label}.branch must be DO-178C")
    for field, pattern in (("commit", COMMIT_RE), ("tree", COMMIT_RE), ("cargo_lock_sha256", SHA256_RE)):
        if not isinstance(manifest[field], str) or not pattern.fullmatch(manifest[field]):
            fail(f"{label}.{field} has invalid provenance")
    if expected_commit is not None and manifest["commit"] != expected_commit:
        fail(f"{label}.commit does not match expected commit {expected_commit}")
    if not isinstance(manifest["run_id"], str) or not manifest["run_id"].strip():
        fail(f"{label}.run_id must be non-empty")
    validate_created_utc(manifest["created_utc"], f"{label}.created_utc")
    if manifest["target"] != "x86_64-pc-windows-msvc" or manifest["test_id"] != "windows::test::records_os_mediated_native_failures":
        fail(f"{label} has the wrong target or test identity")
    if manifest["requested_toolchain"] != "1.88":
        fail(f"{label}.requested_toolchain must remain pinned to 1.88")
    if not isinstance(manifest["resolved_toolchain"], str) or "host: x86_64-pc-windows-msvc" not in manifest["resolved_toolchain"]:
        fail(f"{label}.resolved_toolchain does not identify the native compiler host")
    if manifest["review_status"] != "independent_review_pending":
        fail(f"{label} cannot claim independent review")
    if manifest["status"] not in VALID_MANIFEST_STATUSES:
        fail(f"{label}.status is invalid")
    if not isinstance(manifest["dirty"], bool):
        fail(f"{label}.dirty must be boolean")
    host = manifest["host"]
    if not isinstance(host, dict):
        fail(f"{label}.host must be an object")
    for field in ("system", "release", "version", "machine", "python", "target"):
        if not isinstance(host.get(field), str) or not host[field]:
            fail(f"{label}.host.{field} must be non-empty")
    successful = manifest["status"] in {"pass", "focused_only"}
    if successful and (host["system"] != "Windows" or host["target"] != manifest["target"]):
        fail(f"{label} cannot claim native evidence on a non-native host")
    if successful and (manifest["tree"] == "0" * 40 or manifest["cargo_lock_sha256"] == "0" * 64):
        fail(f"{label} successful evidence must retain non-placeholder provenance")
    if manifest["status"] == "pass" and (manifest["dirty"] or manifest["native_exit"] != 0):
        fail(f"{label} cannot be pass with dirty provenance or non-zero exit")
    if manifest["status"] == "focused_only" and (not manifest["dirty"] or manifest["native_exit"] != 0):
        fail(f"{label} focused evidence must identify a dirty run with zero native exit")
    if manifest["command"] != NATIVE_FAULT_COMMAND:
        fail(f"{label}.command has drifted from the registered native-fault procedure")
    environment = manifest["environment"]
    if not isinstance(environment, dict) or set(environment) != {
        "CARGO_INCREMENTAL",
        "RUST_BACKTRACE",
        "FS2_WINDOWS_NATIVE_FAULT_EVIDENCE",
    }:
        fail(f"{label}.environment must retain exactly the controlled overrides")
    if environment["CARGO_INCREMENTAL"] != "0" or environment["RUST_BACKTRACE"] != "1":
        fail(f"{label}.environment has unsafe Cargo or diagnostic overrides")
    if portable_path_name(environment["FS2_WINDOWS_NATIVE_FAULT_EVIDENCE"]) != "windows-native-faults.json":
        fail(f"{label}.environment has the wrong native-fault evidence target")
    payload = manifest["native_faults"]
    if not isinstance(payload, dict):
        fail(f"{label}.native_faults must be an object")
    validate_native_fault_payload(payload, f"{label}.native_faults", successful)
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{label}.artifacts must be non-empty")
    run_root = path.parent.resolve()
    artifact_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "bytes"}:
            fail(f"{label} contains an incomplete artifact")
        if not isinstance(artifact["path"], str) or not artifact["path"] or artifact["path"] in artifact_paths:
            fail(f"{label} contains an invalid or duplicate artifact path")
        if not isinstance(artifact["bytes"], int) or isinstance(artifact["bytes"], bool) or artifact["bytes"] < 0:
            fail(f"{label} contains an invalid artifact size")
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
        artifact_paths.add(artifact["path"])
    if successful and not {"windows-native-faults.json", "stdout.log", "stderr.log"}.issubset(artifact_paths):
        fail(f"{label} is missing required native-fault artifacts")
    if manifest["status"] == "indeterminate" and "timeout.txt" not in artifact_paths:
        fail(f"{label} must retain the native-fault timeout reason")


def validate_windows_appverifier_manifest(
    path: Path, expected_commit: str | None = None
) -> None:
    manifest = load_json(path)
    label = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
    required_fields(manifest, APPVERIFIER_MANIFEST_FIELDS, label)
    if manifest["record_type"] != "windows_appverifier_run" or manifest["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if manifest["repository"] != "arthurianresolve/fs2-rs":
        fail(f"{label} has the wrong repository")
    if manifest["branch"] != "DO-178C" and manifest["status"] != "provenance_error":
        fail(f"{label}.branch must be DO-178C")
    for field, pattern in (("commit", COMMIT_RE), ("tree", COMMIT_RE), ("cargo_lock_sha256", SHA256_RE)):
        if not isinstance(manifest[field], str) or not pattern.fullmatch(manifest[field]):
            fail(f"{label}.{field} has invalid provenance")
    if expected_commit is not None and manifest["commit"] != expected_commit:
        fail(f"{label}.commit does not match expected commit {expected_commit}")
    if not isinstance(manifest["run_id"], str) or not manifest["run_id"].strip():
        fail(f"{label}.run_id must be non-empty")
    validate_created_utc(manifest["created_utc"], f"{label}.created_utc")
    if manifest["target"] != "x86_64-pc-windows-msvc":
        fail(f"{label}.target is invalid")
    if manifest["requested_toolchain"] != "1.88":
        fail(f"{label}.requested_toolchain must remain pinned to 1.88")
    if not isinstance(manifest["resolved_toolchain"], str) or "host: x86_64-pc-windows-msvc" not in manifest["resolved_toolchain"]:
        fail(f"{label}.resolved_toolchain does not identify the native compiler host")
    if manifest["review_status"] != "independent_review_pending":
        fail(f"{label} cannot claim independent review")
    if manifest["status"] not in VALID_MANIFEST_STATUSES:
        fail(f"{label}.status is invalid")
    if not isinstance(manifest["dirty"], bool):
        fail(f"{label}.dirty must be boolean")
    host = manifest["host"]
    if not isinstance(host, dict) or not isinstance(host.get("administrator"), bool):
        fail(f"{label}.host must record the administrator preflight")
    for field in ("system", "release", "version", "machine", "python", "target"):
        if not isinstance(host.get(field), str) or not host[field]:
            fail(f"{label}.host.{field} must be non-empty")
    verifier = manifest["application_verifier"]
    if not isinstance(verifier, dict) or set(verifier) != {"path", "version", "sha256"}:
        fail(f"{label}.application_verifier is invalid")
    if not isinstance(verifier["path"], str) or not verifier["path"]:
        fail(f"{label}.application_verifier.path must be non-empty")
    if not isinstance(verifier["version"], str) or not verifier["version"]:
        fail(f"{label}.application_verifier.version must be non-empty")
    if not isinstance(verifier["sha256"], str) or not SHA256_RE.fullmatch(verifier["sha256"]):
        fail(f"{label}.application_verifier.sha256 is invalid")
    configuration = manifest["configuration"]
    if configuration != {
        "layer": "lowres",
        "file_probability": 1000000,
        "timeout_ms": 0,
        "target_image": "fs2-windows-appverifier-probe.exe",
    }:
        fail(f"{label}.configuration has drifted from the targeted file-fault contract")
    commands = manifest["commands"]
    command_fields = {
        "build",
        "probe",
        "initial_delete",
        "initial_query",
        "configure",
        "query",
        "cleanup_delete",
        "cleanup_query",
    }
    if not isinstance(commands, dict) or set(commands) != command_fields:
        fail(f"{label}.commands must retain the complete AppVerifier procedure")
    expected_build = [
        "cargo",
        "+1.88",
        "test",
        "--package",
        "fs2",
        "--target",
        "x86_64-pc-windows-msvc",
        "--locked",
        "--test",
        "windows_appverifier",
        "--no-run",
        "--message-format=json",
    ]
    expected_delete = [
        verifier["path"],
        "-delete",
        "settings",
        "-for",
        "fs2-windows-appverifier-probe.exe",
    ]
    expected_configure = [
        verifier["path"],
        "-enable",
        "lowres",
        "-for",
        "fs2-windows-appverifier-probe.exe",
        "-with",
        "file=1000000",
        "timeout=0",
    ]
    expected_query = [
        verifier["path"],
        "-query",
        "lowres",
        "-for",
        "fs2-windows-appverifier-probe.exe",
    ]
    probe_command = commands["probe"]
    if (
        commands["build"] != expected_build
        or commands["initial_delete"] != expected_delete
        or commands["initial_query"] != expected_query
        or commands["configure"] != expected_configure
        or commands["query"] != expected_query
        or commands["cleanup_delete"] != expected_delete
        or commands["cleanup_query"] != expected_query
        or not isinstance(probe_command, list)
        or len(probe_command) != 4
        or portable_path_name(probe_command[0]) != "fs2-windows-appverifier-probe.exe"
        or probe_command[1:] != ["--exact", "appverifier_file_fault_is_observed", "--nocapture"]
    ):
        fail(f"{label}.commands has drifted from the targeted AppVerifier procedure")
    controlled_environment = manifest["controlled_environment"]
    if not isinstance(controlled_environment, dict) or set(controlled_environment) != {"baseline", "injected"}:
        fail(f"{label}.controlled_environment must retain baseline and injected overrides")
    baseline_environment = controlled_environment["baseline"]
    injected_environment = controlled_environment["injected"]
    if (
        not isinstance(baseline_environment, dict)
        or set(baseline_environment) != {"FS2_APPVERIFIER_PROBE_PATH"}
        or portable_path_name(baseline_environment["FS2_APPVERIFIER_PROBE_PATH"]) != "Cargo.toml"
        or not isinstance(injected_environment, dict)
        or injected_environment
        != {
            **baseline_environment,
            "FS2_EXPECT_APPVERIFIER_FILE_FAULT": "1",
        }
    ):
        fail(f"{label}.controlled_environment has drifted from the probe contract")
    initial_state = manifest["initial_state"]
    configured_state = manifest["configured_state"]
    cleanup = manifest["cleanup"]
    if not isinstance(initial_state, dict) or set(initial_state) != {
        "delete_native_exit",
        "query_native_exit",
        "query_observation",
        "verified_absent",
    }:
        fail(f"{label}.initial_state is invalid")
    if not isinstance(configured_state, dict) or set(configured_state) != {
        "enable_native_exit",
        "query_native_exit",
        "query_observation",
        "verified",
    }:
        fail(f"{label}.configured_state is invalid")
    if not isinstance(cleanup, dict) or set(cleanup) != {
        "delete_native_exit",
        "query_native_exit",
        "query_observation",
        "verified_absent",
    }:
        fail(f"{label}.cleanup is invalid")
    if not isinstance(initial_state["verified_absent"], bool):
        fail(f"{label}.initial_state.verified_absent must be boolean")
    if not isinstance(configured_state["verified"], bool):
        fail(f"{label}.configured_state.verified must be boolean")
    if not isinstance(cleanup["verified_absent"], bool):
        fail(f"{label}.cleanup.verified_absent must be boolean")
    validate_appverifier_query_observation(
        initial_state["query_observation"], f"{label}.initial_state.query_observation"
    )
    validate_appverifier_query_observation(
        configured_state["query_observation"],
        f"{label}.configured_state.query_observation",
    )
    validate_appverifier_query_observation(
        cleanup["query_observation"], f"{label}.cleanup.query_observation"
    )
    probe = manifest["probe"]
    if (
        not isinstance(probe, dict)
        or set(probe) != {"test_target", "test_id", "binary", "sha256"}
        or probe.get("test_target") != "windows_appverifier"
        or probe.get("test_id") != "appverifier_file_fault_is_observed"
    ):
        fail(f"{label}.probe has the wrong test identity")
    successful = manifest["status"] in {"pass", "focused_only"}
    if successful:
        if host["administrator"] is not True or host["system"] != "Windows" or host.get("target") != manifest["target"]:
            fail(f"{label} cannot claim an injected run without elevated native execution")
        if manifest["tree"] == "0" * 40 or manifest["cargo_lock_sha256"] == "0" * 64:
            fail(f"{label} successful evidence must retain non-placeholder provenance")
        if manifest["status"] == "pass" and manifest["dirty"]:
            fail(f"{label} cannot be pass with dirty provenance")
        if manifest["status"] == "focused_only" and not manifest["dirty"]:
            fail(f"{label} focused evidence must identify a dirty run")
        if probe.get("binary") != "fs2-windows-appverifier-probe.exe":
            fail(f"{label}.probe.binary is invalid")
        if not isinstance(probe.get("sha256"), str) or not SHA256_RE.fullmatch(probe["sha256"]):
            fail(f"{label}.probe.sha256 is invalid")
        absent_observation = {
            "lowres_enabled": False,
            "file_probability": None,
            "timeout_ms": None,
        }
        configured_observation = {
            "lowres_enabled": True,
            "file_probability": 1000000,
            "timeout_ms": 0,
        }
        if initial_state != {
            "delete_native_exit": 0,
            "query_native_exit": 0,
            "query_observation": absent_observation,
            "verified_absent": True,
        }:
            fail(f"{label} did not verify an unconfigured baseline state")
        if configured_state != {
            "enable_native_exit": 0,
            "query_native_exit": 0,
            "query_observation": configured_observation,
            "verified": True,
        }:
            fail(f"{label} did not verify the configured lowres state")
        baseline = manifest["baseline"]
        injected = manifest["injected"]
        if baseline.get("native_exit") != 0 or injected.get("native_exit") != 0:
            fail(f"{label} successful probes must have zero native exits")
        validate_appverifier_observation(
            baseline.get("observation"),
            expected_fault=False,
            label=f"{label}.baseline.observation",
        )
        validate_appverifier_observation(
            injected.get("observation"),
            expected_fault=True,
            label=f"{label}.injected.observation",
        )
        if cleanup != {
            "delete_native_exit": 0,
            "query_native_exit": 0,
            "query_observation": absent_observation,
            "verified_absent": True,
        }:
            fail(f"{label} did not verify Application Verifier cleanup")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{label}.artifacts must be non-empty")
    run_root = path.parent.resolve()
    artifact_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "bytes"}:
            fail(f"{label} contains an incomplete artifact")
        if not isinstance(artifact["path"], str) or not artifact["path"] or artifact["path"] in artifact_paths:
            fail(f"{label} contains an invalid or duplicate artifact path")
        if not isinstance(artifact["bytes"], int) or isinstance(artifact["bytes"], bool) or artifact["bytes"] < 0:
            fail(f"{label} contains an invalid artifact size")
        artifact_path = (run_root / artifact["path"]).resolve()
        try:
            artifact_path.relative_to(run_root)
        except ValueError:
            fail(f"{label} contains an artifact outside its run directory")
        if not artifact_path.is_file():
            fail(f"{label} references missing artifact: {artifact['path']}")
        if artifact["sha256"] != sha256(artifact_path) or artifact["bytes"] != artifact_path.stat().st_size:
            fail(f"{label} contains a stale artifact digest or size")
        artifact_paths.add(artifact["path"])
    if successful:
        required_artifacts = {
            "build-stdout.jsonl",
            "build-stderr.log",
            "fs2-windows-appverifier-probe.exe",
            "initial-delete-stdout.log",
            "initial-delete-stderr.log",
            "initial-query-stdout.log",
            "initial-query-stderr.log",
            "baseline-stdout.log",
            "baseline-stderr.log",
            "configure-stdout.log",
            "configure-stderr.log",
            "query-stdout.log",
            "query-stderr.log",
            "injected-stdout.log",
            "injected-stderr.log",
            "cleanup-delete-stdout.log",
            "cleanup-delete-stderr.log",
            "cleanup-query-stdout.log",
            "cleanup-query-stderr.log",
        }
        if not required_artifacts.issubset(artifact_paths):
            fail(f"{label} is missing required AppVerifier evidence artifacts")
        probe_artifact = next(
            artifact
            for artifact in artifacts
            if artifact["path"] == "fs2-windows-appverifier-probe.exe"
        )
        if probe_artifact["sha256"] != probe["sha256"]:
            fail(f"{label}.probe.sha256 does not match the retained executable")
    if manifest["status"] == "indeterminate" and not (
        {"preflight-error.txt", "timeout.txt"} & artifact_paths
    ):
        fail(f"{label} must retain the indeterminate preflight or timeout reason")


def validate_static_records() -> None:
    records = {}
    for filename in REQUIRED_RECORDS:
        path = COVERAGE / filename
        if not path.is_file():
            fail(f"required record is missing: coverage/{filename}")
        records[filename] = load_json(path)
    context = records["assurance-context.json"]
    requirements = records["requirements.json"]
    requirements_review = records["requirements-review.json"]
    surface = records["surface.json"]
    decisions = records["decision-inventory.json"]
    verifications = validate_verification_inventory(records["verification-inventory.json"])
    from validate_mcdc import validate_record as validate_mcdc_record

    mcdc_ids = validate_mcdc_record(records["mcdc.json"], verifications)
    validate_context(context)
    requirement_ids = validate_requirements(requirements, verifications)
    validate_requirements_review(
        requirements_review,
        requirements,
        records["verification-inventory.json"],
        requirement_ids,
    )
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
    validate_configuration_management(records["configuration-management.json"])
    validate_archive_control(records["archive-control.json"])
    validate_archive_retrieval(records["archive-retrieval.json"])
    expected_review_status = validate_windows_native_fault_review(
        records["windows-native-fault-review.json"]
    )
    independent_review_approved = expected_review_status == "independent_review_approved"
    validate_evidence_index(
        records["evidence-index.json"], independent_review_approved
    )
    validate_assurance_control_links(
        context,
        records["configuration-management.json"],
        records["archive-control.json"],
        records["archive-retrieval.json"],
        records["evidence-index.json"],
    )
    validate_gap_register(records["gap-register.json"], independent_review_approved)
    validate_windows_native_fault_assessment(
        records["windows-native-faults.json"],
        verifications,
        expected_review_status,
    )
    review_schema = records["windows-native-fault-review.schema.json"]
    if (
        review_schema.get("record_type")
        != "windows_native_fault_independent_review_schema"
        or review_schema.get("schema_version") != 1
        or set(review_schema.get("required", []))
        != WINDOWS_NATIVE_FAULT_REVIEW_FIELDS
        or review_schema.get("enums")
        != {
            "status": [
                "assigned_awaiting_clean_baseline",
                "assigned_ready_for_review",
                "in_review",
                "changes_requested",
                "approved",
                "rejected",
            ],
            "reviewer_acceptance": ["pending", "accepted", "declined"],
            "independence_status": ["declaration_pending", "accepted", "rejected"],
            "check_status": ["not_reviewed", "pass", "fail"],
            "decision_status": ["pending", "recorded"],
        }
        or not isinstance(review_schema.get("promotion_rule"), str)
        or "Assignment is not review acceptance" not in review_schema["promotion_rule"]
    ):
        fail("coverage/windows-native-fault-review.schema.json has the wrong identity")
    fault_schema = records["windows-native-fault-run.schema.json"]
    if (
        fault_schema.get("record_type") != "windows_native_fault_run_schema"
        or fault_schema.get("schema_version") != 1
        or set(fault_schema.get("required", [])) != NATIVE_FAULT_MANIFEST_FIELDS
        or fault_schema.get("enums")
        != {
            "status": ["pass", "fail", "indeterminate", "provenance_error", "focused_only"],
            "review_status": ["independent_review_pending"],
        }
        or fault_schema.get("target") != "x86_64-pc-windows-msvc"
        or not isinstance(fault_schema.get("promotion_rule"), str)
        or "independent review" not in fault_schema["promotion_rule"]
    ):
        fail("coverage/windows-native-fault-run.schema.json has the wrong identity")
    appverifier_schema = records["windows-appverifier-run.schema.json"]
    if (
        appverifier_schema.get("record_type") != "windows_appverifier_run_schema"
        or appverifier_schema.get("schema_version") != 1
        or set(appverifier_schema.get("required", [])) != APPVERIFIER_MANIFEST_FIELDS
        or appverifier_schema.get("enums")
        != {
            "status": ["pass", "fail", "indeterminate", "provenance_error", "focused_only"],
            "review_status": ["independent_review_pending"],
        }
        or not isinstance(appverifier_schema.get("promotion_rule"), str)
        or "independent review" not in appverifier_schema["promotion_rule"]
    ):
        fail("coverage/windows-appverifier-run.schema.json has the wrong identity")


def validate_manifest(path: Path, expected_commit: str | None = None) -> None:
    manifest = load_json(path)
    label = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
    required_fields(
        manifest,
        {
            "run_id", "repository", "branch", "commit", "tree", "dirty", "cargo_lock_sha256",
            "host", "target", "profile", "requested_toolchain", "resolved_toolchain",
            "cargo_llvm_cov", "command", "environment", "provider", "native_exit", "status", "artifacts",
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
    host = manifest["host"]
    if not isinstance(host, dict) or not isinstance(host.get("target"), str) or not host["target"]:
        fail(f"{label}.host.target must record the compiler host target")
    if not isinstance(host.get("version"), str) or not host["version"]:
        fail(f"{label}.host.version must record the host OS version")
    if manifest["status"] == "pass" and host["target"] != manifest["target"]:
        fail(f"{label} cannot claim native pass coverage for a non-native target")
    if manifest["profile"] not in {"stable", "branch", "condition"}:
        fail(f"{label}.profile is invalid")
    if not isinstance(manifest["target"], str) or not manifest["target"]:
        fail(f"{label}.target must be non-empty")
    if not isinstance(manifest["command"], list) or not manifest["command"] or not all(isinstance(item, str) and item for item in manifest["command"]):
        fail(f"{label}.command must be a non-empty string list")
    if not isinstance(manifest["environment"], dict):
        fail(f"{label}.environment must be an object")
    provider = manifest["provider"]
    if not isinstance(provider, dict):
        fail(f"{label}.provider must be an object")
    required_fields(
        provider,
        {
            "schema_version",
            "api",
            "library",
            "module_present",
            "symbol_present",
            "outcome",
            "error_raw_os",
        },
        f"{label}.provider",
    )
    if (
        provider["schema_version"] != 1
        or provider["api"] != "GetDiskSpaceInformationW"
        or provider["library"] != "kernel32.dll"
    ):
        fail(f"{label}.provider has an invalid Windows provider identity")
    if provider["outcome"] not in {
        "available",
        "unavailable",
        "error",
        "not_run",
        "not_applicable",
        "invalid",
    }:
        fail(f"{label}.provider.outcome is invalid")
    is_windows = manifest["target"].endswith("-pc-windows-msvc")
    if is_windows:
        if not isinstance(provider["module_present"], bool) or not isinstance(provider["symbol_present"], bool):
            fail(f"{label}.provider presence values must be boolean on Windows")
        if (
            manifest["status"] in {"pass", "focused_only"}
            and provider["outcome"] in {"not_run", "invalid"}
        ):
            fail(f"{label} cannot claim pass without a valid Windows provider probe")
    elif provider["outcome"] != "not_applicable" or provider["module_present"] is not None or provider["symbol_present"] is not None:
        fail(f"{label}.provider must be not_applicable outside Windows")
    if provider["error_raw_os"] is not None and (
        not isinstance(provider["error_raw_os"], int) or isinstance(provider["error_raw_os"], bool)
    ):
        fail(f"{label}.provider.error_raw_os must be an integer or null")
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
    artifact_paths = set()
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
        artifact_paths.add(artifact["path"])
    if (
        manifest["status"] in {"pass", "focused_only"}
        and is_windows
        and "windows-provider.json" not in artifact_paths
    ):
        fail(f"{label} is missing the Windows provider probe artifact")


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
    parser.add_argument("--windows-native-fault-manifest", type=Path)
    parser.add_argument("--windows-appverifier-manifest", type=Path)
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
        requested_manifests = sum(
            value is not None
            for value in (
                args.runs_dir,
                args.manifest,
                args.windows_native_fault_manifest,
                args.windows_appverifier_manifest,
            )
        )
        if requested_manifests > 1:
            fail("manifest selection arguments are mutually exclusive")
        if args.runs_dir:
            count = validate_runs(args.runs_dir.resolve(), expected_commit, args.require_pass)
            print(f"coverage records and {count} run manifest(s) are valid")
        elif args.manifest:
            validate_manifest(args.manifest.resolve(), expected_commit)
            print("coverage records and run manifest are valid")
        elif args.windows_native_fault_manifest:
            path = args.windows_native_fault_manifest.resolve()
            validate_windows_native_fault_manifest(path, expected_commit)
            if args.require_pass and load_json(path)["status"] != "pass":
                fail(f"{path} is not promotable: status must be pass")
            print("coverage records and Windows native-fault manifest are valid")
        elif args.windows_appverifier_manifest:
            path = args.windows_appverifier_manifest.resolve()
            validate_windows_appverifier_manifest(path, expected_commit)
            if args.require_pass and load_json(path)["status"] != "pass":
                fail(f"{path} is not promotable: status must be pass")
            print("coverage records and Windows Application Verifier manifest are valid")
        else:
            print("coverage records are valid; no run manifests were requested")
    except (ValidationError, OSError) as error:
        print(f"coverage validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
