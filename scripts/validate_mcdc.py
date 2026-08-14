#!/usr/bin/env python3
"""Validate the internal source-level MC/DC assessment records.

This validator checks the bookkeeping and pair algebra needed for an internal
MC/DC review.  It deliberately does not turn the records into certification,
object-code, qualified-tool, independence, or authority evidence.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_REF_RE = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OBSERVATION_STATES = {"true", "false", "not_evaluated"}
DECISION_STATUSES = {"closed_internal", "assessment_open", "deferred"}


class ValidationError(Exception):
    """An MC/DC record-validation failure."""


def fail(message: str) -> None:
    raise ValidationError(message)


def required_fields(value: dict[str, Any], fields: set[str], label: str) -> None:
    missing = fields - value.keys()
    if missing:
        fail(f"{label} is missing fields: {sorted(missing)}")


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


def source_path(reference: str, label: str) -> Path:
    match = SOURCE_REF_RE.fullmatch(reference) if isinstance(reference, str) else None
    if match is None:
        fail(f"{label} must be a source reference such as src/lib.rs:10")
    path = (ROOT / match.group("path")).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as error:
        fail(f"{label} escapes the repository")
    if not path.is_file():
        fail(f"{label} references a missing file")
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if start < 1 or end < start or end > line_count:
        fail(f"{label} has an invalid source span")
    return path


def validate_observation(
    observation: Any,
    label: str,
    condition_ids: set[str],
    observation_ids: set[str],
    verification_ids: set[str] | None,
) -> None:
    if not isinstance(observation, dict):
        fail(f"{label} must be an object")
    required_fields(
        observation,
        {"id", "verification_id", "condition_states", "decision", "oracle", "result"},
        label,
    )
    identifier = observation["id"]
    if not isinstance(identifier, str) or not re.fullmatch(r"OBS-[A-Z0-9-]+", identifier):
        fail(f"{label}.id is invalid")
    if identifier in observation_ids:
        fail(f"{label}.id is duplicated")
    observation_ids.add(identifier)
    verification_id = observation["verification_id"]
    if not isinstance(verification_id, str) or not verification_id:
        fail(f"{label}.verification_id is invalid")
    if verification_ids is not None and verification_id not in verification_ids:
        fail(f"{label} references unknown verification {verification_id!r}")
    states = observation["condition_states"]
    if not isinstance(states, dict) or set(states) != condition_ids:
        fail(f"{label}.condition_states must cover exactly every condition occurrence")
    if any(state not in OBSERVATION_STATES for state in states.values()):
        fail(f"{label}.condition_states contains an invalid tri-state value")
    if not isinstance(observation["decision"], bool):
        fail(f"{label}.decision must be boolean")
    if observation["oracle"] not in {"pass", "fail"}:
        fail(f"{label}.oracle must be pass or fail")
    if observation["result"] != "pass":
        fail(f"{label}.result must be pass")


def validate_pair(
    pair: Any,
    label: str,
    condition_ids: set[str],
    observations: dict[str, dict[str, Any]],
    pair_ids: set[str],
) -> None:
    if not isinstance(pair, dict):
        fail(f"{label} must be an object")
    required_fields(
        pair,
        {"id", "target_condition", "baseline_observation", "modified_observation", "result"},
        label,
    )
    identifier = pair["id"]
    if not isinstance(identifier, str) or not re.fullmatch(r"PAIR-[A-Z0-9-]+", identifier):
        fail(f"{label}.id is invalid")
    if identifier in pair_ids:
        fail(f"{label}.id is duplicated")
    pair_ids.add(identifier)
    target = pair["target_condition"]
    if target not in condition_ids:
        fail(f"{label}.target_condition is not a condition occurrence")
    baseline = observations.get(pair["baseline_observation"])
    modified = observations.get(pair["modified_observation"])
    if baseline is None or modified is None:
        fail(f"{label} references an unknown observation")
    baseline_states = baseline["condition_states"]
    modified_states = modified["condition_states"]
    for condition_id in condition_ids:
        if condition_id == target:
            if baseline_states[condition_id] == modified_states[condition_id]:
                fail(f"{label} does not change the target condition")
            if "not_evaluated" in (baseline_states[condition_id], modified_states[condition_id]):
                fail(f"{label} target condition must be evaluated in both observations")
        elif baseline_states[condition_id] != modified_states[condition_id]:
            fail(f"{label} changes a non-target condition")
    if baseline["decision"] == modified["decision"]:
        fail(f"{label} does not change the decision outcome")
    if baseline["oracle"] != "pass" or modified["oracle"] != "pass":
        fail(f"{label} requires passing oracle outcomes on both observations")
    if pair["result"] != "pass":
        fail(f"{label}.result must be pass")


def validate_record(
    record: dict[str, Any], verification_ids: set[str] | None = None
) -> set[str]:
    label = "coverage/mcdc.json"
    required_fields(
        record,
        {
            "record_type",
            "schema_version",
            "status",
            "owner",
            "claim_class",
            "credit",
            "tool_support",
            "decisions",
            "out_of_scope",
            "open_dispositions",
        },
        label,
    )
    if record["record_type"] != "source_mcdc_assessment" or record["schema_version"] != 1:
        fail(f"{label} has the wrong record type or schema version")
    if record["status"] not in {"draft", "assessment_open"}:
        fail(f"{label}.status must retain an open review state")
    if record["claim_class"] != "internal_engineering_evidence" or record["credit"] != "none":
        fail(f"{label} contains an unsupported assurance claim")
    tool_support = record["tool_support"]
    if (
        not isinstance(tool_support, dict)
        or tool_support.get("cargo_llvm_cov_mcdc") != "not_available_on_pinned_nightly"
        or tool_support.get("source_object_mapping")
        != "module_symbol_inventory_reviewed_semantic_mapping_open"
        or tool_support.get("source_object_reconciliation_ref")
        != "coverage/source-object-reconciliation.json"
    ):
        fail(f"{label}.tool_support must record the pinned-tool limitation")
    llvm_assessment = tool_support.get("llvm_mcdc_design_assessment")
    if not isinstance(llvm_assessment, dict) or set(llvm_assessment) != {
        "reference",
        "title",
        "publication_context",
        "classification",
        "design_mechanism",
        "historical_limit",
        "current_clang_context",
        "rust_applicability",
        "disposition",
        "adopted_controls",
        "deferred_claims",
    }:
        fail(f"{label}.tool_support lacks the registered LLVM MC/DC assessment")
    if (
        llvm_assessment["reference"]
        != "https://llvm.org/devmtg/2022-11/slides/TechTalk4-MCDC-EnablingSafetyCriticalCodeCoverage.pdf"
        or llvm_assessment["classification"]
        != "advisory_technical_design_input_not_certification_basis"
        or llvm_assessment["disposition"]
        != "adopt_semantic_and_validation_requirements_defer_rust_tool_claim"
        or "pinned Rust nightly probe rejects mcdc"
        not in llvm_assessment["rust_applicability"]
    ):
        fail(f"{label}.tool_support overstates LLVM MC/DC applicability to Rust")
    for field in ("adopted_controls", "deferred_claims"):
        values = llvm_assessment[field]
        if not isinstance(values, list) or len(values) < 3 or not all(
            isinstance(value, str) and value.strip() for value in values
        ):
            fail(f"{label}.tool_support.{field} is incomplete")
    decisions = record["decisions"]
    if not isinstance(decisions, list) or not decisions:
        fail(f"{label}.decisions must be non-empty")
    decision_ids: set[str] = set()
    for index, decision in enumerate(decisions):
        item_label = f"{label}.decisions[{index}]"
        if not isinstance(decision, dict):
            fail(f"{item_label} must be an object")
        required_fields(
            decision,
            {
                "id",
                "source",
                "source_sha256",
                "symbol",
                "requirement_ids",
                "verification_ids",
                "conditions",
                "observations",
                "pairs",
                "status",
            },
            item_label,
        )
        identifier = decision["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"MCDC-[A-Z0-9-]+", identifier) or identifier in decision_ids:
            fail(f"{item_label}.id must be a unique MCDC identifier")
        decision_ids.add(identifier)
        path = source_path(decision["source"], f"{item_label}.source")
        digest = decision["source_sha256"]
        if (
            not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
            or digest != canonical_source_sha256(path)
        ):
            fail(f"{item_label}.source_sha256 does not match the current source")
        if not isinstance(decision["symbol"], str) or not decision["symbol"]:
            fail(f"{item_label}.symbol must be non-empty")
        for field in ("requirement_ids", "verification_ids"):
            values = decision[field]
            if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
                fail(f"{item_label}.{field} must be a non-empty string list")
        if verification_ids is not None:
            unknown = set(decision["verification_ids"]) - verification_ids
            if unknown:
                fail(f"{item_label} references unknown verifications: {sorted(unknown)}")
        conditions = decision["conditions"]
        if not isinstance(conditions, list) or not conditions:
            fail(f"{item_label}.conditions must be non-empty")
        condition_ids: set[str] = set()
        for condition_index, condition in enumerate(conditions):
            condition_label = f"{item_label}.conditions[{condition_index}]"
            if not isinstance(condition, dict) or set(condition) != {"id", "expression", "occurrence"}:
                fail(f"{condition_label} has an invalid shape")
            condition_id = condition["id"]
            if not isinstance(condition_id, str) or not re.fullmatch(r"C\d+", condition_id) or condition_id in condition_ids:
                fail(f"{condition_label}.id must be unique and use C<n> form")
            condition_ids.add(condition_id)
            if not all(isinstance(condition[field], str) and condition[field] for field in ("expression", "occurrence")):
                fail(f"{condition_label} expressions must be non-empty strings")
        observations = decision["observations"]
        if not isinstance(observations, list) or not observations:
            fail(f"{item_label}.observations must be non-empty")
        observation_ids: set[str] = set()
        observation_map: dict[str, dict[str, Any]] = {}
        for observation_index, observation in enumerate(observations):
            observation_label = f"{item_label}.observations[{observation_index}]"
            validate_observation(observation, observation_label, condition_ids, observation_ids, verification_ids)
            observation_map[observation["id"]] = observation
        pairs = decision["pairs"]
        if not isinstance(pairs, list) or not pairs:
            fail(f"{item_label}.pairs must be non-empty")
        pair_ids: set[str] = set()
        covered_conditions: set[str] = set()
        for pair_index, pair in enumerate(pairs):
            pair_label = f"{item_label}.pairs[{pair_index}]"
            validate_pair(pair, pair_label, condition_ids, observation_map, pair_ids)
            covered_conditions.add(pair["target_condition"])
        if covered_conditions != condition_ids:
            fail(f"{item_label} does not have a valid pair for every condition occurrence")
        if decision["status"] not in DECISION_STATUSES:
            fail(f"{item_label}.status is invalid")
    out_of_scope = record["out_of_scope"]
    if not isinstance(out_of_scope, list) or not out_of_scope or not all(isinstance(item, dict) for item in out_of_scope):
        fail(f"{label}.out_of_scope must retain explicit reviewed dispositions")
    if not isinstance(record["open_dispositions"], list) or not record["open_dispositions"]:
        fail(f"{label}.open_dispositions must retain authority-owned decisions")
    return decision_ids


if __name__ == "__main__":
    import json

    value = json.loads((ROOT / "coverage" / "mcdc.json").read_text(encoding="utf-8"))
    validate_record(value)
    print("MC/DC records are structurally valid")
