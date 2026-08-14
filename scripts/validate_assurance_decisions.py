#!/usr/bin/env python3
"""Validate the internal DAL B assignment and reviewer-role separation."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AssuranceDecisionError(Exception):
    """An internal assurance decision record is invalid."""


def fail(message: str) -> None:
    raise AssuranceDecisionError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str):
        fail(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} must be a timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label} must include a timezone")


def string_list(value: Any, label: str) -> None:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        fail(f"{label} must be a non-empty string list")


def validate_software_level(record: dict[str, Any]) -> None:
    fields = {
        "record_type", "schema_version", "status", "id", "owner", "repository",
        "branch", "assigned_software_level", "determination",
        "applicable_certification_basis_ref", "authority_acceptance_ref",
        "application", "open_items", "non_claims",
    }
    if set(record) != fields:
        fail("software-level assignment fields do not match the registered contract")
    if (
        record["record_type"] != "internal_software_level_assignment"
        or record["schema_version"] != 1
        or record["status"] != "draft"
        or record["id"] != "SLA-DO178C-001"
        or record["owner"] != "fs2 DO-178C coverage workstream"
        or record["repository"] != "arthurianresolve/fs2-rs"
        or record["branch"] != "DO-178C"
        or record["assigned_software_level"] != "DAL_B"
        or record["applicable_certification_basis_ref"] is not None
        or record["authority_acceptance_ref"] is not None
    ):
        fail("software-level assignment identity or claim boundary is invalid")
    determination = record["determination"]
    if determination != {
        "status": "determined_internal",
        "decision_maker": "project owner",
        "decision_basis": "explicit user determination",
        "decision_ref": "conversation-confirmation:SLA-DO178C-001:2026-08-14T04:52:18Z",
        "determined_at": "2026-08-14T04:52:18Z",
    }:
        fail("software-level determination is not the recorded explicit decision")
    timestamp(determination["determined_at"], "software-level determined_at")
    application = record["application"]
    if not isinstance(application, dict) or set(application) != {
        "planning_and_internal_assurance", "structural_coverage", "independence", "tool_assurance"
    } or not all(isinstance(value, str) and value.strip() for value in application.values()):
        fail("software-level application is incomplete")
    string_list(record["open_items"], "software-level open_items")
    string_list(record["non_claims"], "software-level non_claims")


def validate_independence_plan(record: dict[str, Any]) -> None:
    fields = {
        "record_type", "schema_version", "status", "id", "owner", "assurance_context",
        "software_level", "scope", "roles", "separation_controls", "review_gate",
        "conflict_assessment", "limitations", "non_claims",
    }
    if set(record) != fields:
        fail("independence-plan fields do not match the registered contract")
    if (
        record["record_type"] != "internal_assurance_independence_plan"
        or record["schema_version"] != 1
        or record["status"] != "draft"
        or record["id"] != "IND-DO178C-001"
        or record["owner"] != "fs2 DO-178C coverage workstream"
        or record["assurance_context"] != "internal_assurance"
        or record["software_level"] != "DAL_B"
        or not isinstance(record["scope"], str)
        or not record["scope"].strip()
    ):
        fail("independence-plan identity or scope is invalid")
    roles = record["roles"]
    if not isinstance(roles, dict) or set(roles) != {
        "implementation_agent", "human_reviewer", "publication_service_account"
    }:
        fail("independence-plan roles are invalid")
    implementation = roles["implementation_agent"]
    if not isinstance(implementation, dict) or set(implementation) != {
        "identity", "responsibility", "decision_authority"
    } or implementation["identity"] != "OpenAI Codex implementation agent" or implementation["decision_authority"] is not False:
        fail("independence-plan implementation role can approve its own work")
    reviewer = roles["human_reviewer"]
    if not isinstance(reviewer, dict) or set(reviewer) != {
        "person_id", "identity_basis", "responsibility", "organizational_independence",
        "assignment_status", "declaration_ref", "declared_at",
    } or reviewer != {
        "person_id": "IR-PERSON-001",
        "identity_basis": "self-attested person",
        "responsibility": "perform the implementation review and decide internal approval or rejection",
        "organizational_independence": "declared_internal",
        "assignment_status": "accepted",
        "declaration_ref": "conversation-confirmation:IND-DO178C-001:2026-08-14T04:52:18Z",
        "declared_at": "2026-08-14T04:52:18Z",
    }:
        fail("independence-plan human reviewer declaration is invalid")
    timestamp(reviewer["declared_at"], "independence-plan reviewer declared_at")
    publisher = roles["publication_service_account"]
    if publisher != {
        "identity_provider": "github",
        "login": "arthurianresolve",
        "account_id": 268402532,
        "node_id": "U_kgDOD_9_ZA",
        "responsibility": "mechanically publish the approved atomic commit to the DO-178C branch",
        "decision_authority": False,
    }:
        fail("independence-plan publication service account is invalid")
    string_list(record["separation_controls"], "independence-plan separation_controls")
    conflict = record["conflict_assessment"]
    if conflict != {
        "shared_service_account_disclosed": True,
        "disposition": "no_internal_conflict_under_role_separation",
        "rationale": "The implementation agent and human reviewer act independently in developer and reviewer/approver roles. The shared GitHub service account performs publication only and has no decision authority.",
        "conflicts_of_interest": [],
        "assessed_by": "IR-PERSON-001",
        "assessment_ref": "conversation-confirmation:IND-DO178C-001-conflict:2026-08-14T04:58:08Z",
        "assessed_at": "2026-08-14T04:58:08Z",
    }:
        fail("independence-plan shared-service-account disposition is invalid")
    timestamp(conflict["assessed_at"], "independence-plan conflict assessed_at")
    gate = record["review_gate"]
    if not isinstance(gate, dict) or set(gate) != {
        "status", "preparation_parent_commit", "digest_algorithm",
        "candidate_change_digest", "mechanical_review_markers", "decision",
        "decision_ref", "decided_at",
    }:
        fail("independence-plan review gate is invalid")
    if (
        gate["preparation_parent_commit"] != "d1054422079406ba9e4d59805016d9c97a6b01ed"
        or gate["digest_algorithm"] != "sha256-canonical-review-scope-v1"
        or gate["mechanical_review_markers"]
        != [
            "coverage/tool-assessment.json#TOOL-F-001",
            "coverage/tool-assessment.json#TOOL-F-003",
            "coverage/tool-assessment.json#TOOL-F-004",
            "coverage/tool-assessment.json#TOOL-F-005",
        ]
        or (
            gate["candidate_change_digest"] is not None
            and not SHA256_RE.fullmatch(str(gate["candidate_change_digest"]))
        )
    ):
        fail("independence-plan review scope binding is invalid")
    if gate["status"] == "awaiting_implementation_review":
        if any(
            gate[field] is not None
            for field in ("decision", "decision_ref", "decided_at")
        ):
            fail("pending implementation review contains premature decision data")
    elif gate["status"] == "approved_for_atomic_publication":
        if (
            not SHA256_RE.fullmatch(str(gate["candidate_change_digest"]))
            or gate["decision"] != "approve"
            or not isinstance(gate["decision_ref"], str)
            or not gate["decision_ref"].strip()
        ):
            fail("approved implementation review lacks exact change-set binding")
        timestamp(gate["decided_at"], "independence-plan decided_at")
    else:
        fail("independence-plan review gate status is invalid")
    string_list(record["limitations"], "independence-plan limitations")
    string_list(record["non_claims"], "independence-plan non_claims")


def validate_static() -> None:
    validate_software_level(
        load_json(ROOT / "coverage" / "software-level-assignment.json")
    )
    validate_independence_plan(
        load_json(ROOT / "coverage" / "independence-plan.json")
    )


if __name__ == "__main__":
    validate_static()
    print("software-level and independence decision records are valid")
