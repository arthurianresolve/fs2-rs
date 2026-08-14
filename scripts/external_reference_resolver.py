#!/usr/bin/env python3
"""Resolve digest-bound external assurance records without granting authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "coverage" / "external-reference-registry.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Z][A-Z0-9-]+$")
RECORD_TYPES = {
    "applicable_certification_basis": "approved",
    "software_level_assignment": "approved",
    "tool_qualification_decision": "approved",
    "archive_authority_decision": "approved",
    "independence_plan": "approved",
    "authority_acceptance": "accepted",
}
REQUIRED_TYPES = [
    "applicable_certification_basis",
    "tool_qualification_decision",
    "archive_authority_decision",
    "independence_plan",
    "authority_acceptance",
]
NON_CLAIMS = [
    "Resolution verifies registered identity, applicability, revision, configuration, status, and bytes; it does not validate the decision's technical or legal sufficiency.",
    "A resolved record does not by itself establish certification credit, tool qualification, organizational independence, release approval, or authority acceptance.",
]


class ExternalReferenceError(Exception):
    """An external-reference registry or controlled record is invalid."""


def fail(message: str) -> None:
    raise ExternalReferenceError(message)


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


def safe_registry_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "//" in value:
        fail(f"{label} must be a canonical POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        fail(f"{label} must not be absolute or contain traversal components")
    if len(path.parts) < 3 or path.parts[:2] != ("coverage", "external-records"):
        fail(f"{label} must be below coverage/external-records")
    return path


def validate_string_list(value: Any, label: str, *, allow_empty: bool = False) -> None:
    if not isinstance(value, list) or (not allow_empty and not value) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        fail(f"{label} must be {'a' if not allow_empty else 'an optional'} non-empty string list")


def validate_registry(registry: dict[str, Any]) -> None:
    fields = {
        "record_type", "schema_version", "status", "owner", "repository", "branch",
        "scope", "required_types", "path_policy", "records", "open_items", "non_claims",
    }
    if set(registry) != fields:
        fail("external-reference registry fields do not match the registered contract")
    if (
        registry["record_type"] != "external_assurance_reference_registry"
        or registry["schema_version"] != 1
        or registry["status"] not in {"not_ready", "draft"}
        or registry["owner"] != "fs2 DO-178C coverage workstream"
        or registry["repository"] != "arthurianresolve/fs2-rs"
        or registry["branch"] != "DO-178C"
        or registry["scope"] != "controlled_external_records_for_future_assurance_decisions"
        or registry["required_types"] != REQUIRED_TYPES
        or registry["path_policy"]
        != "canonical_digest_bound_json_below_coverage/external-records"
    ):
        fail("external-reference registry identity or scope is invalid")
    records = registry["records"]
    if not isinstance(records, list):
        fail("external-reference registry records must be a list")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_types: set[str] = set()
    for index, entry in enumerate(records):
        label = f"external-reference registry records[{index}]"
        if not isinstance(entry, dict) or set(entry) != {
            "id", "record_type", "path", "sha256", "expected_status", "repository",
            "branch", "revision", "configuration_id",
        }:
            fail(f"{label} has invalid fields")
        identifier = entry["id"]
        record_type = entry["record_type"]
        if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier) or identifier in seen_ids:
            fail(f"{label}.id is invalid or duplicated")
        if record_type not in RECORD_TYPES or record_type in seen_types:
            fail(f"{label}.record_type is invalid or duplicated")
        path = safe_registry_path(entry["path"], f"{label}.path").as_posix()
        if path in seen_paths or not SHA256_RE.fullmatch(str(entry["sha256"])):
            fail(f"{label} path or digest is invalid")
        if (
            entry["expected_status"] != RECORD_TYPES[record_type]
            or entry["repository"] != registry["repository"]
            or entry["branch"] != registry["branch"]
            or not COMMIT_RE.fullmatch(str(entry["revision"]))
            or not isinstance(entry["configuration_id"], str)
            or not re.fullmatch(r"CM-DO178C-\d{4}", entry["configuration_id"])
        ):
            fail(f"{label} applicability binding is invalid")
        seen_ids.add(identifier)
        seen_paths.add(path)
        seen_types.add(record_type)
    validate_string_list(registry["open_items"], "external-reference registry open_items")
    validate_string_list(registry["non_claims"], "external-reference registry non_claims")
    if registry["records"] == [] and registry["status"] != "not_ready":
        fail("empty external-reference registry must remain not_ready")
    if not all(claim in registry["non_claims"] for claim in NON_CLAIMS):
        fail("external-reference registry omits a required non-claim")


def validate_external_record(record: dict[str, Any], entry: dict[str, Any], label: str) -> None:
    fields = {
        "record_type", "schema_version", "id", "status", "issuer", "repository",
        "branch", "revision", "configuration_id", "decision", "effective_utc",
        "source_refs", "non_claims",
    }
    if set(record) != fields:
        fail(f"{label} fields do not match the external-record envelope")
    for field in ("record_type", "id", "status", "repository", "branch", "revision", "configuration_id"):
        expected_field = "expected_status" if field == "status" else field
        if record[field] != entry[expected_field]:
            fail(f"{label}.{field} does not match the registry")
    if record["schema_version"] != 1:
        fail(f"{label}.schema_version is invalid")
    issuer = record["issuer"]
    if not isinstance(issuer, dict) or set(issuer) != {"name", "role", "organization"} or not all(
        isinstance(value, str) and value.strip() for value in issuer.values()
    ):
        fail(f"{label}.issuer is incomplete")
    if not isinstance(record["decision"], str) or not record["decision"].strip():
        fail(f"{label}.decision must be non-empty")
    if not isinstance(record["effective_utc"], str) or "T" not in record["effective_utc"]:
        fail(f"{label}.effective_utc must be a timestamp")
    try:
        parsed = datetime.fromisoformat(record["effective_utc"].replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label}.effective_utc must be a timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label}.effective_utc must include a timezone")
    validate_string_list(record["source_refs"], f"{label}.source_refs")
    validate_string_list(record["non_claims"], f"{label}.non_claims")


def resolve_registry(
    registry_path: Path = REGISTRY_PATH, *, result_path: Path | None = None,
    verified_utc: str | None = None,
) -> dict[str, Any]:
    registry_path = registry_path.resolve()
    registry = load_json(registry_path)
    validate_registry(registry)
    repository_root = registry_path.parent.parent
    resolved: list[dict[str, Any]] = []
    for entry in registry["records"]:
        relative = safe_registry_path(entry["path"], f"external record {entry['id']} path")
        controlled_root = repository_root / "coverage" / "external-records"
        if controlled_root.is_symlink():
            fail("controlled external-record directory must not be a symbolic link")
        unresolved_path = repository_root.joinpath(*relative.parts)
        if unresolved_path.is_symlink():
            fail(f"external record {entry['id']} is missing or unsafe")
        path = unresolved_path.resolve()
        try:
            path.relative_to(controlled_root.resolve())
        except ValueError:
            fail(f"external record {entry['id']} escapes the controlled directory")
        if path.is_symlink() or not path.is_file():
            fail(f"external record {entry['id']} is missing or unsafe")
        observed_digest = sha256(path)
        if observed_digest != entry["sha256"]:
            fail(f"external record {entry['id']} digest does not match the registry")
        record = load_json(path)
        validate_external_record(record, entry, f"external record {entry['id']}")
        resolved.append(
            {
                "id": entry["id"],
                "record_type": entry["record_type"],
                "path": entry["path"],
                "sha256": observed_digest,
                "status": entry["expected_status"],
                "revision": entry["revision"],
                "configuration_id": entry["configuration_id"],
            }
        )
    resolved_types = {record["record_type"] for record in resolved}
    missing_types = [record_type for record_type in REQUIRED_TYPES if record_type not in resolved_types]
    verified_utc = verified_utc or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    result = {
        "record_type": "external_assurance_reference_resolution",
        "schema_version": 1,
        "status": "resolved" if not missing_types else "pending_missing_records",
        "repository": registry["repository"],
        "branch": registry["branch"],
        "registry_sha256": sha256(registry_path),
        "resolved_records": resolved,
        "missing_types": missing_types,
        "verified_utc": verified_utc,
        "non_claims": NON_CLAIMS,
    }
    if result_path is not None:
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--require-resolved", action="store_true")
    args = parser.parse_args()
    try:
        result = resolve_registry(args.registry, result_path=args.result)
    except (ExternalReferenceError, OSError) as error:
        print(f"external assurance references are invalid: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.require_resolved and result["status"] != "resolved":
        print(
            "external assurance references remain unresolved: "
            + ", ".join(result["missing_types"]),
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
