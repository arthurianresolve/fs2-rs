#!/usr/bin/env python3
"""Publish and retrieve immutable packages through a filesystem endpoint.

The endpoint is deliberately restricted to technical trials.  A mounted
enterprise repository can use the same byte transport, but archive ownership,
access, backup, retention, disposition, and acceptance remain external
authority decisions.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterator
from typing import Any

from assurance_archive import ArchiveError, verify_archive
from independent_archive_verify import (
    IndependentVerificationError,
    verify_package,
)


NON_CLAIMS = [
    "The filesystem transport is configured for an internal technical trial and is not an approved controlled external archive.",
    "No transport result establishes archive ownership, access approval, backup adequacy, retention authority, disposition authority, certification credit, release approval, or authority acceptance.",
]
ENDPOINT_SCHEMA_REQUIRED = [
    "record_type", "schema_version", "endpoint_id", "status", "provider_kind",
    "destination_root", "archive_owner", "access_control_approval", "backup_policy",
    "retention_period", "retention_authority", "disposition_authority", "non_claims",
]


class ArchiveTransportError(Exception):
    """A package transport operation could not be completed safely."""


def fail(message: str) -> None:
    raise ArchiveTransportError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    created = False
    try:
        with path.open("xb") as output:
            created = True
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        fail(f"refusing to overwrite existing result: {path}")
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise


def validate_endpoint(endpoint: dict[str, Any]) -> Path:
    fields = {
        "record_type", "schema_version", "endpoint_id", "status", "provider_kind",
        "destination_root", "archive_owner", "access_control_approval", "backup_policy",
        "retention_period", "retention_authority", "disposition_authority", "non_claims",
    }
    if set(endpoint) != fields:
        fail("archive endpoint fields do not match the technical-trial contract")
    if (
        endpoint["record_type"] != "assurance_archive_filesystem_endpoint"
        or endpoint["schema_version"] != 1
        or endpoint["status"] != "technical_trial_only"
        or endpoint["provider_kind"] != "filesystem_directory_v1"
        or not isinstance(endpoint["endpoint_id"], str)
        or not endpoint["endpoint_id"].strip()
        or any(
            endpoint[field] is not None
            for field in (
                "archive_owner", "access_control_approval", "backup_policy",
                "retention_period", "retention_authority", "disposition_authority",
            )
        )
        or endpoint["non_claims"] != NON_CLAIMS
    ):
        fail("archive endpoint overstates its technical-trial authority")
    root_value = endpoint["destination_root"]
    if not isinstance(root_value, str) or not root_value.strip():
        fail("archive endpoint destination_root must be non-empty")
    root = Path(root_value)
    if not root.is_absolute():
        fail("archive endpoint destination_root must be absolute")
    if root.is_symlink() or not root.is_dir():
        fail("archive endpoint destination_root is missing or unsafe")
    return root.resolve()


def validate_endpoint_schema(schema: dict[str, Any]) -> None:
    if (
        schema.get("record_type") != "assurance_archive_filesystem_endpoint_schema"
        or schema.get("schema_version") != 1
        or schema.get("required") != ENDPOINT_SCHEMA_REQUIRED
        or schema.get("enums")
        != {
            "status": ["technical_trial_only"],
            "provider_kind": ["filesystem_directory_v1"],
        }
        or schema.get("authority_rule")
        != "This adapter cannot designate or approve an external archive. Authority-owned fields remain null for technical trials; a controlled provider and archive-authority record are required before external archival acceptance."
    ):
        fail("external archive endpoint schema is invalid")


def ensure_disjoint(first: Path, second: Path, label: str) -> None:
    first = first.resolve()
    second = second.resolve()
    if first == second or first in second.parents or second in first.parents:
        fail(f"{label} paths must not overlap")


def external_result_path(value: Path | None, *protected: Path) -> Path | None:
    if value is None:
        return None
    result = value.resolve()
    if result.exists():
        fail(f"refusing to overwrite existing result: {result}")
    for boundary in protected:
        ensure_disjoint(result, boundary, "result and protected data")
    return result


def endpoint_directory(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir(exist_ok=True)
    if path.is_symlink() or not path.is_dir() or path.resolve().parent != root:
        fail(f"archive endpoint {name} directory is unsafe")
    return path


@contextmanager
def publication_lock(receipts: Path, package_id: str) -> Iterator[None]:
    lock = receipts / f".{package_id}.publish.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        fail(f"package publication is already in progress: {package_id}")
    try:
        os.close(descriptor)
        yield
    finally:
        lock.unlink(missing_ok=True)


def verify_both(package_dir: Path, expected_commit: str) -> tuple[dict[str, Any], dict[str, Any]]:
    primary = verify_archive(
        package_dir=package_dir,
        expected_commit=expected_commit,
    )
    independent = verify_package(
        package_dir=package_dir,
        expected_commit=expected_commit,
    )
    fields = ("package_id", "commit", "tree", "workflow_run_id", "manifest_sha256", "file_count", "total_bytes")
    if any(primary[field] != independent[field] for field in fields):
        fail("primary and independent package verification results disagree")
    return primary, independent


def receipt(
    *, operation: str, endpoint: dict[str, Any], primary: dict[str, Any],
    independent: dict[str, Any], location: Path,
) -> dict[str, Any]:
    return {
        "record_type": "assurance_archive_transport_result",
        "schema_version": 1,
        "status": "pass_technical_trial",
        "operation": operation,
        "endpoint_id": endpoint["endpoint_id"],
        "provider_kind": endpoint["provider_kind"],
        "package_id": primary["package_id"],
        "commit": primary["commit"],
        "tree": primary["tree"],
        "workflow_run_id": primary["workflow_run_id"],
        "manifest_sha256": primary["manifest_sha256"],
        "file_count": primary["file_count"],
        "total_bytes": primary["total_bytes"],
        "independent_digest_utility": independent["digest_utility"],
        "location": str(location),
        "completed_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "external_archive_verified": False,
        "non_claims": NON_CLAIMS,
    }


def publish(
    *, package_dir: Path, endpoint_path: Path, expected_commit: str,
    result_path: Path | None = None,
) -> dict[str, Any]:
    endpoint = load_json(endpoint_path.resolve())
    root = validate_endpoint(endpoint)
    package_dir = package_dir.resolve()
    ensure_disjoint(package_dir, root, "source package and endpoint")
    result_path = external_result_path(result_path, package_dir, root)
    primary, independent = verify_both(package_dir, expected_commit)
    packages = endpoint_directory(root, "packages")
    receipts = endpoint_directory(root, "receipts")
    destination = packages / primary["package_id"]
    endpoint_receipt = receipts / f"{primary['package_id']}.json"
    with publication_lock(receipts, primary["package_id"]):
        if destination.exists() or endpoint_receipt.exists():
            fail("refusing to overwrite an existing package or publication receipt")
        stage = packages / f".staging-{primary['package_id']}-{uuid.uuid4().hex}"
        published = False
        try:
            shutil.copytree(package_dir, stage, symlinks=False)
            copied_primary, copied_independent = verify_both(stage, expected_commit)
            os.replace(stage, destination)
            published = True
            result = receipt(
                operation="publish",
                endpoint=endpoint,
                primary=copied_primary,
                independent=copied_independent,
                location=destination,
            )
            write_json_exclusive(endpoint_receipt, result)
            if result_path is not None:
                write_json_exclusive(result_path, result)
            return result
        except BaseException:
            if published and not endpoint_receipt.exists() and destination.is_dir():
                shutil.rmtree(destination)
            raise
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def retrieve(
    *, package_id: str, output_dir: Path, endpoint_path: Path,
    expected_commit: str, result_path: Path | None = None,
) -> dict[str, Any]:
    endpoint = load_json(endpoint_path.resolve())
    root = validate_endpoint(endpoint)
    if not package_id or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in package_id):
        fail("package_id contains unsafe characters")
    packages = endpoint_directory(root, "packages")
    source_entry = packages / package_id
    if source_entry.is_symlink():
        fail("requested package is missing or unsafe")
    source = source_entry.resolve()
    try:
        source.relative_to(packages)
    except ValueError:
        fail("package_id escapes the endpoint")
    if source.name != package_id or source.is_symlink() or not source.is_dir():
        fail("requested package is missing or unsafe")
    output_dir = output_dir.resolve()
    ensure_disjoint(source, output_dir, "archived package and retrieval output")
    ensure_disjoint(root, output_dir, "endpoint and retrieval output")
    result_path = external_result_path(result_path, root, output_dir)
    if output_dir.exists():
        fail("refusing to overwrite an existing retrieval output")
    primary, independent = verify_both(source, expected_commit)
    if primary["package_id"] != package_id:
        fail("requested package ID does not match its manifest")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = output_dir.parent / f".retrieving-{package_id}-{uuid.uuid4().hex}"
    if stage.exists():
        fail("retrieval staging path unexpectedly exists")
    try:
        shutil.copytree(source, stage, symlinks=False)
        copied_primary, copied_independent = verify_both(stage, expected_commit)
        os.replace(stage, output_dir)
        result = receipt(
            operation="retrieve",
            endpoint=endpoint,
            primary=copied_primary,
            independent=copied_independent,
            location=output_dir,
        )
        if result_path is not None:
            write_json_exclusive(result_path, result)
        return result
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--package-dir", type=Path, required=True)
    publish_parser.add_argument("--endpoint", type=Path, required=True)
    publish_parser.add_argument("--expected-commit", required=True)
    publish_parser.add_argument("--result", type=Path)
    retrieve_parser = subparsers.add_parser("retrieve")
    retrieve_parser.add_argument("--package-id", required=True)
    retrieve_parser.add_argument("--output-dir", type=Path, required=True)
    retrieve_parser.add_argument("--endpoint", type=Path, required=True)
    retrieve_parser.add_argument("--expected-commit", required=True)
    retrieve_parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "publish":
            result = publish(
                package_dir=args.package_dir,
                endpoint_path=args.endpoint,
                expected_commit=args.expected_commit,
                result_path=args.result,
            )
        else:
            result = retrieve(
                package_id=args.package_id,
                output_dir=args.output_dir,
                endpoint_path=args.endpoint,
                expected_commit=args.expected_commit,
                result_path=args.result,
            )
    except (
        ArchiveTransportError,
        ArchiveError,
        IndependentVerificationError,
        OSError,
    ) as error:
        print(f"archive transport failed: {error}", file=sys.stderr)
        return 1
    print(
        f"{result['operation']} {result['package_id']} passed technical-trial "
        f"verification at {result['location']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
