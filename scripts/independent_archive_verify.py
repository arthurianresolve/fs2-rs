#!/usr/bin/env python3
"""Independently verify an internal assurance package with a native digest tool.

This implementation intentionally does not import the package producer or its
verification code.  It reduces one common-mode dependency; it does not provide
organizational independence, tool qualification, or external-archive approval.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


MANIFEST_NAME = "assurance-archive-manifest.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
NON_CLAIMS = [
    "This independent implementation verifies byte integrity in internal staging; it is not an approved controlled external archive.",
    "Using a separate verifier and native digest utility does not establish organizational independence or tool qualification.",
    "A pass does not establish certification credit, release approval, retention authority, disposition authority, or authority acceptance.",
]


class IndependentVerificationError(Exception):
    """The independent archive check failed closed."""


def fail(message: str) -> None:
    raise IndependentVerificationError(message)


def filesystem_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    value = os.path.abspath(os.fspath(path))
    if value.startswith("\\\\?\\"):
        return Path(value)
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + value[2:])
    return Path("\\\\?\\" + value)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(filesystem_path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def safe_relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "//" in value:
        fail(f"{label} must be a canonical POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        fail(f"{label} must not be absolute or contain traversal components")
    return path


class NativeDigest:
    def __init__(self) -> None:
        self.name, self.executable, self.prefix, self.parser = self._select()
        self.version = self._version()

    @staticmethod
    def _select() -> tuple[str, str, list[str], str]:
        if os.name == "nt" and shutil.which("certutil"):
            return "certutil", shutil.which("certutil") or "certutil", [], "certutil"
        if shutil.which("sha256sum"):
            return "sha256sum", shutil.which("sha256sum") or "sha256sum", [], "first"
        if shutil.which("shasum"):
            return "shasum", shutil.which("shasum") or "shasum", ["-a", "256"], "first"
        if shutil.which("openssl"):
            return "openssl", shutil.which("openssl") or "openssl", ["dgst", "-sha256"], "last"
        fail("no supported native SHA-256 utility is available")

    def _version(self) -> str:
        commands = {
            "certutil": [self.executable, "-?"],
            "sha256sum": [self.executable, "--version"],
            "shasum": [self.executable, "--version"],
            "openssl": [self.executable, "version"],
        }
        result = subprocess.run(
            commands[self.name], capture_output=True, text=True, check=False
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output.splitlines()[0] if output else f"{self.name} version unavailable"

    def digest(self, path: Path) -> str:
        native = str(filesystem_path(path))
        command = (
            [self.executable, "-hashfile", native, "SHA256"]
            if self.name == "certutil"
            else [self.executable, *self.prefix, native]
        )
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            fail(f"{self.name} failed for {path}: {detail}")
        output = result.stdout
        if self.parser == "certutil":
            candidates = [
                re.sub(r"\s+", "", line).lower()
                for line in output.splitlines()
                if SHA256_RE.fullmatch(re.sub(r"\s+", "", line).lower())
            ]
            if len(candidates) != 1:
                fail(f"certutil returned an ambiguous digest for {path}")
            return candidates[0]
        tokens = output.strip().split()
        candidate = tokens[0] if self.parser == "first" and tokens else tokens[-1] if tokens else ""
        candidate = candidate.lower()
        if not SHA256_RE.fullmatch(candidate):
            fail(f"{self.name} returned an invalid digest for {path}")
        return candidate

    def canonical_json_digest(self, value: Any) -> str:
        encoded = (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temporary:
                temporary.write(encoded)
                temporary_path = Path(temporary.name)
            return self.digest(temporary_path)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            if filesystem_path(path).is_symlink():
                fail(f"package contains a symbolic-link directory: {path}")
        for name in names:
            path = current_path / name
            native = filesystem_path(path)
            if native.is_symlink() or not native.is_file():
                fail(f"package contains a non-regular file: {path}")
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def directory_inventory(root: Path) -> list[str]:
    observed: list[str] = []
    for current, directories, _ in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            native = filesystem_path(path)
            if native.is_symlink() or not native.is_dir():
                fail(f"package contains a non-regular directory: {path}")
            observed.append(path.relative_to(root).as_posix())
    return sorted(observed)


def registered_directories(paths: list[str]) -> list[str]:
    registered = {
        parent.as_posix()
        for value in paths
        for parent in PurePosixPath(value).parents
        if parent.as_posix() != "."
    }
    if len({value.casefold() for value in registered}) != len(registered):
        fail("archive directory inventory collides by case")
    return sorted(registered)


def required_artifacts(control: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if control.get("record_type") != "assurance_archive_control" or control.get("schema_version") != 1:
        fail("packaged archive control has the wrong identity")
    staging = control.get("internal_staging")
    required = staging.get("required_artifacts") if isinstance(staging, dict) else None
    if not isinstance(required, dict) or not required:
        fail("packaged archive control has no required-artifact inventory")
    normalized: dict[str, dict[str, Any]] = {}
    for name, spec in required.items():
        if not isinstance(name, str) or not ARTIFACT_NAME_RE.fullmatch(name) or name in normalized:
            fail(f"invalid required artifact name: {name!r}")
        if not isinstance(spec, dict) or set(spec) != {"manifest", "kind", "profile", "target"}:
            fail(f"required artifact {name} has an invalid specification")
        manifest_path = safe_relative_path(spec["manifest"], f"required artifact {name} manifest")
        kind = spec["kind"]
        profile = spec["profile"]
        if kind == "coverage":
            if profile not in {"stable", "branch", "condition"}:
                fail(f"required artifact {name} has an invalid coverage profile")
        elif kind in {"windows_native_fault", "object_analysis"}:
            if profile is not None:
                fail(f"required artifact {name} must have a null profile")
        else:
            fail(f"required artifact {name} has an invalid kind")
        if not isinstance(spec["target"], str) or not spec["target"]:
            fail(f"required artifact {name} has an invalid target")
        normalized[name] = {
            "manifest": manifest_path.as_posix(),
            "kind": kind,
            "profile": profile,
            "target": spec["target"],
        }
    return normalized


def validate_source_manifest(
    manifest: dict[str, Any], spec: dict[str, Any], package: dict[str, Any], label: str
) -> str:
    for field, expected in (
        ("repository", package["repository"]),
        ("branch", package["branch"]),
        ("commit", package["commit"]),
        ("tree", package["tree"]),
        ("target", spec["target"]),
        ("dirty", False),
        ("status", "pass"),
    ):
        if manifest.get(field) != expected:
            fail(f"{label} has unexpected {field}")
    if spec["kind"] == "coverage" and manifest.get("profile") != spec["profile"]:
        fail(f"{label} has the wrong coverage profile")
    if spec["kind"] == "windows_native_fault" and (
        manifest.get("record_type") != "windows_native_fault_run"
        or manifest.get("schema_version") != 1
    ):
        fail(f"{label} has the wrong native-fault identity")
    if spec["kind"] == "object_analysis" and (
        manifest.get("record_type") != "object_analysis_run"
        or manifest.get("schema_version") != 1
        or manifest.get("profile") != "release"
    ):
        fail(f"{label} has the wrong object-analysis identity")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        fail(f"{label} has an invalid run ID")
    return run_id


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    fields = {
        "record_type", "schema_version", "package_id", "status", "repository",
        "branch", "commit", "tree", "dirty", "source_workflow", "control_record",
        "source_artifacts", "source_artifact_manifests", "files", "created_utc", "non_claims",
    }
    if set(manifest) != fields:
        fail("archive manifest fields do not match the registered contract")
    if (
        manifest["record_type"] != "assurance_archive_manifest"
        or manifest["schema_version"] != 1
        or manifest["status"] != "internal_staging"
        or manifest["repository"] != "arthurianresolve/fs2-rs"
        or manifest["branch"] != "DO-178C"
        or manifest["dirty"] is not False
        or not COMMIT_RE.fullmatch(str(manifest["commit"]))
        or not COMMIT_RE.fullmatch(str(manifest["tree"]))
    ):
        fail("archive manifest identity or provenance is invalid")
    workflow = manifest["source_workflow"]
    if not isinstance(workflow, dict) or set(workflow) != {"provider", "run_id"} or workflow["provider"] != "github_actions" or not isinstance(workflow["run_id"], str) or not workflow["run_id"].isdigit():
        fail("archive manifest workflow provenance is invalid")
    if manifest["package_id"] != f"ASSURANCE-{manifest['commit'][:12]}-{workflow['run_id']}":
        fail("archive manifest package ID is inconsistent")


def verify_package(
    *, package_dir: Path, expected_commit: str | None = None,
    result_path: Path | None = None, verified_utc: str | None = None,
    digest: NativeDigest | None = None,
) -> dict[str, Any]:
    if package_dir.is_symlink():
        fail("archive package directory is missing or unsafe")
    package_dir = package_dir.resolve()
    if not package_dir.is_dir():
        fail("archive package directory is missing or unsafe")
    if {path.name for path in package_dir.iterdir()} != {MANIFEST_NAME, "control", "evidence"}:
        fail("archive package root inventory is invalid")
    digest = digest or NativeDigest()
    manifest_path = package_dir / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("archive manifest is missing or unsafe")
    manifest = load_json(manifest_path)
    validate_manifest_shape(manifest)
    if expected_commit is not None and (
        not COMMIT_RE.fullmatch(expected_commit) or manifest["commit"] != expected_commit
    ):
        fail("archive manifest does not match the expected commit")

    control_record = manifest["control_record"]
    if not isinstance(control_record, dict) or set(control_record) != {
        "source_path", "packaged_path", "digest_contract", "sha256"
    } or control_record["source_path"] != "coverage/archive-control.json" or control_record["packaged_path"] != "control/archive-control.json" or control_record["digest_contract"] != "canonical_json_v1" or not SHA256_RE.fullmatch(str(control_record["sha256"])):
        fail("archive manifest control-record binding is invalid")
    control_root = package_dir / "control"
    if control_root.is_symlink() or not control_root.is_dir() or {path.name for path in control_root.iterdir()} != {"archive-control.json"}:
        fail("archive control directory inventory is invalid")
    packaged_control_path = package_dir / "control" / "archive-control.json"
    if packaged_control_path.is_symlink() or not packaged_control_path.is_file():
        fail("packaged archive control is missing or unsafe")
    packaged_control = load_json(packaged_control_path)
    if digest.canonical_json_digest(packaged_control) != control_record["sha256"]:
        fail("packaged archive control digest is stale")
    expected = required_artifacts(packaged_control)

    source_artifacts = manifest["source_artifacts"]
    if not isinstance(source_artifacts, list) or source_artifacts != sorted(expected) or len(source_artifacts) != len(set(source_artifacts)):
        fail("archive source-artifact inventory differs from packaged control")
    source_records = manifest["source_artifact_manifests"]
    if not isinstance(source_records, list) or len(source_records) != len(expected):
        fail("archive source-manifest inventory is incomplete")
    source_by_name: dict[str, dict[str, Any]] = {}
    seen_run_ids: set[str] = set()
    for record in source_records:
        if not isinstance(record, dict) or set(record) != {
            "name", "kind", "profile", "target", "manifest", "manifest_sha256", "run_id"
        }:
            fail("archive source-manifest record has invalid fields")
        name = record["name"]
        spec = expected.get(name)
        if spec is None or name in source_by_name or {
            key: record[key] for key in ("manifest", "kind", "profile", "target")
        } != spec or not SHA256_RE.fullmatch(str(record["manifest_sha256"])) or not isinstance(record["run_id"], str) or not record["run_id"] or record["run_id"] in seen_run_ids:
            fail("archive source-manifest record is inconsistent")
        safe_relative_path(record["manifest"], f"source manifest {name}")
        source_by_name[name] = record
        seen_run_ids.add(record["run_id"])
    if list(source_by_name) != source_artifacts:
        fail("archive source-manifest order is not canonical")

    evidence_root = package_dir / "evidence"
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        fail("archive evidence directory is missing or unsafe")
    records = manifest["files"]
    if not isinstance(records, list) or not records:
        fail("archive file inventory is empty")
    recorded_paths: list[str] = []
    casefold_paths: set[str] = set()
    total_bytes = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            fail("archive file record has invalid fields")
        relative = safe_relative_path(record["path"], "archive file path")
        spelling = relative.as_posix()
        if spelling.casefold() in casefold_paths or relative.parts[0] not in expected:
            fail(f"archive file path is duplicated or unregistered: {spelling}")
        casefold_paths.add(spelling.casefold())
        if not SHA256_RE.fullmatch(str(record["sha256"])) or not isinstance(record["bytes"], int) or isinstance(record["bytes"], bool) or record["bytes"] < 0:
            fail(f"archive file metadata is invalid: {spelling}")
        path = evidence_root.joinpath(*relative.parts)
        native = filesystem_path(path)
        if native.is_symlink() or not native.is_file() or native.stat().st_size != record["bytes"]:
            fail(f"archive file is missing, unsafe, or resized: {spelling}")
        if digest.digest(path) != record["sha256"]:
            fail(f"archive file digest changed: {spelling}")
        recorded_paths.append(spelling)
        total_bytes += record["bytes"]
    if recorded_paths != sorted(recorded_paths):
        fail("archive file inventory order is not canonical")
    actual_paths = [
        path.relative_to(evidence_root).as_posix() for path in regular_files(evidence_root)
    ]
    if actual_paths != recorded_paths:
        fail("archive evidence inventory has missing or extra files")
    if directory_inventory(evidence_root) != registered_directories(recorded_paths):
        fail("archive evidence inventory has missing or extra directories")

    for name in source_artifacts:
        record = source_by_name[name]
        relative = PurePosixPath(name) / PurePosixPath(record["manifest"])
        path = evidence_root.joinpath(*relative.parts)
        if digest.digest(path) != record["manifest_sha256"]:
            fail(f"source manifest digest changed: {name}")
        run_id = validate_source_manifest(load_json(path), expected[name], manifest, name)
        if run_id != record["run_id"]:
            fail(f"source manifest run ID changed: {name}")

    verified_utc = verified_utc or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    result = {
        "record_type": "independent_assurance_archive_verification",
        "schema_version": 1,
        "status": "pass",
        "scope": "internal_staging_independent_integrity_check",
        "package_id": manifest["package_id"],
        "commit": manifest["commit"],
        "tree": manifest["tree"],
        "workflow_run_id": manifest["source_workflow"]["run_id"],
        "manifest_sha256": digest.digest(manifest_path),
        "file_count": len(records),
        "total_bytes": total_bytes,
        "digest_utility": {"name": digest.name, "version": digest.version},
        "discrepancies": [],
        "verified_utc": verified_utc,
        "external_archive_verified": False,
        "non_claims": NON_CLAIMS,
    }
    if result_path is not None:
        write_json(result_path.resolve(), result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        result = verify_package(
            package_dir=args.package_dir,
            expected_commit=args.expected_commit,
            result_path=args.result,
        )
    except (IndependentVerificationError, OSError) as error:
        print(f"independent archive verification failed: {error}", file=sys.stderr)
        return 1
    print(
        f"independently verified {result['file_count']} files for "
        f"{result['package_id']} with {result['digest_utility']['name']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
