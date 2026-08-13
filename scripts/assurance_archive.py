#!/usr/bin/env python3
"""Create and verify immutable internal assurance-evidence staging packages.

The package format is intentionally limited to internal staging.  It provides
byte-level integrity, exact Git provenance, and a repeatable retrieval check;
it does not turn GitHub Actions artifacts into a controlled external archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "assurance-archive-manifest.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ArchiveError(Exception):
    """An assurance package could not be created or verified."""


def fail(message: str) -> None:
    raise ArchiveError(message)


def filesystem_path(path: Path) -> Path:
    """Return a Windows extended-length spelling without changing logical paths."""
    if os.name != "nt":
        return path
    value = os.path.abspath(os.fspath(path))
    if value.startswith("\\\\?\\"):
        return Path(value)
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + value[2:])
    return Path("\\\\?\\" + value)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with filesystem_path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(filesystem_path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    filesystem_path(path.parent).mkdir(parents=True, exist_ok=True)
    filesystem_path(path).write_bytes(canonical_json_bytes(value))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def validate_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str):
        fail(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label} must include a timezone offset")


def safe_relative_path(value: Any, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "//" in value
    ):
        fail(f"{label} must be a canonical non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} must not be absolute or contain traversal components")
    if path.as_posix() != value:
        fail(f"{label} must use canonical POSIX spelling")
    return path


def required_artifacts(control_record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if (
        control_record.get("record_type") != "assurance_archive_control"
        or control_record.get("schema_version") != 1
    ):
        fail("archive control record has the wrong identity")
    staging = control_record.get("internal_staging")
    if not isinstance(staging, dict):
        fail("archive control record is missing internal_staging")
    required = staging.get("required_artifacts")
    if not isinstance(required, dict) or not required:
        fail("archive control record must define required artifacts")
    normalized: dict[str, dict[str, Any]] = {}
    for name, spec in required.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
            or name in normalized
        ):
            fail(f"invalid required artifact name: {name!r}")
        if not isinstance(spec, dict) or set(spec) != {
            "manifest",
            "kind",
            "profile",
            "target",
        }:
            fail(f"required artifact {name} has an invalid specification")
        manifest_path = safe_relative_path(
            spec["manifest"], f"required artifact {name} manifest"
        ).as_posix()
        kind = spec["kind"]
        profile = spec["profile"]
        target = spec["target"]
        if kind == "coverage":
            if profile not in {"stable", "branch", "condition"}:
                fail(f"required artifact {name} has an invalid coverage profile")
        elif kind == "windows_native_fault":
            if profile is not None:
                fail(f"required artifact {name} must not define a coverage profile")
        else:
            fail(f"required artifact {name} has an invalid kind")
        if not isinstance(target, str) or not target:
            fail(f"required artifact {name} has an invalid target")
        normalized[name] = {
            "manifest": manifest_path,
            "kind": kind,
            "profile": profile,
            "target": target,
        }
    return normalized


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def validate_source_manifest(
    path: Path,
    spec: dict[str, Any],
    *,
    repository: str,
    branch: str,
    commit: str,
    tree: str,
) -> dict[str, Any]:
    manifest = read_json(path)
    for field, expected in (
        ("repository", repository),
        ("branch", branch),
        ("commit", commit),
        ("tree", tree),
        ("target", spec["target"]),
        ("dirty", False),
        ("status", "pass"),
    ):
        if manifest.get(field) != expected:
            fail(f"{path} has unexpected {field}: {manifest.get(field)!r}")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        fail(f"{path} has an invalid run ID")
    if spec["kind"] == "coverage":
        if manifest.get("profile") != spec["profile"]:
            fail(f"{path} has the wrong coverage profile")
    elif (
        manifest.get("record_type") != "windows_native_fault_run"
        or manifest.get("schema_version") != 1
    ):
        fail(f"{path} has the wrong Windows native-fault identity")
    return manifest


def regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            directory = current_path / name
            native_directory = filesystem_path(directory)
            if native_directory.is_symlink():
                fail(f"input contains a symbolic-link directory: {directory}")
        for name in names:
            path = current_path / name
            native_path = filesystem_path(path)
            if native_path.is_symlink() or not native_path.is_file():
                fail(f"input contains a non-regular file: {path}")
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def ensure_disjoint(input_root: Path, output_dir: Path) -> None:
    input_root = input_root.resolve()
    output_dir = output_dir.resolve()
    if (
        input_root == output_dir
        or input_root in output_dir.parents
        or output_dir in input_root.parents
    ):
        fail("input and output directories must not overlap")


def create_archive(
    *,
    input_root: Path,
    output_dir: Path,
    control_record_path: Path,
    repository: str,
    branch: str,
    commit: str,
    tree: str,
    workflow_run_id: str,
    created_utc: str | None = None,
) -> Path:
    input_root = input_root.resolve()
    output_dir = output_dir.resolve()
    control_record_path = control_record_path.resolve()
    ensure_disjoint(input_root, output_dir)
    if not input_root.is_dir():
        fail(f"input root does not exist: {input_root}")
    if output_dir.exists() and any(output_dir.iterdir()):
        fail(f"output directory is not empty: {output_dir}")
    if repository != "arthurianresolve/fs2-rs" or branch != "DO-178C":
        fail("package repository or branch is outside the registered scope")
    if not COMMIT_RE.fullmatch(commit) or not COMMIT_RE.fullmatch(tree):
        fail("package commit and tree must be full lowercase Git object IDs")
    if not isinstance(workflow_run_id, str) or not workflow_run_id.isdigit():
        fail("workflow run ID must contain decimal digits")
    created_utc = created_utc or utc_now()
    validate_timestamp(created_utc, "created_utc")

    control = read_json(control_record_path)
    expected = required_artifacts(control)
    entries = sorted(input_root.iterdir(), key=lambda path: path.name)
    if any(not entry.is_dir() or entry.is_symlink() for entry in entries):
        fail("input root must contain only regular artifact directories")
    observed_names = {entry.name for entry in entries}
    if observed_names != set(expected):
        missing = sorted(set(expected) - observed_names)
        extra = sorted(observed_names - set(expected))
        fail(f"artifact inventory mismatch; missing={missing}, extra={extra}")

    source_files: list[tuple[str, Path]] = []
    source_manifest_records: list[dict[str, Any]] = []
    casefold_paths: set[str] = set()
    for artifact_name in sorted(expected):
        artifact_root = input_root / artifact_name
        spec = expected[artifact_name]
        expected_manifest = artifact_root / Path(spec["manifest"])
        native_manifest = filesystem_path(expected_manifest)
        if not native_manifest.is_file() or native_manifest.is_symlink():
            fail(
                f"artifact {artifact_name} is missing registered manifest "
                f"{spec['manifest']}"
            )
        source_manifest = validate_source_manifest(
            expected_manifest,
            spec,
            repository=repository,
            branch=branch,
            commit=commit,
            tree=tree,
        )
        source_manifest_records.append(
            {
                "name": artifact_name,
                "kind": spec["kind"],
                "profile": spec["profile"],
                "target": spec["target"],
                "manifest": spec["manifest"],
                "manifest_sha256": sha256(expected_manifest),
                "run_id": source_manifest["run_id"],
            }
        )
        files = regular_files(artifact_root)
        if not files:
            fail(f"artifact {artifact_name} is empty")
        for source in files:
            relative = PurePosixPath(artifact_name) / PurePosixPath(
                source.relative_to(artifact_root).as_posix()
            )
            spelling = relative.as_posix()
            folded = spelling.casefold()
            if folded in casefold_paths:
                fail(f"artifact files collide by case: {spelling}")
            casefold_paths.add(folded)
            source_files.append((spelling, source))

    evidence_root = output_dir / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    packaged_control_path = output_dir / "control" / "archive-control.json"
    write_json(packaged_control_path, control)
    file_records: list[dict[str, Any]] = []
    for relative, source in sorted(source_files):
        destination = evidence_root / Path(PurePosixPath(relative))
        filesystem_path(destination.parent).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(filesystem_path(source), filesystem_path(destination))
        source_digest = sha256(source)
        if sha256(destination) != source_digest:
            fail(f"copied artifact failed digest verification: {relative}")
        file_records.append(
            {
                "path": relative,
                "sha256": source_digest,
                "bytes": filesystem_path(destination).stat().st_size,
            }
        )

    package_id = f"ASSURANCE-{commit[:12]}-{workflow_run_id}"
    manifest = {
        "record_type": "assurance_archive_manifest",
        "schema_version": 1,
        "package_id": package_id,
        "status": "internal_staging",
        "repository": repository,
        "branch": branch,
        "commit": commit,
        "tree": tree,
        "dirty": False,
        "source_workflow": {
            "provider": "github_actions",
            "run_id": workflow_run_id,
        },
        "control_record": {
            "source_path": "coverage/archive-control.json",
            "packaged_path": "control/archive-control.json",
            "digest_contract": "canonical_json_v1",
            "sha256": canonical_json_sha256(control),
        },
        "source_artifacts": sorted(expected),
        "source_artifact_manifests": source_manifest_records,
        "files": file_records,
        "created_utc": created_utc,
        "non_claims": [
            "This package is immutable internal staging, not a controlled external archive.",
            "Integrity verification is not certification, tool qualification, release approval, or authority acceptance.",
        ],
    }
    manifest_path = output_dir / MANIFEST_NAME
    write_json(manifest_path, manifest)
    return manifest_path


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    fields = {
        "record_type",
        "schema_version",
        "package_id",
        "status",
        "repository",
        "branch",
        "commit",
        "tree",
        "dirty",
        "source_workflow",
        "control_record",
        "source_artifacts",
        "source_artifact_manifests",
        "files",
        "created_utc",
        "non_claims",
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
    ):
        fail("archive manifest identity or assurance state is invalid")
    if not COMMIT_RE.fullmatch(str(manifest["commit"])) or not COMMIT_RE.fullmatch(
        str(manifest["tree"])
    ):
        fail("archive manifest has invalid Git provenance")
    workflow = manifest["source_workflow"]
    if (
        not isinstance(workflow, dict)
        or set(workflow) != {"provider", "run_id"}
        or workflow["provider"] != "github_actions"
        or not isinstance(workflow["run_id"], str)
        or not workflow["run_id"].isdigit()
    ):
        fail("archive manifest has invalid workflow provenance")
    expected_id = f"ASSURANCE-{manifest['commit'][:12]}-{workflow['run_id']}"
    if manifest["package_id"] != expected_id:
        fail("archive manifest package ID does not match its provenance")
    control = manifest["control_record"]
    if (
        not isinstance(control, dict)
        or set(control)
        != {"source_path", "packaged_path", "digest_contract", "sha256"}
        or control["source_path"] != "coverage/archive-control.json"
        or control["packaged_path"] != "control/archive-control.json"
        or control["digest_contract"] != "canonical_json_v1"
        or not SHA256_RE.fullmatch(str(control["sha256"]))
    ):
        fail("archive manifest has invalid control-record provenance")
    validate_timestamp(manifest["created_utc"], "archive manifest created_utc")
    non_claims = manifest["non_claims"]
    if (
        not isinstance(non_claims, list)
        or len(non_claims) < 2
        or not all(isinstance(item, str) and item.strip() for item in non_claims)
        or not any("not a controlled external archive" in item for item in non_claims)
    ):
        fail("archive manifest non-claims are incomplete")


def verify_archive(
    *,
    package_dir: Path,
    expected_commit: str | None = None,
    control_record_path: Path | None = None,
    result_path: Path | None = None,
    verified_utc: str | None = None,
) -> dict[str, Any]:
    if package_dir.is_symlink():
        fail("archive package directory is missing or unsafe")
    package_dir = package_dir.resolve()
    if not package_dir.is_dir():
        fail("archive package directory is missing or unsafe")
    root_entries = {path.name for path in package_dir.iterdir()}
    if root_entries != {MANIFEST_NAME, "control", "evidence"}:
        fail(f"archive package root inventory is invalid: {sorted(root_entries)}")
    manifest_path = package_dir / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("archive manifest is missing or unsafe")
    manifest = read_json(manifest_path)
    validate_manifest_shape(manifest)
    if expected_commit is not None:
        if not COMMIT_RE.fullmatch(expected_commit):
            fail("expected commit must be a full lowercase Git object ID")
        if manifest["commit"] != expected_commit:
            fail("archive manifest commit does not match the expected commit")

    source_artifacts = manifest["source_artifacts"]
    if (
        not isinstance(source_artifacts, list)
        or not source_artifacts
        or source_artifacts != sorted(source_artifacts)
        or len(source_artifacts) != len(set(source_artifacts))
        or not all(
            isinstance(name, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
            for name in source_artifacts
        )
    ):
        fail("archive manifest source_artifacts is invalid")

    source_manifests = manifest["source_artifact_manifests"]
    if not isinstance(source_manifests, list) or len(source_manifests) != len(
        source_artifacts
    ):
        fail("archive manifest source_artifact_manifests is incomplete")
    source_specs: dict[str, dict[str, Any]] = {}
    source_run_ids: set[str] = set()
    for index, record in enumerate(source_manifests):
        label = f"archive manifest source_artifact_manifests[{index}]"
        if not isinstance(record, dict) or set(record) != {
            "name",
            "kind",
            "profile",
            "target",
            "manifest",
            "manifest_sha256",
            "run_id",
        }:
            fail(f"{label} has invalid fields")
        name = record["name"]
        if name not in source_artifacts or name in source_specs:
            fail(f"{label}.name is unknown or duplicated")
        if record["kind"] == "coverage":
            if record["profile"] not in {"stable", "branch", "condition"}:
                fail(f"{label}.profile is invalid")
        elif record["kind"] == "windows_native_fault":
            if record["profile"] is not None:
                fail(f"{label}.profile must be null")
        else:
            fail(f"{label}.kind is invalid")
        if not isinstance(record["target"], str) or not record["target"]:
            fail(f"{label}.target is invalid")
        safe_relative_path(record["manifest"], f"{label}.manifest")
        if not SHA256_RE.fullmatch(str(record["manifest_sha256"])):
            fail(f"{label}.manifest_sha256 is invalid")
        if (
            not isinstance(record["run_id"], str)
            or not record["run_id"]
            or record["run_id"] in source_run_ids
        ):
            fail(f"{label}.run_id is invalid or duplicated")
        source_run_ids.add(record["run_id"])
        source_specs[name] = {
            "manifest": record["manifest"],
            "kind": record["kind"],
            "profile": record["profile"],
            "target": record["target"],
        }
    if list(source_specs) != source_artifacts:
        fail("archive source manifest inventory is not canonically sorted")

    packaged_control_relative = safe_relative_path(
        manifest["control_record"]["packaged_path"],
        "archive manifest control_record.packaged_path",
    )
    control_root = package_dir / "control"
    if control_root.is_symlink() or not control_root.is_dir():
        fail("archive control directory is missing or unsafe")
    if {path.name for path in control_root.iterdir()} != {"archive-control.json"}:
        fail("archive control directory inventory is invalid")
    packaged_control_path = package_dir.joinpath(*packaged_control_relative.parts)
    if (
        filesystem_path(packaged_control_path).is_symlink()
        or not filesystem_path(packaged_control_path).is_file()
    ):
        fail("archive packaged control record is missing or unsafe")
    packaged_control = read_json(packaged_control_path)
    if (
        canonical_json_sha256(packaged_control)
        != manifest["control_record"]["sha256"]
    ):
        fail("archive packaged control-record digest is stale")
    expected = required_artifacts(packaged_control)
    if source_artifacts != sorted(expected) or source_specs != expected:
        fail("archive source-artifact inventory differs from the packaged control record")
    if control_record_path is not None:
        current_control = read_json(control_record_path.resolve())
        if (
            canonical_json_sha256(current_control)
            != manifest["control_record"]["sha256"]
            or current_control != packaged_control
        ):
            fail("provided control record differs from the packaged control record")

    records = manifest["files"]
    if not isinstance(records, list) or not records:
        fail("archive manifest files must be non-empty")
    recorded_paths: list[str] = []
    seen_casefold: set[str] = set()
    total_bytes = 0
    evidence_root = package_dir / "evidence"
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        fail("archive evidence directory is missing or unsafe")
    for index, record in enumerate(records):
        label = f"archive manifest files[{index}]"
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            fail(f"{label} has invalid fields")
        relative = safe_relative_path(record["path"], f"{label}.path")
        spelling = relative.as_posix()
        if spelling.casefold() in seen_casefold:
            fail(f"{label}.path is duplicated or collides by case")
        seen_casefold.add(spelling.casefold())
        if relative.parts[0] not in source_artifacts:
            fail(f"{label}.path references an unregistered source artifact")
        if not SHA256_RE.fullmatch(str(record["sha256"])):
            fail(f"{label}.sha256 is invalid")
        if (
            not isinstance(record["bytes"], int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] < 0
        ):
            fail(f"{label}.bytes is invalid")
        artifact_path = evidence_root.joinpath(*relative.parts)
        native_artifact_path = filesystem_path(artifact_path)
        if native_artifact_path.is_symlink() or not native_artifact_path.is_file():
            fail(f"archive file is missing or unsafe: {spelling}")
        if native_artifact_path.stat().st_size != record["bytes"]:
            fail(f"archive file size changed: {spelling}")
        if sha256(artifact_path) != record["sha256"]:
            fail(f"archive file digest changed: {spelling}")
        recorded_paths.append(spelling)
        total_bytes += record["bytes"]
    if recorded_paths != sorted(recorded_paths):
        fail("archive manifest file inventory is not canonically sorted")

    actual_paths = [
        path.relative_to(evidence_root).as_posix()
        for path in regular_files(evidence_root)
    ]
    if actual_paths != recorded_paths:
        missing = sorted(set(recorded_paths) - set(actual_paths))
        extra = sorted(set(actual_paths) - set(recorded_paths))
        fail(f"archive file inventory mismatch; missing={missing}, extra={extra}")

    source_manifest_by_name = {
        record["name"]: record for record in source_manifests
    }
    for name in source_artifacts:
        record = source_manifest_by_name[name]
        manifest_relative = PurePosixPath(name) / PurePosixPath(record["manifest"])
        source_manifest_path = evidence_root.joinpath(*manifest_relative.parts)
        if sha256(source_manifest_path) != record["manifest_sha256"]:
            fail(f"source artifact manifest digest changed: {name}")
        source_manifest = validate_source_manifest(
            source_manifest_path,
            source_specs[name],
            repository=manifest["repository"],
            branch=manifest["branch"],
            commit=manifest["commit"],
            tree=manifest["tree"],
        )
        if source_manifest["run_id"] != record["run_id"]:
            fail(f"source artifact run ID changed: {name}")

    verified_utc = verified_utc or utc_now()
    validate_timestamp(verified_utc, "verified_utc")
    result = {
        "record_type": "assurance_archive_retrieval_result",
        "schema_version": 1,
        "status": "pass",
        "scope": "internal_github_actions_staging",
        "package_id": manifest["package_id"],
        "commit": manifest["commit"],
        "tree": manifest["tree"],
        "workflow_run_id": manifest["source_workflow"]["run_id"],
        "manifest_sha256": sha256(manifest_path),
        "file_count": len(records),
        "total_bytes": total_bytes,
        "discrepancies": [],
        "verified_utc": verified_utc,
        "external_archive_verified": False,
        "non_claims": [
            "This result verifies an internal staging package, not retrieval from a controlled external archive.",
            "A pass does not establish retention, backup, disposition authority, certification credit, or authority acceptance.",
        ],
    }
    if result_path is not None:
        write_json(result_path.resolve(), result)
    return result


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def create_from_cli(args: argparse.Namespace) -> None:
    commit = git("rev-parse", "HEAD")
    if commit != args.expected_commit:
        fail(f"HEAD {commit} does not match expected commit {args.expected_commit}")
    if git("status", "--porcelain", "--untracked-files=no"):
        fail("tracked working tree is dirty")
    tree = git("rev-parse", "HEAD^{tree}")
    manifest_path = create_archive(
        input_root=args.input_root,
        output_dir=args.output_dir,
        control_record_path=args.control_record,
        repository=args.repository,
        branch=args.branch,
        commit=commit,
        tree=tree,
        workflow_run_id=args.workflow_run_id,
    )
    print(f"created {manifest_path} ({sha256(manifest_path)})")


def verify_from_cli(args: argparse.Namespace) -> None:
    result = verify_archive(
        package_dir=args.package_dir,
        expected_commit=args.expected_commit,
        control_record_path=args.control_record,
        result_path=args.result,
    )
    print(
        f"verified {result['file_count']} files for {result['package_id']} "
        f"({result['manifest_sha256']})"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--input-root", type=Path, required=True)
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--control-record", type=Path, required=True)
    create.add_argument("--repository", default="arthurianresolve/fs2-rs")
    create.add_argument("--branch", default="DO-178C")
    create.add_argument("--expected-commit", required=True)
    create.add_argument("--workflow-run-id", required=True)
    create.set_defaults(action=create_from_cli)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--package-dir", type=Path, required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--control-record", type=Path)
    verify.add_argument("--result", type=Path)
    verify.set_defaults(action=verify_from_cli)

    args = parser.parse_args()
    if not COMMIT_RE.fullmatch(args.expected_commit):
        parser.error("--expected-commit must be a full lowercase Git object ID")
    try:
        args.action(args)
    except (ArchiveError, OSError) as error:
        print(f"assurance archive operation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
