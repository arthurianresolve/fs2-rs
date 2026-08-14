#!/usr/bin/env python3
"""Bind an implementation review to a reproducible pre-commit change set."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = PurePosixPath("coverage/independence-plan.json")
TOOL_ASSESSMENT_PATH = PurePosixPath("coverage/tool-assessment.json")
DIGEST_ALGORITHM = "sha256-canonical-review-scope-v1"
MECHANICAL_TOOL_REVIEWS = {
    "TOOL-F-001",
    "TOOL-F-003",
    "TOOL-F-004",
    "TOOL-F-005",
}


class ImplementationReviewDigestError(Exception):
    """The review scope cannot be represented or verified safely."""


def fail(message: str) -> None:
    raise ImplementationReviewDigestError(message)


def git(root: Path, *args: str, check: bool = True) -> bytes:
    process = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git {' '.join(args)} failed: {detail}")
    return process.stdout


def safe_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        fail("review scope contains a non-canonical path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        fail(f"review scope path is unsafe: {value!r}")
    return path


def split_nul(output: bytes) -> list[str]:
    if not output:
        return []
    if not output.endswith(b"\0"):
        fail("git returned a non-NUL-terminated path list")
    try:
        return [item.decode("utf-8") for item in output[:-1].split(b"\0")]
    except UnicodeDecodeError as error:
        fail(f"review scope contains a non-UTF-8 path: {error}")


def candidate_paths(root: Path, baseline: str) -> list[PurePosixPath]:
    changed = split_nul(
        git(root, "diff", "--no-renames", "--name-only", "-z", baseline, "--")
    )
    untracked = split_nul(
        git(root, "ls-files", "--others", "--exclude-standard", "-z")
    )
    paths = {safe_path(value) for value in changed + untracked}
    if not paths:
        fail("implementation review scope is empty")
    return sorted(paths, key=lambda item: item.as_posix())


def normalize_text(data: bytes) -> bytes:
    if b"\0" in data:
        return data
    return data.replace(b"\r\n", b"\n")


def normalize_plan(data: bytes) -> bytes:
    try:
        plan = json.loads(normalize_text(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"independence plan is not valid UTF-8 JSON: {error}")
    try:
        gate = plan["review_gate"]
        gate["status"] = "awaiting_implementation_review"
        gate["candidate_change_digest"] = None
        gate["decision"] = None
        gate["decision_ref"] = None
        gate["decided_at"] = None
    except (KeyError, TypeError) as error:
        fail(f"independence plan review gate is incomplete: {error}")
    return (
        json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def normalize_tool_assessment(data: bytes) -> bytes:
    try:
        assessment = json.loads(normalize_text(data).decode("utf-8"))
        functions = assessment["functions"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        fail(f"tool assessment is not valid reviewable JSON: {error}")
    observed: set[str] = set()
    for function in functions:
        identifier = function.get("id")
        if identifier not in MECHANICAL_TOOL_REVIEWS:
            continue
        review = function.get("review")
        if not isinstance(review, dict):
            fail(f"tool assessment {identifier} has no review marker")
        review["status"] = "pending_user_review"
        review["reviewer"] = None
        observed.add(identifier)
    if observed != MECHANICAL_TOOL_REVIEWS:
        fail("tool assessment omits a mechanical implementation-review marker")
    return (
        json.dumps(
            assessment, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def baseline_bytes(root: Path, baseline: str, path: PurePosixPath) -> bytes | None:
    process = subprocess.run(
        ["git", "show", f"{baseline}:{path.as_posix()}"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode == 0:
        return normalize_text(process.stdout)
    return None


def candidate_bytes(root: Path, path: PurePosixPath) -> bytes | None:
    absolute = root.joinpath(*path.parts)
    if not absolute.exists():
        return None
    if absolute.is_symlink() or not absolute.is_file():
        fail(f"review scope path is not a regular file: {path.as_posix()}")
    data = absolute.read_bytes()
    if path == PLAN_PATH:
        return normalize_plan(data)
    if path == TOOL_ASSESSMENT_PATH:
        return normalize_tool_assessment(data)
    return normalize_text(data)


def build_review_scope(root: Path, baseline: str) -> dict[str, Any]:
    root = root.resolve()
    resolved = git(root, "rev-parse", f"{baseline}^{{commit}}").decode("ascii").strip()
    if resolved != baseline:
        fail("review baseline must be a full canonical commit identifier")
    files: list[dict[str, Any]] = []
    for path in candidate_paths(root, baseline):
        before = baseline_bytes(root, baseline, path)
        after = candidate_bytes(root, path)
        if before == after:
            continue
        change = "added" if before is None else "deleted" if after is None else "modified"
        files.append(
            {
                "path": path.as_posix(),
                "change": change,
                "baseline_sha256": None if before is None else sha256(before),
                "candidate_sha256": None if after is None else sha256(after),
            }
        )
    if not files:
        fail("implementation review scope has no material file changes")
    return {
        "schema_version": 1,
        "digest_algorithm": DIGEST_ALGORITHM,
        "preparation_parent_commit": baseline,
        "files": files,
    }


def review_scope_digest(scope: dict[str, Any]) -> str:
    canonical = json.dumps(
        scope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(canonical)


def validate_review_scope_binding(plan: dict[str, Any], root: Path = ROOT) -> str:
    gate = plan.get("review_gate")
    if not isinstance(gate, dict):
        fail("independence plan has no review gate")
    if gate.get("digest_algorithm") != DIGEST_ALGORITHM:
        fail("independence plan review digest algorithm is invalid")
    baseline = gate.get("preparation_parent_commit")
    expected = gate.get("candidate_change_digest")
    if not isinstance(baseline, str) or not isinstance(expected, str):
        fail("independence plan has no bound review baseline or candidate digest")
    observed = review_scope_digest(build_review_scope(root, baseline))
    if observed != expected:
        fail(
            "implementation review candidate digest does not match the current change set "
            f"(expected {expected}, observed {observed})"
        )
    return observed


def main() -> int:
    plan = json.loads((ROOT / PLAN_PATH.as_posix()).read_text(encoding="utf-8"))
    baseline = plan["review_gate"]["preparation_parent_commit"]
    scope = build_review_scope(ROOT, baseline)
    result = {"candidate_change_digest": review_scope_digest(scope), **scope}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
