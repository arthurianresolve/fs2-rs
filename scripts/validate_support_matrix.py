#!/usr/bin/env python3
"""Validate the support registry and emit the CI matrices it owns."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "support-matrix.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
EVIDENCE_LEVELS = {"runtime", "compile", "not-covered"}
ALLOCATION_CAPABILITIES = {"physical-reservation", "unsupported", "unknown"}
MATRIX_EXPRESSION_PREFIX = "${{fromJSON(needs.support-matrix.outputs.matrices)."
MATRIX_EXPRESSION_SUFFIX = "}}"


def is_ci_job_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and bool(value)
        and value[0].isalnum()
        and all(character.isalnum() or character == "_" for character in value)
    )


def fail(message: str) -> None:
    raise SystemExit(f"support matrix is invalid: {message}")


def matrix_reference(value: object) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = "".join(value.split())
    if not normalized.startswith(MATRIX_EXPRESSION_PREFIX) or not normalized.endswith(
        MATRIX_EXPRESSION_SUFFIX
    ):
        return None

    referenced = normalized[
        len(MATRIX_EXPRESSION_PREFIX) : -len(MATRIX_EXPRESSION_SUFFIX)
    ]
    return referenced if is_ci_job_name(referenced) else None


def validate_matrix(data: dict) -> dict:
    if data.get("version") != 4:
        fail("version must be 4")
    if set(data.get("evidence_levels", [])) != EVIDENCE_LEVELS:
        fail("evidence_levels must contain runtime, compile, and not-covered")

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        fail("targets must be a non-empty list")

    seen_targets: set[str] = set()
    jobs: set[str] = set()
    for entry in targets:
        required = {"target", "platform", "evidence", "allocation", "ci_job", "ci"}
        if not isinstance(entry, dict):
            fail(f"target entry must be an object: {entry!r}")
        if not required <= entry.keys():
            fail(f"target entry is missing fields: {sorted(required - entry.keys())}")

        target = entry["target"]
        if not isinstance(target, str) or not target or target in seen_targets:
            fail(f"target must be a unique non-empty string: {target!r}")
        seen_targets.add(target)
        if entry["evidence"] not in EVIDENCE_LEVELS:
            fail(f"unknown evidence level for {target}")
        if entry["allocation"] not in ALLOCATION_CAPABILITIES:
            fail(f"unknown allocation capability for {target}")
        if entry["evidence"] == "not-covered" and entry["allocation"] != "unknown":
            fail(f"not-covered target {target} must have unknown allocation capability")
        if entry["evidence"] != "not-covered" and entry["allocation"] == "unknown":
            fail(f"covered target {target} must declare an allocation capability")

        job = entry["ci_job"]
        ci = entry["ci"]
        if job is None:
            if ci is not None:
                fail(f"not-covered target {target} must not have CI metadata")
            continue
        if not is_ci_job_name(job):
            fail(f"invalid CI job name for {target}: {job!r}")
        if not isinstance(ci, dict):
            fail(f"CI metadata for {target} must be an object")

        runner = ci.get("runner")
        toolchains = ci.get("toolchains")
        if not isinstance(runner, str) or not runner:
            fail(f"CI metadata for {target} must define a runner")
        if not isinstance(toolchains, list) or not toolchains or not all(
            isinstance(toolchain, str) for toolchain in toolchains
        ):
            fail(f"CI metadata for {target} must define toolchains")

        jobs.add(job)
        if entry["evidence"] == "runtime" and toolchains != ["1.97.1", "stable"]:
            fail(f"runtime target {target} must use Rust 1.97.1 and stable")
        if entry["evidence"] == "compile" and toolchains not in (["1.97.1"], ["nightly"]):
            fail(f"compile target {target} must use Rust 1.97.1 or nightly")

    if not jobs:
        fail("at least one CI job is required")

    return data


def load_matrix(matrix_path: Path = MATRIX_PATH) -> dict:
    data = validate_matrix(json.loads(matrix_path.read_text(encoding="utf-8")))
    validate_workflow(data, load_workflow())
    return data


def load_workflow(workflow_path: Path = WORKFLOW_PATH) -> dict:
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    if not isinstance(workflow, dict):
        fail("workflow must be a YAML object")
    return workflow


def validate_workflow(data: dict, workflow: dict) -> None:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        fail("workflow must define a jobs object")

    declared = {
        entry["ci_job"]
        for entry in data["targets"]
        if entry["ci_job"] is not None
    }
    consumed = set()
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            fail(f"workflow job {job_name} must be an object")
        strategy = job.get("strategy")
        if not isinstance(strategy, dict) or "matrix" not in strategy:
            continue

        referenced = matrix_reference(strategy["matrix"])
        if referenced is None:
            fail(f"workflow job {job_name} must consume a generated support matrix")
        if referenced != job_name:
            fail(f"workflow job {job_name} consumes matrix {referenced!r}")
        if referenced not in declared:
            fail(f"workflow consumes undeclared matrix {referenced!r}")
        consumed.add(referenced)

    if consumed != declared:
        missing = sorted(declared - consumed)
        unused = sorted(consumed - declared)
        fail(f"workflow matrix consumption drift: missing={missing}, unused={unused}")


def matrices(data: dict) -> dict[str, dict[str, list[dict[str, str]]]]:
    generated: dict[str, dict[str, list[dict[str, str]]]] = {}
    for entry in data["targets"]:
        if entry["ci_job"] is None:
            continue
        matrix_name = entry["ci_job"]
        matrix = generated.setdefault(matrix_name, {"include": []})
        for toolchain in entry["ci"]["toolchains"]:
            matrix["include"].append(
                {
                    "os": entry["ci"]["runner"],
                    "target": entry["target"],
                    "toolchain": toolchain,
                }
            )
    return generated


def write_github_output(path: Path, generated: dict) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as output:
        value = json.dumps(generated, separators=(",", ":"))
        output.write(f"matrices={value}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    generated = matrices(load_matrix())
    if args.github_output:
        write_github_output(args.github_output, generated)
    else:
        print(json.dumps(generated, indent=2))


if __name__ == "__main__":
    main()
