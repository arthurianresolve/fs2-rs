#!/usr/bin/env python3
"""Validate the support registry and emit the CI matrices it owns."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "support-matrix.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
CARGO = os.environ.get("CARGO", "cargo")
EVIDENCE_LEVELS = {"runtime", "compile", "not-covered"}
ALLOCATION_CAPABILITIES = {"physical-reservation", "unsupported", "unknown"}
APPROVED_RUNNERS = {
    "macos-15-intel",
    "macos-latest",
    "ubuntu-latest",
    "windows-latest",
}
APPROVED_TARGETS = {
    "aarch64-apple-darwin",
    "aarch64-linux-android",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "armv7-unknown-linux-uclibceabihf",
    "i686-linux-android",
    "i686-pc-windows-gnu",
    "i686-unknown-linux-gnu",
    "powerpc64-unknown-linux-gnu",
    "riscv64gc-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-gnu",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-freebsd",
    "x86_64-unknown-illumos",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-netbsd",
    "x86_64-unknown-redox",
}
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
MATRIX_TARGET_EXPRESSION = "${{ matrix.target }}"
MATRIX_EXPRESSION = re.compile(
    r"fromJSON\s*\(\s*needs\s*\.\s*support-matrix\s*\.\s*outputs\s*\.\s*matrices\s*\)\s*\.\s*([A-Za-z0-9_]+)"
)


@dataclass(frozen=True, slots=True)
class CiSpec:
    job: str
    runner: str
    toolchains: tuple[str, ...]
    coverage: bool


@dataclass(frozen=True, slots=True)
class TargetSpec:
    target: str
    platform: str
    evidence: str
    allocation: str
    ci: CiSpec | None


@dataclass(frozen=True, slots=True)
class SupportRegistry:
    version: int
    evidence_levels: frozenset[str]
    targets: tuple[TargetSpec, ...]

    @property
    def ci_jobs(self) -> frozenset[str]:
        return frozenset(target.ci.job for target in self.targets if target.ci is not None)

    @property
    def matrix_jobs(self) -> frozenset[str]:
        return self.ci_jobs | {"coverage"}


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

    expression = value.strip()
    if not expression.startswith("${{") or not expression.endswith("}}"):
        return None

    match = MATRIX_EXPRESSION.fullmatch(expression[3:-2].strip())
    if match is None:
        return None

    referenced = match.group(1)
    return referenced if is_ci_job_name(referenced) else None


def has_unquoted_matrix_target(command: str) -> bool:
    """Return whether any matrix target expansion is outside double quotes."""
    in_double_quotes = False
    escaped = False
    index = 0
    while index < len(command):
        if command.startswith(MATRIX_TARGET_EXPRESSION, index):
            if not in_double_quotes:
                return True
            index += len(MATRIX_TARGET_EXPRESSION)
            escaped = False
            continue

        character = command[index]
        if character == '"' and not escaped:
            in_double_quotes = not in_double_quotes
        escaped = character == "\\" and not escaped
        index += 1

    return False


def parse_registry(data: object) -> SupportRegistry:
    if not isinstance(data, dict):
        fail("matrix must be a JSON object")
    if data.get("version") != 5:
        fail("version must be 5")
    evidence_levels = data.get("evidence_levels")
    if not isinstance(evidence_levels, list) or not all(
        isinstance(level, str) for level in evidence_levels
    ) or set(evidence_levels) != EVIDENCE_LEVELS:
        fail("evidence_levels must contain runtime, compile, and not-covered")

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        fail("targets must be a non-empty list")

    parsed_targets: list[TargetSpec] = []
    seen_targets: set[str] = set()
    jobs: set[str] = set()
    for entry in targets:
        if not isinstance(entry, dict):
            fail(f"target entry must be an object: {entry!r}")
        required = {"target", "platform", "evidence", "allocation", "ci"}
        if not required <= entry.keys():
            fail(f"target entry is missing fields: {sorted(required - entry.keys())}")
        unexpected = set(entry) - required
        if unexpected:
            fail(f"target entry has unknown fields: {sorted(unexpected)}")

        target = entry["target"]
        if not isinstance(target, str) or target not in APPROVED_TARGETS:
            fail(f"target is not approved: {target!r}")
        if target in seen_targets:
            fail(f"target must be unique: {target!r}")
        seen_targets.add(target)
        platform = entry["platform"]
        if not isinstance(platform, str) or not platform:
            fail(f"platform must be a non-empty string for {target}")
        evidence = entry["evidence"]
        allocation = entry["allocation"]
        if not isinstance(evidence, str) or evidence not in EVIDENCE_LEVELS:
            fail(f"unknown evidence level for {target}")
        if not isinstance(allocation, str) or allocation not in ALLOCATION_CAPABILITIES:
            fail(f"unknown allocation capability for {target}")
        if evidence == "not-covered" and allocation != "unknown":
            fail(f"not-covered target {target} must have unknown allocation capability")
        if evidence != "not-covered" and allocation == "unknown":
            fail(f"covered target {target} must declare an allocation capability")

        ci = entry["ci"]
        if evidence == "not-covered":
            if ci is not None:
                fail(f"not-covered target {target} must not have CI metadata")
            parsed_targets.append(
                TargetSpec(target, platform, evidence, allocation, None)
            )
            continue
        if not isinstance(ci, dict):
            fail(f"CI metadata for {target} must be an object")
        ci_required = {"job", "runner", "toolchains"}
        if not ci_required <= ci.keys():
            fail(f"CI metadata for {target} is missing fields: {sorted(ci_required - ci.keys())}")
        ci_unexpected = set(ci) - ci_required - {"coverage"}
        if ci_unexpected:
            fail(f"CI metadata for {target} has unknown fields: {sorted(ci_unexpected)}")
        job = ci.get("job")
        if not is_ci_job_name(job):
            fail(f"invalid CI job name for {target}: {job!r}")

        runner = ci.get("runner")
        toolchains = ci.get("toolchains")
        if not isinstance(runner, str) or runner not in APPROVED_RUNNERS:
            fail(f"CI metadata for {target} selects an unapproved runner: {runner!r}")
        if not isinstance(toolchains, list) or not toolchains or not all(
            isinstance(toolchain, str) for toolchain in toolchains
        ):
            fail(f"CI metadata for {target} must define toolchains")
        coverage = ci.get("coverage", False)
        if not isinstance(coverage, bool):
            fail(f"CI coverage selection for {target} must be a boolean")
        if coverage and evidence != "runtime":
            fail(f"compile target {target} cannot provide native coverage")

        jobs.add(job)
        parsed_ci = CiSpec(job, runner, tuple(toolchains), coverage)
        parsed_targets.append(
            TargetSpec(target, platform, evidence, allocation, parsed_ci)
        )

    if not jobs:
        fail("at least one CI job is required")
    if not any(target.evidence == "runtime" for target in parsed_targets):
        fail("at least one runtime target is required")
    if not any(target.ci is not None and target.ci.coverage for target in parsed_targets):
        fail("at least one native coverage target is required")

    return SupportRegistry(5, frozenset(evidence_levels), tuple(parsed_targets))


def load_matrix(
    matrix_path: Path = MATRIX_PATH, *, rust_version: str | None = None
) -> SupportRegistry:
    registry = parse_registry(json.loads(matrix_path.read_text(encoding="utf-8")))
    validate_toolchain_policy(
        registry, rust_version if rust_version is not None else package_rust_version()
    )
    validate_workflow(registry, load_workflow())
    return registry


def package_rust_version() -> str:
    result = subprocess.run(
        [CARGO, "metadata", "--manifest-path", str(ROOT / "Cargo.toml"),
         "--no-deps", "--format-version", "1", "--locked"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"cargo metadata failed while reading rust-version: {detail}")
    try:
        metadata = json.loads(result.stdout)
        package = next(package for package in metadata["packages"] if package["name"] == "fs2")
        rust_version = package["rust_version"]
    except (KeyError, StopIteration, TypeError, json.JSONDecodeError):
        fail("cargo metadata did not provide fs2 rust-version")
    if not isinstance(rust_version, str) or not rust_version:
        fail("fs2 rust-version must be a non-empty string")
    return rust_version


def validate_toolchain_policy(registry: SupportRegistry, rust_version: str) -> None:
    for target in registry.targets:
        if target.ci is None:
            continue
        toolchains = list(target.ci.toolchains)
        if target.evidence == "runtime" and toolchains != [rust_version, "stable"]:
            fail(
                f"runtime target {target.target} must use Rust {rust_version} and stable"
            )
        if target.evidence == "compile" and toolchains not in ([rust_version], ["nightly"]):
            fail(f"compile target {target.target} must use Rust {rust_version} or nightly")


def load_workflow(workflow_path: Path = WORKFLOW_PATH) -> dict:
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    if not isinstance(workflow, dict):
        fail("workflow must be a YAML object")
    return workflow


def validate_workflow(registry: SupportRegistry, workflow: dict) -> None:
    if not isinstance(workflow, dict):
        fail("workflow must be a YAML object")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        fail("workflow must define a jobs object")

    declared = registry.matrix_jobs
    expected_matrices = matrices(registry)
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            fail(f"workflow job {job_name} must be an object")

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            fail(f"workflow job {job_name} steps must be a list")
        for step in steps:
            if not isinstance(step, dict):
                fail(f"workflow job {job_name} contains an invalid step")
            action = step.get("uses")
            if isinstance(action, str) and not (
                action.startswith("./") or PINNED_ACTION.fullmatch(action)
            ):
                fail(f"workflow action is not pinned to a commit: {action}")
            command = step.get("run")
            if isinstance(command, str) and has_unquoted_matrix_target(command):
                fail(f"workflow job {job_name} uses an unquoted matrix target")

        strategy = job.get("strategy")
        if not isinstance(strategy, dict) or "matrix" not in strategy:
            if job_name in declared:
                fail(f"workflow job {job_name} must define a literal support matrix")
            continue

        configured = strategy["matrix"]
        referenced = matrix_reference(configured)
        if referenced is not None:
            fail(f"workflow must not consume runtime-generated matrix {referenced!r}")
        if job_name in declared and configured != expected_matrices[job_name]:
            fail(f"workflow job {job_name} literal matrix drifted from support data")

    missing = sorted(declared - set(jobs))
    if missing:
        fail(f"workflow support jobs are missing: {missing}")


def matrices(registry: SupportRegistry) -> dict[str, dict[str, list[dict[str, str]]]]:
    generated: dict[str, dict[str, list[dict[str, str]]]] = {}
    for target in registry.targets:
        if target.ci is None:
            continue
        matrix_name = target.ci.job
        matrix = generated.setdefault(matrix_name, {"include": []})
        for toolchain in target.ci.toolchains:
            matrix["include"].append(
                {
                    "os": target.ci.runner,
                    "target": target.target,
                    "toolchain": toolchain,
                }
            )

    generated["coverage"] = {
        "include": [
            {
                "os": target.ci.runner,
                "target": target.target,
                "toolchain": target.ci.toolchains[0],
            }
            for target in registry.targets
            if target.ci is not None and target.ci.coverage
        ]
    }
    return generated


def write_github_output(path: Path, generated: dict, rust_version: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as output:
        value = json.dumps(generated, separators=(",", ":"))
        output.write(f"matrices={value}\n")
        output.write(f"rust_version={rust_version}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    rust_version = package_rust_version()
    generated = matrices(load_matrix(rust_version=rust_version))
    if args.github_output:
        write_github_output(args.github_output, generated, rust_version)
    else:
        print(json.dumps(generated, indent=2))


if __name__ == "__main__":
    main()
