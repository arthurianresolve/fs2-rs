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
MATRIX_EXPRESSION = re.compile(
    r"fromJSON\s*\(\s*needs\s*\.\s*support-matrix\s*\.\s*outputs\s*\.\s*matrices\s*\)\s*\.\s*([A-Za-z0-9_]+)"
)
PROFILE_JOB_NAMES = {
    "stable": "coverage",
    "branch": "coverage_branch",
    "condition": "coverage_condition",
}
EXPECTED_PROFILE_METRICS = {
    "stable": ("line", "region"),
    "branch": ("branch",),
    "condition": ("condition_diagnostic",),
}
BRANCH_TOOLCHAIN = "nightly-2026-07-23"


@dataclass(frozen=True, slots=True)
class CoverageProfile:
    name: str
    requested_toolchain: str
    metrics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CiSpec:
    job: str
    runner: str
    toolchains: tuple[str, ...]
    coverage_profiles: tuple[str, ...]

    @property
    def coverage(self) -> bool:
        """Compatibility view for callers that only need a boolean."""
        return bool(self.coverage_profiles)


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
    coverage_profiles: dict[str, CoverageProfile]
    targets: tuple[TargetSpec, ...]

    @property
    def ci_jobs(self) -> frozenset[str]:
        return frozenset(target.ci.job for target in self.targets if target.ci is not None)

    @property
    def matrix_jobs(self) -> frozenset[str]:
        return self.ci_jobs | {PROFILE_JOB_NAMES[name] for name in self.coverage_profiles}


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


def parse_coverage_profiles(data: object) -> dict[str, CoverageProfile]:
    if not isinstance(data, dict) or set(data) != set(EXPECTED_PROFILE_METRICS):
        fail("coverage_profiles must define exactly stable, branch, and condition")
    profiles: dict[str, CoverageProfile] = {}
    for name, expected_metrics in EXPECTED_PROFILE_METRICS.items():
        raw = data.get(name)
        if not isinstance(raw, dict) or set(raw) != {"requested_toolchain", "metrics"}:
            fail(f"coverage profile {name} has an invalid shape")
        requested_toolchain = raw["requested_toolchain"]
        metrics = raw["metrics"]
        if not isinstance(requested_toolchain, str) or not requested_toolchain:
            fail(f"coverage profile {name} must define a requested toolchain")
        if not isinstance(metrics, list) or tuple(metrics) != expected_metrics:
            fail(f"coverage profile {name} must define metrics {list(expected_metrics)}")
        profiles[name] = CoverageProfile(name, requested_toolchain, tuple(metrics))
    for name in ("branch", "condition"):
        if profiles[name].requested_toolchain != BRANCH_TOOLCHAIN:
            fail(f"{name} coverage must use {BRANCH_TOOLCHAIN}")
    return profiles


def parse_registry(data: object) -> SupportRegistry:
    if not isinstance(data, dict):
        fail("matrix must be a JSON object")
    if set(data) != {"version", "evidence_levels", "coverage_profiles", "targets"}:
        fail("matrix has unknown or missing top-level fields")
    if data.get("version") != 7:
        fail("version must be 7")
    evidence_levels = data.get("evidence_levels")
    if not isinstance(evidence_levels, list) or not all(
        isinstance(level, str) for level in evidence_levels
    ) or set(evidence_levels) != EVIDENCE_LEVELS:
        fail("evidence_levels must contain runtime, compile, and not-covered")
    coverage_profiles = parse_coverage_profiles(data.get("coverage_profiles"))

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
        if not isinstance(target, str) or not target or target in seen_targets:
            fail(f"target must be a unique non-empty string: {target!r}")
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
            parsed_targets.append(TargetSpec(target, platform, evidence, allocation, None))
            continue
        if not isinstance(ci, dict):
            fail(f"CI metadata for {target} must be an object")
        ci_required = {"job", "runner", "toolchains"}
        if not ci_required <= ci.keys():
            fail(f"CI metadata for {target} is missing fields: {sorted(ci_required - ci.keys())}")
        ci_unexpected = set(ci) - ci_required - {"coverage_profiles"}
        if ci_unexpected:
            fail(f"CI metadata for {target} has unknown fields: {sorted(ci_unexpected)}")
        job = ci.get("job")
        if not is_ci_job_name(job):
            fail(f"invalid CI job name for {target}: {job!r}")

        runner = ci.get("runner")
        toolchains = ci.get("toolchains")
        if not isinstance(runner, str) or not runner:
            fail(f"CI metadata for {target} must define a runner")
        if not isinstance(toolchains, list) or not toolchains or not all(
            isinstance(toolchain, str) for toolchain in toolchains
        ):
            fail(f"CI metadata for {target} must define toolchains")
        selected_profiles = ci.get("coverage_profiles", [])
        if not isinstance(selected_profiles, list) or not all(
            isinstance(profile, str) for profile in selected_profiles
        ) or len(set(selected_profiles)) != len(selected_profiles):
            fail(f"coverage_profiles for {target} must be a unique string list")
        unknown_profiles = set(selected_profiles) - set(coverage_profiles)
        if unknown_profiles:
            fail(f"unknown coverage profiles for {target}: {sorted(unknown_profiles)}")
        if selected_profiles and evidence != "runtime":
            fail(f"compile target {target} cannot provide native coverage")
        if evidence == "runtime" and selected_profiles and set(selected_profiles) != set(coverage_profiles):
            fail(f"runtime coverage target {target} must select every defined coverage profile")

        jobs.add(job)
        parsed_ci = CiSpec(job, runner, tuple(toolchains), tuple(selected_profiles))
        parsed_targets.append(TargetSpec(target, platform, evidence, allocation, parsed_ci))

    if not jobs:
        fail("at least one CI job is required")
    if not any(target.evidence == "runtime" for target in parsed_targets):
        fail("at least one runtime target is required")
    if not any(target.ci is not None and target.ci.coverage for target in parsed_targets):
        fail("at least one native coverage target is required")

    return SupportRegistry(7, frozenset(evidence_levels), coverage_profiles, tuple(parsed_targets))


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
    if registry.coverage_profiles["stable"].requested_toolchain != rust_version:
        fail(
            "stable coverage profile must use the package rust-version "
            f"{rust_version}"
        )
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
    consumed = set()
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            fail(f"workflow job {job_name} must be an object")
        strategy = job.get("strategy")
        if not isinstance(strategy, dict) or "matrix" not in strategy:
            continue

        referenced = matrix_reference(strategy["matrix"])
        if job_name in declared and referenced is None:
            fail(f"workflow job {job_name} must consume a generated support matrix")
        if job_name in declared and referenced != job_name:
            fail(f"workflow job {job_name} consumes matrix {referenced!r}")
        if job_name not in declared and referenced is not None:
            fail(f"workflow consumes undeclared matrix {referenced!r}")
        if referenced is not None:
            consumed.add(referenced)

    if consumed != declared:
        missing = sorted(declared - consumed)
        fail(f"workflow matrix consumption drift: missing={missing}")


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

    for profile_name, profile in registry.coverage_profiles.items():
        job_name = PROFILE_JOB_NAMES[profile_name]
        generated[job_name] = {
            "include": [
                {
                    "os": target.ci.runner,
                    "target": target.target,
                    "toolchain": profile.requested_toolchain,
                }
                for target in registry.targets
                if target.ci is not None and profile_name in target.ci.coverage_profiles
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
