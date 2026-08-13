#!/usr/bin/env python3
"""Validate raw coverage profiles and report the internal closure metrics.

Raw LLVM line/region/branch/condition numbers remain diagnostic tool output.
Promotable staging bundles must nevertheless close every required emitted raw
metric at 100 percent.  The LLVM instantiation denominator and the absent LLVM
MC/DC field remain explicitly diagnostic/non-produced rather than being
silently treated as DO-178C metrics.  The exact source-level condition-pair
closure reported here is repository-owned internal evidence only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from validate_coverage import ValidationError, load_json, validate_manifest, validate_static_records
from validate_support_matrix import load_matrix
from validate_mcdc import validate_record


ROOT = Path(__file__).resolve().parents[1]
PROFILE_METRICS = {
    "stable": ("lines", "regions", "functions"),
    "branch": ("lines", "regions", "branches", "functions"),
    "condition": ("lines", "regions", "branches", "functions"),
}


def validate_profile_configuration(manifest: dict[str, Any]) -> None:
    """Ensure each manifest carries the instrumentation contract it names."""
    profile = manifest["profile"]
    command = manifest["command"]
    environment = manifest["environment"]
    if profile == "stable":
        if manifest["requested_toolchain"] != "1.88" or "--branch" in command:
            raise ValidationError("stable profile has branch or toolchain configuration drift")
    elif profile == "branch":
        if manifest["requested_toolchain"] != "nightly-2026-07-23" or "--branch" not in command:
            raise ValidationError("branch profile is missing its pinned nightly branch configuration")
        if "RUSTFLAGS" in environment:
            raise ValidationError("branch profile must not carry condition instrumentation flags")
    elif profile == "condition":
        if manifest["requested_toolchain"] != "nightly-2026-07-23" or "--branch" not in command:
            raise ValidationError("condition profile is missing its pinned nightly branch configuration")
        if environment.get("RUSTFLAGS") != "-Z coverage-options=condition":
            raise ValidationError("condition profile is missing its explicit Rust condition instrumentation flag")


def expected_coverage_runs() -> dict[tuple[str, str], str]:
    """Return the exact profile/target set required by the support registry."""
    registry = load_matrix()
    expected: dict[tuple[str, str], str] = {}
    for target in registry.targets:
        if target.ci is None:
            continue
        for profile in target.ci.coverage_profiles:
            expected[(profile, target.target)] = registry.coverage_profiles[profile].requested_toolchain
    if not expected:
        raise ValidationError("support matrix declares no native coverage runs")
    return expected


def validate_matrix_runs(
    manifests: list[dict[str, Any]], expected: dict[tuple[str, str], str]
) -> None:
    """Require a complete, non-duplicated and provenance-consistent run set."""
    actual: dict[tuple[str, str], dict[str, Any]] = {}
    for manifest in manifests:
        key = (manifest["profile"], manifest["target"])
        if key in actual:
            raise ValidationError(f"duplicate coverage run for {key[0]}/{key[1]}")
        actual[key] = manifest

    expected_keys = set(expected)
    actual_keys = set(actual)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        raise ValidationError(
            f"coverage matrix mismatch: missing={missing}, unexpected={unexpected}"
        )

    provenance = {
        (manifest["commit"], manifest["tree"], manifest["cargo_lock_sha256"])
        for manifest in manifests
    }
    if len(provenance) != 1:
        raise ValidationError("coverage matrix runs do not share commit, tree, and lockfile provenance")

    for key, requested_toolchain in expected.items():
        manifest = actual[key]
        if manifest["requested_toolchain"] != requested_toolchain:
            raise ValidationError(
                f"{key[0]}/{key[1]} requested toolchain drift: "
                f"{manifest['requested_toolchain']!r} != {requested_toolchain!r}"
            )


def report_path(manifest_path: Path, manifest: dict[str, Any]) -> Path:
    for artifact in manifest["artifacts"]:
        if artifact["path"] == "coverage.json":
            path = (manifest_path.parent / artifact["path"]).resolve()
            if path.is_file():
                return path
    raise ValidationError(f"{manifest_path} has no coverage.json artifact")


def load_totals(report: Path) -> dict[str, dict[str, Any]]:
    value = json.loads(report.read_text(encoding="utf-8"))
    try:
        totals = value["data"][0]["totals"]
    except (KeyError, IndexError, TypeError):
        raise ValidationError(f"{report} has no LLVM totals object") from None
    if not isinstance(totals, dict):
        raise ValidationError(f"{report} totals must be an object")
    return totals


def validate_full_metric(
    totals: dict[str, dict[str, Any]], metric: str, label: str
) -> None:
    value = totals.get(metric)
    if not isinstance(value, dict):
        raise ValidationError(f"{label} is missing the {metric} metric object")
    count = value.get("count")
    covered = value.get("covered")
    notcovered = value.get(
        "notcovered",
        count - covered
        if isinstance(count, (int, float)) and isinstance(covered, (int, float))
        else None,
    )
    percent = value.get("percent")
    if not all(isinstance(item, (int, float)) and not isinstance(item, bool)
               for item in (count, covered, notcovered, percent)):
        raise ValidationError(f"{label}.{metric} has non-numeric totals")
    if count <= 0:
        raise ValidationError(f"{label}.{metric} has an empty denominator")
    if covered != count or notcovered != 0 or percent != 100:
        raise ValidationError(
            f"{label}.{metric} is not closed: "
            f"covered={covered}, count={count}, notcovered={notcovered}, percent={percent}"
        )


def metric_summary(manifest_path: Path, require_full: bool = False) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    validate_manifest(manifest_path)
    validate_profile_configuration(manifest)
    profile = manifest["profile"]
    totals = load_totals(report_path(manifest_path, manifest))
    required = PROFILE_METRICS[profile]
    missing = [metric for metric in required if metric not in totals]
    if missing:
        raise ValidationError(f"{manifest_path} is missing raw metrics: {missing}")
    if require_full:
        for metric in required:
            validate_full_metric(totals, metric, str(manifest_path))
    if profile in {"branch", "condition"} and totals.get("mcdc", {}).get("count") != 0:
        raise ValidationError(f"{manifest_path} unexpectedly reports an MC/DC tool result")
    return {
        "run_id": manifest["run_id"],
        "profile": profile,
        "target": manifest["target"],
        "commit": manifest["commit"],
        "metrics": {metric: totals[metric] for metric in required},
        "mcdc_tool_count": totals.get("mcdc", {}).get("count", 0),
        "condition_semantics": (
            "instrumentation_only"
            if profile == "condition"
            else "not_requested"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-dir", type=Path, required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument(
        "--require-matrix",
        action="store_true",
        help="require exactly the complete native coverage set from support-matrix.json",
    )
    args = parser.parse_args()
    try:
        validate_static_records()
        runs_dir = args.runs_dir.resolve()
        manifests = sorted(runs_dir.rglob("run-manifest.json"))
        if not manifests:
            raise ValidationError(f"no manifests found under {runs_dir}")
        summaries = []
        manifest_values = []
        for manifest in manifests:
            validate_manifest(manifest, args.expected_commit)
            value = load_json(manifest)
            if args.require_pass and value["status"] != "pass":
                raise ValidationError(f"{manifest} is not promotable: status must be pass")
            summaries.append(metric_summary(manifest, require_full=args.require_pass))
            manifest_values.append(value)

        if args.require_matrix:
            validate_matrix_runs(manifest_values, expected_coverage_runs())

        mcdc = load_json(ROOT / "coverage" / "mcdc.json")
        mcdc_ids = validate_record(mcdc)
        pairs = sum(len(decision["pairs"]) for decision in mcdc["decisions"])
        conditions = sum(len(decision["conditions"]) for decision in mcdc["decisions"])
        decision_inventory = load_json(ROOT / "coverage" / "decision-inventory.json")["decisions"]
        assessed_decisions = sum(
            decision["mcdc_disposition"] == "assessed_internal_source_pairs"
            for decision in decision_inventory
        )
        open_assessments = sum(
            decision["mcdc_disposition"] == "assessment_open_no_record"
            for decision in decision_inventory
        )
        not_applicable = sum(
            decision["mcdc_disposition"].startswith("not_applicable_")
            for decision in decision_inventory
        )
        print(json.dumps({
            "raw_profile_runs": summaries,
            "internal_source_mcdc": {
                "decision_records": len(mcdc_ids),
                "condition_occurrences": conditions,
                "covered_unique_cause_pairs": pairs,
                "closure_percent": 100.0,
                "closure_scope": "assessed_internal_source_pairs_only",
                "decision_inventory_total": len(decision_inventory),
                "assessed_decisions": assessed_decisions,
                "open_assessment_decisions": open_assessments,
                "not_applicable_decisions": not_applicable,
                "credit": "none",
            },
        }, indent=2, sort_keys=True))
    except (ValidationError, OSError, json.JSONDecodeError) as error:
        print(f"coverage metric validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
