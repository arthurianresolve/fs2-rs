#!/usr/bin/env python3
"""Validate the support registry and emit the CI matrices it owns."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "support-matrix.json"
EVIDENCE_LEVELS = {"runtime", "compile", "not-covered"}
JOB_IDS = {"check", "cross-check", "uclibc"}
EXPECTED_TARGETS = {
    "check": {
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-msvc",
    },
    "cross-check": {
        "i686-unknown-linux-gnu",
        "x86_64-unknown-illumos",
        "x86_64-unknown-redox",
    },
    "uclibc": {"armv7-unknown-linux-uclibceabihf"},
}


def fail(message: str) -> None:
    raise SystemExit(f"support matrix is invalid: {message}")


def load_matrix() -> dict:
    data = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    if data.get("version") != 2:
        fail("version must be 2")
    if set(data.get("evidence_levels", [])) != EVIDENCE_LEVELS:
        fail("evidence_levels must contain runtime, compile, and not-covered")

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        fail("targets must be a non-empty list")

    seen: set[str] = set()
    for entry in targets:
        required = {"target", "platform", "evidence", "allocation", "ci_job", "ci"}
        if not required <= entry.keys():
            fail(f"target entry is missing fields: {sorted(required - entry.keys())}")
        target = entry["target"]
        if not isinstance(target, str) or not target or target in seen:
            fail(f"target must be a unique non-empty string: {target!r}")
        seen.add(target)
        if entry["evidence"] not in EVIDENCE_LEVELS:
            fail(f"unknown evidence level for {target}")

        job = entry["ci_job"]
        ci = entry["ci"]
        if job is None:
            if ci is not None:
                fail(f"not-covered target {target} must not have CI metadata")
            continue
        if job not in JOB_IDS:
            fail(f"unknown CI job {job!r} for {target}")
        if not isinstance(ci, dict) or not isinstance(ci.get("runner"), str):
            fail(f"CI metadata for {target} must define a runner")
        toolchains = ci.get("toolchains")
        if not isinstance(toolchains, list) or not toolchains or not all(
            isinstance(toolchain, str) for toolchain in toolchains
        ):
            fail(f"CI metadata for {target} must define toolchains")

        if job == "check":
            if entry["evidence"] != "runtime" or len(toolchains) != 2:
                fail(f"native target {target} must have runtime evidence on two toolchains")
        elif job == "cross-check":
            if entry["evidence"] != "compile" or toolchains != ["1.97.1"]:
                fail(f"cross target {target} must have compile evidence on Rust 1.97.1")
        elif job == "uclibc":
            if entry["evidence"] != "compile" or toolchains != ["nightly"]:
                fail(f"uClibc target {target} must have compile evidence on nightly")

    for job, expected in EXPECTED_TARGETS.items():
        actual = {entry["target"] for entry in targets if entry["ci_job"] == job}
        if actual != expected:
            fail(f"{job} targets differ from the owned set: {sorted(actual)}")

    return data


def matrices(data: dict) -> dict[str, dict[str, list[dict[str, str]]]]:
    result: dict[str, dict[str, list[dict[str, str]]]] = {
        "native": {"include": []},
        "cross": {"include": []},
        "uclibc": {"include": []},
    }
    for entry in data["targets"]:
        job = entry["ci_job"]
        if job is None:
            continue
        output = "native" if job == "check" else job.removesuffix("-check")
        for toolchain in entry["ci"]["toolchains"]:
            result[output]["include"].append(
                {
                    "os": entry["ci"]["runner"],
                    "target": entry["target"],
                    "toolchain": toolchain,
                }
            )
    return result


def write_github_output(path: Path, generated: dict) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as output:
        for name, value in generated.items():
            output.write(f"{name}={json.dumps(value, separators=(',', ':'))}\n")


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
