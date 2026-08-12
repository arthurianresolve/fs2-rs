#!/usr/bin/env python3
"""Compile and run one frozen v0.4 consumer against legacy and current fs2."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY = ROOT / "compatibility"
CONSUMER = COMPATIBILITY / "v04_consumer.rs"
EXPECTED_CONSUMER_SHA256 = "54417492d4e1b37216c25397bbce05ae48a28e244b24e31de936c5f6970d577d"
SUBJECTS = ("legacy", "current")
CARGO = os.environ.get("CARGO", "cargo")


@dataclass(frozen=True, slots=True)
class CompatibilityPackage:
    name: str
    edition: str


def run(*arguments: str) -> None:
    command = [CARGO, *arguments]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def consumer_digest(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline=None) as consumer:
        contents = consumer.read()
    return hashlib.sha256(contents.encode("utf-8")).hexdigest()


def validate_frozen_consumer(path: Path = CONSUMER) -> str:
    digest = consumer_digest(path)
    if digest != EXPECTED_CONSUMER_SHA256:
        raise SystemExit(
            "frozen v0.4 consumer changed; update the expected digest only with "
            "an intentional compatibility-fixture review"
        )
    return digest


def compatibility_packages() -> tuple[CompatibilityPackage, ...]:
    result = subprocess.run(
        [
            CARGO,
            "metadata",
            "--manifest-path",
            str(COMPATIBILITY / "Cargo.toml"),
            "--no-deps",
            "--format-version",
            "1",
            "--locked",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"cargo metadata failed for compatibility workspace: {detail}")

    try:
        packages = json.loads(result.stdout)["packages"]
    except (KeyError, TypeError, json.JSONDecodeError):
        raise SystemExit("cargo metadata did not describe compatibility packages")

    if not isinstance(packages, list):
        raise SystemExit("cargo metadata did not describe compatibility packages")

    discovered_list: list[CompatibilityPackage] = []
    for package in packages:
        if not isinstance(package, dict):
            raise SystemExit("cargo metadata contained an invalid package entry")
        name = package.get("name")
        if not isinstance(name, str) or not name.startswith("fs2-compat-edition-"):
            continue
        edition = package.get("edition")
        if not isinstance(edition, str) or not edition:
            raise SystemExit(f"compatibility package {name} is missing an edition")
        discovered_list.append(CompatibilityPackage(name, edition))

    discovered = tuple(discovered_list)
    if not discovered:
        raise SystemExit("compatibility workspace has no edition packages")
    editions = [package.edition for package in discovered]
    if len(editions) != len(set(editions)):
        raise SystemExit("compatibility workspace has duplicate Rust editions")

    return tuple(sorted(discovered, key=lambda package: package.edition))


def main() -> None:
    digest = validate_frozen_consumer()
    print(f"v0.4 consumer sha256={digest}")

    run("fmt", "--manifest-path", str(COMPATIBILITY / "Cargo.toml"), "--all", "--", "--check")
    packages = compatibility_packages()
    for package in packages:
        for subject in SUBJECTS:
            run(
                "check",
                "--manifest-path",
                str(COMPATIBILITY / "Cargo.toml"),
                "--package",
                package.name,
                "--no-default-features",
                "--features",
                subject,
                "--locked",
            )

    runtime_packages = [package for package in packages if package.edition == "2015"]
    if len(runtime_packages) != 1:
        raise SystemExit("compatibility workspace must define exactly one Rust 2015 package")

    for subject in SUBJECTS:
        run(
            "run",
            "--manifest-path",
            str(COMPATIBILITY / "Cargo.toml"),
            "--package",
            runtime_packages[0].name,
            "--no-default-features",
            "--features",
            subject,
            "--locked",
        )


if __name__ == "__main__":
    main()
