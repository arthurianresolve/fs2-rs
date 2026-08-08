#!/usr/bin/env python3
"""Compile and run one frozen v0.4 consumer against legacy and current fs2."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY = ROOT / "compatibility"
CONSUMER = COMPATIBILITY / "v04_consumer.rs"
EDITIONS = ("2015", "2018", "2021", "2024")
SUBJECTS = ("legacy", "current")
CARGO = os.environ.get("CARGO", "cargo")


def run(*arguments: str) -> None:
    command = [CARGO, *arguments]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    digest = hashlib.sha256(CONSUMER.read_bytes()).hexdigest()
    print(f"v0.4 consumer sha256={digest}")

    run("fmt", "--manifest-path", str(COMPATIBILITY / "Cargo.toml"), "--all", "--", "--check")
    for edition in EDITIONS:
        package = f"fs2-compat-edition-{edition}"
        for subject in SUBJECTS:
            run(
                "check",
                "--manifest-path",
                str(COMPATIBILITY / "Cargo.toml"),
                "--package",
                package,
                "--no-default-features",
                "--features",
                subject,
                "--locked",
            )

    for subject in SUBJECTS:
        run(
            "run",
            "--manifest-path",
            str(COMPATIBILITY / "Cargo.toml"),
            "--package",
            "fs2-compat-edition-2015",
            "--no-default-features",
            "--features",
            subject,
            "--locked",
        )


if __name__ == "__main__":
    main()
