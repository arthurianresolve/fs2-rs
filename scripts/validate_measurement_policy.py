#!/usr/bin/env python3
"""Validate the benchmark policy used by all measurement runners."""

from __future__ import annotations

import argparse
from pathlib import Path

from measurement_policy import MEASUREMENT_POLICY_PATH, load_measurement_policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, default=MEASUREMENT_POLICY_PATH)
    args = parser.parse_args()
    load_measurement_policy(args.path)
    print(f"measurement policy valid: {args.path}")


if __name__ == "__main__":
    main()
