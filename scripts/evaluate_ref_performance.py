#!/usr/bin/env python3
"""Apply the canonical performance policy to ref-to-ref pair records."""

from __future__ import annotations

import argparse
import json
from math import exp, isfinite, log
from pathlib import Path

from measurement_policy import MEASUREMENT_POLICY
from performance_policy import DEFAULT_NON_INFERIORITY_MARGIN, evaluate_ratios


DEFAULT_MAX_PAIR_SPREAD = float(MEASUREMENT_POLICY["ref_to_ref"]["max_pair_spread"])


def load_pair_records(path: Path) -> list[dict[str, object]]:
    records = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(records, list):
        raise ValueError("pair record input must be a JSON array")
    return records


def ratios_by_metric(records: list[dict[str, object]]) -> dict[str, list[float]]:
    ratios: dict[str, list[float]] = {}
    for record in records:
        key = f"{record['benchmark']}::{record['metric']}"
        ratios.setdefault(key, []).append(float(record["ratio"]))
    return ratios


def directional_ratios_by_block(
    records: list[dict[str, object]],
) -> dict[tuple[str, str, int], list[float]]:
    grouped: dict[tuple[str, str, int], list[float]] = {}
    for record in records:
        key = (str(record["benchmark"]), str(record["metric"]), int(record["block"]))
        grouped.setdefault(key, []).append(float(record["ratio"]))

    for (benchmark, metric, block), ratios in grouped.items():
        if len(ratios) != 2 or any(
            not isfinite(ratio) or ratio <= 0 for ratio in ratios
        ):
            raise ValueError(
                f"{benchmark}::{metric} block {block} must contain two "
                "finite positive ratios"
            )
    return grouped


def drift_corrected_ratios_by_metric(
    records: list[dict[str, object]],
) -> dict[str, list[float]]:
    ratios: dict[str, list[float]] = {}
    for (benchmark, metric, _), directional in sorted(
        directional_ratios_by_block(records).items()
    ):
        key = f"{benchmark}::{metric}"
        block_ratio = exp((log(directional[0]) + log(directional[1])) / 2.0)
        ratios.setdefault(key, []).append(block_ratio)
    return ratios


def find_unstable_blocks(
    records: list[dict[str, object]], max_pair_spread: float
) -> list[dict[str, object]]:
    if not 0 <= max_pair_spread < 1:
        raise ValueError("max pair spread must be at least 0 and less than 1")

    unstable = []
    for (benchmark, metric, block), ratios in sorted(
        directional_ratios_by_block(records).items()
    ):
        spread = max(ratios) / min(ratios) - 1.0
        if spread > max_pair_spread:
            unstable.append(
                {
                    "benchmark": benchmark,
                    "metric": metric,
                    "block": block,
                    "ratios": ratios,
                    "pair_spread": spread,
                    "max_pair_spread": max_pair_spread,
                }
            )
    return unstable


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--non-inferiority-margin",
        type=float,
        default=DEFAULT_NON_INFERIORITY_MARGIN,
    )
    parser.add_argument(
        "--max-pair-spread",
        type=float,
        default=DEFAULT_MAX_PAIR_SPREAD,
    )
    args = parser.parse_args()

    records = load_pair_records(args.pairs)
    directional_ratios = ratios_by_metric(records)
    block_ratios = drift_corrected_ratios_by_metric(records)
    report = evaluate_ratios(block_ratios, args.non_inferiority_margin)
    unstable_blocks = find_unstable_blocks(records, args.max_pair_spread)
    summary = []
    for decision in report.decisions:
        benchmark, metric = decision.benchmark.split("::", 1)
        summary.append(
            {
                "benchmark": benchmark,
                "metric": metric,
                "pair_count": len(directional_ratios[decision.benchmark]),
                "block_count": report.replicate_count,
                "median_ratio": decision.median_ratio,
                "exact_lower95_ratio": decision.lower_bound,
                "exact_upper95_ratio": decision.upper_bound,
                "ratios": block_ratios[decision.benchmark],
                "directional_ratios": directional_ratios[decision.benchmark],
                "disposition": decision.decision,
            }
        )

    output = {
        "non_inferiority_margin": report.non_inferiority_margin,
        "non_inferiority_limit": report.non_inferiority_limit,
        "confidence_level": report.confidence_level,
        "replication_unit": "drift-corrected-abba-block",
        "unstable_blocks": unstable_blocks,
        "summary": summary,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
