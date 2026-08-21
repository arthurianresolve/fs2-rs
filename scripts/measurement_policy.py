"""Load and validate the shared benchmark measurement policy."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
MEASUREMENT_POLICY_PATH = BENCHMARKS / "measurement-policy.json"

# Measurement geometry belongs to the schema validator rather than the
# statistical decision implementation.
PAIRS_PER_BUILD_REPLICATE = 4
MIN_GATING_REPLICATES = 6
MIN_GATING_PAIRS = PAIRS_PER_BUILD_REPLICATE * MIN_GATING_REPLICATES
MIN_DRIFT_CORRECTED_BLOCKS = 8


def _policy_section(policy: object, name: str) -> dict[str, object]:
    if not isinstance(policy, dict) or not isinstance(policy.get(name), dict):
        raise ValueError(f"measurement policy is missing section {name!r}")
    return policy[name]


def _policy_integer(section: dict[str, object], name: str, minimum: int) -> int:
    value = section.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(
            f"measurement policy field {name!r} must be an integer >= {minimum}"
        )
    return value


def _policy_fraction(policy: dict[str, object], name: str) -> float:
    value = policy.get(name)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 <= value < 1
    ):
        raise ValueError(
            f"measurement policy field {name!r} must be at least 0 and less than 1"
        )
    return float(value)


def _balanced_pair_order(section: dict[str, object], name: str) -> tuple[str, ...]:
    value = section.get("pair_order")
    order = tuple(value) if isinstance(value, list) else ()
    if (
        len(order) != PAIRS_PER_BUILD_REPLICATE
        or order.count("A") != PAIRS_PER_BUILD_REPLICATE // 2
        or order.count("B") != PAIRS_PER_BUILD_REPLICATE // 2
        or any(subject not in ("A", "B") for subject in order)
    ):
        raise ValueError(
            f"{name} pair_order must contain a balanced four-entry A/B order"
        )
    return order


def load_measurement_policy(path: Path = MEASUREMENT_POLICY_PATH) -> dict[str, object]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"unable to read measurement policy {path}: {error}") from error
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("measurement policy schema_version must be 1")
    _policy_fraction(policy, "non_inferiority_margin")

    criterion = _policy_section(policy, "criterion")
    _policy_integer(criterion, "sample_size", 10)
    _policy_integer(criterion, "warm_up_seconds", 1)
    _policy_integer(criterion, "measurement_seconds", 1)

    ref_to_ref = _policy_section(policy, "ref_to_ref")
    minimum_blocks = _policy_integer(
        ref_to_ref, "minimum_blocks", MIN_DRIFT_CORRECTED_BLOCKS
    )
    _policy_integer(ref_to_ref, "blocks", minimum_blocks)
    _policy_fraction(ref_to_ref, "max_pair_spread")
    _balanced_pair_order(ref_to_ref, "ref_to_ref")

    cross_crate = _policy_section(policy, "cross_crate")
    pairs = _policy_integer(cross_crate, "pairs", MIN_GATING_PAIRS)
    if pairs % (PAIRS_PER_BUILD_REPLICATE * 2) != 0:
        raise ValueError("cross_crate pairs must provide balanced build replicates")
    _balanced_pair_order(cross_crate, "cross_crate")
    return policy


MEASUREMENT_POLICY = load_measurement_policy()
CRITERION_POLICY = _policy_section(MEASUREMENT_POLICY, "criterion")
DEFAULT_NON_INFERIORITY_MARGIN = float(
    MEASUREMENT_POLICY["non_inferiority_margin"]
)
PAIR_ORDER = tuple(_policy_section(MEASUREMENT_POLICY, "cross_crate")["pair_order"])
DEFAULT_PAIRS = int(_policy_section(MEASUREMENT_POLICY, "cross_crate")["pairs"])
DEFAULT_SAMPLE_SIZE = int(CRITERION_POLICY["sample_size"])
DEFAULT_WARM_UP_TIME = float(CRITERION_POLICY["warm_up_seconds"])
DEFAULT_MEASUREMENT_TIME = float(CRITERION_POLICY["measurement_seconds"])
