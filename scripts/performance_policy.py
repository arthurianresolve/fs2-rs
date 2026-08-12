"""Pure ordering and decision policy for paired performance evidence."""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from math import comb, isfinite


PASS = "pass"
NON_INFERIOR = "non-inferior"
INCONCLUSIVE_OR_SLOWER = "inconclusive-or-slower"
DEFAULT_NON_INFERIORITY_MARGIN = 0.0
ONE_SIDED_ALPHA = 0.05
CONFIDENCE_LEVEL = 1.0 - ONE_SIDED_ALPHA
MIN_EXACT_MEDIAN_SAMPLES = 5
MIN_GATING_REPLICATES = 6
PAIRS_PER_BUILD_REPLICATE = 4


@dataclass(frozen=True, slots=True)
class BenchmarkDecision:
    benchmark: str
    median_ratio: float
    lower_bound: float
    upper_bound: float
    decision: str

    @property
    def passed(self) -> bool:
        return self.decision in (PASS, NON_INFERIOR)


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    decisions: tuple[BenchmarkDecision, ...]
    non_inferiority_margin: float
    confidence_level: float
    replicate_count: int

    @property
    def non_inferiority_limit(self) -> float:
        return 1.0 + self.non_inferiority_margin

    @property
    def passed(self) -> bool:
        return bool(self.decisions) and all(
            decision.passed for decision in self.decisions
        )


@dataclass(frozen=True, slots=True)
class PairPlan:
    baseline_slot: str
    candidate_slot: str
    order: tuple[str, str]


def alternating_order(pair_index: int) -> tuple[str, str]:
    if pair_index < 0:
        raise ValueError("pair index must be non-negative")
    if pair_index % 2 == 0:
        return "baseline", "candidate"
    return "candidate", "baseline"


def pair_plan(pair_index: int) -> PairPlan:
    order = alternating_order(pair_index)
    if pair_index % PAIRS_PER_BUILD_REPLICATE < PAIRS_PER_BUILD_REPLICATE // 2:
        return PairPlan("a", "b", order)
    return PairPlan("b", "a", order)


def exact_median_bounds(ratios: list[float]) -> tuple[float, float]:
    """Return exact distribution-free one-sided confidence bounds for the median."""
    count = len(ratios)
    if count < MIN_EXACT_MEDIAN_SAMPLES:
        raise ValueError(
            f"at least {MIN_EXACT_MEDIAN_SAMPLES} independent replicates are required "
            f"for finite one-sided {CONFIDENCE_LEVEL:.0%} median bounds"
        )

    rank = 0
    tail_outcomes = 0
    all_outcomes = 1 << count
    for observations in range(count):
        tail_outcomes += comb(count, observations)
        if tail_outcomes / all_outcomes > ONE_SIDED_ALPHA:
            break
        rank = observations + 1

    ordered = sorted(ratios)
    return ordered[rank - 1], ordered[-rank]


def ratios_by_benchmark(
    paired_results: list[tuple[dict[str, float], dict[str, float]]],
) -> dict[str, list[float]]:
    if not paired_results:
        raise ValueError("at least one paired result is required")

    benchmark_names = paired_results[0][0].keys()
    if benchmark_names != paired_results[0][1].keys():
        raise ValueError("baseline and candidate produced different benchmark sets")
    if not benchmark_names:
        raise ValueError("at least one benchmark is required")

    for baseline, candidate in paired_results[1:]:
        if baseline.keys() != benchmark_names or candidate.keys() != benchmark_names:
            raise ValueError("paired results produced different benchmark sets")

    ratios = {benchmark: [] for benchmark in sorted(benchmark_names)}
    for benchmark in sorted(benchmark_names):
        for baseline, candidate in paired_results:
            baseline_estimate = baseline[benchmark]
            candidate_estimate = candidate[benchmark]
            if (
                not isfinite(baseline_estimate)
                or not isfinite(candidate_estimate)
                or baseline_estimate <= 0
                or candidate_estimate <= 0
            ):
                raise ValueError("benchmark estimates must be finite and positive")
            ratio = candidate_estimate / baseline_estimate
            if not isfinite(ratio):
                raise ValueError("benchmark ratios must be finite")
            ratios[benchmark].append(ratio)
    return ratios


def summarize_replicate(
    paired_results: list[tuple[dict[str, float], dict[str, float]]],
) -> tuple[dict[str, float], dict[str, float]]:
    ratios = ratios_by_benchmark(paired_results)
    baseline = {benchmark: 1.0 for benchmark in ratios}
    candidate = {
        benchmark: statistics.median(values) for benchmark, values in ratios.items()
    }
    return baseline, candidate


def evaluate(
    paired_results: list[tuple[dict[str, float], dict[str, float]]],
    non_inferiority_margin: float = DEFAULT_NON_INFERIORITY_MARGIN,
) -> ComparisonReport:
    if not 0 <= non_inferiority_margin < 1:
        raise ValueError("non-inferiority margin must be at least 0 and less than 1")

    non_inferiority_limit = 1 + non_inferiority_margin
    ratios = ratios_by_benchmark(paired_results)
    replicate_count = len(paired_results)
    if replicate_count < MIN_GATING_REPLICATES:
        raise ValueError(
            f"at least {MIN_GATING_REPLICATES} independent replicates are required "
            "for a gating decision"
        )

    decisions = []
    for benchmark, benchmark_ratios in ratios.items():

        median_ratio = statistics.median(benchmark_ratios)
        lower_bound, upper_bound = exact_median_bounds(benchmark_ratios)
        if upper_bound <= 1.0:
            decision = PASS
        elif upper_bound <= non_inferiority_limit:
            decision = NON_INFERIOR
        else:
            decision = INCONCLUSIVE_OR_SLOWER
        decisions.append(
            BenchmarkDecision(
                benchmark, median_ratio, lower_bound, upper_bound, decision
            )
        )

    return ComparisonReport(
        decisions=tuple(decisions),
        non_inferiority_margin=non_inferiority_margin,
        confidence_level=CONFIDENCE_LEVEL,
        replicate_count=replicate_count,
    )
