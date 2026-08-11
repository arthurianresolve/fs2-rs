"""Pure ordering and decision policy for paired performance evidence."""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass


PASS = "pass"
INCONCLUSIVE_OR_SLOWER = "inconclusive-or-slower"


@dataclass(frozen=True, slots=True)
class BenchmarkDecision:
    benchmark: str
    median_ratio: float
    upper_bound: float
    decision: str

    @property
    def passed(self) -> bool:
        return self.decision == PASS


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    decisions: tuple[BenchmarkDecision, ...]

    @property
    def passed(self) -> bool:
        return all(decision.passed for decision in self.decisions)


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
    if pair_index % 4 < 2:
        return PairPlan("a", "b", order)
    return PairPlan("b", "a", order)


def bootstrap_upper_bound(ratios: list[float], resamples: int) -> float:
    if not ratios:
        raise ValueError("at least one ratio is required")
    if resamples < 1:
        raise ValueError("at least one bootstrap resample is required")

    rng = random.Random(0)
    count = len(ratios)
    medians = [
        statistics.median(ratios[rng.randrange(count)] for _ in range(count))
        for _ in range(resamples)
    ]
    medians.sort()
    return medians[min(len(medians) - 1, int(0.95 * len(medians)))]


def evaluate(
    paired_results: list[tuple[dict[str, float], dict[str, float]]],
    bootstrap_resamples: int,
) -> ComparisonReport:
    if not paired_results:
        raise ValueError("at least one paired result is required")

    benchmark_names = paired_results[0][0].keys()
    if benchmark_names != paired_results[0][1].keys():
        raise ValueError("baseline and candidate produced different benchmark sets")

    for baseline, candidate in paired_results[1:]:
        if baseline.keys() != benchmark_names or candidate.keys() != benchmark_names:
            raise ValueError("paired results produced different benchmark sets")

    decisions = []
    for benchmark in sorted(benchmark_names):
        ratios = []
        for baseline, candidate in paired_results:
            baseline_estimate = baseline[benchmark]
            candidate_estimate = candidate[benchmark]
            if baseline_estimate <= 0 or candidate_estimate <= 0:
                raise ValueError("benchmark estimates must be positive")
            ratios.append(candidate_estimate / baseline_estimate)

        median_ratio = statistics.median(ratios)
        upper_bound = bootstrap_upper_bound(ratios, bootstrap_resamples)
        decision = PASS if upper_bound <= 1.0 else INCONCLUSIVE_OR_SLOWER
        decisions.append(
            BenchmarkDecision(benchmark, median_ratio, upper_bound, decision)
        )

    return ComparisonReport(tuple(decisions))
