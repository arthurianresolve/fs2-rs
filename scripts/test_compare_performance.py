import argparse
import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from compare_performance import (
    BENCHMARKS,
    ROOT,
    balanced_pair_count,
    benchmark_workload,
    cargo,
    criterion_output_root,
    freeze_repositories,
    non_inferiority_margin,
    parse_arguments,
    prepare_subject,
    stage_repository,
    subject_arguments,
)
from performance_policy import (
    CONFIDENCE_LEVEL,
    INCONCLUSIVE_OR_SLOWER,
    NON_INFERIOR,
    PASS,
    alternating_order,
    evaluate,
    exact_median_bounds,
    pair_plan,
    ratios_by_benchmark,
    summarize_replicate,
)


def paired_operation_ratios(
    *ratios: float,
) -> list[tuple[dict[str, float], dict[str, float]]]:
    return [({"operation": 1.0}, {"operation": ratio}) for ratio in ratios]


class PerformanceComparisonTests(unittest.TestCase):
    def test_pair_count_balances_logical_build_placement(self):
        self.assertEqual(balanced_pair_count("24"), 24)
        self.assertEqual(balanced_pair_count("32"), 32)
        for value in ("8", "12", "16"):
            with self.assertRaisesRegex(
                argparse.ArgumentTypeError, "at least six independent build replicates"
            ):
                balanced_pair_count(value)

    def test_non_inferiority_margin_is_a_fraction(self):
        self.assertEqual(non_inferiority_margin("0"), 0)
        self.assertEqual(non_inferiority_margin("0.05"), 0.05)
        for value in ("-0.01", "1"):
            with self.assertRaisesRegex(
                argparse.ArgumentTypeError, "at least 0 and less than 1"
            ):
                non_inferiority_margin(value)

    def test_non_inferiority_option_reaches_comparison_namespace(self):
        args = parse_arguments(
            [
                "--baseline",
                str(ROOT),
                "--candidate",
                str(ROOT),
                "--non-inferiority-margin",
                "0.03",
            ]
        )

        self.assertEqual(args.non_inferiority_margin, 0.03)

    def test_non_inferiority_margin_defaults_to_zero(self):
        args = parse_arguments(
            ["--baseline", str(ROOT), "--candidate", str(ROOT.parent)]
        )

        self.assertEqual(args.non_inferiority_margin, 0.0)

    @mock.patch("compare_performance.subprocess.run")
    def test_successful_cargo_output_is_quiet(self, run):
        run.return_value = subprocess.CompletedProcess(
            ["cargo", "check"],
            0,
            stdout="routine Cargo progress\n",
        )
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            captured = cargo(["check"])

        self.assertEqual(captured, "routine Cargo progress\n")
        self.assertEqual(output.getvalue(), "")

    @mock.patch("compare_performance.subprocess.run")
    def test_failed_cargo_output_remains_visible(self, run):
        run.return_value = subprocess.CompletedProcess(
            ["cargo", "check"],
            1,
            stdout="compiler diagnostic\n",
        )
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(SystemExit, "command exited with 1"):
                cargo(["check"])

        self.assertIn("compiler diagnostic", output.getvalue())

    @mock.patch("compare_performance.subprocess.run")
    def test_cargo_merges_environment_overrides(self, run):
        run.return_value = subprocess.CompletedProcess(["cargo", "check"], 0, stdout="")

        cargo(["check"], {"CRITERION_HOME": "criterion-output"})

        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["CRITERION_HOME"], "criterion-output")
        self.assertIn("PATH", environment)

    def test_alternates_subject_order(self):
        self.assertEqual(alternating_order(0), ("baseline", "candidate"))
        self.assertEqual(alternating_order(1), ("candidate", "baseline"))
        self.assertEqual(alternating_order(2), ("baseline", "candidate"))

    def test_counterbalances_subject_slots_and_order(self):
        plans = [pair_plan(index) for index in range(4)]

        self.assertEqual(
            [(plan.baseline_slot, plan.candidate_slot) for plan in plans],
            [("a", "b"), ("a", "b"), ("b", "a"), ("b", "a")],
        )
        self.assertEqual(
            [plan.order for plan in plans],
            [
                ("baseline", "candidate"),
                ("candidate", "baseline"),
                ("baseline", "candidate"),
                ("candidate", "baseline"),
            ],
        )

    def test_exact_median_bounds_use_extremes_for_six_replicates(self):
        self.assertEqual(
            exact_median_bounds([0.97, 0.98, 0.99, 1.0, 1.01, 1.02]),
            (0.97, 1.02),
        )

    def test_exact_median_bounds_tighten_at_eight_replicates(self):
        self.assertEqual(
            exact_median_bounds([0.93, 0.95, 0.97, 0.99, 1.01, 1.03, 1.05, 1.07]),
            (0.95, 1.05),
        )

    def test_exact_median_bounds_reject_insufficient_replicates(self):
        with self.assertRaisesRegex(ValueError, "at least 5 independent replicates"):
            exact_median_bounds([0.98, 0.99, 1.0, 1.01])

    def test_evaluates_faster_candidate_as_pass(self):
        paired = paired_operation_ratios(0.94, 0.95, 0.96, 0.97, 0.98, 0.99)

        report = evaluate(paired)

        self.assertTrue(report.passed)
        self.assertEqual(report.decisions[0].decision, PASS)

    def test_accepts_explicit_one_percent_non_inferiority(self):
        paired = paired_operation_ratios(0.995, 0.998, 1.001, 1.004, 1.007, 1.009)

        report = evaluate(paired, non_inferiority_margin=0.01)

        self.assertTrue(report.passed)
        self.assertEqual(report.decisions[0].decision, NON_INFERIOR)
        self.assertEqual(report.non_inferiority_margin, 0.01)
        self.assertEqual(report.non_inferiority_limit, 1.01)
        self.assertEqual(report.confidence_level, CONFIDENCE_LEVEL)
        self.assertEqual(report.replicate_count, 6)

    def test_rejects_candidate_outside_explicit_margin(self):
        paired = paired_operation_ratios(0.99, 1.0, 1.005, 1.008, 1.01, 1.011)

        report = evaluate(paired, non_inferiority_margin=0.01)

        self.assertFalse(report.passed)
        self.assertEqual(report.decisions[0].decision, INCONCLUSIVE_OR_SLOWER)

    def test_default_zero_margin_rejects_a_slower_candidate(self):
        paired = paired_operation_ratios(1.001, 1.002, 1.003, 1.004, 1.005, 1.006)

        report = evaluate(paired)

        self.assertFalse(report.passed)

    def test_evaluate_rejects_insufficient_replicates(self):
        with self.assertRaisesRegex(ValueError, "at least 6 independent replicates"):
            evaluate(paired_operation_ratios(0.98, 0.99, 1.0, 1.01, 1.02))

    def test_rejects_invalid_non_inferiority_margin(self):
        paired = paired_operation_ratios(1.0, 1.0, 1.0, 1.0, 1.0, 1.0)

        for margin in (-0.01, 1.0):
            with self.assertRaisesRegex(ValueError, "non-inferiority margin"):
                evaluate(paired, non_inferiority_margin=margin)

    def test_rejects_mismatched_benchmark_sets(self):
        with self.assertRaisesRegex(ValueError, "different benchmark sets"):
            evaluate([({"first": 1.0}, {"second": 1.0})] * 6)

    def test_rejects_non_finite_benchmark_estimates(self):
        for value in (float("nan"), float("inf")):
            with self.assertRaisesRegex(ValueError, "finite and positive"):
                ratios_by_benchmark([({"operation": value}, {"operation": 1.0})])

    def test_rejects_non_finite_benchmark_ratios(self):
        with self.assertRaisesRegex(ValueError, "benchmark ratios must be finite"):
            ratios_by_benchmark([({"operation": 5e-324}, {"operation": 1e308})])

    def test_computes_ratios_by_benchmark(self):
        paired = [
            ({"operation": 100.0}, {"operation": 98.0}),
            ({"operation": 200.0}, {"operation": 202.0}),
        ]

        self.assertEqual(ratios_by_benchmark(paired), {"operation": [0.98, 1.01]})

    def test_summarizes_each_build_replicate_once(self):
        paired = [
            ({"operation": 100.0}, {"operation": 98.0}),
            ({"operation": 100.0}, {"operation": 99.0}),
            ({"operation": 100.0}, {"operation": 101.0}),
            ({"operation": 100.0}, {"operation": 102.0}),
        ]

        baseline, candidate = summarize_replicate(paired)

        self.assertEqual(baseline, {"operation": 1.0})
        self.assertEqual(candidate, {"operation": 1.0})

    def test_prepared_subject_reuses_exact_workload(self):
        with tempfile.TemporaryDirectory(prefix="fs2-performance-test-") as temporary:
            manifest, _ = prepare_subject(Path(temporary), "subject", ROOT)
            copied = manifest.parent / "benches" / "fs2.rs"

            self.assertEqual(copied.read_bytes(), (BENCHMARKS / "benches" / "fs2.rs").read_bytes())
            self.assertIn(ROOT.as_posix(), manifest.read_text(encoding="utf-8"))

    def test_prepared_subject_accepts_explicit_target(self):
        with tempfile.TemporaryDirectory(prefix="fs2-performance-test-") as temporary:
            root = Path(temporary)
            target = root / "cache" / "subject-a"

            manifest, prepared_target = prepare_subject(
                root / "work",
                "subject",
                ROOT,
                target=target,
            )

            self.assertEqual(prepared_target, target)
            self.assertEqual(
                criterion_output_root(manifest),
                manifest.parent / "target" / "criterion",
            )

    def test_staged_repository_preserves_sources_without_build_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="fs2-stage-test-") as temporary:
            temporary_root = Path(temporary)
            repository = temporary_root / "repository"
            (repository / "src").mkdir(parents=True)
            (repository / ".git").mkdir()
            (repository / "target").mkdir()
            source = b"pub fn staged() {}\n"
            (repository / "src" / "lib.rs").write_bytes(source)

            staged = stage_repository(temporary_root / "staged", "subject-a", repository)

            self.assertEqual((staged / "src" / "lib.rs").read_bytes(), source)
            self.assertFalse((staged / ".git").exists())
            self.assertFalse((staged / "target").exists())

    def test_frozen_repositories_do_not_observe_later_source_edits(self):
        with tempfile.TemporaryDirectory(prefix="fs2-freeze-test-") as temporary:
            temporary_root = Path(temporary)
            repository = temporary_root / "repository"
            (repository / "src").mkdir(parents=True)
            source = repository / "src" / "lib.rs"
            source.write_text("pub fn original() {}\n", encoding="utf-8")

            frozen = freeze_repositories(
                temporary_root / "frozen",
                {"candidate": repository},
            )
            source.write_text("pub fn changed() {}\n", encoding="utf-8")

            frozen_source = frozen["candidate"] / "src" / "lib.rs"
            self.assertEqual(
                frozen_source.read_text(encoding="utf-8"),
                "pub fn original() {}\n",
            )

    def test_legacy_benchmark_workload_is_available(self):
        workload = benchmark_workload("fs2_legacy")

        self.assertTrue(workload.is_file())
        self.assertNotIn("FsStatsQuery", workload.read_text(encoding="utf-8"))

    def test_cross_crate_workload_selects_subject_feature(self):
        workload = benchmark_workload("fs_compat")

        self.assertTrue(workload.is_file())
        self.assertNotIn("duplicate", workload.read_text(encoding="utf-8"))
        self.assertEqual(
            subject_arguments("fs_compat", "fs4"),
            ["--no-default-features", "--features", "subject-fs4"],
        )

    def test_fs4_requires_cross_crate_workload(self):
        with self.assertRaisesRegex(SystemExit, "does not support package fs4"):
            subject_arguments("fs2_legacy", "fs4")

    def test_prepared_fs4_subject_uses_cargo_package_alias(self):
        with tempfile.TemporaryDirectory(prefix="fs4-performance-test-") as temporary:
            manifest, _ = prepare_subject(Path(temporary), "subject", ROOT, "fs4")

            text = manifest.read_text(encoding="utf-8")
            self.assertIn('fs2 = { package = "fs4", path = ', text)
            self.assertIn('features = ["sync"]', text)


if __name__ == "__main__":
    unittest.main()
