import argparse
import contextlib
import io
import json
import subprocess
import sys
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
    freeze_benchmark_inputs,
    freeze_repositories,
    ensure_no_transient_failures,
    non_inferiority_margin,
    parse_arguments,
    prepare_subject,
    stage_repository,
    subject_arguments,
    transient_failure_records,
    transient_failure_count,
    unescape_failure_label,
    write_json_report,
)
from performance_policy import (
    CONFIDENCE_LEVEL,
    INCONCLUSIVE_OR_SLOWER,
    NON_INFERIOR,
    PASS,
    ComparisonReport,
    alternating_order,
    evaluate,
    exact_median_bounds,
    pair_plan,
    ratios_by_benchmark,
    summarize_replicate,
)
from performance_harness import run_logged_process
from evaluate_ref_performance import (
    drift_corrected_ratios_by_metric,
    find_unstable_blocks,
)
from measurement_policy import load_measurement_policy


def paired_operation_ratios(
    *ratios: float,
) -> list[tuple[dict[str, float], dict[str, float]]]:
    return [({"operation": 1.0}, {"operation": ratio}) for ratio in ratios]


class PerformanceComparisonTests(unittest.TestCase):
    def test_logged_process_preserves_streams_and_native_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"

            exit_code = run_logged_process(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys; print('stdout marker'); "
                        "print('stderr marker', file=sys.stderr); sys.exit(7)"
                    ),
                ],
                root,
                stdout,
                stderr,
            )

            self.assertEqual(exit_code, 7)
            self.assertEqual(stdout.read_text(encoding="utf-8").strip(), "stdout marker")
            self.assertEqual(stderr.read_text(encoding="utf-8").strip(), "stderr marker")

    def test_flags_asymmetric_abba_block_without_hiding_consistent_slowdown(self):
        def records(*ratios: float) -> list[dict[str, object]]:
            return [
                {
                    "benchmark": "fs2",
                    "metric": "total_space",
                    "block": 1,
                    "ratio": ratio,
                }
                for ratio in ratios
            ]

        self.assertEqual(len(find_unstable_blocks(records(1.25, 0.99), 0.20)), 1)
        self.assertEqual(find_unstable_blocks(records(1.10, 1.08), 0.20), [])

        with self.assertRaisesRegex(ValueError, "max pair spread"):
            find_unstable_blocks(records(1.0, 1.0), 1.0)

    def test_abba_block_ratio_cancels_opposing_directional_drift(self):
        records = [
            {
                "benchmark": "fs2",
                "metric": "total_space",
                "block": 1,
                "ratio": ratio,
            }
            for ratio in (1.10, 0.90)
        ]

        ratios = drift_corrected_ratios_by_metric(records)

        self.assertAlmostEqual(ratios["fs2::total_space"][0], (1.10 * 0.90) ** 0.5)

    def test_abba_block_ratio_preserves_consistent_slowdown(self):
        records = [
            {
                "benchmark": "fs2",
                "metric": "total_space",
                "block": 1,
                "ratio": ratio,
            }
            for ratio in (1.08, 1.10)
        ]

        ratios = drift_corrected_ratios_by_metric(records)

        self.assertGreater(ratios["fs2::total_space"][0], 1.08)

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

    def test_non_inferiority_margin_defaults_to_controlled_policy(self):
        args = parse_arguments(
            ["--baseline", str(ROOT), "--candidate", str(ROOT.parent)]
        )

        policy = load_measurement_policy()
        self.assertEqual(args.non_inferiority_margin, 0.02)
        self.assertEqual(
            args.non_inferiority_margin, policy["non_inferiority_margin"]
        )

    def test_measurement_defaults_match_the_controlled_policy(self):
        args = parse_arguments(["--baseline", str(ROOT), "--candidate", str(ROOT.parent)])

        policy = load_measurement_policy()
        self.assertEqual(args.pairs, policy["cross_crate"]["pairs"])
        self.assertEqual(args.sample_size, policy["criterion"]["sample_size"])
        self.assertEqual(args.warm_up_time, policy["criterion"]["warm_up_seconds"])
        self.assertEqual(args.measurement_time, policy["criterion"]["measurement_seconds"])
        self.assertEqual(policy["ref_to_ref"]["blocks"], 8)
        self.assertEqual(policy["ref_to_ref"]["minimum_blocks"], 8)

    def test_transient_failure_count_reads_machine_markers(self):
        output = (
            "[fs2-bench] FS2_BENCH_FAILURE\tfree_space\t3\n"
            "[fs2-bench] FS2_BENCH_FAILURE\ttotal_space\t2\n"
        )

        self.assertEqual(
            transient_failure_records(output),
            [
                {"label": "free_space", "count": 3},
                {"label": "total_space", "count": 2},
            ],
        )
        self.assertEqual(transient_failure_count(output), 5)

    def test_failure_labels_round_trip_the_machine_encoding(self):
        self.assertEqual(unescape_failure_label(r"a\\b\t\r\n"), "a\\b\t\r\n")
        self.assertEqual(
            transient_failure_records(
                "[fs2-bench] FS2_BENCH_FAILURE\ta\\\\b\\t\\r\\n\t1\n"
            ),
            [{"label": "a\\b\t\r\n", "count": 1}],
        )

    def test_transient_failures_block_performance_decisions(self):
        with self.assertRaisesRegex(ValueError, "no performance decision"):
            ensure_no_transient_failures([{"label": "free_space", "count": 1}])

    def test_measurement_policy_rejects_invalid_pair_order(self):
        policy = load_measurement_policy()
        policy["cross_crate"]["pair_order"] = ["A", "A", "A", "B"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "measurement-policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "pair_order"):
                load_measurement_policy(path)

    def test_measurement_policy_rejects_invalid_non_inferiority_margin(self):
        policy = load_measurement_policy()
        policy["non_inferiority_margin"] = 1.0
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "measurement-policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non_inferiority_margin"):
                load_measurement_policy(path)

    def test_measurement_policy_rejects_too_few_abba_blocks(self):
        policy = load_measurement_policy()
        policy["ref_to_ref"]["blocks"] = 7
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "measurement-policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "blocks"):
                load_measurement_policy(path)

    def test_json_report_replacement_is_atomic_at_the_path_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            write_json_report(path, {"schema_version": 1, "valid": False})

            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(report["valid"])
            self.assertFalse(list(path.parent.glob("*.tmp")))

    @mock.patch("performance_harness.subprocess.run")
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

    @mock.patch("performance_harness.subprocess.run")
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

    @mock.patch("performance_harness.subprocess.run")
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

    def test_explicit_zero_margin_rejects_a_slower_candidate(self):
        paired = paired_operation_ratios(1.001, 1.002, 1.003, 1.004, 1.005, 1.006)

        report = evaluate(paired, non_inferiority_margin=0.0)

        self.assertFalse(report.passed)

    def test_default_margin_accepts_a_candidate_within_two_percent(self):
        paired = paired_operation_ratios(1.001, 1.002, 1.003, 1.004, 1.005, 1.006)

        report = evaluate(paired)

        self.assertTrue(report.passed)
        self.assertEqual(report.decisions[0].decision, NON_INFERIOR)

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

    def test_rejects_empty_benchmark_set(self):
        with self.assertRaisesRegex(ValueError, "at least one benchmark"):
            evaluate([({}, {})] * 6)

    def test_empty_report_cannot_pass(self):
        report = ComparisonReport((), 0.0, CONFIDENCE_LEVEL, 6)

        self.assertFalse(report.passed)

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

    def test_frozen_benchmark_inputs_do_not_observe_later_edits(self):
        with tempfile.TemporaryDirectory(prefix="fs2-freeze-test-") as temporary:
            temporary_root = Path(temporary)
            source = temporary_root / "source"
            benchmarks = source / "benchmarks"
            benches = benchmarks / "benches"
            benches.mkdir(parents=True)
            workload = benches / "fs2.rs"
            workload.write_text("fn original() {}\n", encoding="utf-8")
            lockfile = source / "Cargo.lock"
            lockfile.write_text("original lock\n", encoding="utf-8")

            frozen_benchmarks, frozen_lockfile = freeze_benchmark_inputs(
                temporary_root / "frozen", benchmarks, lockfile
            )
            workload.write_text("fn changed() {}\n", encoding="utf-8")
            lockfile.write_text("changed lock\n", encoding="utf-8")

            self.assertEqual(
                (frozen_benchmarks / "benches" / "fs2.rs").read_text(
                    encoding="utf-8"
                ),
                "fn original() {}\n",
            )
            self.assertEqual(
                frozen_lockfile.read_text(encoding="utf-8"),
                "original lock\n",
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
