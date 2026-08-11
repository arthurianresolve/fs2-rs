import tempfile
import unittest
from pathlib import Path

from compare_performance import (
    BENCHMARKS,
    ROOT,
    benchmark_workload,
    criterion_output_root,
    prepare_subject,
    stage_repository,
    subject_arguments,
)
from performance_policy import (
    INCONCLUSIVE_OR_SLOWER,
    PASS,
    alternating_order,
    bootstrap_upper_bound,
    evaluate,
    pair_plan,
)


class PerformanceComparisonTests(unittest.TestCase):
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

    def test_bootstrap_upper_bound_is_deterministic(self):
        ratios = [0.98, 0.99, 1.0, 0.99, 0.98]

        self.assertEqual(
            bootstrap_upper_bound(ratios, 1_000),
            bootstrap_upper_bound(ratios, 1_000),
        )
        self.assertLessEqual(bootstrap_upper_bound(ratios, 1_000), 1.0)

    def test_evaluates_faster_candidate_as_pass(self):
        paired = [
            ({"operation": 100.0}, {"operation": 90.0}),
            ({"operation": 102.0}, {"operation": 91.0}),
        ]

        report = evaluate(paired, 1_000)

        self.assertTrue(report.passed)
        self.assertEqual(report.decisions[0].decision, PASS)

    def test_rejects_inconclusive_or_slower_candidate(self):
        paired = [
            ({"operation": 100.0}, {"operation": 101.0}),
            ({"operation": 99.0}, {"operation": 100.0}),
        ]

        report = evaluate(paired, 1_000)

        self.assertFalse(report.passed)
        self.assertEqual(report.decisions[0].decision, INCONCLUSIVE_OR_SLOWER)

    def test_rejects_mismatched_benchmark_sets(self):
        with self.assertRaisesRegex(ValueError, "different benchmark sets"):
            evaluate([({"first": 1.0}, {"second": 1.0})], 1_000)

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
