import tempfile
import unittest
from pathlib import Path

from compare_performance import (
    BENCHMARKS,
    ROOT,
    benchmark_workload,
    bootstrap_upper_bound,
    prepare_subject,
    subject_arguments,
)


class PerformanceComparisonTests(unittest.TestCase):
    def test_bootstrap_upper_bound_is_deterministic(self):
        ratios = [0.98, 0.99, 1.0, 0.99, 0.98]

        self.assertEqual(
            bootstrap_upper_bound(ratios, 1_000),
            bootstrap_upper_bound(ratios, 1_000),
        )
        self.assertLessEqual(bootstrap_upper_bound(ratios, 1_000), 1.0)

    def test_prepared_subject_reuses_exact_workload(self):
        with tempfile.TemporaryDirectory(prefix="fs2-performance-test-") as temporary:
            manifest, _ = prepare_subject(Path(temporary), "subject", ROOT)
            copied = manifest.parent / "benches" / "fs2.rs"

            self.assertEqual(copied.read_bytes(), (BENCHMARKS / "benches" / "fs2.rs").read_bytes())
            self.assertIn(ROOT.as_posix(), manifest.read_text(encoding="utf-8"))

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
