import tempfile
import unittest
from pathlib import Path

from compare_performance import BENCHMARKS, ROOT, bootstrap_upper_bound, prepare_subject


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


if __name__ == "__main__":
    unittest.main()
