import tempfile
import unittest
from pathlib import Path

import compare_paired_stats as paired


class PairedStatsTests(unittest.TestCase):
    def test_exact_one_sided_median_bounds_for_eight_replicates(self):
        lower, upper, achieved = paired.exact_median_bounds(range(1, 9), 0.95)

        self.assertEqual(lower, 2)
        self.assertEqual(upper, 7)
        self.assertAlmostEqual(achieved, 247 / 256)

    def test_parse_measurements_accepts_rotated_complete_output(self):
        rows = ["\t".join(paired.FIELDS)]
        for metric in reversed(sorted(paired.METRICS)):
            rows.append(f"{metric}\t10\t11\t1.01\t0.001\t5\t1\t0")

        records = paired.parse_measurements("\n".join(rows), "ab-run01", "ab")

        self.assertEqual(len(records), len(paired.METRICS))
        self.assertTrue(all(record["run"] == "ab-run01" for record in records))

    def test_parse_measurements_rejects_missing_metric(self):
        text = "\t".join(paired.FIELDS) + "\nfree_space\t10\t11\t1.01\t0.001\t5\t0\t0\n"

        with self.assertRaisesRegex(paired.BenchmarkError, "did not emit every"):
            paired.parse_measurements(text, "ab-run01", "ab")

    def test_summary_uses_upper_bound_for_non_regression(self):
        records = []
        for metric in paired.METRICS:
            for run, ratio in enumerate((0.99, 1.0, 1.0, 1.0, 1.0, 1.01, 1.019, 1.03), 1):
                records.append({"run": run, "mode": "ab", "metric": metric, "ratio": ratio})

        summary, passed = paired.summarize(records, "ab", 8, 0.95, 0.02)

        self.assertTrue(passed)
        self.assertTrue(all(item["exact_upper_ratio"] == 1.019 for item in summary))

    def test_aa_summary_rejects_directional_bias(self):
        records = []
        ratios = (1.0, 1.0, 1.0, 1.0, 1.03, 1.03, 1.03, 1.03)
        for metric in paired.METRICS:
            for run, ratio in enumerate(ratios, 1):
                records.append({"run": run, "mode": "aa", "metric": metric, "ratio": ratio})

        _, passed = paired.summarize(records, "aa", 8, 0.95, 0.02)

        self.assertFalse(passed)

    def test_manifest_keeps_exact_revisions_in_distinct_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            baseline = root / "baseline.git"
            candidate = root / "candidate.git"
            baseline.mkdir()
            candidate.mkdir()

            paired.write_manifest(project, baseline, candidate, "a" * 40, "b" * 40)

            manifest = (project / "Cargo.toml").read_text(encoding="ascii")
            self.assertIn(baseline.as_uri(), manifest)
            self.assertIn(candidate.as_uri(), manifest)
            self.assertIn("a" * 40, manifest)
            self.assertIn("b" * 40, manifest)


if __name__ == "__main__":
    unittest.main()
