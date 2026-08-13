import json
import tempfile
import unittest
from pathlib import Path

from validate_coverage import ValidationError
from validate_coverage_metrics import load_totals, report_path, validate_full_metric


class CoverageMetricTests(unittest.TestCase):
    def test_loads_llvm_totals(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "coverage.json"
            report.write_text(json.dumps({"data": [{"totals": {"lines": {"count": 1}}}]}), encoding="utf-8")
            self.assertEqual(load_totals(report)["lines"]["count"], 1)

    def test_rejects_report_without_totals(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "coverage.json"
            report.write_text(json.dumps({"data": []}), encoding="utf-8")
            with self.assertRaises(ValidationError):
                load_totals(report)

    def test_resolves_only_manifest_coverage_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "coverage.json"
            report.write_text("{}", encoding="utf-8")
            manifest = {"artifacts": [{"path": "coverage.json"}]}
            self.assertEqual(report_path(root / "run-manifest.json", manifest), report)

    def test_rejects_missing_coverage_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValidationError):
                report_path(Path(temporary) / "run-manifest.json", {"artifacts": []})

    def test_requires_a_closed_raw_metric(self):
        with self.assertRaises(ValidationError):
            validate_full_metric(
                {"lines": {"count": 2, "covered": 1, "notcovered": 1, "percent": 50}},
                "lines",
                "fixture",
            )

    def test_accepts_a_closed_raw_metric(self):
        validate_full_metric(
            {"lines": {"count": 2, "covered": 2, "notcovered": 0, "percent": 100}},
            "lines",
            "fixture",
        )


if __name__ == "__main__":
    unittest.main()
