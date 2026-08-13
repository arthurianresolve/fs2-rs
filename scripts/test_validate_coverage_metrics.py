import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_coverage import ValidationError
from validate_coverage_metrics import (
    load_totals,
    report_path,
    validate_full_metric,
    validate_matrix_runs,
    validate_profile_configuration,
)


class CoverageMetricTests(unittest.TestCase):
    def manifest(self, profile, target, toolchain, commit="a" * 40, tree="b" * 40, lock="c" * 64):
        return {
            "profile": profile,
            "target": target,
            "requested_toolchain": toolchain,
            "commit": commit,
            "tree": tree,
            "cargo_lock_sha256": lock,
        }

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

    def test_accepts_complete_consistent_matrix(self):
        expected = {
            ("stable", "x86_64-unknown-linux-gnu"): "1.88",
            ("branch", "x86_64-unknown-linux-gnu"): "nightly-2026-07-23",
        }
        manifests = [
            self.manifest(profile, target, toolchain)
            for (profile, target), toolchain in expected.items()
        ]
        validate_matrix_runs(manifests, expected)

    def test_rejects_incomplete_matrix(self):
        expected = {
            ("stable", "x86_64-unknown-linux-gnu"): "1.88",
            ("branch", "x86_64-unknown-linux-gnu"): "nightly-2026-07-23",
        }
        with self.assertRaises(ValidationError):
            validate_matrix_runs([self.manifest("stable", "x86_64-unknown-linux-gnu", "1.88")], expected)

    def test_rejects_mixed_provenance(self):
        expected = {
            ("stable", "x86_64-unknown-linux-gnu"): "1.88",
            ("branch", "x86_64-unknown-linux-gnu"): "nightly-2026-07-23",
        }
        manifests = [
            self.manifest("stable", "x86_64-unknown-linux-gnu", "1.88"),
            self.manifest("branch", "x86_64-unknown-linux-gnu", "nightly-2026-07-23", tree="d" * 40),
        ]
        with self.assertRaises(ValidationError):
            validate_matrix_runs(manifests, expected)

    def test_accepts_condition_instrumentation_contract(self):
        manifest = self.manifest("condition", "x86_64-unknown-linux-gnu", "nightly-2026-07-23")
        manifest["command"] = ["cargo", "llvm-cov", "--branch"]
        manifest["environment"] = {"RUSTFLAGS": "-Z coverage-options=condition"}
        validate_profile_configuration(manifest)

    def test_rejects_condition_profile_without_instrumentation_flag(self):
        manifest = self.manifest("condition", "x86_64-unknown-linux-gnu", "nightly-2026-07-23")
        manifest["command"] = ["cargo", "llvm-cov", "--branch"]
        manifest["environment"] = {}
        with self.assertRaises(ValidationError):
            validate_profile_configuration(manifest)


if __name__ == "__main__":
    unittest.main()
