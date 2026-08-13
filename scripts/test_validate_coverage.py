import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_coverage import canonical_text_sha256, rustc_host_target, sha256
from validate_coverage import (
    COVERAGE,
    ROOT,
    ValidationError,
    canonical_source_sha256,
    load_json,
    validate_context,
    validate_decisions,
    validate_evidence_index,
    validate_gap_register,
    validate_manifest,
    validate_policy,
    validate_requirements,
    validate_static_records,
    validate_surface,
    validate_tool_assessment,
    check_status,
    parse_cargo_test_list,
)


class CoverageRecordTests(unittest.TestCase):
    def setUp(self):
        self.context = load_json(COVERAGE / "assurance-context.json")
        self.requirements = load_json(COVERAGE / "requirements.json")
        self.surface = load_json(COVERAGE / "surface.json")
        self.decisions = load_json(COVERAGE / "decision-inventory.json")
        self.policy = load_json(COVERAGE / "policy.json")
        self.tool = load_json(COVERAGE / "tool-assessment.json")

    def test_static_records_are_valid(self):
        validate_static_records()

    def test_context_rejects_certification_credit(self):
        invalid = copy.deepcopy(self.context)
        invalid["certification_credit"] = "accepted"

        with self.assertRaises(ValidationError):
            validate_context(invalid)

    def test_requirements_reject_unknown_source(self):
        invalid = copy.deepcopy(self.requirements)
        invalid["requirements"][0]["source_refs"] = ["src/missing.rs:1"]

        with self.assertRaises(ValidationError):
            validate_requirements(invalid)

    def test_surface_rejects_stale_hash(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][0]["sha256"] = "0" * 64

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_surface_rejects_implicit_exclusion(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][0]["denominator"] = "excluded_with_classification"

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_surface_rejects_overlapping_spans(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][1]["line_spans"] = ["80-234"]

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_surface_rejects_test_module_declared_as_production(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][2]["line_spans"] = ["1-171"]
        invalid["records"][3]["line_spans"] = ["173-354"]

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_decision_inventory_rejects_unmapped_requirement(self):
        invalid = copy.deepcopy(self.decisions)
        invalid["decisions"][0]["requirement_ids"] = ["REQ-NOT-MAPPED"]

        with self.assertRaises(ValidationError):
            validate_decisions(invalid, validate_requirements(self.requirements))

    def test_decision_inventory_rejects_mcdc_disposition_drift(self):
        invalid = copy.deepcopy(self.decisions)
        invalid["decisions"][1]["mcdc_disposition"] = "assessment_open_no_record"

        with self.assertRaises(ValidationError):
            validate_decisions(invalid, validate_requirements(self.requirements))

    def test_decision_inventory_accepts_error_propagation_disposition(self):
        valid = copy.deepcopy(self.decisions)
        valid["decisions"][7]["mcdc_disposition"] = "not_applicable_error_propagation"

        validate_decisions(valid, validate_requirements(self.requirements))

    def test_policy_keeps_branch_and_mcdc_separate(self):
        invalid = copy.deepcopy(self.policy)
        invalid["metrics"]["branch"]["mcdc_claim"] = True

        with self.assertRaises(ValidationError):
            validate_policy(invalid)

    def test_tool_assessment_rejects_qualification_claim(self):
        invalid = copy.deepcopy(self.tool)
        invalid["qualification_status"] = "qualified"

        with self.assertRaises(ValidationError):
            validate_tool_assessment(invalid)

    def test_evidence_index_rejects_local_promotion(self):
        invalid = load_json(COVERAGE / "evidence-index.json")
        invalid["runs"][0]["disposition"] = "promoted"

        with self.assertRaises(ValidationError):
            validate_evidence_index(invalid)

    def test_gap_register_requires_closed_gap_basis(self):
        invalid = load_json(COVERAGE / "gap-register.json")
        invalid["gaps"][0].pop("closure_basis")

        with self.assertRaises(ValidationError):
            validate_gap_register(invalid)

    def test_invalid_fixture_is_rejected(self):
        invalid = load_json(COVERAGE / "fixtures" / "invalid-unknown-status.json")

        with self.assertRaises(ValidationError):
            check_status(invalid, "coverage/fixtures/invalid-unknown-status.json")

    def test_source_hash_is_line_ending_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "lf.rs"
            crlf = root / "crlf.rs"
            lf.write_bytes(b"fn main() {\n    println!(\"ok\");\n}\n")
            crlf.write_bytes(b"fn main() {\r\n    println!(\"ok\");\r\n}\r\n")

            self.assertEqual(canonical_source_sha256(lf), canonical_source_sha256(crlf))

    def test_lock_hash_is_line_ending_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "Cargo.lock"
            crlf = root / "Cargo-crlf.lock"
            lf.write_bytes(b"version = 3\n[[package]]\nname = \"fs2\"\n")
            crlf.write_bytes(b"version = 3\r\n[[package]]\r\nname = \"fs2\"\r\n")

            self.assertEqual(canonical_text_sha256(lf), canonical_text_sha256(crlf))

    def test_extracts_rustc_host_target(self):
        self.assertEqual(
            rustc_host_target("rustc test\nhost: x86_64-pc-windows-msvc\n"),
            "x86_64-pc-windows-msvc",
        )

    def test_parses_grouped_cargo_test_listing(self):
        output = """
        Running unittests src\\lib.rs
        allocation::tests::example: test
        test result: ok
        Running tests\\upstream_compat.rs
        upstream_surface: test
        Doc-tests fs2
        src\\stats.rs - stats::FsStatsQuery (line 31): test
        """

        self.assertEqual(
            parse_cargo_test_list(output),
            {
                "unit": {"allocation::tests::example"},
                "integration": {"upstream_surface"},
                "doctest": {"src/stats.rs:FsStatsQuery (line 31)"},
            },
        )


class RunManifestTests(unittest.TestCase):
    def make_manifest(self, run_root: Path) -> dict:
        report = run_root / "coverage.json"
        stdout = run_root / "stdout.log"
        stderr = run_root / "stderr.log"
        report.write_text('{"data": []}\n', encoding="utf-8")
        stdout.write_text("test output\n", encoding="utf-8")
        stderr.write_text("warning output\n", encoding="utf-8")
        (run_root / "windows-provider.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "api": "GetDiskSpaceInformationW",
                    "library": "kernel32.dll",
                    "module_present": True,
                    "symbol_present": True,
                    "outcome": "available",
                    "error_raw_os": None,
                }
            ),
            encoding="utf-8",
        )
        lock_hash = sha256(ROOT / "Cargo.lock")
        return {
            "run_id": "test-run",
            "repository": "arthurianresolve/fs2-rs",
            "branch": "DO-178C",
            "commit": "d1e0e22eaed156e2420058f52f119e10330e24df",
            "tree": "0" * 40,
            "dirty": False,
            "cargo_lock_sha256": lock_hash,
            "host": {
                "system": "test",
                "release": "test",
                "machine": "test",
                "python": "test",
                "version": "test",
                "target": "x86_64-pc-windows-msvc",
            },
            "target": "x86_64-pc-windows-msvc",
            "profile": "stable",
            "requested_toolchain": "stable",
            "resolved_toolchain": "rustc test",
            "cargo_llvm_cov": "cargo-llvm-cov test",
            "command": ["cargo", "+stable", "llvm-cov"],
            "environment": {"CARGO_INCREMENTAL": "0"},
            "provider": {
                "schema_version": 1,
                "api": "GetDiskSpaceInformationW",
                "library": "kernel32.dll",
                "module_present": True,
                "symbol_present": True,
                "outcome": "available",
                "error_raw_os": None,
            },
            "native_exit": 0,
            "status": "pass",
            "artifacts": [],
        }

    def test_manifest_accepts_complete_pass_record(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["artifacts"] = [
                {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                for name in ("coverage.json", "stdout.log", "stderr.log", "windows-provider.json")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            validate_manifest(path, manifest["commit"])

    def test_manifest_rejects_pass_with_dirty_tree(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["dirty"] = True
            manifest["artifacts"] = [
                {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                for name in ("coverage.json", "stdout.log", "stderr.log", "windows-provider.json")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)

    def test_manifest_rejects_pass_with_non_native_target(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["host"]["target"] = "x86_64-unknown-linux-gnu"
            manifest["artifacts"] = [
                {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                for name in ("coverage.json", "stdout.log", "stderr.log", "windows-provider.json")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)

    def test_manifest_rejects_pass_without_provider_artifact(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["artifacts"] = [
                {
                    "path": name,
                    "sha256": sha256(run_root / name),
                    "bytes": (run_root / name).stat().st_size,
                }
                for name in ("coverage.json", "stdout.log", "stderr.log")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)


if __name__ == "__main__":
    unittest.main()
