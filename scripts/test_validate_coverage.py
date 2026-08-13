import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_coverage import sha256
from validate_coverage import (
    COVERAGE,
    ROOT,
    ValidationError,
    canonical_source_sha256,
    load_json,
    validate_context,
    validate_decisions,
    validate_manifest,
    validate_policy,
    validate_requirements,
    validate_static_records,
    validate_surface,
    validate_tool_assessment,
    check_status,
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

    def test_decision_inventory_rejects_unmapped_requirement(self):
        invalid = copy.deepcopy(self.decisions)
        invalid["decisions"][0]["requirement_ids"] = ["REQ-NOT-MAPPED"]

        with self.assertRaises(ValidationError):
            validate_decisions(invalid, validate_requirements(self.requirements))

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


class RunManifestTests(unittest.TestCase):
    def make_manifest(self, run_root: Path) -> dict:
        report = run_root / "coverage.json"
        stdout = run_root / "stdout.log"
        stderr = run_root / "stderr.log"
        report.write_text('{"data": []}\n', encoding="utf-8")
        stdout.write_text("test output\n", encoding="utf-8")
        stderr.write_text("warning output\n", encoding="utf-8")
        lock_hash = sha256(ROOT / "Cargo.lock")
        return {
            "run_id": "test-run",
            "repository": "arthurianresolve/fs2-rs",
            "branch": "DO-178C",
            "commit": "d1e0e22eaed156e2420058f52f119e10330e24df",
            "tree": "0" * 40,
            "dirty": False,
            "cargo_lock_sha256": lock_hash,
            "host": {"system": "test", "release": "test", "machine": "test", "python": "test"},
            "target": "x86_64-pc-windows-msvc",
            "profile": "stable",
            "requested_toolchain": "stable",
            "resolved_toolchain": "rustc test",
            "cargo_llvm_cov": "cargo-llvm-cov test",
            "command": ["cargo", "+stable", "llvm-cov"],
            "environment": {"CARGO_INCREMENTAL": "0"},
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
                for name in ("coverage.json", "stdout.log", "stderr.log")
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
                for name in ("coverage.json", "stdout.log", "stderr.log")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)


if __name__ == "__main__":
    unittest.main()
