import copy
import json
import tempfile
import unittest
from pathlib import Path

from validate_object_analysis import (
    NON_CLAIMS,
    ObjectAnalysisError,
    expected_source_inventory,
    sha256,
    validate_manifest,
    validate_static,
)


class ObjectAnalysisValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fs2-object-analysis-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.manifest_path = self.root / "object-analysis-manifest.json"
        for name in (
            "archive-members.txt",
            "cargo.stderr.log",
            "cargo.stdout.jsonl",
            "defined-symbols.txt",
            "disassembly.txt",
            "fs2.rlib",
            "object-structure.txt",
        ):
            (self.root / name).write_bytes(f"retained {name}\n".encode())
        self.manifest = {
            "record_type": "object_analysis_run",
            "schema_version": 1,
            "run_id": "object-run-1",
            "repository": "arthurianresolve/fs2-rs",
            "branch": "DO-178C",
            "commit": "1" * 40,
            "tree": "2" * 40,
            "dirty": False,
            "cargo_lock_sha256": "3" * 64,
            "host": {
                "system": "Linux",
                "release": "test",
                "version": "test",
                "machine": "x86_64",
                "python": "3.14",
                "target": "x86_64-unknown-linux-gnu",
            },
            "target": "x86_64-unknown-linux-gnu",
            "object_format": "ELF",
            "profile": "release",
            "source_inventory": {
                "record_ref": "coverage/surface.json",
                "records": expected_source_inventory("x86_64-unknown-linux-gnu"),
            },
            "toolchain": {
                "requested": "1.88",
                "rustc": "rustc test",
                "cargo": "cargo test",
                "llvm_ar": "llvm-ar test",
                "llvm_nm": "llvm-nm test",
                "llvm_readobj": "llvm-readobj test",
                "llvm_objdump": "llvm-objdump test",
            },
            "command": [
                "cargo",
                "+1.88",
                "rustc",
                "--package",
                "fs2",
                "--lib",
                "--release",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--locked",
            ],
            "native_exits": {
                "cargo": 0,
                "llvm_ar": 0,
                "llvm_nm": 0,
                "llvm_readobj": 0,
                "llvm_objdump": 0,
            },
            "status": "pass",
            "analysis": {
                "archive_member_count": 2,
                "object_member_count": 1,
                "defined_symbol_count": 1,
                "fs2_symbol_observed": True,
                "source_object_mapping_status": "not_established_inventory_only",
                "generated_code_disposition": "pending_target_review",
            },
            "artifacts": [],
            "created_utc": "2026-08-14T05:00:00Z",
            "limitations": ["inventory only"],
            "non_claims": NON_CLAIMS,
        }
        self.write_manifest()

    def write_manifest(self):
        self.manifest["artifacts"] = [
            {
                "path": path.name,
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(self.root.iterdir(), key=lambda item: item.name)
            if path.name != self.manifest_path.name
        ]
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_static_controls_are_valid(self):
        validate_static()

    def test_accepts_complete_clean_native_manifest(self):
        validated = validate_manifest(
            self.manifest_path, expected_commit="1" * 40, require_pass=True
        )
        self.assertEqual(validated["object_format"], "ELF")

    def test_rejects_tampered_retained_output(self):
        (self.root / "disassembly.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_rejects_dirty_passing_manifest(self):
        self.manifest["dirty"] = True
        self.write_manifest()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_rejects_target_object_format_mismatch(self):
        self.manifest["object_format"] = "COFF"
        self.write_manifest()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_rejects_stale_source_inventory(self):
        self.manifest["source_inventory"]["records"] = copy.deepcopy(
            self.manifest["source_inventory"]["records"][:-1]
        )
        self.write_manifest()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_rejects_source_object_equivalence_overclaim(self):
        self.manifest["analysis"]["source_object_mapping_status"] = "established"
        self.write_manifest()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_rejects_missing_retained_output(self):
        (self.root / "fs2.rlib").unlink()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_rejects_unindexed_directory(self):
        (self.root / "empty").mkdir()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path)

    def test_require_pass_rejects_focused_only_run(self):
        self.manifest["status"] = "focused_only"
        self.manifest["dirty"] = True
        self.write_manifest()
        with self.assertRaises(ObjectAnalysisError):
            validate_manifest(self.manifest_path, require_pass=True)


if __name__ == "__main__":
    unittest.main()
