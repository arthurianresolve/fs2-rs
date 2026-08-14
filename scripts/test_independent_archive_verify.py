import ast
import tempfile
import unittest
from pathlib import Path

from assurance_archive import create_archive, write_json
from independent_archive_verify import (
    IndependentVerificationError,
    NativeDigest,
    verify_package,
)


class IndependentArchiveVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fs2-independent-archive-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.package = self.root / "package"
        self.control = self.root / "archive-control.json"
        self.commit = "1" * 40
        self.tree = "2" * 40
        write_json(
            self.control,
            {
                "record_type": "assurance_archive_control",
                "schema_version": 1,
                "internal_staging": {
                    "required_artifacts": {
                        "object-analysis-linux": {
                            "manifest": "object-analysis-manifest.json",
                            "kind": "object_analysis",
                            "profile": None,
                            "target": "x86_64-unknown-linux-gnu",
                        }
                    }
                },
            },
        )
        artifact = self.inputs / "object-analysis-linux"
        artifact.mkdir(parents=True)
        write_json(
            artifact / "object-analysis-manifest.json",
            {
                "record_type": "object_analysis_run",
                "schema_version": 1,
                "run_id": "object-run-1",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "commit": self.commit,
                "tree": self.tree,
                "dirty": False,
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "status": "pass",
            },
        )
        (artifact / "object.txt").write_text("retained object\n", encoding="utf-8")
        create_archive(
            input_root=self.inputs,
            output_dir=self.package,
            control_record_path=self.control,
            repository="arthurianresolve/fs2-rs",
            branch="DO-178C",
            commit=self.commit,
            tree=self.tree,
            workflow_run_id="12345",
            created_utc="2026-08-14T05:00:00Z",
        )

    def test_round_trip_uses_native_digest_utility(self):
        result_path = self.root / "independent-result.json"
        result = verify_package(
            package_dir=self.package,
            expected_commit=self.commit,
            result_path=result_path,
            verified_utc="2026-08-14T05:01:00Z",
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["file_count"], 2)
        self.assertIn(result["digest_utility"]["name"], {"certutil", "sha256sum", "shasum", "openssl"})
        self.assertTrue(result_path.is_file())

    def test_verifier_has_no_primary_archive_import(self):
        source = Path(__file__).with_name("independent_archive_verify.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertNotIn("assurance_archive", imports)

    def test_native_digest_detects_known_file(self):
        path = self.root / "known.txt"
        path.write_text("abc", encoding="ascii")
        self.assertEqual(
            NativeDigest().digest(path),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_rejects_tampered_evidence(self):
        path = self.package / "evidence" / "object-analysis-linux" / "object.txt"
        path.write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(IndependentVerificationError):
            verify_package(package_dir=self.package, expected_commit=self.commit)

    def test_rejects_extra_package_file(self):
        (self.package / "extra.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaises(IndependentVerificationError):
            verify_package(package_dir=self.package, expected_commit=self.commit)

    def test_rejects_unindexed_empty_directory(self):
        (self.package / "evidence" / "object-analysis-linux" / "empty").mkdir()
        with self.assertRaises(IndependentVerificationError):
            verify_package(package_dir=self.package, expected_commit=self.commit)

    def test_rejects_wrong_expected_commit(self):
        with self.assertRaises(IndependentVerificationError):
            verify_package(package_dir=self.package, expected_commit="3" * 40)

    def test_rejects_tampered_packaged_control(self):
        path = self.package / "control" / "archive-control.json"
        control = __import__("json").loads(path.read_text(encoding="utf-8"))
        control["internal_staging"]["changed"] = True
        write_json(path, control)
        with self.assertRaises(IndependentVerificationError):
            verify_package(package_dir=self.package, expected_commit=self.commit)


if __name__ == "__main__":
    unittest.main()
