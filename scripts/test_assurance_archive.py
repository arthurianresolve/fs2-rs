import copy
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from assurance_archive import (  # noqa: E402
    ArchiveError,
    create_archive,
    filesystem_path,
    read_json,
    verify_archive,
    write_json,
)


class AssuranceArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.input_root = self.root / "input"
        self.output_dir = self.root / "package"
        self.control_path = self.root / "archive-control.json"
        self.commit = "1" * 40
        self.tree = "2" * 40

        write_json(
            self.control_path,
            {
                "record_type": "assurance_archive_control",
                "schema_version": 1,
                "internal_staging": {
                    "required_artifacts": {
                        "coverage-linux": {
                            "manifest": "run-manifest.json",
                            "kind": "coverage",
                            "profile": "stable",
                            "target": "x86_64-unknown-linux-gnu",
                        },
                        "windows-native-faults": {
                            "manifest": "windows-native-fault-manifest.json",
                            "kind": "windows_native_fault",
                            "profile": None,
                            "target": "x86_64-pc-windows-msvc",
                        },
                        "object-analysis-linux": {
                            "manifest": "object-analysis-manifest.json",
                            "kind": "object_analysis",
                            "profile": None,
                            "target": "x86_64-unknown-linux-gnu",
                        },
                    }
                },
            },
        )
        coverage = self.input_root / "coverage-linux"
        coverage.mkdir(parents=True)
        write_json(
            coverage / "run-manifest.json",
            {
                "run_id": "coverage-run-1",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "commit": self.commit,
                "tree": self.tree,
                "dirty": False,
                "target": "x86_64-unknown-linux-gnu",
                "profile": "stable",
                "status": "pass",
            },
        )
        (coverage / "report.json").write_text('{"lines":10}\n', encoding="utf-8")
        native = self.input_root / "windows-native-faults"
        native.mkdir(parents=True)
        write_json(
            native / "windows-native-fault-manifest.json",
            {
                "record_type": "windows_native_fault_run",
                "schema_version": 1,
                "run_id": "windows-native-run-1",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "commit": self.commit,
                "tree": self.tree,
                "dirty": False,
                "target": "x86_64-pc-windows-msvc",
                "status": "pass",
            },
        )
        objects = self.input_root / "object-analysis-linux"
        objects.mkdir(parents=True)
        write_json(
            objects / "object-analysis-manifest.json",
            {
                "record_type": "object_analysis_run",
                "schema_version": 1,
                "run_id": "object-analysis-run-1",
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

    def create(self) -> Path:
        return create_archive(
            input_root=self.input_root,
            output_dir=self.output_dir,
            control_record_path=self.control_path,
            repository="arthurianresolve/fs2-rs",
            branch="DO-178C",
            commit=self.commit,
            tree=self.tree,
            workflow_run_id="12345",
            created_utc="2026-08-13T12:00:00Z",
        )

    def test_round_trip_writes_digest_bound_retrieval_result(self):
        manifest_path = self.create()
        result_path = self.root / "retrieval-result.json"

        result = verify_archive(
            package_dir=self.output_dir,
            expected_commit=self.commit,
            control_record_path=self.control_path,
            result_path=result_path,
            verified_utc="2026-08-13T12:01:00Z",
        )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["file_count"], 4)
        self.assertEqual(read_json(result_path), result)
        self.assertTrue(manifest_path.is_file())

    def test_rejects_tampered_file(self):
        self.create()
        artifact = self.output_dir / "evidence" / "coverage-linux" / "report.json"
        artifact.write_text('{"lines":11}\n', encoding="utf-8")

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_missing_file(self):
        self.create()
        artifact = self.output_dir / "evidence" / "coverage-linux" / "report.json"
        artifact.unlink()

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_unindexed_extra_file(self):
        self.create()
        artifact = self.output_dir / "evidence" / "coverage-linux" / "extra.txt"
        artifact.write_text("extra\n", encoding="utf-8")

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_unindexed_empty_directory(self):
        self.create()
        (self.output_dir / "evidence" / "coverage-linux" / "empty").mkdir()

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_unindexed_package_root_file(self):
        self.create()
        (self.output_dir / "extra.txt").write_text("extra\n", encoding="utf-8")

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_wrong_source_manifest_profile(self):
        manifest_path = self.input_root / "coverage-linux" / "run-manifest.json"
        manifest = read_json(manifest_path)
        manifest["profile"] = "branch"
        write_json(manifest_path, manifest)

        with self.assertRaises(ArchiveError):
            self.create()

    def test_rejects_manifest_path_traversal(self):
        manifest_path = self.create()
        manifest = read_json(manifest_path)
        manifest["files"][0]["path"] = "../outside.txt"
        write_json(manifest_path, manifest)

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_duplicate_manifest_path(self):
        manifest_path = self.create()
        manifest = read_json(manifest_path)
        manifest["files"].append(copy.deepcopy(manifest["files"][0]))
        write_json(manifest_path, manifest)

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_wrong_expected_commit(self):
        self.create()

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit="3" * 40)

    def test_rejects_control_record_drift(self):
        self.create()
        control = read_json(self.control_path)
        control["internal_staging"]["note"] = "changed"
        write_json(self.control_path, control)

        with self.assertRaises(ArchiveError):
            verify_archive(
                package_dir=self.output_dir,
                expected_commit=self.commit,
                control_record_path=self.control_path,
            )

    def test_rejects_tampered_packaged_control_record(self):
        self.create()
        packaged = self.output_dir / "control" / "archive-control.json"
        control = read_json(packaged)
        control["internal_staging"]["note"] = "tampered"
        write_json(packaged, control)

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_extra_packaged_control_file(self):
        self.create()
        (self.output_dir / "control" / "extra.json").write_text(
            "{}\n", encoding="utf-8"
        )

        with self.assertRaises(ArchiveError):
            verify_archive(package_dir=self.output_dir, expected_commit=self.commit)

    def test_rejects_missing_source_artifact(self):
        missing = self.input_root / "coverage-linux"
        for path in missing.iterdir():
            path.unlink()
        missing.rmdir()

        with self.assertRaises(ArchiveError):
            self.create()

    def test_rejects_overlapping_input_and_output(self):
        with self.assertRaises(ArchiveError):
            create_archive(
                input_root=self.input_root,
                output_dir=self.input_root / "package",
                control_record_path=self.control_path,
                repository="arthurianresolve/fs2-rs",
                branch="DO-178C",
                commit=self.commit,
                tree=self.tree,
                workflow_run_id="12345",
            )

    def test_rejects_nonempty_output(self):
        self.output_dir.mkdir()
        (self.output_dir / "keep.txt").write_text("keep\n", encoding="utf-8")

        with self.assertRaises(ArchiveError):
            self.create()

    def test_rejects_symlink_input_when_supported(self):
        link = self.input_root / "coverage-linux" / "linked.json"
        try:
            link.symlink_to(self.input_root / "coverage-linux" / "report.json")
        except OSError:
            self.skipTest("symbolic links are unavailable on this host")

        with self.assertRaises(ArchiveError):
            self.create()

    def test_round_trip_supports_long_artifact_paths(self):
        self.addCleanup(
            shutil.rmtree, filesystem_path(self.root), ignore_errors=True
        )
        parts = [f"segment-{index}-abcdefghijklmnopqrstuvwxyz" for index in range(8)]
        path = self.input_root / "coverage-linux"
        for part in parts:
            path /= part
        path /= "retained-object-file.rcgu.o"
        filesystem_path(path.parent).mkdir(parents=True)
        filesystem_path(path).write_bytes(b"retained object bytes")

        self.create()
        result = verify_archive(
            package_dir=self.output_dir,
            expected_commit=self.commit,
            control_record_path=self.control_path,
        )

        self.assertEqual(result["status"], "pass")
        if os.name == "nt":
            self.assertGreater(len(os.path.abspath(path)), 260)


if __name__ == "__main__":
    unittest.main()
