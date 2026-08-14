import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from archive_transport import (
    NON_CLAIMS,
    ArchiveTransportError,
    publish,
    retrieve,
    validate_endpoint_schema,
)
from assurance_archive import ArchiveError, create_archive, write_json
from independent_archive_verify import IndependentVerificationError


class ArchiveTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fs2-archive-transport-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.package = self.root / "package"
        self.endpoint_root = self.root / "endpoint"
        self.endpoint_root.mkdir()
        self.endpoint_path = self.root / "endpoint.json"
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
                        "coverage-linux": {
                            "manifest": "run-manifest.json",
                            "kind": "coverage",
                            "profile": "stable",
                            "target": "x86_64-unknown-linux-gnu",
                        }
                    }
                },
            },
        )
        artifact = self.inputs / "coverage-linux"
        artifact.mkdir(parents=True)
        write_json(
            artifact / "run-manifest.json",
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
        (artifact / "coverage.json").write_text("{}\n", encoding="utf-8")
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
        self.endpoint = {
            "record_type": "assurance_archive_filesystem_endpoint",
            "schema_version": 1,
            "endpoint_id": "trial-endpoint-1",
            "status": "technical_trial_only",
            "provider_kind": "filesystem_directory_v1",
            "destination_root": str(self.endpoint_root.resolve()),
            "archive_owner": None,
            "access_control_approval": None,
            "backup_policy": None,
            "retention_period": None,
            "retention_authority": None,
            "disposition_authority": None,
            "non_claims": NON_CLAIMS,
        }
        self.write_endpoint()

    def write_endpoint(self):
        self.endpoint_path.write_text(
            json.dumps(self.endpoint, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_publish_and_retrieve_are_verified_and_non_promotional(self):
        published = publish(
            package_dir=self.package,
            endpoint_path=self.endpoint_path,
            expected_commit=self.commit,
        )
        output = self.root / "retrieved"
        retrieved = retrieve(
            package_id=published["package_id"],
            output_dir=output,
            endpoint_path=self.endpoint_path,
            expected_commit=self.commit,
        )
        self.assertEqual(published["status"], "pass_technical_trial")
        self.assertEqual(retrieved["status"], "pass_technical_trial")
        self.assertFalse(published["external_archive_verified"])
        self.assertTrue((output / "assurance-archive-manifest.json").is_file())

    def test_publish_refuses_overwrite(self):
        publish(
            package_dir=self.package,
            endpoint_path=self.endpoint_path,
            expected_commit=self.commit,
        )
        with self.assertRaises(ArchiveTransportError):
            publish(
                package_dir=self.package,
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
            )

    def test_publish_lock_rejects_competing_writer(self):
        package_id = f"ASSURANCE-{self.commit[:12]}-12345"
        receipts = self.endpoint_root / "receipts"
        receipts.mkdir()
        (receipts / f".{package_id}.publish.lock").write_text("", encoding="utf-8")
        with self.assertRaises(ArchiveTransportError):
            publish(
                package_dir=self.package,
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
            )
        self.assertFalse((self.endpoint_root / "packages" / package_id).exists())

    def test_publish_rolls_back_package_if_endpoint_receipt_fails(self):
        package_id = f"ASSURANCE-{self.commit[:12]}-12345"
        with patch(
            "archive_transport.write_json_exclusive",
            side_effect=ArchiveTransportError("injected receipt failure"),
        ):
            with self.assertRaises(ArchiveTransportError):
                publish(
                    package_dir=self.package,
                    endpoint_path=self.endpoint_path,
                    expected_commit=self.commit,
                )
        self.assertFalse((self.endpoint_root / "packages" / package_id).exists())
        self.assertFalse(
            (self.endpoint_root / "receipts" / f".{package_id}.publish.lock").exists()
        )

    def test_publish_rejects_result_inside_source_package(self):
        with self.assertRaises(ArchiveTransportError):
            publish(
                package_dir=self.package,
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
                result_path=self.package / "transport-result.json",
            )

    def test_retrieve_rejects_output_inside_endpoint(self):
        published = publish(
            package_dir=self.package,
            endpoint_path=self.endpoint_path,
            expected_commit=self.commit,
        )
        with self.assertRaises(ArchiveTransportError):
            retrieve(
                package_id=published["package_id"],
                output_dir=self.endpoint_root / "retrieved",
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
            )

    def test_retrieve_refuses_existing_output(self):
        published = publish(
            package_dir=self.package,
            endpoint_path=self.endpoint_path,
            expected_commit=self.commit,
        )
        output = self.root / "retrieved"
        output.mkdir()
        with self.assertRaises(ArchiveTransportError):
            retrieve(
                package_id=published["package_id"],
                output_dir=output,
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
            )

    def test_retrieve_rejects_tampered_archived_package(self):
        published = publish(
            package_dir=self.package,
            endpoint_path=self.endpoint_path,
            expected_commit=self.commit,
        )
        retained = (
            self.endpoint_root
            / "packages"
            / published["package_id"]
            / "evidence"
            / "coverage-linux"
            / "coverage.json"
        )
        retained.write_text('{"tampered":true}\n', encoding="utf-8")
        with self.assertRaises(
            (ArchiveTransportError, ArchiveError, IndependentVerificationError)
        ):
            retrieve(
                package_id=published["package_id"],
                output_dir=self.root / "retrieved",
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
            )

    def test_endpoint_cannot_claim_archive_authority(self):
        self.endpoint["archive_owner"] = "unapproved owner"
        self.write_endpoint()
        with self.assertRaises(ArchiveTransportError):
            publish(
                package_dir=self.package,
                endpoint_path=self.endpoint_path,
                expected_commit=self.commit,
            )

    def test_checked_in_endpoint_schema_is_valid(self):
        validate_endpoint_schema(
            json.loads(
                (Path(__file__).parents[1] / "coverage" / "external-archive-endpoint.schema.json").read_text(
                    encoding="utf-8"
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
