import copy
import json
import tempfile
import unittest
from pathlib import Path

from external_reference_resolver import (
    NON_CLAIMS,
    RECORD_TYPES,
    REGISTRY_PATH,
    ExternalReferenceError,
    load_json,
    resolve_registry,
    sha256,
    validate_registry,
)


class ExternalReferenceResolverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fs2-external-reference-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.coverage = self.root / "coverage"
        self.records = self.coverage / "external-records"
        self.records.mkdir(parents=True)
        self.registry_path = self.coverage / "external-reference-registry.json"
        self.registry = load_json(REGISTRY_PATH)

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def populate_all_records(self):
        entries = []
        for index, (record_type, status) in enumerate(RECORD_TYPES.items(), 1):
            identifier = f"EXT-{index:03d}"
            relative = f"coverage/external-records/{record_type}.json"
            record = {
                "record_type": record_type,
                "schema_version": 1,
                "id": identifier,
                "status": status,
                "issuer": {
                    "name": "Test Issuer",
                    "role": "authorized test role",
                    "organization": "Test Organization",
                },
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "revision": "1" * 40,
                "configuration_id": "CM-DO178C-0005",
                "decision": f"test decision for {record_type}",
                "effective_utc": "2026-08-14T05:00:00Z",
                "source_refs": ["controlled-test-source"],
                "non_claims": ["test fixture only"],
            }
            path = self.root / relative
            self.write_json(path, record)
            entries.append(
                {
                    "id": identifier,
                    "record_type": record_type,
                    "path": relative,
                    "sha256": sha256(path),
                    "expected_status": status,
                    "repository": "arthurianresolve/fs2-rs",
                    "branch": "DO-178C",
                    "revision": "1" * 40,
                    "configuration_id": "CM-DO178C-0005",
                }
            )
        self.registry["status"] = "draft"
        self.registry["records"] = entries
        self.registry["non_claims"] = NON_CLAIMS
        self.write_json(self.registry_path, self.registry)

    def test_checked_in_registry_is_valid_and_pending(self):
        validate_registry(load_json(REGISTRY_PATH))
        result = resolve_registry(REGISTRY_PATH)
        self.assertEqual(result["status"], "pending_missing_records")
        self.assertEqual(result["resolved_records"], [])
        self.assertEqual(result["missing_types"], self.registry["required_types"])

    def test_resolves_complete_typed_digest_bound_registry(self):
        self.populate_all_records()
        result = resolve_registry(self.registry_path)
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(len(result["resolved_records"]), len(RECORD_TYPES))
        self.assertEqual(result["missing_types"], [])

    def test_rejects_digest_mismatch(self):
        self.populate_all_records()
        self.registry["records"][0]["sha256"] = "0" * 64
        self.write_json(self.registry_path, self.registry)
        with self.assertRaises(ExternalReferenceError):
            resolve_registry(self.registry_path)

    def test_rejects_record_revision_mismatch(self):
        self.populate_all_records()
        first = self.registry["records"][0]
        path = self.root / first["path"]
        record = json.loads(path.read_text(encoding="utf-8"))
        record["revision"] = "2" * 40
        self.write_json(path, record)
        first["sha256"] = sha256(path)
        self.write_json(self.registry_path, self.registry)
        with self.assertRaises(ExternalReferenceError):
            resolve_registry(self.registry_path)

    def test_rejects_path_traversal(self):
        invalid = copy.deepcopy(self.registry)
        invalid["status"] = "draft"
        invalid["records"] = [
            {
                "id": "EXT-001",
                "record_type": "applicable_certification_basis",
                "path": "coverage/external-records/../outside.json",
                "sha256": "0" * 64,
                "expected_status": "approved",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "revision": "1" * 40,
                "configuration_id": "CM-DO178C-0005",
            }
        ]
        with self.assertRaises(ExternalReferenceError):
            validate_registry(invalid)

    def test_rejects_duplicate_record_type(self):
        self.populate_all_records()
        duplicate = copy.deepcopy(self.registry["records"][0])
        duplicate["id"] = "EXT-999"
        duplicate["path"] = "coverage/external-records/duplicate.json"
        self.registry["records"].append(duplicate)
        with self.assertRaises(ExternalReferenceError):
            validate_registry(self.registry)


if __name__ == "__main__":
    unittest.main()
