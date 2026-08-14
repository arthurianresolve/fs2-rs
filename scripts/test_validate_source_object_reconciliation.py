import copy
import json
import unittest

from validate_source_object_reconciliation import (
    ROOT,
    ReconciliationError,
    validate_record,
)


class SourceObjectReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(
            (ROOT / "coverage" / "source-object-reconciliation.json").read_text(
                encoding="utf-8"
            )
        )

    def test_current_reconciliation_is_valid(self):
        validate_record(self.record)

    def test_rejects_stale_source_symbol_count(self):
        invalid = copy.deepcopy(self.record)
        invalid["targets"][0]["source_records"][0]["direct_symbol_count"] = 1
        with self.assertRaises(ReconciliationError):
            validate_record(invalid)

    def test_rejects_object_code_coverage_overclaim(self):
        invalid = copy.deepcopy(self.record)
        invalid["object_code_coverage"]["status"] = "closed"
        with self.assertRaises(ReconciliationError):
            validate_record(invalid)


if __name__ == "__main__":
    unittest.main()
