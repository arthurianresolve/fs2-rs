import copy
import json
import unittest

from validate_mcdc import ValidationError, validate_record


class McdcValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open("coverage/mcdc.json", encoding="utf-8") as source:
            cls.record = json.load(source)
        with open("coverage/verification-inventory.json", encoding="utf-8") as source:
            cls.verification_ids = {item["id"] for item in json.load(source)["verifications"]}

    def allocation_decision(self, record):
        return next(
            decision
            for decision in record["decisions"]
            if decision["id"] == "MCDC-ALLOC-EXTEND"
        )

    def test_current_record_is_valid(self):
        validate_record(self.record, self.verification_ids)

    def test_rejects_changed_source_digest(self):
        invalid = copy.deepcopy(self.record)
        invalid["decisions"][0]["source_sha256"] = "0" * 64
        with self.assertRaises(ValidationError):
            validate_record(invalid, self.verification_ids)

    def test_rejects_missing_condition_occurrence(self):
        invalid = copy.deepcopy(self.record)
        self.allocation_decision(invalid)["observations"][0]["condition_states"].pop("C2")
        with self.assertRaises(ValidationError):
            validate_record(invalid, self.verification_ids)

    def test_rejects_pair_that_changes_a_non_target(self):
        invalid = copy.deepcopy(self.record)
        self.allocation_decision(invalid)["pairs"][0]["modified_observation"] = (
            "OBS-ALLOC-EXTEND-TF"
        )
        with self.assertRaises(ValidationError):
            validate_record(invalid, self.verification_ids)

    def test_rejects_pair_without_decision_change(self):
        invalid = copy.deepcopy(self.record)
        self.allocation_decision(invalid)["observations"][1]["decision"] = True
        with self.assertRaises(ValidationError):
            validate_record(invalid, self.verification_ids)


if __name__ == "__main__":
    unittest.main()
