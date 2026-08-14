import copy
import unittest

from validate_assurance_decisions import (
    ROOT,
    AssuranceDecisionError,
    load_json,
    validate_independence_plan,
    validate_software_level,
    validate_static,
)


class AssuranceDecisionValidationTests(unittest.TestCase):
    def setUp(self):
        self.level = load_json(ROOT / "coverage" / "software-level-assignment.json")
        self.independence = load_json(ROOT / "coverage" / "independence-plan.json")

    def test_static_records_are_valid(self):
        validate_static()

    def test_dal_b_is_an_assignment_not_only_a_planning_target(self):
        self.assertEqual(self.level["assigned_software_level"], "DAL_B")
        self.assertEqual(self.level["determination"]["status"], "determined_internal")

    def test_rejects_undetermined_level(self):
        invalid = copy.deepcopy(self.level)
        invalid["assigned_software_level"] = None
        with self.assertRaises(AssuranceDecisionError):
            validate_software_level(invalid)

    def test_rejects_implementation_agent_approval_authority(self):
        invalid = copy.deepcopy(self.independence)
        invalid["roles"]["implementation_agent"]["decision_authority"] = True
        with self.assertRaises(AssuranceDecisionError):
            validate_independence_plan(invalid)

    def test_rejects_service_account_as_decision_authority(self):
        invalid = copy.deepcopy(self.independence)
        invalid["roles"]["publication_service_account"]["decision_authority"] = True
        with self.assertRaises(AssuranceDecisionError):
            validate_independence_plan(invalid)

    def test_rejects_premature_review_decision(self):
        invalid = copy.deepcopy(self.independence)
        invalid["review_gate"].update(
            {
                "status": "awaiting_implementation_review",
                "decision": "approve",
                "decision_ref": None,
                "decided_at": None,
            }
        )
        with self.assertRaises(AssuranceDecisionError):
            validate_independence_plan(invalid)

    def test_accepts_change_set_bound_approval_without_self_referential_commit(self):
        approved = copy.deepcopy(self.independence)
        approved["review_gate"].update(
            {
                "status": "approved_for_atomic_publication",
                "candidate_change_digest": "a" * 64,
                "decision": "approve",
                "decision_ref": "conversation-confirmation:test",
                "decided_at": "2026-08-14T05:00:00Z",
            }
        )
        validate_independence_plan(approved)

    def test_rejects_shared_service_account_conflict_overstatement(self):
        invalid = copy.deepcopy(self.independence)
        invalid["conflict_assessment"]["conflicts_of_interest"] = ["unresolved"]
        with self.assertRaises(AssuranceDecisionError):
            validate_independence_plan(invalid)


if __name__ == "__main__":
    unittest.main()
