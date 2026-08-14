import json
import unittest

from implementation_review_digest import (
    normalize_plan,
    normalize_text,
    normalize_tool_assessment,
    review_scope_digest,
)


class ImplementationReviewDigestTests(unittest.TestCase):
    def test_normalizes_text_line_endings(self):
        self.assertEqual(normalize_text(b"one\r\ntwo\r\n"), b"one\ntwo\n")

    def test_does_not_normalize_binary_data(self):
        self.assertEqual(normalize_text(b"one\0\r\ntwo"), b"one\0\r\ntwo")

    def test_normalizes_only_review_decision_fields(self):
        plan = {
            "scope": "candidate",
            "review_gate": {
                "status": "approved_for_atomic_publication",
                "preparation_parent_commit": "1" * 40,
                "digest_algorithm": "sha256-canonical-review-scope-v1",
                "candidate_change_digest": "2" * 64,
                "mechanical_review_markers": [],
                "decision": "approve",
                "decision_ref": "decision:test",
                "decided_at": "2026-08-14T05:00:00Z",
            },
        }
        normalized = json.loads(normalize_plan(json.dumps(plan).encode("utf-8")))
        self.assertEqual(normalized["scope"], "candidate")
        self.assertEqual(
            normalized["review_gate"],
            {
                "status": "awaiting_implementation_review",
                "preparation_parent_commit": "1" * 40,
                "digest_algorithm": "sha256-canonical-review-scope-v1",
                "candidate_change_digest": None,
                "mechanical_review_markers": [],
                "decision": None,
                "decision_ref": None,
                "decided_at": None,
            },
        )

    def test_scope_digest_is_order_stable_for_mapping_keys(self):
        left = {"schema_version": 1, "files": [{"path": "a"}]}
        right = {"files": [{"path": "a"}], "schema_version": 1}
        self.assertEqual(review_scope_digest(left), review_scope_digest(right))

    def test_normalizes_registered_tool_review_markers(self):
        assessment = {
            "functions": [
                {
                    "id": identifier,
                    "review": {
                        "status": "reviewed_internal",
                        "reviewer": "IR-PERSON-001",
                        "evidence_refs": ["evidence"],
                    },
                }
                for identifier in (
                    "TOOL-F-001",
                    "TOOL-F-002",
                    "TOOL-F-003",
                    "TOOL-F-004",
                    "TOOL-F-005",
                    "TOOL-F-006",
                )
            ]
        }
        normalized = json.loads(
            normalize_tool_assessment(json.dumps(assessment).encode("utf-8"))
        )
        reviews = {
            function["id"]: function["review"] for function in normalized["functions"]
        }
        for identifier in ("TOOL-F-001", "TOOL-F-003", "TOOL-F-004", "TOOL-F-005"):
            self.assertEqual(reviews[identifier]["status"], "pending_user_review")
            self.assertIsNone(reviews[identifier]["reviewer"])
        self.assertEqual(reviews["TOOL-F-002"]["status"], "reviewed_internal")
        self.assertEqual(reviews["TOOL-F-006"]["reviewer"], "IR-PERSON-001")


if __name__ == "__main__":
    unittest.main()
