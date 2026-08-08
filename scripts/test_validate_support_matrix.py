import copy
import unittest

from validate_support_matrix import (
    load_matrix,
    load_workflow,
    matrices,
    validate_matrix,
    validate_workflow,
)


class SupportMatrixTests(unittest.TestCase):
    def setUp(self):
        self.data = load_matrix()

    def test_generates_every_declared_matrix(self):
        generated = matrices(self.data)
        declared = {
            entry["ci_job"]
            for entry in self.data["targets"]
            if entry["ci_job"] is not None
        }

        self.assertEqual(declared, set(generated))
        expected_counts = {}
        for entry in self.data["targets"]:
            if entry["ci_job"] is not None:
                expected_counts[entry["ci_job"]] = expected_counts.get(entry["ci_job"], 0) + len(
                    entry["ci"]["toolchains"]
                )

        actual_counts = {
            job: len(matrix["include"]) for job, matrix in generated.items()
        }
        self.assertEqual(actual_counts, expected_counts)

    def test_rejects_duplicate_targets(self):
        invalid = copy.deepcopy(self.data)
        invalid["targets"][1]["target"] = invalid["targets"][0]["target"]

        with self.assertRaises(SystemExit):
            validate_matrix(invalid)

    def test_rejects_uncovered_ci_metadata(self):
        invalid = copy.deepcopy(self.data)
        invalid["targets"][-1]["ci"] = {"runner": "ubuntu-latest", "toolchains": ["stable"]}

        with self.assertRaises(SystemExit):
            validate_matrix(invalid)

    def test_rejects_unknown_allocation_capability(self):
        invalid = copy.deepcopy(self.data)
        invalid["targets"][0]["allocation"] = "not-a-real-capability"

        with self.assertRaises(SystemExit):
            validate_matrix(invalid)

    def test_declared_matrices_are_consumed_by_workflow_jobs(self):
        validate_workflow(self.data, load_workflow())

    def test_accepts_whitespace_in_matrix_expression(self):
        workflow = copy.deepcopy(load_workflow())
        workflow["jobs"]["check"]["strategy"]["matrix"] = (
            " ${{  fromJSON(needs.support-matrix.outputs.matrices) . check  }} "
        )

        validate_workflow(self.data, workflow)

    def test_rejects_workflow_matrix_consumption_drift(self):
        invalid = copy.deepcopy(load_workflow())
        invalid["jobs"]["uclibc"]["strategy"]["matrix"] = (
            "${{ fromJSON(needs.support-matrix.outputs.matrices).missing }}"
        )

        with self.assertRaises(SystemExit):
            validate_workflow(self.data, invalid)

    def test_rejects_unregistered_matrix_job(self):
        invalid = copy.deepcopy(load_workflow())
        invalid["jobs"]["unregistered"] = {
            "strategy": {"matrix": {"include": [{"target": "manual"}]}}
        }

        with self.assertRaises(SystemExit):
            validate_workflow(self.data, invalid)

if __name__ == "__main__":
    unittest.main()
