import copy
import unittest

from validate_support_matrix import (
    load_matrix,
    matrices,
    validate_matrix,
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

if __name__ == "__main__":
    unittest.main()
