import copy
import json
import tempfile
import unittest
from pathlib import Path

from validate_support_matrix import (
    MATRIX_PATH,
    load_matrix,
    load_workflow,
    matrices,
    parse_registry,
    package_rust_version,
    validate_toolchain_policy,
    validate_workflow,
    write_github_output,
)


EXPECTED_MATRICES = (
    '{"check":{"include":[{"os":"ubuntu-latest","target":"x86_64-unknown-linux-gnu","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"x86_64-unknown-linux-gnu","toolchain":"stable"},'
    '{"os":"macos-15-intel","target":"x86_64-apple-darwin","toolchain":"1.88"},'
    '{"os":"macos-15-intel","target":"x86_64-apple-darwin","toolchain":"stable"},'
    '{"os":"macos-latest","target":"aarch64-apple-darwin","toolchain":"1.88"},'
    '{"os":"macos-latest","target":"aarch64-apple-darwin","toolchain":"stable"},'
    '{"os":"windows-latest","target":"x86_64-pc-windows-msvc","toolchain":"1.88"},'
    '{"os":"windows-latest","target":"x86_64-pc-windows-msvc","toolchain":"stable"}]},'
    '"cross_check":{"include":[{"os":"ubuntu-latest","target":"i686-unknown-linux-gnu","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"aarch64-unknown-linux-gnu","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"aarch64-unknown-linux-musl","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"powerpc64-unknown-linux-gnu","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"riscv64gc-unknown-linux-gnu","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"aarch64-linux-android","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"i686-linux-android","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"aarch64-pc-windows-msvc","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"x86_64-unknown-freebsd","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"x86_64-unknown-netbsd","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"x86_64-unknown-illumos","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"x86_64-unknown-redox","toolchain":"1.88"}]},'
    '"mingw":{"include":[{"os":"ubuntu-latest","target":"i686-pc-windows-gnu","toolchain":"1.88"},'
    '{"os":"ubuntu-latest","target":"x86_64-pc-windows-gnu","toolchain":"1.88"}]},'
    '"uclibc":{"include":[{"os":"ubuntu-latest","target":"armv7-unknown-linux-uclibceabihf","toolchain":"nightly"}]},'
    '"coverage":{"include":[{"os":"ubuntu-latest","target":"x86_64-unknown-linux-gnu","toolchain":"1.88"},'
    '{"os":"macos-latest","target":"aarch64-apple-darwin","toolchain":"1.88"},'
    '{"os":"windows-latest","target":"x86_64-pc-windows-msvc","toolchain":"1.88"}]}}'
)


class SupportMatrixTests(unittest.TestCase):
    def setUp(self):
        self.data = load_matrix()
        self.raw = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))

    def test_generates_every_declared_matrix(self):
        generated = matrices(self.data)
        declared = self.data.matrix_jobs

        self.assertEqual(declared, set(generated))
        expected_counts = {}
        for target in self.data.targets:
            if target.ci is not None:
                expected_counts[target.ci.job] = expected_counts.get(target.ci.job, 0) + len(
                    target.ci.toolchains
                )
        expected_counts["coverage"] = sum(
            target.ci is not None and target.ci.coverage for target in self.data.targets
        )

        actual_counts = {
            job: len(matrix["include"]) for job, matrix in generated.items()
        }
        self.assertEqual(actual_counts, expected_counts)

    def test_coverage_matrix_projects_runtime_targets_at_msrv(self):
        expected = [
            {
                "os": target.ci.runner,
                "target": target.target,
                "toolchain": target.ci.toolchains[0],
            }
            for target in self.data.targets
            if target.ci is not None and target.ci.coverage
        ]

        self.assertEqual(matrices(self.data)["coverage"]["include"], expected)

    def test_generated_matrix_is_byte_stable(self):
        generated = json.dumps(matrices(self.data), separators=(",", ":"))

        self.assertEqual(generated, EXPECTED_MATRICES)

    def test_rejects_duplicate_targets(self):
        invalid = copy.deepcopy(self.raw)
        invalid["targets"][1]["target"] = invalid["targets"][0]["target"]

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_uncovered_ci_metadata(self):
        invalid = copy.deepcopy(self.raw)
        invalid["targets"][-1]["ci"] = {"runner": "ubuntu-latest", "toolchains": ["stable"]}

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_duplicated_ci_job_field(self):
        invalid = copy.deepcopy(self.raw)
        invalid["targets"][0]["ci_job"] = "check"

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_unknown_allocation_capability(self):
        invalid = copy.deepcopy(self.raw)
        invalid["targets"][0]["allocation"] = "not-a-real-capability"

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_non_string_capabilities(self):
        for field in ("evidence", "allocation"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(self.raw)
                invalid["targets"][0][field] = []

                with self.assertRaises(SystemExit):
                    parse_registry(invalid)

    def test_rejects_invalid_platform(self):
        invalid = copy.deepcopy(self.raw)
        invalid["targets"][0]["platform"] = ""

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_non_object_matrix(self):
        with self.assertRaises(SystemExit):
            parse_registry([])

    def test_rejects_malformed_evidence_levels(self):
        invalid = copy.deepcopy(self.raw)
        invalid["evidence_levels"] = None

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_registry_without_runtime_evidence(self):
        invalid = copy.deepcopy(self.raw)
        for target in invalid["targets"]:
            if target["evidence"] == "runtime":
                target["evidence"] = "compile"
                target["ci"].pop("coverage", None)

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_compile_target_selected_for_native_coverage(self):
        invalid = copy.deepcopy(self.raw)
        compile_target = next(
            target for target in invalid["targets"] if target["evidence"] == "compile"
        )
        compile_target["ci"]["coverage"] = True

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_non_boolean_native_coverage_selection(self):
        invalid = copy.deepcopy(self.raw)
        invalid["targets"][0]["ci"]["coverage"] = "yes"

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_rejects_registry_without_native_coverage_target(self):
        invalid = copy.deepcopy(self.raw)
        for target in invalid["targets"]:
            if target["ci"] is not None:
                target["ci"].pop("coverage", None)

        with self.assertRaises(SystemExit):
            parse_registry(invalid)

    def test_declared_matrices_are_consumed_by_workflow_jobs(self):
        validate_workflow(self.data, load_workflow())

    def test_registry_toolchains_match_package_rust_version(self):
        validate_toolchain_policy(self.data, package_rust_version())

    def test_compatibility_gate_uses_generated_rust_version(self):
        compatibility_step = next(
            step
            for step in load_workflow()["jobs"]["check"]["steps"]
            if step.get("run") == "python scripts/validate_compatibility.py"
        )
        self.assertEqual(
            compatibility_step["if"],
            "matrix.toolchain == needs.support-matrix.outputs.rust_version",
        )

    def test_github_output_includes_canonical_rust_version(self):
        with tempfile.TemporaryDirectory(prefix="fs2-support-matrix-test-") as temporary:
            output = Path(temporary) / "github-output"
            write_github_output(output, matrices(self.data), "1.88")
            self.assertTrue(
                output.read_text(encoding="utf-8").endswith("rust_version=1.88\n")
            )

    def test_accepts_whitespace_in_matrix_expression(self):
        workflow = copy.deepcopy(load_workflow())
        workflow["jobs"]["check"]["strategy"]["matrix"] = (
            " ${{  fromJSON(needs.support-matrix.outputs.matrices) . check  }} "
        )

        validate_workflow(self.data, workflow)

    def test_rejects_whitespace_inside_matrix_job_name(self):
        workflow = copy.deepcopy(load_workflow())
        workflow["jobs"]["check"]["strategy"]["matrix"] = (
            "${{ fromJSON(needs.support-matrix.outputs.matrices).c h e c k }}"
        )

        with self.assertRaises(SystemExit):
            validate_workflow(self.data, workflow)

    def test_rejects_workflow_matrix_consumption_drift(self):
        invalid = copy.deepcopy(load_workflow())
        invalid["jobs"]["uclibc"]["strategy"]["matrix"] = (
            "${{ fromJSON(needs.support-matrix.outputs.matrices).missing }}"
        )

        with self.assertRaises(SystemExit):
            validate_workflow(self.data, invalid)

    def test_allows_unregistered_literal_matrix_job(self):
        invalid = copy.deepcopy(load_workflow())
        invalid["jobs"]["unregistered"] = {
            "strategy": {"matrix": {"include": [{"target": "manual"}]}}
        }

        validate_workflow(self.data, invalid)

    def test_rejects_unregistered_generated_matrix_job(self):
        invalid = copy.deepcopy(load_workflow())
        invalid["jobs"]["unregistered"] = {
            "strategy": {
                "matrix": "${{ fromJSON(needs.support-matrix.outputs.matrices).check }}"
            }
        }

        with self.assertRaises(SystemExit):
            validate_workflow(self.data, invalid)

    def test_dependency_resolving_cargo_commands_are_locked(self):
        workflow = load_workflow()
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                command = step.get("run") if isinstance(step, dict) else None
                if not isinstance(command, str) or not command.lstrip().startswith("cargo "):
                    continue
                if command.lstrip().startswith("cargo fmt "):
                    continue
                self.assertIn("--locked", command, msg=f"{job_name}: {command}")

    def test_workflow_has_manual_and_monthly_canary_triggers(self):
        triggers = load_workflow()["on"]

        self.assertIn("workflow_dispatch", triggers)
        self.assertEqual(triggers["schedule"], [{"cron": "17 1 1 * *"}])

if __name__ == "__main__":
    unittest.main()
