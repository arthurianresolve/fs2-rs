import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_coverage import canonical_text_sha256, rustc_host_target, sha256
from validate_coverage import (
    COVERAGE,
    ROOT,
    ValidationError,
    canonical_source_sha256,
    load_json,
    validate_context,
    validate_archive_control,
    validate_archive_retrieval,
    validate_assurance_control_links,
    validate_configuration_management,
    validate_decisions,
    validate_evidence_index,
    validate_gap_register,
    validate_manifest,
    validate_policy,
    validate_requirements,
    validate_requirements_review,
    validate_static_records,
    validate_surface,
    validate_tool_assessment,
    validate_windows_appverifier_manifest,
    validate_native_fault_payload,
    validate_windows_native_fault_assessment,
    validate_windows_native_fault_manifest,
    validate_windows_native_fault_review,
    check_status,
    parse_cargo_test_list,
)


class CoverageRecordTests(unittest.TestCase):
    def setUp(self):
        self.context = load_json(COVERAGE / "assurance-context.json")
        self.requirements = load_json(COVERAGE / "requirements.json")
        self.surface = load_json(COVERAGE / "surface.json")
        self.decisions = load_json(COVERAGE / "decision-inventory.json")
        self.policy = load_json(COVERAGE / "policy.json")
        self.tool = load_json(COVERAGE / "tool-assessment.json")
        self.requirements_review = load_json(COVERAGE / "requirements-review.json")
        self.configuration_management = load_json(
            COVERAGE / "configuration-management.json"
        )
        self.archive_control = load_json(COVERAGE / "archive-control.json")
        self.archive_retrieval = load_json(COVERAGE / "archive-retrieval.json")
        self.verification_inventory = load_json(
            COVERAGE / "verification-inventory.json"
        )
        self.native_faults = load_json(COVERAGE / "windows-native-faults.json")
        self.native_fault_review = load_json(
            COVERAGE / "windows-native-fault-review.json"
        )

    def test_static_records_are_valid(self):
        validate_static_records()

    def test_context_rejects_certification_credit(self):
        invalid = copy.deepcopy(self.context)
        invalid["certification_credit"] = "accepted"

        with self.assertRaises(ValidationError):
            validate_context(invalid)

    def test_context_rejects_unapproved_independence_claim(self):
        invalid = copy.deepcopy(self.context)
        invalid["independence_status"] = "accepted"

        with self.assertRaises(ValidationError):
            validate_context(invalid)

    def test_requirements_reject_unknown_source(self):
        invalid = copy.deepcopy(self.requirements)
        invalid["requirements"][0]["source_refs"] = ["src/missing.rs:1"]

        with self.assertRaises(ValidationError):
            validate_requirements(invalid)

    def test_requirements_reject_out_of_range_source_span(self):
        invalid = copy.deepcopy(self.requirements)
        invalid["requirements"][0]["source_refs"] = ["src/allocation.rs:1-9999"]

        with self.assertRaises(ValidationError):
            validate_requirements(invalid)

    def test_requirements_review_rejects_stale_requirements_digest(self):
        invalid = copy.deepcopy(self.requirements_review)
        invalid["reviewed_artifacts"]["requirements"]["sha256"] = "0" * 64

        with self.assertRaises(ValidationError):
            validate_requirements_review(
                invalid,
                self.requirements,
                self.verification_inventory,
                {record["id"] for record in self.requirements["requirements"]},
            )

    def test_requirements_review_rejects_independence_claim(self):
        invalid = copy.deepcopy(self.requirements_review)
        invalid["reviewer"]["independent"] = True

        with self.assertRaises(ValidationError):
            validate_requirements_review(
                invalid,
                self.requirements,
                self.verification_inventory,
                {record["id"] for record in self.requirements["requirements"]},
            )

    def test_requirements_review_rejects_incomplete_inventory(self):
        invalid = copy.deepcopy(self.requirements_review)
        invalid["requirements"].pop()

        with self.assertRaises(ValidationError):
            validate_requirements_review(
                invalid,
                self.requirements,
                self.verification_inventory,
                {record["id"] for record in self.requirements["requirements"]},
            )

    def test_surface_rejects_stale_hash(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][0]["sha256"] = "0" * 64

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_surface_rejects_implicit_exclusion(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][0]["denominator"] = "excluded_with_classification"

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_surface_rejects_overlapping_spans(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][1]["line_spans"] = ["80-234"]

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_surface_rejects_test_module_declared_as_production(self):
        invalid = copy.deepcopy(self.surface)
        invalid["records"][2]["line_spans"] = ["1-171"]
        invalid["records"][3]["line_spans"] = ["173-354"]

        with self.assertRaises(ValidationError):
            validate_surface(invalid, validate_requirements(self.requirements))

    def test_decision_inventory_rejects_unmapped_requirement(self):
        invalid = copy.deepcopy(self.decisions)
        invalid["decisions"][0]["requirement_ids"] = ["REQ-NOT-MAPPED"]

        with self.assertRaises(ValidationError):
            validate_decisions(invalid, validate_requirements(self.requirements))

    def test_decision_inventory_rejects_mcdc_disposition_drift(self):
        invalid = copy.deepcopy(self.decisions)
        invalid["decisions"][1]["mcdc_disposition"] = "assessment_open_no_record"

        with self.assertRaises(ValidationError):
            validate_decisions(invalid, validate_requirements(self.requirements))

    def test_decision_inventory_accepts_error_propagation_disposition(self):
        valid = copy.deepcopy(self.decisions)
        valid["decisions"][7]["mcdc_disposition"] = "not_applicable_error_propagation"

        validate_decisions(valid, validate_requirements(self.requirements))

    def test_policy_keeps_branch_and_mcdc_separate(self):
        invalid = copy.deepcopy(self.policy)
        invalid["metrics"]["branch"]["mcdc_claim"] = True

        with self.assertRaises(ValidationError):
            validate_policy(invalid)

    def test_tool_assessment_rejects_qualification_claim(self):
        invalid = copy.deepcopy(self.tool)
        invalid["qualification_status"] = "qualified"

        with self.assertRaises(ValidationError):
            validate_tool_assessment(invalid)

    def test_tool_assessment_rejects_topology_drift(self):
        invalid = copy.deepcopy(self.tool)
        invalid["topology"].pop()

        with self.assertRaises(ValidationError):
            validate_tool_assessment(invalid)

    def test_tool_assessment_rejects_independent_fallback_claim(self):
        invalid = copy.deepcopy(self.tool)
        invalid["functions"][0]["fallback"]["independent"] = True

        with self.assertRaises(ValidationError):
            validate_tool_assessment(invalid)

    def test_tool_assessment_rejects_proposed_tql_without_basis(self):
        invalid = copy.deepcopy(self.tool)
        invalid["functions"][0]["proposed_tql"] = "TQL-5"

        with self.assertRaises(ValidationError):
            validate_tool_assessment(invalid)

    def test_configuration_management_rejects_partial_candidate_binding(self):
        invalid = copy.deepcopy(self.configuration_management)
        invalid["candidate"]["state"] = "awaiting_clean_exact_commit"
        for field in (
            "commit",
            "tree",
            "ci_run_id",
            "assurance_package_manifest_sha256",
            "retrieval_result_sha256",
        ):
            invalid["candidate"][field] = None
        invalid["candidate"]["commit"] = "1" * 40

        with self.assertRaises(ValidationError):
            validate_configuration_management(invalid)

    def test_configuration_management_rejects_release_candidate_claim(self):
        invalid = copy.deepcopy(self.configuration_management)
        invalid["release_control"]["current_state"] = "release_candidate"

        with self.assertRaises(ValidationError):
            validate_configuration_management(invalid)

    def test_archive_control_rejects_external_archive_claim(self):
        invalid = copy.deepcopy(self.archive_control)
        invalid["external_archive"]["status"] = "archived"

        with self.assertRaises(ValidationError):
            validate_archive_control(invalid)

    def test_archive_control_rejects_missing_required_artifact(self):
        invalid = copy.deepcopy(self.archive_control)
        invalid["internal_staging"]["required_artifacts"].pop(
            "windows-native-faults"
        )

        with self.assertRaises(ValidationError):
            validate_archive_control(invalid)

    def test_archive_retrieval_rejects_partial_pending_result(self):
        invalid = copy.deepcopy(self.archive_retrieval)
        invalid["status"] = "not_ready"
        invalid["result"] = "pending"
        for field in (
            "package_id",
            "source_commit",
            "source_tree",
            "workflow_run_id",
            "manifest_sha256",
            "retrieval_result_sha256",
            "file_count",
            "total_bytes",
            "retrieved_at",
            "verified_by",
        ):
            invalid[field] = None
        invalid["discrepancies"] = []
        invalid["source_commit"] = "1" * 40

        with self.assertRaises(ValidationError):
            validate_archive_retrieval(invalid)

    def test_assurance_controls_reject_mixed_pending_states(self):
        invalid_retrieval = copy.deepcopy(self.archive_retrieval)
        invalid_retrieval["result"] = (
            "pass" if invalid_retrieval["result"] == "pending" else "pending"
        )

        with self.assertRaises(ValidationError):
            validate_assurance_control_links(
                self.context,
                self.configuration_management,
                self.archive_control,
                invalid_retrieval,
                load_json(COVERAGE / "evidence-index.json"),
            )

    def test_assurance_controls_reject_context_baseline_drift(self):
        invalid_context = copy.deepcopy(self.context)
        invalid_context["baseline"]["reference"] = "1" * 40

        with self.assertRaises(ValidationError):
            validate_assurance_control_links(
                invalid_context,
                self.configuration_management,
                self.archive_control,
                self.archive_retrieval,
                load_json(COVERAGE / "evidence-index.json"),
            )

    def test_evidence_index_rejects_local_promotion(self):
        invalid = load_json(COVERAGE / "evidence-index.json")
        invalid["runs"][0]["disposition"] = "promoted"

        with self.assertRaises(ValidationError):
            validate_evidence_index(invalid)

    def test_gap_register_requires_closed_gap_basis(self):
        invalid = load_json(COVERAGE / "gap-register.json")
        invalid["gaps"][0].pop("closure_basis")

        with self.assertRaises(ValidationError):
            validate_gap_register(invalid)

    def test_gap_register_requires_apple_matrix_profile(self):
        invalid = load_json(COVERAGE / "gap-register.json")
        invalid["clean_local_snapshot"]["profiles"].pop("macos_stable")

        with self.assertRaises(ValidationError):
            validate_gap_register(invalid)

    def test_gap_register_rejects_native_fault_closure_before_review(self):
        invalid = load_json(COVERAGE / "gap-register.json")
        native = next(gap for gap in invalid["gaps"] if gap["id"] == "GAP-WINDOWS-NATIVE-ERRORS")
        native["status"] = "closed"
        native["closure_basis"] = "technical tests passed"

        with self.assertRaises(ValidationError):
            validate_gap_register(invalid)

    def test_native_fault_assessment_rejects_driver_verifier_claim(self):
        invalid = copy.deepcopy(self.native_faults)
        invalid["tool_disposition"]["driver_verifier"]["applicability"] = "applicable"

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_assessment(invalid, {"windows::test::records_os_mediated_native_failures", "appverifier_file_fault_is_observed"})

    def test_native_fault_assessment_rejects_review_status_drift(self):
        invalid = copy.deepcopy(self.native_faults)
        invalid["review_status"] = "independent_review_pending"

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_assessment(
                invalid,
                {"windows::test::records_os_mediated_native_failures", "appverifier_file_fault_is_observed"},
                "independent_review_approved",
            )

    def test_native_fault_assessment_rejects_promoted_external_basis(self):
        invalid = copy.deepcopy(self.native_faults)
        invalid["external_references"][0]["source_role"] = "approved_certification_basis"

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_assessment(invalid, {"windows::test::records_os_mediated_native_failures", "appverifier_file_fault_is_observed"})

    def test_native_fault_assessment_rejects_external_reference_drift(self):
        invalid = copy.deepcopy(self.native_faults)
        invalid["external_references"][0]["url"] = "https://example.invalid/application-verifier"

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_assessment(invalid, {"windows::test::records_os_mediated_native_failures", "appverifier_file_fault_is_observed"})

    def approved_native_fault_review(self) -> dict:
        approved = copy.deepcopy(self.native_fault_review)
        approved["status"] = "approved"
        approved["assignment"]["reviewer_acceptance"] = "accepted"
        approved["independence"].update(
            {
                "status": "accepted",
                "implementation_authorship": "confirmed",
                "organizational_independence": "confirmed",
                "technical_independence": "confirmed",
                "expected_results_independently_established": "confirmed",
                "common_mode_independence": "confirmed",
                "same_identity_rationale": "The reviewer documented role separation and reconciled the shared publication identity.",
                "declaration_ref": "review-evidence:independence-declaration-001",
                "declared_at": "2026-08-14T10:00:00+00:00",
            }
        )
        approved["candidate_baseline"].update(
            {
                "reviewed_commit": "1" * 40,
                "reviewed_tree": "2" * 40,
                "clean_native_fault_manifest_ref": "github-actions:run-1/artifact/windows-native-faults",
                "clean_native_fault_manifest_sha256": "3" * 64,
                "state": "clean_candidate_bound",
            }
        )
        for check in approved["checklist"]:
            check["status"] = "pass"
        approved["decision"] = {
            "status": "recorded",
            "outcome": "approve",
            "reviewer_login": "arthurianresolve",
            "reviewed_commit": "1" * 40,
            "native_fault_manifest_sha256": "3" * 64,
            "attestation": "I independently reviewed every registered objective and accept the internal result.",
            "decision_ref": "review-evidence:decision-001",
            "decided_at": "2026-08-14T11:00:00+00:00",
        }
        approved["closure_effect"] = {
            "gap_id": "GAP-WINDOWS-NATIVE-ERRORS",
            "current_effect": "independent_review_condition_satisfied",
            "independent_review_condition_satisfied": True,
            "gap_closure_permitted": True,
            "remaining_conditions": [],
        }
        approved["updated_at"] = "2026-08-14T11:00:00+00:00"
        return approved

    def test_native_fault_review_accepts_current_candidate_pending_state(self):
        self.assertEqual(
            validate_windows_native_fault_review(self.native_fault_review),
            "independent_review_pending",
        )

    def test_native_fault_review_accepts_bound_candidate_before_reviewer_acceptance(self):
        ready = copy.deepcopy(self.native_fault_review)
        ready["status"] = "assigned_ready_for_review"
        ready["candidate_baseline"].update(
            {
                "reviewed_commit": "1" * 40,
                "reviewed_tree": "2" * 40,
                "clean_native_fault_manifest_ref": "github-actions:run-1/artifact/windows-native-faults",
                "clean_native_fault_manifest_sha256": "3" * 64,
                "state": "clean_candidate_bound",
            }
        )
        ready["assignment"]["reviewer_acceptance"] = "pending"
        ready["independence"] = copy.deepcopy(self.native_fault_review["independence"])
        ready["independence"].update(
            {
                "status": "declaration_pending",
                "implementation_authorship": "not_assessed",
                "organizational_independence": "not_assessed",
                "technical_independence": "not_assessed",
                "expected_results_independently_established": "not_assessed",
                "common_mode_independence": "not_assessed",
                "same_identity_rationale": None,
                "declaration_ref": None,
                "declared_at": None,
            }
        )
        ready["decision"] = {
            "status": "pending",
            "outcome": None,
            "reviewer_login": None,
            "reviewed_commit": None,
            "native_fault_manifest_sha256": None,
            "attestation": None,
            "decision_ref": None,
            "decided_at": None,
        }
        for check in ready["checklist"]:
            check["status"] = "not_reviewed"
            check["finding_refs"] = []
        ready["closure_effect"] = {
            "gap_id": "GAP-WINDOWS-NATIVE-ERRORS",
            "current_effect": "none_review_incomplete",
            "independent_review_condition_satisfied": False,
            "gap_closure_permitted": False,
            "remaining_conditions": ["obtain reviewer acceptance and complete the review"],
        }
        ready["closure_effect"]["current_effect"] = "none_review_incomplete"

        self.assertEqual(
            validate_windows_native_fault_review(ready),
            "independent_review_pending",
        )

    def test_native_fault_review_rejects_reviewer_identity_drift(self):
        invalid = copy.deepcopy(self.native_fault_review)
        invalid["assignment"]["reviewer"]["login"] = "someone-else"

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_review(invalid)

    def test_native_fault_review_rejects_premature_approval(self):
        invalid = self.approved_native_fault_review()
        invalid["assignment"]["reviewer_acceptance"] = "pending"

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_review(invalid)

    def test_native_fault_review_accepts_complete_approval_transition(self):
        self.assertEqual(
            validate_windows_native_fault_review(self.approved_native_fault_review()),
            "independent_review_approved",
        )

    def test_native_fault_review_rejects_missing_same_identity_rationale(self):
        invalid = self.approved_native_fault_review()
        invalid["independence"]["same_identity_rationale"] = None

        with self.assertRaises(ValidationError):
            validate_windows_native_fault_review(invalid)

    def test_native_fault_payload_rejects_activation_drift(self):
        payload = WindowsFaultManifestTests().native_payload()
        payload["scenarios"][0]["activation"] = "adapter_stub"

        with self.assertRaises(ValidationError):
            validate_native_fault_payload(payload, "test payload", True)

    def test_invalid_fixture_is_rejected(self):
        invalid = load_json(COVERAGE / "fixtures" / "invalid-unknown-status.json")

        with self.assertRaises(ValidationError):
            check_status(invalid, "coverage/fixtures/invalid-unknown-status.json")

    def test_source_hash_is_line_ending_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "lf.rs"
            crlf = root / "crlf.rs"
            lf.write_bytes(b"fn main() {\n    println!(\"ok\");\n}\n")
            crlf.write_bytes(b"fn main() {\r\n    println!(\"ok\");\r\n}\r\n")

            self.assertEqual(canonical_source_sha256(lf), canonical_source_sha256(crlf))

    def test_lock_hash_is_line_ending_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "Cargo.lock"
            crlf = root / "Cargo-crlf.lock"
            lf.write_bytes(b"version = 3\n[[package]]\nname = \"fs2\"\n")
            crlf.write_bytes(b"version = 3\r\n[[package]]\r\nname = \"fs2\"\r\n")

            self.assertEqual(canonical_text_sha256(lf), canonical_text_sha256(crlf))

    def test_extracts_rustc_host_target(self):
        self.assertEqual(
            rustc_host_target("rustc test\nhost: x86_64-pc-windows-msvc\n"),
            "x86_64-pc-windows-msvc",
        )

    def test_parses_grouped_cargo_test_listing(self):
        output = """
        Running unittests src\\lib.rs
        allocation::tests::example: test
        test result: ok
        Running tests\\upstream_compat.rs
        upstream_surface: test
        Doc-tests fs2
        src\\stats.rs - stats::FsStatsQuery (line 31): test
        """

        self.assertEqual(
            parse_cargo_test_list(output),
            {
                "unit": {"allocation::tests::example"},
                "integration": {"upstream_surface"},
                "doctest": {"src/stats.rs:FsStatsQuery (line 31)"},
            },
        )


class RunManifestTests(unittest.TestCase):
    def make_manifest(self, run_root: Path) -> dict:
        report = run_root / "coverage.json"
        stdout = run_root / "stdout.log"
        stderr = run_root / "stderr.log"
        report.write_text('{"data": []}\n', encoding="utf-8")
        stdout.write_text("test output\n", encoding="utf-8")
        stderr.write_text("warning output\n", encoding="utf-8")
        (run_root / "windows-provider.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "api": "GetDiskSpaceInformationW",
                    "library": "kernel32.dll",
                    "module_present": True,
                    "symbol_present": True,
                    "outcome": "available",
                    "error_raw_os": None,
                }
            ),
            encoding="utf-8",
        )
        lock_hash = sha256(ROOT / "Cargo.lock")
        return {
            "run_id": "test-run",
            "repository": "arthurianresolve/fs2-rs",
            "branch": "DO-178C",
            "commit": "d1e0e22eaed156e2420058f52f119e10330e24df",
            "tree": "0" * 40,
            "dirty": False,
            "cargo_lock_sha256": lock_hash,
            "host": {
                "system": "test",
                "release": "test",
                "machine": "test",
                "python": "test",
                "version": "test",
                "target": "x86_64-pc-windows-msvc",
            },
            "target": "x86_64-pc-windows-msvc",
            "profile": "stable",
            "requested_toolchain": "stable",
            "resolved_toolchain": "rustc test",
            "cargo_llvm_cov": "cargo-llvm-cov test",
            "command": ["cargo", "+stable", "llvm-cov"],
            "environment": {"CARGO_INCREMENTAL": "0"},
            "provider": {
                "schema_version": 1,
                "api": "GetDiskSpaceInformationW",
                "library": "kernel32.dll",
                "module_present": True,
                "symbol_present": True,
                "outcome": "available",
                "error_raw_os": None,
            },
            "native_exit": 0,
            "status": "pass",
            "artifacts": [],
        }

    def test_manifest_accepts_complete_pass_record(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["artifacts"] = [
                {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                for name in ("coverage.json", "stdout.log", "stderr.log", "windows-provider.json")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            validate_manifest(path, manifest["commit"])

    def test_manifest_rejects_pass_with_dirty_tree(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["dirty"] = True
            manifest["artifacts"] = [
                {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                for name in ("coverage.json", "stdout.log", "stderr.log", "windows-provider.json")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)

    def test_manifest_rejects_pass_with_non_native_target(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["host"]["target"] = "x86_64-unknown-linux-gnu"
            manifest["artifacts"] = [
                {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                for name in ("coverage.json", "stdout.log", "stderr.log", "windows-provider.json")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)

    def test_manifest_rejects_pass_without_provider_artifact(self):
        with tempfile.TemporaryDirectory(prefix="fs2-coverage-manifest-") as directory:
            run_root = Path(directory)
            manifest = self.make_manifest(run_root)
            manifest["artifacts"] = [
                {
                    "path": name,
                    "sha256": sha256(run_root / name),
                    "bytes": (run_root / name).stat().st_size,
                }
                for name in ("coverage.json", "stdout.log", "stderr.log")
            ]
            path = run_root / "run-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ValidationError):
                validate_manifest(path)


class WindowsFaultManifestTests(unittest.TestCase):
    def native_payload(self) -> dict:
        return {
            "schema_version": 1,
            "evidence_class": "internal_engineering",
            "fault_model": "os_mediated_error_activation",
            "status": "pass",
            "scenarios": [
                {"id": "WIN-NATIVE-ALLOC-READONLY", "api_boundary": "SetFileInformationByHandle", "activation": "read_only_file_handle", "expected_raw_os": 5, "actual_raw_os": 5},
                {"id": "WIN-NATIVE-LOCK-CONTENTION", "api_boundary": "LockFileEx", "activation": "exclusive_lock_owned_by_peer_handle", "expected_raw_os": 33, "actual_raw_os": 33},
                {"id": "WIN-NATIVE-VOLUME-UNAVAILABLE", "api_boundary": "Windows volume and space providers", "activation": "unavailable_volume_root", "expected_raw_os": None, "actual_raw_os": 2},
                {"id": "WIN-WIN32-DUPLICATE-INVALID-HANDLE", "api_boundary": "DuplicateHandle", "activation": "null_source_handle", "expected_raw_os": 6, "actual_raw_os": 6},
                {"id": "WIN-WIN32-ALLOCATION-QUERY-INVALID-HANDLE", "api_boundary": "GetFileInformationByHandleEx", "activation": "null_file_handle", "expected_raw_os": 6, "actual_raw_os": 6},
                {"id": "WIN-WIN32-ALLOCATION-WRITE-INVALID-HANDLE", "api_boundary": "SetFileInformationByHandle", "activation": "null_file_handle", "expected_raw_os": 6, "actual_raw_os": 6},
                {"id": "WIN-WIN32-LOCK-INVALID-HANDLE", "api_boundary": "LockFileEx", "activation": "null_file_handle", "expected_raw_os": 6, "actual_raw_os": 6},
                {"id": "WIN-WIN32-UNLOCK-INVALID-HANDLE", "api_boundary": "UnlockFile", "activation": "null_file_handle", "expected_raw_os": 6, "actual_raw_os": 6},
            ],
            "limitations": ["one", "two", "three"],
        }

    def test_native_fault_manifest_is_fail_closed_for_review(self):
        with tempfile.TemporaryDirectory(prefix="fs2-native-fault-manifest-") as directory:
            run_root = Path(directory)
            payload = self.native_payload()
            (run_root / "windows-native-faults.json").write_text(json.dumps(payload), encoding="utf-8")
            (run_root / "stdout.log").write_text("pass\n", encoding="utf-8")
            (run_root / "stderr.log").write_text("", encoding="utf-8")
            manifest = {
                "record_type": "windows_native_fault_run",
                "schema_version": 1,
                "run_id": "test-native-fault",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "commit": "d1e0e22eaed156e2420058f52f119e10330e24df",
                "tree": "2" * 40,
                "dirty": False,
                "cargo_lock_sha256": canonical_text_sha256(ROOT / "Cargo.lock"),
                "host": {"system": "Windows", "release": "test", "version": "test", "machine": "AMD64", "python": "test", "target": "x86_64-pc-windows-msvc"},
                "target": "x86_64-pc-windows-msvc",
                "requested_toolchain": "1.88",
                "resolved_toolchain": "rustc test\nhost: x86_64-pc-windows-msvc",
                "test_id": "windows::test::records_os_mediated_native_failures",
                "command": ["cargo", "+1.88", "test", "--package", "fs2", "--lib", "--target", "x86_64-pc-windows-msvc", "--locked", "windows::test::records_os_mediated_native_failures", "--", "--exact", "--test-threads=1", "--nocapture"],
                "environment": {"CARGO_INCREMENTAL": "0", "RUST_BACKTRACE": "1", "FS2_WINDOWS_NATIVE_FAULT_EVIDENCE": str(run_root / "windows-native-faults.json")},
                "native_exit": 0,
                "native_faults": payload,
                "review_status": "independent_review_pending",
                "status": "pass",
                "created_utc": "2026-08-13T10:00:00+00:00",
                "artifacts": [
                    {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                    for name in ("windows-native-faults.json", "stdout.log", "stderr.log")
                ],
            }
            path = run_root / "windows-native-fault-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            validate_windows_native_fault_manifest(path, manifest["commit"])

            manifest["review_status"] = "approved"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValidationError):
                validate_windows_native_fault_manifest(path)

    def test_appverifier_indeterminate_manifest_retains_preflight_reason(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-manifest-") as directory:
            run_root = Path(directory)
            reason = run_root / "preflight-error.txt"
            reason.write_text("elevation required\n", encoding="utf-8")
            manifest = {
                "record_type": "windows_appverifier_run",
                "schema_version": 1,
                "run_id": "test-appverifier",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "commit": "d1e0e22eaed156e2420058f52f119e10330e24df",
                "tree": "0" * 40,
                "dirty": True,
                "cargo_lock_sha256": canonical_text_sha256(ROOT / "Cargo.lock"),
                "host": {"system": "Windows", "release": "test", "version": "test", "machine": "AMD64", "python": "test", "target": "x86_64-pc-windows-msvc", "administrator": False},
                "target": "x86_64-pc-windows-msvc",
                "requested_toolchain": "1.88",
                "resolved_toolchain": "rustc test\nhost: x86_64-pc-windows-msvc",
                "application_verifier": {"path": "appverif.exe", "version": "test", "sha256": "0" * 64},
                "probe": {"test_target": "windows_appverifier", "test_id": "appverifier_file_fault_is_observed", "binary": None, "sha256": None},
                "configuration": {"layer": "lowres", "file_probability": 1000000, "timeout_ms": 0, "target_image": "fs2-windows-appverifier-probe.exe"},
                "commands": {
                    "build": ["cargo", "+1.88", "test", "--package", "fs2", "--target", "x86_64-pc-windows-msvc", "--locked", "--test", "windows_appverifier", "--no-run", "--message-format=json"],
                    "probe": [str(run_root / "fs2-windows-appverifier-probe.exe"), "--exact", "appverifier_file_fault_is_observed", "--nocapture"],
                    "initial_delete": ["appverif.exe", "-delete", "settings", "-for", "fs2-windows-appverifier-probe.exe"],
                    "initial_query": ["appverif.exe", "-query", "lowres", "-for", "fs2-windows-appverifier-probe.exe"],
                    "configure": ["appverif.exe", "-enable", "lowres", "-for", "fs2-windows-appverifier-probe.exe", "-with", "file=1000000", "timeout=0"],
                    "query": ["appverif.exe", "-query", "lowres", "-for", "fs2-windows-appverifier-probe.exe"],
                    "cleanup_delete": ["appverif.exe", "-delete", "settings", "-for", "fs2-windows-appverifier-probe.exe"],
                    "cleanup_query": ["appverif.exe", "-query", "lowres", "-for", "fs2-windows-appverifier-probe.exe"],
                },
                "controlled_environment": {
                    "baseline": {"FS2_APPVERIFIER_PROBE_PATH": str(ROOT / "Cargo.toml")},
                    "injected": {"FS2_APPVERIFIER_PROBE_PATH": str(ROOT / "Cargo.toml"), "FS2_EXPECT_APPVERIFIER_FILE_FAULT": "1"},
                },
                "initial_state": {"delete_native_exit": None, "query_native_exit": None, "query_observation": None, "verified_absent": False},
                "baseline": {"native_exit": None, "observation": None},
                "configured_state": {"enable_native_exit": None, "query_native_exit": None, "query_observation": None, "verified": False},
                "injected": {"native_exit": None, "observation": None},
                "cleanup": {"delete_native_exit": None, "query_native_exit": None, "query_observation": None, "verified_absent": False},
                "review_status": "independent_review_pending",
                "status": "indeterminate",
                "created_utc": "2026-08-13T10:00:00+00:00",
                "artifacts": [{"path": reason.name, "sha256": sha256(reason), "bytes": reason.stat().st_size}],
            }
            path = run_root / "windows-appverifier-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            validate_windows_appverifier_manifest(path, manifest["commit"])

            manifest["artifacts"] = []
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValidationError):
                validate_windows_appverifier_manifest(path)

    def test_appverifier_pass_requires_verified_configuration_lifecycle(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-pass-") as directory:
            run_root = Path(directory)
            artifact_names = (
                "build-stdout.jsonl",
                "build-stderr.log",
                "fs2-windows-appverifier-probe.exe",
                "initial-delete-stdout.log",
                "initial-delete-stderr.log",
                "initial-query-stdout.log",
                "initial-query-stderr.log",
                "baseline-stdout.log",
                "baseline-stderr.log",
                "configure-stdout.log",
                "configure-stderr.log",
                "query-stdout.log",
                "query-stderr.log",
                "injected-stdout.log",
                "injected-stderr.log",
                "cleanup-delete-stdout.log",
                "cleanup-delete-stderr.log",
                "cleanup-query-stdout.log",
                "cleanup-query-stderr.log",
            )
            for name in artifact_names:
                (run_root / name).write_bytes(f"{name}\n".encode())
            probe_path = run_root / "fs2-windows-appverifier-probe.exe"
            absent = {
                "lowres_enabled": False,
                "file_probability": None,
                "timeout_ms": None,
            }
            configured = {
                "lowres_enabled": True,
                "file_probability": 1000000,
                "timeout_ms": 0,
            }
            verifier_path = "appverif.exe"
            query_command = [
                verifier_path,
                "-query",
                "lowres",
                "-for",
                "fs2-windows-appverifier-probe.exe",
            ]
            delete_command = [
                verifier_path,
                "-delete",
                "settings",
                "-for",
                "fs2-windows-appverifier-probe.exe",
            ]
            manifest = {
                "record_type": "windows_appverifier_run",
                "schema_version": 1,
                "run_id": "test-appverifier-pass",
                "repository": "arthurianresolve/fs2-rs",
                "branch": "DO-178C",
                "commit": "d1e0e22eaed156e2420058f52f119e10330e24df",
                "tree": "2" * 40,
                "dirty": False,
                "cargo_lock_sha256": canonical_text_sha256(ROOT / "Cargo.lock"),
                "host": {"system": "Windows", "release": "test", "version": "test", "machine": "AMD64", "python": "test", "target": "x86_64-pc-windows-msvc", "administrator": True},
                "target": "x86_64-pc-windows-msvc",
                "requested_toolchain": "1.88",
                "resolved_toolchain": "rustc test\nhost: x86_64-pc-windows-msvc",
                "application_verifier": {"path": verifier_path, "version": "test", "sha256": "0" * 64},
                "probe": {"test_target": "windows_appverifier", "test_id": "appverifier_file_fault_is_observed", "binary": probe_path.name, "sha256": sha256(probe_path)},
                "configuration": {"layer": "lowres", "file_probability": 1000000, "timeout_ms": 0, "target_image": probe_path.name},
                "commands": {
                    "build": ["cargo", "+1.88", "test", "--package", "fs2", "--target", "x86_64-pc-windows-msvc", "--locked", "--test", "windows_appverifier", "--no-run", "--message-format=json"],
                    "probe": [str(probe_path), "--exact", "appverifier_file_fault_is_observed", "--nocapture"],
                    "initial_delete": delete_command,
                    "initial_query": query_command,
                    "configure": [verifier_path, "-enable", "lowres", "-for", probe_path.name, "-with", "file=1000000", "timeout=0"],
                    "query": query_command,
                    "cleanup_delete": delete_command,
                    "cleanup_query": query_command,
                },
                "controlled_environment": {
                    "baseline": {"FS2_APPVERIFIER_PROBE_PATH": str(ROOT / "Cargo.toml")},
                    "injected": {"FS2_APPVERIFIER_PROBE_PATH": str(ROOT / "Cargo.toml"), "FS2_EXPECT_APPVERIFIER_FILE_FAULT": "1"},
                },
                "initial_state": {"delete_native_exit": 0, "query_native_exit": 0, "query_observation": absent, "verified_absent": True},
                "baseline": {"native_exit": 0, "observation": {"schema_version": 1, "fault_expected": False, "control_create_file": "success", "control_raw_os_error": None, "fs2_outcome": "success", "fs2_raw_os_error": None}},
                "configured_state": {"enable_native_exit": 0, "query_native_exit": 0, "query_observation": configured, "verified": True},
                "injected": {"native_exit": 0, "observation": {"schema_version": 1, "fault_expected": True, "control_create_file": "error", "control_raw_os_error": 8, "fs2_outcome": "success", "fs2_raw_os_error": None}},
                "cleanup": {"delete_native_exit": 0, "query_native_exit": 0, "query_observation": absent, "verified_absent": True},
                "review_status": "independent_review_pending",
                "status": "pass",
                "artifacts": [
                    {"path": name, "sha256": sha256(run_root / name), "bytes": (run_root / name).stat().st_size}
                    for name in artifact_names
                ],
                "created_utc": "2026-08-13T10:00:00+00:00",
            }
            path = run_root / "windows-appverifier-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            validate_windows_appverifier_manifest(path, manifest["commit"])

            manifest["cleanup"]["verified_absent"] = False
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValidationError):
                validate_windows_appverifier_manifest(path)

if __name__ == "__main__":
    unittest.main()
