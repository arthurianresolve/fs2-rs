import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_coverage import CollectionError
import collect_windows_appverifier as appverifier
from collect_windows_appverifier import (
    MARKER,
    find_test_executable,
    parse_appverifier_query,
    parse_probe,
    query_is_absent,
)
from collect_windows_native_faults import EXPECTED_SCENARIOS, load_fault_record


class NativeFaultCollectorTests(unittest.TestCase):
    def payload(self) -> dict:
        return {
            "schema_version": 1,
            "evidence_class": "internal_engineering",
            "fault_model": "os_mediated_error_activation",
            "status": "pass",
            "scenarios": [
                {
                    "id": identifier,
                    "api_boundary": api,
                    "activation": activation,
                    "expected_raw_os": expected,
                    "actual_raw_os": expected if expected is not None else 2,
                }
                for identifier, (api, activation, expected) in EXPECTED_SCENARIOS.items()
            ],
            "limitations": ["one", "two", "three"],
        }

    def test_loads_complete_native_fault_matrix(self):
        with tempfile.TemporaryDirectory(prefix="fs2-native-fault-payload-") as directory:
            path = Path(directory) / "windows-native-faults.json"
            payload = self.payload()
            path.write_text(json.dumps(payload), encoding="utf-8")

            self.assertEqual(load_fault_record(path), payload)

    def test_rejects_wrong_native_error(self):
        with tempfile.TemporaryDirectory(prefix="fs2-native-fault-payload-") as directory:
            path = Path(directory) / "windows-native-faults.json"
            payload = self.payload()
            payload["scenarios"][0]["actual_raw_os"] = 6
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(CollectionError):
                load_fault_record(path)


class AppVerifierCollectorTests(unittest.TestCase):
    def write_probe(self, path: Path, record: dict) -> None:
        path.write_text(f"test output\n{MARKER}{json.dumps(record)}\n", encoding="utf-8")

    def test_parses_baseline_and_injected_controls(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-probe-") as directory:
            root = Path(directory)
            baseline = root / "baseline.log"
            injected = root / "injected.log"
            baseline_record = {
                "schema_version": 1,
                "fault_expected": False,
                "control_create_file": "success",
                "control_raw_os_error": None,
                "fs2_outcome": "success",
                "fs2_raw_os_error": None,
            }
            injected_record = {
                "schema_version": 1,
                "fault_expected": True,
                "control_create_file": "error",
                "control_raw_os_error": 8,
                "fs2_outcome": "error",
                "fs2_raw_os_error": 8,
            }
            self.write_probe(baseline, baseline_record)
            self.write_probe(injected, injected_record)

            self.assertEqual(parse_probe(baseline, False), baseline_record)
            self.assertEqual(parse_probe(injected, True), injected_record)

    def test_rejects_injected_run_without_activation(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-probe-") as directory:
            path = Path(directory) / "injected.log"
            self.write_probe(
                path,
                {
                    "schema_version": 1,
                    "fault_expected": True,
                    "control_create_file": "success",
                    "control_raw_os_error": None,
                    "fs2_outcome": "success",
                    "fs2_raw_os_error": None,
                },
            )

            with self.assertRaises(CollectionError):
                parse_probe(path, True)

    def test_parses_configured_and_absent_appverifier_queries(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-query-") as directory:
            root = Path(directory)
            configured = root / "configured.log"
            absent = root / "absent.log"
            configured.write_text(
                "Settings for probe.exe:\n"
                "Test [lowres] enabled.\n"
                "TimeOut = 0 (0x0)\n"
                "FILE = 1000000 (0xF4240)\n",
                encoding="utf-16",
            )
            absent.write_text("No settings for probe.exe.\n", encoding="utf-8")

            self.assertEqual(
                parse_appverifier_query(configured),
                {
                    "lowres_enabled": True,
                    "file_probability": 1000000,
                    "timeout_ms": 0,
                },
            )
            self.assertTrue(query_is_absent(parse_appverifier_query(absent)))

    def test_finds_exact_cargo_test_executable(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-build-") as directory:
            root = Path(directory)
            executable = root / "windows_appverifier.exe"
            executable.write_bytes(b"probe")
            output = root / "build.jsonl"
            output.write_text(
                json.dumps(
                    {
                        "reason": "compiler-artifact",
                        "target": {"name": "windows_appverifier"},
                        "executable": str(executable),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            self.assertEqual(find_test_executable(output), executable)

    def test_collection_clears_stale_settings_before_baseline(self):
        with tempfile.TemporaryDirectory(prefix="fs2-appverifier-order-") as directory:
            root = Path(directory)
            output = root / "evidence"
            output.mkdir()
            verifier = root / "appverif.exe"
            verifier.write_bytes(b"verifier")
            source_executable = root / "windows_appverifier.exe"
            source_executable.write_bytes(b"probe")
            events: list[str] = []

            def fake_run_logged(command, *, stdout_path, stderr_path, environment=None, timeout_seconds):
                stderr_path.write_text("", encoding="utf-8")
                if stdout_path.name == "build-stdout.jsonl":
                    events.append("build")
                    stdout_path.write_text("", encoding="utf-8")
                else:
                    injected = environment is not None and environment.get(
                        "FS2_EXPECT_APPVERIFIER_FILE_FAULT"
                    ) == "1"
                    events.append("injected" if injected else "baseline")
                    record = {
                        "schema_version": 1,
                        "fault_expected": injected,
                        "control_create_file": "error" if injected else "success",
                        "control_raw_os_error": 8 if injected else None,
                        "fs2_outcome": "error" if injected else "success",
                        "fs2_raw_os_error": 8 if injected else None,
                    }
                    stdout_path.write_text(
                        f"{MARKER}{json.dumps(record)}\n", encoding="utf-8"
                    )
                return 0

            def fake_run_appverifier(command, output_dir, stem, timeout_seconds):
                events.append(stem)
                stdout = output_dir / f"{stem}-stdout.log"
                stderr = output_dir / f"{stem}-stderr.log"
                if stem == "query":
                    stdout.write_text(
                        "Settings for fs2-windows-appverifier-probe.exe:\n"
                        "Test [lowres] enabled.\n"
                        "TimeOut = 0 (0x0)\n"
                        "FILE = 1000000 (0xF4240)\n",
                        encoding="utf-8",
                    )
                else:
                    stdout.write_text("No settings.\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                return 0

            args = SimpleNamespace(
                output_dir=output,
                expected_commit="1" * 40,
                allow_dirty=False,
                timeout_seconds=30,
            )
            with (
                mock.patch.object(appverifier, "APPVERIFIER", verifier),
                mock.patch.object(appverifier, "is_administrator", return_value=True),
                mock.patch.object(appverifier, "resolve_output_dir", return_value=output),
                mock.patch.object(
                    appverifier,
                    "preflight",
                    return_value=("DO-178C", "2" * 40, False, "3" * 64),
                ),
                mock.patch.object(appverifier, "command_output", return_value="rustc test"),
                mock.patch.object(
                    appverifier,
                    "rustc_host_target",
                    return_value=appverifier.TARGET,
                ),
                mock.patch.object(appverifier, "executable_version", return_value="test"),
                mock.patch.object(
                    appverifier,
                    "find_test_executable",
                    return_value=source_executable,
                ),
                mock.patch.object(appverifier, "run_logged", side_effect=fake_run_logged),
                mock.patch.object(
                    appverifier,
                    "run_appverifier_command",
                    side_effect=fake_run_appverifier,
                ),
            ):
                self.assertEqual(appverifier.collect(args), 0)

            self.assertEqual(
                events,
                [
                    "build",
                    "initial-delete",
                    "initial-query",
                    "baseline",
                    "configure",
                    "query",
                    "injected",
                    "cleanup-delete",
                    "cleanup-query",
                ],
            )


if __name__ == "__main__":
    unittest.main()
