import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_object_analysis import expected_source_inventory
from validate_semantic_source_object import (
    NON_CLAIMS,
    PASS_ARTIFACTS,
    build_semantic_source_object_map,
    sha256,
    validate_manifest,
    validate_static,
)


class SemanticSourceObjectValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fs2-semantic-source-object-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = "x86_64-unknown-linux-gnu"
        self.commit = "1" * 40
        self.tree = "2" * 40
        self.inventory = expected_source_inventory(self.target)
        self.write_companion()
        self.manifest_path = self.root / "semantic-source-object-manifest.json"
        self.write_manifest()

    def write_companion(self):
        mir_lines = []
        llvm_lines = []
        metadata = []
        for index, source in enumerate(self.inventory, 10):
            source_path = source["path"].replace("/", "\\")
            mir_lines.extend(
                [
                    f"fn fixture_{index} at {source_path}:1:1: 1:2 {{",
                    "    switchInt(_1) -> [0: bb1, otherwise: bb2];",
                    "}",
                ]
            )
            file_id = index * 2
            subprogram_id = file_id + 1
            location_id = file_id + 2
            metadata.extend(
                [
                    f'!{file_id} = !DIFile(filename: "{Path(source_path).name}", directory: "C:\\\\fixture\\src")',
                    f'!{subprogram_id} = distinct !DISubprogram(name: "fixture_{index}", file: !{file_id}, line: 1, scopeLine: 1)',
                    f"!{location_id} = !DILocation(line: 1, column: 1, scope: !{subprogram_id})",
                ]
            )
            llvm_lines.extend(
                [
                    f"define void @fixture_{index}() !dbg !{subprogram_id} {{",
                    f"  br i1 true, label %then, label %else, !dbg !{location_id}",
                    "}",
                ]
            )
        (self.root / "fs2.semantic.mir").write_text("\n".join(mir_lines) + "\n", encoding="utf-8")
        (self.root / "fs2.semantic.ll").write_text(
            "\n".join(llvm_lines + metadata) + "\n", encoding="utf-8"
        )
        (self.root / "fs2.semantic.o").write_bytes(b"semantic object\n")
        (self.root / "fs2.production.o").write_bytes(b"production object\n")
        (self.root / "fs2.production.nondebug.o").write_bytes(b"normalized object\n")
        (self.root / "fs2.semantic.nondebug.o").write_bytes(b"normalized object\n")
        (self.root / "object-structure.txt").write_text(
            "    Name: .debug_info (1)\n", encoding="utf-8"
        )
        (self.root / "disassembly.txt").write_text("disassembly\n", encoding="utf-8")
        (self.root / "cargo.stdout.jsonl").write_text("cargo output\n", encoding="utf-8")
        (self.root / "cargo.stderr.log").write_text("cargo stderr\n", encoding="utf-8")
        (self.root / "production.stdout.jsonl").write_text("production output\n", encoding="utf-8")
        (self.root / "production.stderr.log").write_text("production stderr\n", encoding="utf-8")
        (self.root / "object.stdout.jsonl").write_text("object output\n", encoding="utf-8")
        (self.root / "object.stderr.log").write_text("object stderr\n", encoding="utf-8")
        self.map = build_semantic_source_object_map(
            target=self.target,
            commit=self.commit,
            tree=self.tree,
            inventory=self.inventory,
            mir_path=self.root / "fs2.semantic.mir",
            llvm_path=self.root / "fs2.semantic.ll",
            object_path=self.root / "fs2.semantic.o",
            object_structure_path=self.root / "object-structure.txt",
            disassembly_path=self.root / "disassembly.txt",
        )
        (self.root / "semantic-source-object-map.json").write_text(
            json.dumps(self.map, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def write_manifest(self):
        manifest = {
            "record_type": "semantic_source_object_run",
            "schema_version": 1,
            "run_id": "semantic-run-1",
            "repository": "arthurianresolve/fs2-rs",
            "branch": "DO-178C",
            "commit": self.commit,
            "tree": self.tree,
            "dirty": False,
            "cargo_lock_sha256": "3" * 64,
            "host": {
                "system": "Linux",
                "release": "test",
                "version": "test",
                "machine": "x86_64",
                "python": "3.14",
                "target": self.target,
            },
            "target": self.target,
            "object_format": "ELF",
            "profile": "release",
            "source_inventory": {"record_ref": "coverage/surface.json", "records": self.inventory},
            "toolchain": {
                "requested": "1.97.1",
                "rustc": "rustc 1.97.1\nrelease: 1.97.1\nLLVM version: 22.1.6",
                "cargo": "cargo 1.97.1 (test)",
                "llvm_objcopy": "LLVM version: 22.1.6",
                "llvm_readobj": "LLVM version: 22.1.6",
                "llvm_objdump": "LLVM version: 22.1.6",
            },
            "command": [
                "cargo",
                "+1.97.1",
                "rustc",
                "--package",
                "fs2",
                "--lib",
                "--release",
                "--target",
                self.target,
                "--locked",
                "--emit=link,mir,llvm-ir,obj",
                "-C",
                "debuginfo=2",
            ],
            "production_command": [
                "cargo",
                "+1.97.1",
                "rustc",
                "--package",
                "fs2",
                "--lib",
                "--release",
                "--target",
                self.target,
                "--locked",
                "--emit=link,obj",
                "-C",
                "debuginfo=0",
            ],
            "object_command": [
                "cargo",
                "+1.97.1",
                "rustc",
                "--package",
                "fs2",
                "--lib",
                "--release",
                "--target",
                self.target,
                "--locked",
                "--emit=link,obj",
                "-C",
                "debuginfo=2",
            ],
            "native_exits": {
                "production_cargo": 0,
                "object_cargo": 0,
                "cargo": 0,
                "llvm_objcopy_production": 0,
                "llvm_objcopy_companion": 0,
                "llvm_readobj": 0,
                "llvm_objdump": 0,
            },
            "status": "pass",
            "analysis": {
                "mir_function_count": self.map["mir"]["function_count"],
                "mir_switch_count": self.map["mir"]["switch_count"],
                "llvm_function_count": self.map["llvm"]["function_count"],
                "llvm_debug_location_count": self.map["llvm"]["debug_location_count"],
                "llvm_conditional_site_count": self.map["llvm"]["conditional_site_count"],
                "object_debug_section_count": self.map["object"]["debug_section_count"],
                "source_object_mapping_status": "debug_location_bridge_retained_not_equivalence",
                "production_object_binding_status": "production_non_debug_object_bytes_equal",
                "generated_code_disposition": "reviewed_internal_compiler_generated_not_credited",
                "object_code_coverage_status": "not_collected",
            },
            "production_byte_equivalence": {
                "status": "non_debug_object_bytes_equal",
                "comparison": "same-target-release-object-files-equal-after-llvm-objcopy-strip-debug",
                "production_object": {"path": "fs2.production.o", "sha256": sha256(self.root / "fs2.production.o"), "bytes": (self.root / "fs2.production.o").stat().st_size},
                "companion_object": {"path": "fs2.semantic.o", "sha256": sha256(self.root / "fs2.semantic.o"), "bytes": (self.root / "fs2.semantic.o").stat().st_size},
                "production_non_debug_object": {"path": "fs2.production.nondebug.o", "sha256": sha256(self.root / "fs2.production.nondebug.o"), "bytes": (self.root / "fs2.production.nondebug.o").stat().st_size},
                "companion_non_debug_object": {"path": "fs2.semantic.nondebug.o", "sha256": sha256(self.root / "fs2.semantic.nondebug.o"), "bytes": (self.root / "fs2.semantic.nondebug.o").stat().st_size},
            },
            "artifacts": [],
            "created_utc": "2026-08-14T09:00:00Z",
            "limitations": ["fixture evidence only"],
            "non_claims": NON_CLAIMS,
        }
        manifest["artifacts"] = [
            {"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
            for path in sorted(self.root.iterdir(), key=lambda item: item.name)
            if path.name != self.manifest_path.name
        ]
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.manifest = manifest

    def test_static_contracts_are_valid(self):
        validate_static()

    def test_accepts_reproducible_companion_manifest(self):
        validated = validate_manifest(self.manifest_path, expected_commit=self.commit, require_pass=True)
        self.assertEqual(validated["analysis"]["source_object_mapping_status"], "debug_location_bridge_retained_not_equivalence")
        self.assertEqual(validated["analysis"]["production_object_binding_status"], "production_non_debug_object_bytes_equal")
        self.assertEqual(set(item["path"] for item in validated["artifacts"]), PASS_ARTIFACTS)

    def test_rejects_tampered_llvm_input(self):
        (self.root / "fs2.semantic.ll").write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(Exception):
            validate_manifest(self.manifest_path, require_pass=True)

    def test_rejects_production_equivalence_overclaim(self):
        self.manifest["analysis"]["source_object_mapping_status"] = "established"
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2) + "\n", encoding="utf-8")
        with self.assertRaises(Exception):
            validate_manifest(self.manifest_path)


if __name__ == "__main__":
    unittest.main()
