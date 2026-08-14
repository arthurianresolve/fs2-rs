#!/usr/bin/env python3
"""Collect a native semantic source/object companion for internal review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validate_object_analysis import (
    COMMIT_RE,
    ROOT,
    TARGETS,
    canonical_text_sha256,
    expected_source_inventory,
)
from validate_semantic_source_object import (
    NON_CLAIMS,
    SECTION_COMPARISON,
    SemanticSourceObjectError,
    build_semantic_source_object_map,
    validate_manifest,
)


REPOSITORY = "arthurianresolve/fs2-rs"
BRANCH = "DO-178C"
TOOLCHAIN = "1.97.1"


class CollectionError(Exception):
    """Semantic source/object collection could not produce valid evidence."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def readobj_int(value: Any) -> int:
    if isinstance(value, bool):
        raise CollectionError("LLVM object metadata contained a boolean integer")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0)


def readobj_field(block: list[str], field: str) -> str | None:
    prefix = f"{field}:"
    for line in block:
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix) :].strip()
    return None


def readobj_blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    depth = 0
    for line in text.splitlines():
        if current is None:
            if line.startswith("  Section {"):
                current = [line]
                depth = 1
            continue
        current.append(line)
        depth += line.count("{") - line.count("}")
        if depth == 0:
            blocks.append(current)
            current = None
    if current is not None:
        raise CollectionError("LLVM object section output ended inside a section")
    return blocks


def payload_record(
    *,
    index: int,
    type_name: str,
    segment: str,
    flags: int,
    size: int,
    payload: bytes,
) -> dict[str, Any]:
    return {
        "index": index,
        "type": type_name,
        "segment": segment,
        "flags": flags,
        "size": size,
        "sha256": sha256_bytes(payload),
    }


def elf_payload_summary(path: Path, tool: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(tool), "--sections", "--elf-output-style=JSON", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectionError(f"llvm-readobj ELF section inspection failed: {detail}")
    try:
        files = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CollectionError(f"llvm-readobj ELF JSON was invalid: {error}") from error
    if not isinstance(files, list) or len(files) != 1:
        raise CollectionError("llvm-readobj ELF JSON did not contain one object")
    sections = files[0].get("Sections")
    if not isinstance(sections, list):
        raise CollectionError("llvm-readobj ELF JSON did not contain sections")
    excluded = {
        "SHT_NULL",
        "SHT_STRTAB",
        "SHT_SYMTAB",
        "SHT_DYNSYM",
        "SHT_RELA",
        "SHT_REL",
        "SHT_GROUP",
        "SHT_SYMTAB_SHNDX",
    }
    source = path.read_bytes()
    records: list[dict[str, Any]] = []
    for item in sections:
        section = item.get("Section") if isinstance(item, dict) else None
        if not isinstance(section, dict):
            raise CollectionError("llvm-readobj ELF section shape was invalid")
        type_value = section.get("Type")
        type_name = type_value.get("Name") if isinstance(type_value, dict) else None
        if not isinstance(type_name, str):
            raise CollectionError("llvm-readobj ELF section type was invalid")
        if type_name in excluded:
            continue
        flags_value = section.get("Flags")
        flags = flags_value.get("Value") if isinstance(flags_value, dict) else None
        size = readobj_int(section.get("Size", 0))
        offset = readobj_int(section.get("Offset", 0))
        if size < 0 or offset < 0:
            raise CollectionError("llvm-readobj ELF section size or offset was negative")
        if type_name == "SHT_NOBITS":
            payload = b""
        else:
            end = offset + size
            if end > len(source):
                raise CollectionError("llvm-readobj ELF section exceeds object bounds")
            payload = source[offset:end]
        records.append(
            payload_record(
                index=len(records),
                type_name=type_name,
                segment="",
                flags=readobj_int(flags or 0),
                size=size,
                payload=payload,
            )
        )
    return section_payload_summary(records)


def text_payload_summary(path: Path, tool: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(tool), "--file-headers", "--sections", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectionError(f"llvm-readobj section inspection failed: {detail}")
    format_match = re.search(r"^Format: (.+)$", result.stdout, re.MULTILINE)
    if format_match is None:
        raise CollectionError("llvm-readobj section output did not report an object format")
    source = path.read_bytes()
    records: list[dict[str, Any]] = []
    for block in readobj_blocks(result.stdout):
        name_value = readobj_field(block, "Name") or ""
        name = name_value.split(" (", 1)[0]
        lowered = name.lower()
        if lowered.startswith((".debug", ".zdebug", ".symtab", ".strtab", ".shstrtab", ".rel", ".rela", "__debug", "__reloc")):
            continue
        size_value = readobj_field(block, "Size")
        raw_size_value = readobj_field(block, "RawDataSize")
        size = readobj_int(size_value if size_value is not None else raw_size_value or 0)
        offset_value = readobj_field(block, "Offset")
        raw_offset_value = readobj_field(block, "PointerToRawData")
        offset = readobj_int(offset_value if offset_value is not None else raw_offset_value or 0)
        if size < 0 or offset < 0:
            raise CollectionError("llvm-readobj section size or offset was negative")
        if size == 0:
            payload = b""
        else:
            end = offset + size
            if offset == 0 or end > len(source):
                raise CollectionError("llvm-readobj section exceeds object bounds")
            payload = source[offset:end]
        type_value = readobj_field(block, "Type") or "COFF_SECTION"
        type_name = type_value.split(" (", 1)[0]
        segment_value = readobj_field(block, "Segment") or ""
        segment = segment_value.split(" (", 1)[0]
        flags_value = None
        for line in block:
            match = re.match(r"\s+(?:Attributes|Characteristics) \[ \(0x([0-9A-Fa-f]+)\)", line)
            if match:
                flags_value = int(match.group(1), 16)
                break
        records.append(
            payload_record(
                index=len(records),
                type_name=type_name,
                segment=segment,
                flags=flags_value or 0,
                size=size,
                payload=payload,
            )
        )
    return section_payload_summary(records)


def section_payload_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise CollectionError("LLVM object payload comparison found no comparable sections")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "fingerprint": sha256_bytes(encoded),
        "section_count": len(records),
        "sections": records,
    }


def compare_object_payloads(
    production_path: Path,
    semantic_path: Path,
    tool: Path,
    object_format: str,
) -> dict[str, Any]:
    if object_format == "ELF":
        production = elf_payload_summary(production_path, tool)
        semantic = elf_payload_summary(semantic_path, tool)
    else:
        production = text_payload_summary(production_path, tool)
        semantic = text_payload_summary(semantic_path, tool)
    return {
        "method": SECTION_COMPARISON,
        "format": object_format,
        "status": "equal" if production == semantic else "differ",
        "production": production,
        "semantic": semantic,
    }


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectionError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.strip()


def command_output(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectionError(f"{' '.join(command)} failed: {detail}")
    return result.stdout.strip() or result.stderr.strip()


def rustc_host_target(verbose_version: str) -> str:
    for line in verbose_version.splitlines():
        if line.startswith("host:"):
            target = line.split(":", 1)[1].strip()
            if target:
                return target
    raise CollectionError("rustc --version --verbose did not report a host target")


def resolve_output_dir(value: Path) -> Path:
    output_dir = value if value.is_absolute() else ROOT / value
    output_dir = output_dir.resolve()
    try:
        output_dir.relative_to(ROOT)
    except ValueError as error:
        raise CollectionError("--output-dir must be inside the repository") from error
    if output_dir == ROOT or output_dir == (ROOT / "coverage").resolve():
        raise CollectionError("--output-dir must be a fresh staging directory")
    if output_dir.exists():
        raise CollectionError(f"--output-dir already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    return output_dir


def artifact_records(output_dir: Path) -> list[dict[str, Any]]:
    return [
        {"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
        for path in sorted(output_dir.iterdir(), key=lambda item: item.name)
        if path.name != "semantic-source-object-manifest.json" and path.is_file()
    ]


def write_manifest(output_dir: Path, manifest: dict[str, Any]) -> Path:
    manifest["artifacts"] = artifact_records(output_dir)
    path = output_dir / "semantic-source-object-manifest.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def llvm_tool_paths(sysroot: str, host_target: str) -> dict[str, Path]:
    suffix = ".exe" if os.name == "nt" else ""
    directory = Path(sysroot) / "lib" / "rustlib" / host_target / "bin"
    tools = {
        "llvm_objcopy": directory / f"llvm-objcopy{suffix}",
        "llvm_readobj": directory / f"llvm-readobj{suffix}",
        "llvm_objdump": directory / f"llvm-objdump{suffix}",
    }
    missing = [name for name, path in tools.items() if not path.is_file()]
    if missing:
        raise CollectionError(
            "llvm-tools-preview is incomplete; missing " + ", ".join(sorted(missing))
        )
    return tools


def build_command(
    target: str, target_dir: Path, *, emit: str, debuginfo: int
) -> list[str]:
    return [
        "cargo",
        f"+{TOOLCHAIN}",
        "rustc",
        "--package",
        "fs2",
        "--lib",
        "--release",
        "--target",
        target,
        "--locked",
        "--target-dir",
        str(target_dir),
        "--message-format=json-render-diagnostics",
        "--",
        f"--emit={emit}",
        "-C",
        f"debuginfo={debuginfo}",
    ]


def find_compiler_artifacts(
    cargo_stdout: Path, build_root: Path, *, required_kinds: tuple[str, ...]
) -> dict[str, Path]:
    candidates: dict[str, list[Path]] = {"mir": [], "llvm_ir": [], "object": []}
    for line_number, line in enumerate(cargo_stdout.read_text(encoding="utf-8").splitlines(), 1):
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise CollectionError(
                f"cargo JSON output is invalid at line {line_number}: {error}"
            ) from error
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        if not isinstance(target, dict) or target.get("name") != "fs2":
            continue
        filenames = message.get("filenames")
        if not isinstance(filenames, list):
            continue
        for filename in filenames:
            path = Path(str(filename))
            if not path.is_file():
                continue
            if path.suffix == ".mir":
                candidates["mir"].append(path)
            elif path.suffix == ".ll":
                candidates["llvm_ir"].append(path)
            elif path.suffix in {".o", ".obj"}:
                candidates["object"].append(path)
    # Cargo's JSON compiler-artifact message lists the link outputs but does
    # not consistently list the auxiliary files requested through --emit.
    # The build directory is fresh and target-specific, so discover those
    # auxiliary outputs there rather than assuming the JSON message is complete.
    for path in build_root.rglob("*"):
        if not path.is_file() or not path.name.startswith(("fs2-", "libfs2-")):
            continue
        if path.suffix == ".mir":
            candidates["mir"].append(path)
        elif path.suffix == ".ll":
            candidates["llvm_ir"].append(path)
        elif path.suffix in {".o", ".obj"}:
            candidates["object"].append(path)
    result: dict[str, Path] = {}
    for kind in required_kinds:
        paths = candidates[kind]
        unique = sorted(set(paths), key=lambda path: str(path))
        if len(unique) != 1:
            raise CollectionError(
                f"cargo did not report exactly one fs2 {kind} companion; found {len(unique)}"
            )
        result[kind] = unique[0]
    return result


def run_tool(command: list[str], output_path: Path, shared_stderr: Path) -> int:
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )
    output_path.write_text(result.stdout, encoding="utf-8", newline="\n")
    if result.stderr:
        with shared_stderr.open("a", encoding="utf-8", newline="\n") as sink:
            sink.write(f"\n--- {' '.join(command[:2])} stderr ---\n")
            sink.write(result.stderr)
            if not result.stderr.endswith("\n"):
                sink.write("\n")
    return result.returncode


def run_cargo(
    command: list[str], stdout_path: Path, stderr_path: Path, timeout_seconds: int
) -> int | None:
    with stdout_path.open("w", encoding="utf-8", newline="\n") as stdout, stderr_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as stderr:
        try:
            result = subprocess.run(
                command,
                cwd=ROOT,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=timeout_seconds,
                env={**os.environ, "CARGO_INCREMENTAL": "0"},
            )
        except subprocess.TimeoutExpired:
            return None
    return result.returncode


def run_objcopy(
    tool: Path, input_path: Path, output_path: Path, shared_stderr: Path
) -> int:
    shutil.copyfile(input_path, output_path)
    result = subprocess.run(
        [str(tool), "--strip-all", str(output_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout or result.stderr:
        with shared_stderr.open("a", encoding="utf-8", newline="\n") as sink:
            sink.write(f"\n--- {tool.name} --strip-all stderr ---\n")
            if result.stdout:
                sink.write(result.stdout)
            if result.stderr:
                sink.write(result.stderr)
            if not (result.stdout + result.stderr).endswith("\n"):
                sink.write("\n")
    return result.returncode


def artifact_record(path: Path) -> dict[str, Any]:
    return {"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}


def production_byte_equivalence(
    production_object: Path,
    semantic_object: Path,
    production_stripped_object: Path,
    semantic_stripped_object: Path,
    payload_comparison: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": (
            "non_debug_object_payload_equal"
            if payload_comparison["status"] == "equal"
            else "non_debug_object_payload_differ"
        ),
        "comparison": "same-target-release-object-section-payloads-equal-after-llvm-objcopy-strip-all",
        "production_object": artifact_record(production_object),
        "semantic_object": artifact_record(semantic_object),
        "production_stripped_object": artifact_record(production_stripped_object),
        "semantic_stripped_object": artifact_record(semantic_stripped_object),
        "payload_comparison": payload_comparison,
    }


def initial_manifest(
    *,
    run_id: str,
    target: str,
    commit: str,
    tree: str,
    dirty: bool,
    lock_hash: str,
    host_target: str,
    command: list[str],
    production_command: list[str],
    object_command: list[str],
    inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "record_type": "semantic_source_object_run",
        "schema_version": 1,
        "run_id": run_id,
        "repository": REPOSITORY,
        "branch": BRANCH,
        "commit": commit,
        "tree": tree,
        "dirty": dirty,
        "cargo_lock_sha256": lock_hash,
        "host": {
            "system": platform.system() or "unknown",
            "release": platform.release() or "unknown",
            "version": platform.version() or "unknown",
            "machine": platform.machine() or "unknown",
            "python": platform.python_version(),
            "target": host_target,
        },
        "target": target,
        "object_format": TARGETS[target]["object_format"],
        "profile": "release",
        "source_inventory": {
            "record_ref": "coverage/surface.json",
            "records": inventory,
        },
        "toolchain": {
            "requested": TOOLCHAIN,
            "rustc": "unresolved",
            "cargo": "unresolved",
            "llvm_objcopy": "unresolved",
            "llvm_readobj": "unresolved",
            "llvm_objdump": "unresolved",
        },
        "command": command,
        "production_command": production_command,
        "object_command": object_command,
        "native_exits": {
            "production_cargo": None,
            "object_cargo": None,
            "cargo": None,
            "llvm_objcopy_production": None,
            "llvm_objcopy_companion": None,
            "llvm_payload_compare": None,
            "llvm_readobj": None,
            "llvm_objdump": None,
        },
        "status": "provenance_error",
        "analysis": {
            "mir_function_count": 0,
            "mir_switch_count": 0,
            "llvm_function_count": 0,
            "llvm_debug_location_count": 0,
            "llvm_conditional_site_count": 0,
            "object_debug_section_count": 0,
            "source_object_mapping_status": "debug_location_bridge_retained_not_equivalence",
            "production_object_binding_status": "not_established",
            "generated_code_disposition": "reviewed_internal_compiler_generated_not_credited",
            "object_code_coverage_status": "not_collected",
        },
        "production_byte_equivalence": {
            "status": "not_established",
            "comparison": "same-target-release-object-section-payloads-equal-after-llvm-objcopy-strip-all",
            "production_object": None,
            "semantic_object": None,
            "production_stripped_object": None,
            "semantic_stripped_object": None,
            "payload_comparison": None,
        },
        "artifacts": [],
        "created_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "limitations": [
            "The byte comparison is limited to direct release object section payloads after llvm-objcopy --strip-all; symbols, relocations, and format metadata are excluded, so it does not establish full object, rlib/archive, symbol/relocation identity, or source/object equivalence.",
            "The debuginfo companion is a separate diagnostic build; debug-info settings may alter object code. The byte binding uses a separate debuginfo=0 semantic build with the same release inputs.",
            "MIR and LLVM debug locations are compiler diagnostics; no complete source-to-production-object semantic comparison is performed.",
            "Compiler-generated, monomorphized, inlined, runtime, and foreign-library code require target-specific human disposition.",
            "No executed object-code structural coverage or MC/DC result is collected.",
        ],
        "non_claims": NON_CLAIMS,
    }


def collect(args: argparse.Namespace) -> int:
    if args.target not in TARGETS:
        raise CollectionError(f"unregistered target: {args.target!r}")
    expected_commit = args.expected_commit or os.environ.get("GITHUB_SHA") or git(
        "rev-parse", "HEAD"
    )
    if not COMMIT_RE.fullmatch(expected_commit):
        raise CollectionError("expected commit must be a full lowercase Git object ID")
    output_dir = resolve_output_dir(args.output_dir)
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-semantic-"
        + uuid.uuid4().hex[:12]
    )
    actual_commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    lockfile = ROOT / "Cargo.lock"
    lock_hash = canonical_text_sha256(lockfile) if lockfile.is_file() else "0" * 64
    inventory = expected_source_inventory(args.target)
    target_root = ROOT / "target"
    target_root.mkdir(exist_ok=True)
    placeholder_build = target_root / "semantic-source-object-build"
    placeholder_production_build = target_root / "semantic-source-object-production-build"
    placeholder_command = build_command(
        args.target,
        placeholder_build,
        emit="link,mir,llvm-ir,obj",
        debuginfo=2,
    )
    placeholder_production_command = build_command(
        args.target,
        placeholder_production_build,
        emit="link,obj",
        debuginfo=0,
    )
    placeholder_object_command = build_command(
        args.target,
        target_root / "semantic-source-object-object-build",
        emit="link,mir,llvm-ir,obj",
        debuginfo=0,
    )
    manifest = initial_manifest(
        run_id=run_id,
        target=args.target,
        commit=actual_commit,
        tree=tree,
        dirty=dirty,
        lock_hash=lock_hash,
        host_target="unresolved",
        command=placeholder_command,
        production_command=placeholder_production_command,
        object_command=placeholder_object_command,
        inventory=inventory,
    )
    status = "provenance_error"
    try:
        branch = git("branch", "--show-current") or os.environ.get("GITHUB_REF_NAME", "")
        if branch != BRANCH:
            raise CollectionError(f"collector requires branch {BRANCH!r}, found {branch!r}")
        if actual_commit != expected_commit:
            raise CollectionError(
                f"HEAD {actual_commit} does not match expected commit {expected_commit}"
            )
        if dirty and not args.allow_dirty:
            raise CollectionError("working tree is dirty; use a clean checkout for evidence")
        if not lockfile.is_file():
            raise CollectionError("Cargo.lock is missing")
        rustc_version = command_output(["rustc", f"+{TOOLCHAIN}", "--version", "--verbose"])
        host_target = rustc_host_target(rustc_version)
        manifest["host"]["target"] = host_target
        if host_target != args.target:
            raise CollectionError(
                f"native semantic source/object analysis requires host {args.target!r}; found {host_target!r}"
            )
        sysroot = command_output(["rustc", f"+{TOOLCHAIN}", "--print", "sysroot"])
        llvm_tools = llvm_tool_paths(sysroot, host_target)
        manifest["toolchain"] = {
            "requested": TOOLCHAIN,
            "rustc": rustc_version,
            "cargo": command_output(["cargo", f"+{TOOLCHAIN}", "--version"]),
            **{
                name: command_output([str(path), "--version"])
                for name, path in llvm_tools.items()
            },
        }
        with tempfile.TemporaryDirectory(prefix="semantic-source-object-", dir=target_root) as temporary:
            build_root = Path(temporary)
            production_build_root = build_root / "production"
            object_build_root = build_root / "object"
            companion_build_root = build_root / "companion"
            command = build_command(
                args.target,
                companion_build_root,
                emit="link,mir,llvm-ir,obj",
                debuginfo=2,
            )
            production_command = build_command(
                args.target,
                production_build_root,
                emit="link,obj",
                debuginfo=0,
            )
            object_command = build_command(
                args.target,
                object_build_root,
                emit="link,mir,llvm-ir,obj",
                debuginfo=0,
            )
            manifest["command"] = command
            manifest["production_command"] = production_command
            manifest["object_command"] = object_command
            production_stdout = output_dir / "production.stdout.jsonl"
            production_stderr = output_dir / "production.stderr.log"
            object_stdout = output_dir / "object.stdout.jsonl"
            object_stderr = output_dir / "object.stderr.log"
            stdout_path = output_dir / "cargo.stdout.jsonl"
            stderr_path = output_dir / "cargo.stderr.log"
            production_exit = run_cargo(
                production_command,
                production_stdout,
                production_stderr,
                args.timeout_seconds,
            )
            manifest["native_exits"]["production_cargo"] = production_exit
            if production_exit is None:
                status = "indeterminate"
                (output_dir / "timeout.txt").write_text(
                    f"production object build exceeded {args.timeout_seconds} seconds\n",
                    encoding="utf-8",
                    newline="\n",
                )
            elif production_exit != 0:
                status = "fail"
            else:
                object_exit = run_cargo(
                    object_command, object_stdout, object_stderr, args.timeout_seconds
                )
                manifest["native_exits"]["object_cargo"] = object_exit
                companion_exit = run_cargo(
                    command, stdout_path, stderr_path, args.timeout_seconds
                )
                manifest["native_exits"]["cargo"] = companion_exit
                if object_exit is None or companion_exit is None:
                    status = "indeterminate"
                    (output_dir / "timeout.txt").write_text(
                        f"semantic source/object build exceeded {args.timeout_seconds} seconds\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                elif object_exit != 0 or companion_exit != 0:
                    status = "fail"
                else:
                    production_artifact = find_compiler_artifacts(
                        production_stdout,
                        production_build_root,
                        required_kinds=("object",),
                    )
                    companion_artifacts = find_compiler_artifacts(
                        stdout_path,
                        companion_build_root,
                        required_kinds=("mir", "llvm_ir", "object"),
                    )
                    object_artifacts = find_compiler_artifacts(
                        object_stdout,
                        object_build_root,
                        required_kinds=("object",),
                    )
                    retained = {
                        "production_object": output_dir / "fs2.production.o",
                        "production_non_debug_object": output_dir / "fs2.production.nondebug.o",
                        "mir": output_dir / "fs2.semantic.mir",
                        "llvm_ir": output_dir / "fs2.semantic.ll",
                        "object": output_dir / "fs2.semantic.o",
                        "debug_object": output_dir / "fs2.semantic.debug.o",
                        "semantic_stripped_object": output_dir / "fs2.semantic.nondebug.o",
                    }
                    shutil.copyfile(production_artifact["object"], retained["production_object"])
                    for kind in ("mir", "llvm_ir"):
                        shutil.copyfile(companion_artifacts[kind], retained[kind])
                    shutil.copyfile(object_artifacts["object"], retained["object"])
                    shutil.copyfile(companion_artifacts["object"], retained["debug_object"])
                    manifest["native_exits"]["llvm_objcopy_production"] = run_objcopy(
                        llvm_tools["llvm_objcopy"],
                        retained["production_object"],
                        retained["production_non_debug_object"],
                        production_stderr,
                    )
                    manifest["native_exits"]["llvm_objcopy_companion"] = run_objcopy(
                        llvm_tools["llvm_objcopy"],
                        retained["object"],
                        retained["semantic_stripped_object"],
                        stderr_path,
                    )
                    payload_comparison = compare_object_payloads(
                        retained["production_non_debug_object"],
                        retained["semantic_stripped_object"],
                        llvm_tools["llvm_readobj"],
                        TARGETS[args.target]["object_format"],
                    )
                    manifest["native_exits"]["llvm_payload_compare"] = 0
                    object_structure = output_dir / "object-structure.txt"
                    disassembly = output_dir / "disassembly.txt"
                    manifest["native_exits"]["llvm_readobj"] = run_tool(
                        [
                            str(llvm_tools["llvm_readobj"]),
                            "--file-headers",
                            "--sections",
                            "--symbols",
                            str(retained["debug_object"]),
                        ],
                        object_structure,
                        stderr_path,
                    )
                    manifest["native_exits"]["llvm_objdump"] = run_tool(
                        [
                            str(llvm_tools["llvm_objdump"]),
                            "--disassemble",
                            "--demangle",
                            str(retained["debug_object"]),
                        ],
                        disassembly,
                        stderr_path,
                    )
                    manifest["production_byte_equivalence"] = production_byte_equivalence(
                        retained["production_object"],
                        retained["object"],
                        retained["production_non_debug_object"],
                        retained["semantic_stripped_object"],
                        payload_comparison,
                    )
                    source_map = build_semantic_source_object_map(
                        target=args.target,
                        commit=manifest["commit"],
                        tree=manifest["tree"],
                        inventory=manifest["source_inventory"]["records"],
                        mir_path=retained["mir"],
                        llvm_path=retained["llvm_ir"],
                        object_path=retained["debug_object"],
                        object_structure_path=object_structure,
                        disassembly_path=disassembly,
                    )
                    (output_dir / "semantic-source-object-map.json").write_text(
                        json.dumps(source_map, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                    manifest["analysis"] = {
                        "mir_function_count": source_map["mir"]["function_count"],
                        "mir_switch_count": source_map["mir"]["switch_count"],
                        "llvm_function_count": source_map["llvm"]["function_count"],
                        "llvm_debug_location_count": source_map["llvm"]["debug_location_count"],
                        "llvm_conditional_site_count": source_map["llvm"]["conditional_site_count"],
                        "object_debug_section_count": source_map["object"]["debug_section_count"],
                        "source_object_mapping_status": "debug_location_bridge_retained_not_equivalence",
                        "production_object_binding_status": (
                            "production_non_debug_object_payload_equal"
                            if manifest["production_byte_equivalence"]["status"]
                            == "non_debug_object_payload_equal"
                            else manifest["production_byte_equivalence"]["status"]
                        ),
                        "generated_code_disposition": "reviewed_internal_compiler_generated_not_credited",
                        "object_code_coverage_status": "not_collected",
                    }
                    status = (
                        "pass"
                        if all(value == 0 for value in manifest["native_exits"].values())
                        and manifest["production_byte_equivalence"]["status"]
                        == "non_debug_object_payload_equal"
                        and all(
                            manifest["analysis"][field] > 0
                            for field in (
                                "mir_function_count",
                                "llvm_function_count",
                                "llvm_debug_location_count",
                                "object_debug_section_count",
                            )
                        )
                        and retained["production_object"].stat().st_size > 0
                        and retained["object"].stat().st_size > 0
                        else "fail"
                    )
                    if status == "pass" and dirty:
                        status = "focused_only"
    except CollectionError as error:
        (output_dir / "preflight-error.txt").write_text(
            f"{error}\n", encoding="utf-8", newline="\n"
        )
        status = "provenance_error"
    manifest["status"] = status
    manifest_path = write_manifest(output_dir, manifest)
    validate_manifest(
        manifest_path,
        expected_commit=expected_commit if actual_commit == expected_commit else None,
        require_pass=False,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if status in {"pass", "focused_only"} else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--locked",
        action="store_true",
        help="retained for explicit command intent; collection is always locked",
    )
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    try:
        return collect(args)
    except (CollectionError, SemanticSourceObjectError, OSError, ValueError) as error:
        print(
            f"semantic source/object analysis failed before a valid manifest could be written: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
