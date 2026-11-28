"""Exact inputs and finite qualification scope for the native metadata owner."""
from __future__ import annotations

import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

from hia.platform.build import INPUTS
from hia.tools.toolchain import _source_path, compose_source, pinned_toolchain

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PREFIX = "hia/platform/peer_payload/"
SCHEMA = "trnm.hia.payload-metadata-qualification.v1"
COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
ORDER = ("owner", "metadata_runtime", "filesystem", "parent_bridge", "publication", "open", "commands")
IMAGES = (*ORDER, "linux_emitter", "view_fixture")
OBJECTS = ("metadata_codec", "metadata_log", "metadata_runtime")
FALSE = ("whole_payload_owner_qualified", "payload_body_store_qualified",
         "external_recovery_owner_qualified", "whole_peer_package_retired",
         "whole_chain_native", "production_activation", "original_service_budget_qualified",
         "foreign_pointer_ownership_or_concurrent_arena_qualified",
         "runtime_host_proxy", "rust_or_interpreter_fallback", "full_host_dependency_closure_claimed")
LIMITS = {"compiler_seconds": 30, "compiler_functions": 128, "compiler_blocks": 1536,
          "compiler_ops": 8192, "compiler_blocks_per_function": 256,
          "native_seconds": 240, "cleanup_seconds": 3, "cleanup_windows": 1,
          "process_observations": 4096, "original_service_seconds": 4}
CORPORA = {
    "codec": (4472, "d0fe50592d17a61112c8c2e32a41a345648c5a792b3aa7ef17104d7d5f1f7755"),
    "replay": (840, "9830ab6b3205eb3fc9df02b2bf40883418a5a98fd7fc435e05167afe1257489f"),
}
ORIGINAL_ROOTS = ("trillionnium", "tests/fixtures", "tests/fuzz", "tests/vectors")


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def document(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(capture(Path(path)), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))


def capture(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Linked qualification path: " + str(parent))
    before = path.stat()
    need(stat.S_ISREG(before.st_mode), "Missing regular source: " + str(path))
    raw = path.read_bytes()
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
         "Source changed while reading: " + str(path))
    return raw


def relative(name):
    need(type(name) is str and name and Path(name).as_posix() == name
         and not Path(name).is_absolute() and ".." not in Path(name).parts,
         "Noncanonical retained path")
    return Path(name)


def check_environment(environment):
    need(__debug__ and not environment.get("PYTHONOPTIMIZE"), "Optimized Python is not admitted")
    forbidden = {key for key, value in environment.items() if value and (
        key in {"RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUST_TEST_THREADS", "RUST_TEST_NOCAPTURE",
                "RUST_TEST_FORCE_RUN_IN_PROCESS", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
                "PYTHONHOME", "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR"}
        or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_")))}
    need(not forbidden, "Unbound compiler/runtime overrides: " + ", ".join(sorted(forbidden)))
    need(environment.get("HIA_NATIVE_COMPILER_SHA256") == COMPILER, "Different native compiler pin")
    from hia.platform.peer_lease_unix.build import cargo_configuration
    return {"forbidden_overrides": [], "absent_cargo_configuration": cargo_configuration(environment)}


def corpus(kind):
    count, expected = CORPORA[kind]
    raw = lzma.decompress(capture(HERE / "qualification" / (kind + "-cases.json.xz")))
    need(identity(raw)["sha256"] == expected, "Frozen corpus bytes changed: " + kind)
    rows = json.loads(raw)
    need(type(rows) is list and len(rows) == count
         and len({row["name"] for row in rows}) == count, "Corpus roster changed")
    for row in rows:
        need(set(row) == {"name", "op", "payload_hex"}
             and type(row["name"]) is str and re.fullmatch(r"[a-z0-9-]+", row["name"])
             and type(row["op"]) is int and type(row["payload_hex"]) is str
             and bytes.fromhex(row["payload_hex"]).hex() == row["payload_hex"], "Malformed frozen corpus row")
    return raw, rows


def priority_cases():
    """Additional wire-constructor order cases; the original corpus stays exact."""
    _, rows = corpus("codec")
    frame = bytes.fromhex(next(row["payload_hex"] for row in rows if row["name"] == "frame-0"))
    word = lambda number: struct.pack("<Q", number)
    specifications = [
        ("direction-zero-and-local-zero", ((136, bytes(32)), (232, word(0)))),
        ("direction-three-and-remote-zero", ((168, bytes(32)), (232, word(3)))),
        ("direction-max-and-scope-zero", ((200, bytes(32)), (232, word(2**64 - 1)))),
        ("kind-256-and-run-zero", ((248, bytes(32)), (360, word(256)))),
        ("kind-max-and-context-zero", ((280, bytes(32)), (360, word(2**64 - 1)))),
        ("kind-256-and-session-zero", ((312, bytes(32)), (360, word(256)))),
        ("kind-256-and-local-zero", ((136, bytes(32)), (360, word(256)))),
        ("namespace-zero-before-direction", ((0, bytes(32)), (232, word(0)))),
    ]
    answer = []
    for name, changes in specifications:
        raw = bytearray(frame)
        for offset, value in changes:
            raw[offset:offset + len(value)] = value
        answer.append({"name": "priority-" + name, "op": 3, "payload_hex": raw.hex()})
    return answer


def wal_scope_history():
    """Bind the original per-call definition and the failed aggregate verbatim."""
    path = HERE / "qualification/wal-scope-history.json.xz"
    raw = capture(path)
    need(identity(raw) == {"bytes": 119884, "sha256":
         "4e266fca7cc07009b4a0c2fbdc457b1e67fb6be4e89200663861bb60911c8056"},
         "Original WAL scope/failure evidence changed")
    value = json.loads(lzma.decompress(raw))
    files = value["files"]
    receipt = json.loads(files["q/observations/wal-large/receipt.json"])
    old = json.loads(files["q/report.json"])
    need(old["status"] == "FAIL" and receipt["timed_out"] is True
         and receipt["exit_code"] == -15 and receipt["collector_exit_code"] == 124
         and receipt["wall_limit_seconds"] == 240 and receipt["cleanup_limit_seconds"] == 3
         and receipt["elapsed_ns"] == 240175489419,
         "The historical aggregate timeout was relabeled")
    completed = {}
    for mode in ("replay", "index"):
        report = json.loads(files["q/cases/wal-large/results/maximal-aligned-sorted-" + mode + "/report.json"])
        need(report["status"] == "ACTUAL_NATIVE_RETURNED" and report["value"] == 0,
             "Prior individual result changed")
        completed[mode] = report["native_elapsed_ns"]
    return {"evidence": {"path": path.relative_to(ROOT).as_posix(), **identity(raw)},
        "original_scope_sources": {name: identity(text.encode()) for name, text in value["original_scope_sources"].items()},
        "original_native_scope": "each-case-and-mode", "original_native_seconds": 240,
        "original_rust_comparison_seconds": 240, "failed_aggregate_lineage": old["lineage"],
        "failed_aggregate_status": "FAIL", "failed_aggregate_elapsed_ns": receipt["elapsed_ns"],
        "completed_prior_maximum_native_ns": completed,
        "prior_execution_reused": False, "original_service_budget_qualified": False}


def source_capture(*, admitted_hia_paths=None):
    """Re-read complete members and bytes; Core is repeated at admission/readback."""
    pinned_toolchain()
    check_environment(os.environ)
    values = {}

    def add(path):
        path = Path(path).absolute()
        name = path.relative_to(ROOT).as_posix()
        raw = capture(path)
        need(name not in values or values[name] == raw, "Changing source during capture")
        values[name] = raw
        return raw

    for directory, dirs, files in os.walk(HERE, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != "__pycache__")
        for name in dirs:
            need(not (Path(directory) / name).is_symlink(), "Linked owned source directory")
        for name in sorted(files):
            path = Path(directory) / name
            need(path.suffix in {".py", ".rs", ".hepta", ".json", ".md", ".xz", ".c"},
                 "Unexpected owned source member: " + str(path))
            add(path)
    for name in INPUTS:
        add(ROOT / "hia" / name)
    for name in ("hia/tools/toolchain.py", "hia/components.json", "AGENTS.md", "PROJECT_ID",
                 "PROJECT_BOUNDARY.json", "rust-toolchain.toml", "scripts/project-preflight.sh",
                 "scripts/ci/project_boundary.py", "scripts/w1_owned_process_collector_v1.py",
                 "config/portability-inventory-v1.json", "config/pon/work-profile-v1.json",
                 "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
                 "hia/platform/pq_auth/qualification/allocator_observer.c"):
        add(ROOT / name)
    for name in ("build.py", "process.py", "original_build.py", "readback.py",
                 "daemon_reference.rs", "client_reference.rs", "client_owner_reference.rs", "codec_reference.rs"):
        add(ROOT / "hia/platform/peer_lease_unix" / name)
    for name in sorted(document(ROOT / "hia/components.json")["includes"]):
        add(_source_path(name))
    if admitted_hia_paths is None:
        for name in (*IMAGES, *OBJECTS):
            _, dependencies = compose_source(HERE / (name + ".hepta"))
            for path, raw in dependencies:
                need(add(path) == raw, "Composed source changed during admission")
    else:
        need(type(admitted_hia_paths) is tuple
             and admitted_hia_paths == tuple(sorted(set(admitted_hia_paths)))
             and all(type(name) is str for name in admitted_hia_paths), "Invalid admitted dependency roster")
        for name in admitted_hia_paths:
            add(_source_path(name))
    entries = subprocess.check_output(["git", "ls-tree", "-rz", "HEAD", "--", *ORIGINAL_ROOTS], cwd=ROOT)
    original_names = set()
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        need(kind == b"blob" and mode in {b"100644", b"100755"}, "Unsupported original tracked object")
        raw = add(ROOT / os.fsdecode(name))
        original_names.add(os.fsdecode(name))
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        need(actual == object_id.decode(), "Original source differs from current Git blob: " + os.fsdecode(name))
    observed_names = set()
    for prefix in ORIGINAL_ROOTS:
        directory = ROOT / prefix
        if not directory.exists():
            continue
        for parent, directories, filenames in os.walk(directory, followlinks=False):
            need(all(not (Path(parent) / name).is_symlink() for name in directories),
                 "Linked original source directory")
            for name in filenames:
                path = Path(parent) / name
                need(not path.is_symlink(), "Linked original source member")
                observed_names.add(path.relative_to(ROOT).as_posix())
    need(observed_names == original_names, "Original source member namespace changed")
    return values


def source_manifest(values):
    return {name: identity(raw) for name, raw in sorted(values.items())}


def require_sources(expected, admitted):
    need(source_capture(admitted_hia_paths=admitted) == expected,
         "Complete metadata owner source graph changed")


def repository_identity():
    command = lambda *args: subprocess.check_output(["git", *args], cwd=ROOT).decode().strip()
    return {"head": command("rev-parse", "HEAD"), "tree": command("rev-parse", "HEAD^{tree}"),
            "dirty": bool(command("status", "--porcelain=v1", "--untracked-files=all"))}
