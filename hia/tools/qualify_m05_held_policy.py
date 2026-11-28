#!/usr/bin/env python3
"""Standalone original held-policy/LPV1 observation; no Node owner switch."""
from __future__ import annotations

import argparse
from contextlib import closing, ExitStack
from pathlib import Path
import hashlib
import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.platform.execution_state.rust_oracle import (
    clean_build_environment, file_identity, load_json, need, write_json,
)
from hia.platform.mempool_node.rust_oracle import capture_loader_directory
from hia.platform.mempool_node.safe import same
from hia.tests.native_support import NativeModule
from hia.tests.test_m05_local_pool_policy import expected

ADAPTER = ROOT / "hia/tests/rust_m05_held_policy_reference.rs"
POLICY = ROOT / "hia/src/mempool/local_pool_policy.hepta"
MARKER = b"dot-m05-disposable-policy-fixture\n"
SCHEMA = "trnm.hia.m05-held-policy.local-proof.v2"
SQLITE_FENCE = "sqlite-3.54.1-normal-native-linux-layout-v4"
SQLITE_SOURCE = "0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52"
SETTINGS = ("network", "parameters", "genesis", "preview_miner")
PHASES = ("fresh", "cold", "refuse", "cold_after", "stale_before", "stale_control", "stale_refuse")


def git(*args):
    return subprocess.check_output(["git", "-C", ROOT, *args], text=True, timeout=15).strip()


def ids(head):
    return {"head": git("rev-parse", head), "tree": git("rev-parse", head + "^{tree}"),
            "rust_tree": git("rev-parse", head + ":trillionnium"),
            "cargo_lock_blob": git("rev-parse", head + ":trillionnium/Cargo.lock")}


def build_source_binding(build, observation):
    """Record the source of an admitted library separately from this observation."""
    original = ids(build)
    need(original["head"] == build, "Expected full original build commit")
    if original != observation:
        need(original["rust_tree"] == observation["rust_tree"] and
             original["cargo_lock_blob"] == observation["cargo_lock_blob"] and
             git("rev-parse", build + ":rust-toolchain.toml") ==
             git("rev-parse", observation["head"] + ":rust-toolchain.toml"),
             "Original Rust source, lock or toolchain pin differs")
        bases = git("merge-base", build, observation["head"]).splitlines()
        need(bases == [build], "Retained build is not an ancestor of the observation source")
    return {"source": original, "cross_snapshot": original != observation,
            "external_build_input_equivalence_verified_by_observer": False}


def canonical_file(value, prefix=None):
    path = Path(value).absolute()
    need(path == path.resolve(strict=True) and path.is_file() and
         (prefix is None or path.is_relative_to(prefix)), "Unexpected artifact path")
    return path


def checked_hex(value, count=None):
    need(type(value) is str, "Non-string observed bytes")
    result = bytes.fromhex(value)
    need(result.hex() == value and (count is None or len(result) == count), "Noncanonical observed bytes")
    return result


def read_sql(directory):
    uri = (directory / "native.sqlite").as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        row, = db.execute("SELECT context,limits,gc_groups,gc_records,gc_bytes,gc_head,"
                          "checked_parent,checked_generation FROM local_pool_metadata WHERE singleton=1")
        active, = db.execute("SELECT tip,generation FROM active WHERE singleton=1")
    return {"context": row[0].hex(), "limits": row[1].hex(),
            "other": [v.hex() if isinstance(v, bytes) else v for v in row[2:]],
            "active": [active[0].hex(), active[1]]}


def invoke(executable, action, directory):
    p = subprocess.run([executable, action, directory], capture_output=True, timeout=35)
    need(p.returncode == 0 and not p.stderr,
         f"Original {action} exit={p.returncode}: {p.stdout[:2048]!r} / {p.stderr[:2048]!r}")
    pairs = [line.split("\t", 1) for line in p.stdout.decode().splitlines()]
    need(all(len(r) == 2 for r in pairs) and len(dict(pairs)) == len(pairs), "Bad bridge observations")
    return dict(pairs)


def validate_observations(phases, native):
    """Check the actual observations independently of any supplied PASS flag."""
    need(set(phases) == set(PHASES), "Wrong held-policy phase set")
    fresh = phases["fresh"]
    public, row = fresh["public"], fresh["sqlite"]
    need(set(public) == set(SETTINGS) | {"context", "active_parent", "active_generation"},
         "Invalid original public fresh keys")
    identity = b"".join(checked_hex(public[k], 32) for k in SETTINGS)
    context, raw = checked_hex(row["context"], 32), checked_hex(row["limits"])
    need(type(public["active_generation"]) is str and public["active_generation"].isdigit()
         and str(int(public["active_generation"])) == public["active_generation"], "Wrong original generation")
    need(checked_hex(public["context"], 32) == context and
         same(row["active"], [checked_hex(public["active_parent"], 32).hex(), int(public["active_generation"])]),
         "Public and SQLite owner disagree")
    need(type(row["other"]) is list and len(row["other"]) == 6, "Wrong complete policy metadata row")
    for value, extent in zip(row["other"][:4], (8, 8, 8, 32), strict=True):
        checked_hex(value, extent)
    need(same(row["other"][4:], row["active"]), "Wrong checked active BLOB/generation")
    for stage in ("cold", "cold_after", "stale_before"):
        need(same(phases[stage], fresh), "Cold or independent original fixture changed")
    need(same(phases["refuse"], {"public": {**public, "refusals": "POOL_LIMITS,POOL_CONTEXT"},
                             "sqlite": row}), "Refusal changed accepted state")
    altered = raw.replace(b'"max_records":8', b'"max_records":9', 1)
    need(altered != raw and len(altered) == len(raw), "Noncanonical local stale policy control")
    stale = {**row, "limits": altered.hex()}
    need(same(phases["stale_control"], {"public": None, "sqlite": stale}), "Control changed other bindings")
    stale_public = {k: v for k, v in public.items() if k != "context"}
    need(same(phases["stale_refuse"], {"public": {**stale_public, "refusals": "POOL_CONTEXT,POOL_CONTEXT"},
                                   "sqlite": stale}), "Same-context stale raw data was accepted or rewritten")
    frame = b"LPV1" + identity + struct.pack("<5Q", 8, 16384, 8, 0, 8)
    original = context + raw
    need(expected(frame) == (len(original), original), "Independent canonical framing differs")
    need(set(native) == {"direct", "selfhost"}, "Both pinned native backends are mandatory")
    hashes = set()
    for backend, result in native.items():
        need(result["build"]["backend"] == backend
             and result["build"]["whole_chain_native"] is False, "Native provenance scope differs")
        checked_hex(result["build"]["source_sha256"], 32)
        if backend == "selfhost":
            need(result["compiler_sha256"] == "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54",
                 "The actual self-host compiler differs from its pin")
        need(type(result["return"]) is int and result["return"] == len(original)
             and checked_hex(result["request"], len(frame)) == frame
             and checked_hex(result["output"], 301) == original + b"\x95" * (301 - len(original)),
             "Native response prefix or output tail differs")
        hashes.add(checked_hex(result["artifact_sha256"], 32))
    need(len(hashes) == 2, "Two distinct emitted native artifacts are mandatory")
    return {"response_bytes": len(original), "response_sha256": hashlib.sha256(original).hexdigest(),
            "disposable_original_sqlite": True, "cold_readback": True, "stable_after_public_refusals": True,
            "transaction_rollback_tested": False, "restricted_permit_tested": False,
            "native_owner_switch_tested": False, "hosted_qualification": False}


def observe(executable, scratch_parent):
    phases = {}
    with tempfile.TemporaryDirectory(dir=scratch_parent, prefix="trnm-m05-held-policy-") as work:
        fixture = Path(work)
        (fixture / ".m05-test-owned").write_bytes(MARKER)
        positive, mismatch = fixture / "normal", fixture / "same-context-mismatch"
        positive.mkdir(mode=0o700)
        mismatch.mkdir(mode=0o700)

        def record(name, action, directory):
            phases[name] = {"public": invoke(executable, action, directory), "sqlite": read_sql(directory)}

        for name, action in (("fresh", "fresh"), ("cold", "cold"), ("refuse", "refuse"), ("cold_after", "cold")):
            record(name, action, positive)
        record("stale_before", "fresh", mismatch)
        raw = checked_hex(phases["fresh"]["sqlite"]["limits"])
        altered = raw.replace(b'"max_records":8', b'"max_records":9', 1)
        uri = (mismatch / "native.sqlite").as_uri() + "?mode=rw"
        with closing(sqlite3.connect(uri, uri=True)) as db, db:
            need(db.execute("UPDATE local_pool_metadata SET limits=? WHERE singleton=1", (altered,)).rowcount
                 == 1, "Expected one synthetic metadata row")
        phases["stale_control"] = {"public": None, "sqlite": read_sql(mismatch)}
        record("stale_refuse", "refuse_same_context_stale_policy", mismatch)
        need(read_sql(positive) == phases["fresh"]["sqlite"], "Independent fixture affected positive database")

        public = phases["fresh"]["public"]
        frame = b"LPV1" + b"".join(checked_hex(public[k], 32) for k in SETTINGS)
        frame += struct.pack("<5Q", 8, 16384, 8, 0, 8)
        native = {}
        with ExitStack() as lifetime:
            for backend in ("direct", "selfhost"):
                m = lifetime.enter_context(NativeModule(POLICY, byte_exports=("f0",), backend=backend))
                r = m.call("f0", [frame, b"\x95" * 301, b"\xa6" * 1711]).require_returned()
                native[backend] = {"return": r.value, "request": bytes(r.arguments[0]).hex(),
                                   "output": bytes(r.arguments[1]).hex(), "artifact_sha256": m.artifact_sha256,
                                   "build": m.receipt["chain_migration"],
                                   "compiler_sha256": m.receipt.get("compiler_sha256")}
    return phases, native


def cargo_observations(messages):
    entries = [load_json(line) for line in messages.read_bytes().splitlines() if line.startswith(b"{")]
    need(sum(e.get("reason") == "build-finished" and e.get("success") is True for e in entries) == 1,
         "No complete actual Cargo messages")
    lib, = [e for e in entries if e.get("reason") == "compiler-artifact"
            and e["target"]["name"] == "trnm_pon_node" and e["target"]["kind"] == ["lib"]]
    need(lib["fresh"] is False and lib["features"] == ["default"] and lib["profile"]["test"] is False
         and lib["profile"]["opt_level"] == "0" and
         lib["manifest_path"].endswith("/trillionnium/crates/trnm-pon-node/Cargo.toml"),
         "Exact newly compiled original Node library required")
    serde, = [e for e in entries if e.get("reason") == "compiler-artifact"
              and e["target"]["name"] == "serde_json" and e["target"]["kind"] == ["lib"]]
    need(serde["package_id"] == "registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.149"
         and set(serde["features"]) == {"default", "std"}, "Original serde_json differs")
    sqlite, = [e for e in entries if e.get("reason") == "build-script-executed"
               and "/trnm-sqlite-io-boundary#" in e["package_id"]]
    settings = dict(sqlite["env"])
    need(sqlite["cfgs"] == ["trnm_sqlite_layout_witness"]
         and sqlite["linked_libs"] == ["static=trnm_sqlite_layout_witness"]
         and settings.get("TRNM_SQLITE3_BUILD_FENCE") == SQLITE_FENCE
         and settings.get("TRNM_SQLITE3_AMALGAMATION_SHA256") == SQLITE_SOURCE
         and "TRNM_SQLITE3_UNQUALIFIED_REASON" not in settings, "Original SQLite qualification failure")
    return entries, lib, sqlite


def admit(messages, target):
    entries, lib, sqlite = cargo_observations(messages)
    need(lib["manifest_path"] == str(ROOT / "trillionnium/crates/trnm-pon-node/Cargo.toml"),
         "Retained original target comes from a different checkout")
    path, = [canonical_file(p, target) for p in lib["filenames"] if p.endswith(".rlib")]
    witness = canonical_file(Path(sqlite["out_dir"]) / "libtrnm_sqlite_layout_witness.a", target)
    native_dirs = set()
    for e in entries:
        if e.get("reason") == "build-script-executed":
            for row in e["linked_paths"]:
                kind, val = row.split("=", 1)
                p = Path(val).absolute()
                need(kind == "native" and p.is_relative_to(target) and
                     p.is_dir() and p == p.resolve(strict=True), "Unexpected linked native directory")
                native_dirs.add(p)
    return path, witness, sorted(native_dirs)


def publish_observation(args):
    env = clean_build_environment()
    head = ids("HEAD")
    need(head["head"] == args.expect_source and not git("status", "--porcelain", "--untracked-files=no"),
         "Expected exact clean original source")
    build_source = build_source_binding(args.original_build_source or args.expect_source, head)
    target = args.cargo_target.absolute()
    need(target == target.resolve(strict=True) and target.is_dir(), "Exact original Cargo target required")
    messages = canonical_file(args.cargo_messages)
    need(file_identity(messages)["sha256"] == args.cargo_messages_sha256, "Cargo message digest differs")
    rustc = canonical_file(args.rustc)
    version = subprocess.check_output([rustc, "-Vv"], env=env, text=True, timeout=15)
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    need(version.splitlines()[0].split()[:2] == ["rustc", pin] and
         "host: x86_64-unknown-linux-gnu\n" in version, "Expected pinned native Rust compiler")
    sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True, timeout=15).strip())
    need(rustc == sysroot / "bin/rustc", "Noncanonical original compiler path")
    loader = capture_loader_directory(sysroot / "lib")
    lib, witness, paths = admit(messages, target)
    bound = {"node_library": file_identity(lib), "sqlite_witness": file_identity(witness),
             "cargo_messages": file_identity(messages), "compiler": file_identity(rustc),
             "adapter": file_identity(ADAPTER), "native_source": file_identity(POLICY),
             "qualification_reader": file_identity(Path(__file__).resolve())}
    need(bound["node_library"]["sha256"] == args.node_library_sha256, "Original library digest differs")
    root = args.output.absolute()
    need(root.parent == root.parent.resolve(strict=True) and not root.exists() and not root.is_symlink(),
         "No preexisting or aliased output")
    root.mkdir(mode=0o700)
    selected = {"cargo-messages.jsonl": messages, "sqlite-layout-witness.a": witness}
    for name, path in selected.items():
        (root / name).write_bytes(path.read_bytes())
        need(file_identity(root / name) == file_identity(path), "Retained original bytes changed")
    with tempfile.TemporaryDirectory(dir=root, prefix=".held-policy-link-") as temp:
        executable = Path(temp) / "owner-test"
        argv = [str(rustc), "--edition=2021", "-C", "debuginfo=0", str(ADAPTER),
                "--extern", f"trnm_pon_node={lib}", "-L", f"dependency={target / 'debug/deps'}"]
        for path in paths:
            argv.extend(("-L", f"native={path}"))
        argv.extend(("-o", str(executable)))
        link = subprocess.run(argv, env=env, capture_output=True, timeout=90)
        (root / "link.stdout").write_bytes(link.stdout)
        (root / "link.stderr").write_bytes(link.stderr)
        need(link.returncode == 0, "External original Node bridge failed to link")
        binary = file_identity(executable)
        phases, native = observe(executable, root)
        need(file_identity(executable) == binary, "Original bridge drifted")
    paths = {"node_library": lib, "sqlite_witness": witness,
             "cargo_messages": messages, "compiler": rustc, "adapter": ADAPTER,
             "native_source": POLICY, "qualification_reader": Path(__file__).resolve()}
    need({k: file_identity(v) for k, v in paths.items()} == bound and
         capture_loader_directory(sysroot / "lib") == loader and ids("HEAD") == head
         and not git("status", "--porcelain", "--untracked-files=no"), "Original inputs changed")
    derived = validate_observations(phases, native)
    artifacts = {k: file_identity(root / k) for k in (*selected, "link.stdout", "link.stderr")}
    report = {"schema": SCHEMA, "source": head, "scope": "retained-build-local-observation",
              "original_build_source_binding": build_source,
              "original_build_reexecuted_by_this_observer": False, "original_locked_build_inputs": bound,
              "bridge": binary, "loader": loader, "phases": phases, "native": native,
              "derived": derived, "artifacts": artifacts}
    write_json(root / "receipt.json", report)
    print(file_identity(root / "receipt.json")["sha256"])


def readback(root, digest, expect_source, original_build_source=None):
    root = root.absolute()
    need(root == root.resolve(strict=True) and root.is_dir(), "Aliased observation root")
    path = canonical_file(root / "receipt.json", root)
    need(file_identity(path)["sha256"] == digest, "Receipt digest differs")
    report = load_json(path.read_bytes())
    need(report["schema"] == SCHEMA and report["scope"] == "retained-build-local-observation"
         and report["source"] == ids(expect_source)
         and report["original_build_reexecuted_by_this_observer"] is False, "Unexpected retained scope/source")
    need(report["original_build_source_binding"] ==
         build_source_binding(original_build_source or expect_source, report["source"]),
         "Retained original build source binding differs")
    need(set(report["artifacts"]) == {"cargo-messages.jsonl", "sqlite-layout-witness.a",
                                    "link.stdout", "link.stderr"}, "Wrong retained artifact roster")
    for name, identity in report["artifacts"].items():
        need(file_identity(canonical_file(root / name, root)) == identity, "Retained file digest differs")
    bindings = report["original_locked_build_inputs"]
    need(bindings["cargo_messages"] == report["artifacts"]["cargo-messages.jsonl"] and
         bindings["sqlite_witness"] == report["artifacts"]["sqlite-layout-witness.a"],
         "Original build artifact bindings differ")
    cargo_observations(root / "cargo-messages.jsonl")
    need(all(v["build"]["source_sha256"] == bindings["native_source"]["sha256"]
             for v in report["native"].values()), "Retained native source identity differs")
    derived = validate_observations(report["phases"], report["native"])
    need(report["derived"] == derived, "Retained branch interpretation differs")
    return {"scope": "independent-retained-readback-no-rerun", "receipt_sha256": digest,
            "original_build_source": report["original_build_source_binding"]["source"]["head"],
            **derived}


def main():
    need(__debug__, "Optimized Python is not admitted")
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    run = subs.add_parser("observe")
    for name in ("cargo-target", "cargo-messages", "rustc", "output"):
        run.add_argument("--" + name, type=Path, required=True)
    for name in ("cargo-messages-sha256", "node-library-sha256", "expect-source"):
        run.add_argument("--" + name, required=True)
    run.add_argument("--original-build-source")
    verify = subs.add_parser("readback")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--sha256", required=True)
    verify.add_argument("--expect-source", required=True)
    verify.add_argument("--original-build-source")
    args = parser.parse_args()
    if args.command == "observe":
        publish_observation(args)
    else:
        print(json.dumps(readback(args.input, args.sha256, args.expect_source, args.original_build_source),
                         sort_keys=True))


if __name__ == "__main__":
    main()
