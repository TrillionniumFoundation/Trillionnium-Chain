"""Passive LPV1 observations from an actual original Node, never an owner switch."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, closing
from pathlib import Path
import os
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from hia.tools.qualify_m05_held_policy import (
    POLICY, NativeModule, admit, build_source_binding, canonical_file, cargo_observations,
    checked_hex, clean_build_environment, expected, file_identity, git, ids, load_json, need,
    same, write_json,
)

ADAPTER = HERE / "rust_owner_policy_shadow.rs"
PHASES = ("original_only", "matching_shadow", "wrong_parameters_shadow", "matched_shadow_original_refuses")
BACKENDS = ("direct", "selfhost")
FILL = b"\x95" * 301
SCOPE = "passive-owner-settings-local-observation-no-protected-authorization"


def snapshot(directory):
    def rows(db, table):
        return [[x.hex() if isinstance(x, bytes) else x for x in row]
                for row in db.execute("SELECT * FROM " + table + " LIMIT 2")]

    with closing(sqlite3.connect((directory / "native.sqlite").as_uri() + "?mode=ro", uri=True)) as db:
        policy = {t: rows(db, t) for t in
                  ("local_pool_metadata", "local_pool_groups", "local_pool_rows", "local_pool_removals")}
        need(all(not rows for t, rows in policy.items() if t != "local_pool_metadata"),
             "Unexpected nonempty synthetic pool")
        active, = db.execute("SELECT tip,generation FROM active WHERE singleton=1")
        return {"pool": policy, "active": [active[0].hex(), active[1]]}


def ready_line(pipe):
    end = time.monotonic() + 20
    raw = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(pipe, selectors.EVENT_READ)
        while b"\n" not in raw:
            need(selector.select(max(0, end - time.monotonic())), "Original Node barrier timed out")
            chunk = os.read(pipe.fileno(), 4096)
            need(chunk and len(raw) + len(chunk) <= 4096, "Original Node readiness was not bounded")
            raw.extend(chunk)
    need(raw.count(b"\n") == 1 and raw.endswith(b"\n"), "Unexpected early original output")
    return load_json(bytes(raw))


def candidate_frame(ready, phase):
    raw = checked_hex(ready["request"], 172)
    if phase == "wrong_parameters_shadow":
        # LPV1 hashes opaque identity bytes. It cannot authenticate the owner
        # Parameters binding; only the independent upstream comparison can.
        raw = raw[:36] + bytes([raw[36] ^ 1]) + raw[37:]
    return raw


def run_phase(exe, phase, directory, modules, env):
    mode = "refuse" if phase == PHASES[-1] else "fresh"
    with subprocess.Popen([exe, mode, directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, bufsize=0) as proc:
        try:
            ready = ready_line(proc.stdout)
            before = during = None
            native = {}
            try:
                before = snapshot(directory)
                request = candidate_frame(ready, phase)
                owner_bytes = checked_hex(ready["reference_context"], 32) + checked_hex(ready["reference_raw"])
                if phase != "original_only":
                    for backend, module in modules.items():
                        r = module.call("f0", [request, FILL, b"\xa6" * 1711]).require_returned()
                        output = bytes(r.arguments[1])
                        native[backend] = {"return": r.value, "request": bytes(r.arguments[0]).hex(),
                                           "output": output.hex(),
                                           "matches_owner_bytes_at_pause":
                                               r.value == len(owner_bytes) and output[:r.value] == owner_bytes}
                during = snapshot(directory)
            except Exception as exc:
                native = {"observation_error": str(exc)}
            # No candidate data, comparison, result or phase outcome crosses
            # this pipe. Identical fixed token for all paths, including errors.
            stdout, stderr = proc.communicate(input=b"continue\n", timeout=35)
            need(proc.returncode == 0 and not stderr and stdout.count(b"\n") == 1,
                 f"Original Node failed: {stdout!r} {stderr!r}")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    return {"ready": ready, "before": before, "during": during,
            "native": native, "result": load_json(stdout), "after": snapshot(directory)}


def validate(rows):
    need(set(rows) == set(PHASES), "Incorrect shadow phase roster")
    baseline = rows["original_only"]
    for phase, row in rows.items():
        ready = row["ready"]
        original_request = checked_hex(ready["request"], 172)
        context = checked_hex(ready["reference_context"], 32)
        raw = checked_hex(ready["reference_raw"])
        want = context + raw
        need(expected(original_request) == (len(want), want), "Original pre-write reference differs")
        need(same(row["before"], row["during"]) and
             all(same(row[k]["active"], ready["active"]) for k in ("before", "during", "after")),
             "Shadow observation or original call changed the active parent or premature rows")
        if phase == PHASES[-1]:
            need(same(row["before"], baseline["after"]) and same(row["after"], row["before"])
                 and row["result"] == {"outcome": "POOL_CONTEXT", "returned": None,
                                        "readback_context": baseline["ready"]["reference_context"]}
                 and context.hex() != row["result"]["readback_context"],
                 "A matching shadow must not authorize a rejected original update")
        else:
            pool = row["after"]["pool"]["local_pool_metadata"]
            need(len(pool) == 1 and pool[0][:3] == [1, context.hex(), raw.hex()]
                 and pool[0][-2:] == ready["active"]
                 and row["result"] == {"outcome": "accepted", "returned": context.hex(),
                                        "readback_context": context.hex()}
                 and same(row["after"], baseline["after"])
                 and not row["before"]["pool"]["local_pool_metadata"],
                 "Original accepted durable result differs from the no-shadow control")
        native = row["native"]
        need(set(native) == (set() if phase == "original_only" else set(BACKENDS)),
             "Wrong actual backend roster")
        request = candidate_frame(ready, phase)
        for result in native.values():
            count, response = expected(request)
            need(type(result["return"]) is int and result["return"] == count == len(want)
                 and result["request"] == request.hex()
                 and checked_hex(result["output"], len(FILL)) == response + FILL[count:],
                 "Native response differs or echoes into the output tail")
            need(result["matches_owner_bytes_at_pause"] is (response == want),
                 "Recorded pre-write comparison differs from the raw bytes")
            if phase == "wrong_parameters_shadow":
                need(response[:32] != context and response[32:] == raw,
                     "Wrong owner Parameters must produce only a different context")
            else:
                need(response == want, "Valid candidate differs from actual original reference")
    return {"owner_settings_prewrite": True, "wrong_parameters_context_detected": True,
            "matched_candidate_cannot_authorize_original_refusal": True,
            "readonly_during_observation": True, "matched_original_durable_rows": True}


def run(args):
    env = clean_build_environment()
    head = ids("HEAD")
    need(head["head"] == args.expect_source and not git("status", "--porcelain", "--untracked-files=no"),
         "Expected exact clean original source")
    build = build_source_binding(args.original_build_source, head)
    target = args.cargo_target.absolute()
    need(target == target.resolve(strict=True) and target.is_dir(), "Canonical original target required")
    messages = canonical_file(args.cargo_messages)
    need(file_identity(messages)["sha256"] == args.cargo_messages_sha256, "Original Cargo events differ")
    node, witness, native_paths = admit(messages, target)
    need(file_identity(node)["sha256"] == args.node_library_sha256, "Original Node library differs")
    entries, _, _ = cargo_observations(messages)
    libraries = {"trnm_pon_node": node}
    for name in ("serde_json", "trnm_protocol"):
        event, = [x for x in entries if x.get("reason") == "compiler-artifact"
                  and x["target"]["name"] == name and x["target"]["kind"] == ["lib"]]
        libraries[name], = [canonical_file(p, target) for p in event["filenames"] if p.endswith(".rlib")]
    rustc = canonical_file(args.rustc)
    version = subprocess.check_output([rustc, "-Vv"], env=env, text=True, timeout=15)
    sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True, timeout=15).strip())
    need(rustc == sysroot / "bin/rustc" and version.startswith("rustc 1.95.0 (59807616e")
         and "host: x86_64-unknown-linux-gnu\n" in version, "Original Rust compiler differs")
    files = {**libraries, "sqlite_witness": witness, "rustc": rustc, "cargo_messages": messages,
             "native_policy": POLICY, "adapter": ADAPTER, "observer": Path(__file__).resolve()}
    bindings = {k: file_identity(v) for k, v in files.items()}
    rows = {}
    with tempfile.TemporaryDirectory(prefix="m05-owner-shadow-") as work:
        root = Path(work)
        (root / ".disposable-m05-owner-shadow").write_bytes(b"synthetic-local-node-only\n")
        exe = root / "owner-capture"
        link = [rustc, "--edition=2021", "-C", "debuginfo=0", ADAPTER, "-L", f"dependency={target / 'debug/deps'}"]
        for name, imported in libraries.items():
            link += ["--extern", f"{name}={imported}"]
        for path in native_paths:
            link += ["-L", f"native={path}"]
        invoked = subprocess.run([*link, "-o", exe], env=env, capture_output=True, timeout=80)
        need(invoked.returncode == 0 and not invoked.stdout and not invoked.stderr,
             f"Original test adapter linking failed: {invoked.stderr!r}")
        bridge = file_identity(exe)
        with ExitStack() as stack:
            modules = {b: stack.enter_context(NativeModule(POLICY, byte_exports=("f0",), backend=b)) for b in BACKENDS}
            native = {b: {"artifact_sha256": m.artifact_sha256, "compiler_sha256": m.receipt.get("compiler_sha256"),
                          "build": m.receipt["chain_migration"]} for b, m in modules.items()}
            for phase in PHASES:
                directory = root / ("wrong_parameters_shadow" if phase == PHASES[-1] else phase)
                if phase != PHASES[-1]:
                    directory.mkdir(mode=0o700)
                rows[phase] = run_phase(exe, phase, directory, modules, env)
        need(file_identity(exe) == bridge, "Original bridge drifted")
    need({k: file_identity(v) for k, v in files.items()} == bindings
         and ids("HEAD") == head and not git("status", "--porcelain", "--untracked-files=no"),
         "Observed inputs drifted")
    need(native["selfhost"]["compiler_sha256"] ==
         "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
         and all(v["build"]["backend"] == b and v["build"]["whole_chain_native"] is False
                 and v["build"]["source_sha256"] == bindings["native_policy"]["sha256"]
                 for b, v in native.items())
         and len({v["artifact_sha256"] for v in native.values()}) == 2, "Native provenance differs")
    result = {"scope": SCOPE, "original_build": build, "observation_source": head,
              "bindings": bindings, "native": native, "bridge": bridge, "phases": rows,
              "derived": validate(rows), "latest_original_rebuilt": False, "native_authority": False,
              "continuous_owner_tested": False, "transaction_cancellation_tested": False}
    output = args.output.absolute()
    need(output.parent == output.parent.resolve(strict=True) and not output.exists()
         and not output.is_symlink() and not output.is_relative_to(ROOT), "Fresh report path required")
    write_json(output, result)
    print(file_identity(output)["sha256"])


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    for flag in ("cargo-target", "cargo-messages", "rustc", "output"):
        cli.add_argument("--" + flag, type=Path, required=True)
    for flag in ("expect-source", "original-build-source", "cargo-messages-sha256", "node-library-sha256"):
        cli.add_argument("--" + flag, required=True)
    run(cli.parse_args())
