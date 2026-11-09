#!/usr/bin/env python3
"""Synthetic Python controls for the differential runner; never executes Rust.

The fabricated harness strings below are parser fixtures, not native evidence.
The source-restore fixtures are isolated temporary text files, not a repository.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "run_discovery_convergence_differential.py"
spec = importlib.util.spec_from_file_location("discovery_differential", RUNNER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
checks = []


def check(name, action):
    action()
    checks.append(name)


def refused(action):
    try:
        action()
    except module.GateError:
        return
    raise AssertionError("synthetic invalid input was accepted")


def harness(names, passed):
    count = len(names)
    return (f"running {count} tests\n" + "".join(
        f"test {name} ... {'ok' if passed else 'FAILED'}\n" for name in names)
        + f"test result: {'ok' if passed else 'FAILED'}. "
        + f"{count if passed else 0} passed; {0 if passed else count} failed; "
        + "0 ignored; 0 measured; 100 filtered out; finished in 0.01s\n")


def panic(name, body):
    return f"thread '{name}' (123) panicked at source.rs:1:1:\n{body}\n"


def parse(text, error, rc, names, mode):
    return lambda: module.parse_native(text, error, rc, names, mode)


server = module.SERVER_CASES
active = ('real rendezvous omitted the active provider behind eight valid withdrawals: '
          'Err(Invalid("authenticated discovery has no admissible provider"))')
authority = ("assertion `left == right` failed: inactive authority consumed server "
             "verification slots before the live provider\n  left: 6\n right: 4")
red_stdout = harness(server, False)
red_stderr = (panic(server[0], active)
              + "authenticated-v3 inactive authority: revoked=false, server=fixture\n"
              + panic(server[1], authority)
              + "authenticated-v3 inactive authority: revoked=true, server=fixture\n"
              + panic(server[2], authority))
mono = (module.MONOTONIC_CASE,)
mono_marker = "an elapsed original monotonic lease was renewed by the current wall clock"
mono_observation = ("authenticated-v3 original monotonic announcement lease: "
                    "result=Ok(CellDiscoveryObservationV3 { connection_attempts: 1, "
                    "record_validation_attempts: 1, bootstrap_validation_attempts: 1, "
                    "announcement_signature_attempts: 1 })\n")
mono_stdout = harness(mono, False)
mono_stderr = mono_observation + panic(mono[0], mono_marker)


def retained_helper_identity():
    previous = ast.parse((ROOT / "run_exact_gates_previous.py").read_bytes())
    current = ast.parse(RUNNER.read_bytes())
    helpers = ("require", "unique_object", "json_load", "file_identity", "read_json_file",
               "scrub_environment", "cargo_config_inputs", "save_summary", "event")
    for name in helpers:
        left = next(node for node in previous.body if getattr(node, "name", None) == name)
        right = next(node for node in current.body if getattr(node, "name", None) == name)
        assert ast.dump(left) == ast.dump(right), name
    old_class = next(node for node in previous.body if isinstance(node, ast.ClassDef) and node.name == "Runner")
    new_class = next(node for node in current.body if isinstance(node, ast.ClassDef) and node.name == "DifferentialRunner")
    for name in ("checkpoint", "probe", "task_path", "mount_receipt", "host_receipt", "validate_provider"):
        left = next(node for node in old_class.body if getattr(node, "name", None) == name)
        right = next(node for node in new_class.body if getattr(node, "name", None) == name)
        assert ast.dump(left) == ast.dump(right), name


def restore_controls():
    with tempfile.TemporaryDirectory(prefix="discovery-runner-synthetic-", dir=ROOT) as temporary:
        root = Path(temporary)
        runner = module.DifferentialRunner.__new__(module.DifferentialRunner)
        runner.root = root / "source"
        runner.out = root / "out"
        runner.out.mkdir()
        runner.candidate = {path: ("candidate:" + path).encode() for path in
                            (module.AUTH_PATH, module.TESTS_PATH, module.PQ_PATH)}
        alternate = {path: b"red:" + data for path, data in runner.candidate.items()}
        runner.known_hashes = {path: {hashlib.sha256(data).hexdigest(),
                                     hashlib.sha256(alternate[path]).hexdigest()}
                               for path, data in runner.candidate.items()}
        runner.manifest = {}
        runner.candidate_restored = False
        observed = []

        def state(label, expected):
            assert all((runner.root / path).read_bytes() == data for path, data in expected.items())
            observed.append(label)

        runner.source_state = state
        for relative, data in alternate.items():
            path = runner.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
        runner.restore_candidate()
        assert runner.candidate_restored and observed == ["restored-candidate"]
        assert all((runner.root / path).stat().st_mode & 0o777 == 0o644 for path in runner.candidate)
        unknown = b"unknown concurrent edit: preserve this exact file"
        path = runner.root / module.AUTH_PATH
        path.write_bytes(unknown)
        refused(lambda: runner.replace_source(module.AUTH_PATH, runner.candidate[module.AUTH_PATH]))
        refused(runner.restore_candidate)
        assert not runner.candidate_restored
        assert runner.manifest["candidate_source_restored"] is False
        assert path.read_bytes() == unknown
        assert (runner.out / "unexpected-current-auth.rs").read_bytes() == unknown
        assert runner.manifest["unexpected_source"][0]["action"].startswith("left intact")


check("syntax and retained environment/provider helper identity", retained_helper_identity)
check("exact three synthetic target reds accepted", parse(red_stdout, red_stderr, 101, server, "server-red"))
check("exact three synthetic greens accepted", parse(harness(server, True), "", 0, server, "green"))
check("synthetic single clamp red accepted", parse(mono_stdout, mono_stderr, 101, mono, "mutation-red"))
check("synthetic single green accepted", parse(harness(mono, True), "", 0, mono, "green"))
check("compile failure is not red", lambda: refused(parse("", "compile failed", 101, server, "server-red")))
check("empty successful output is not green", lambda: refused(parse("", "", 0, server, "green")))
check("fixture panic is not red", lambda: refused(parse(red_stdout, red_stderr.replace(active, "fixture failed"), 101, server, "server-red")))
check("wrong authority count is not red", lambda: refused(parse(red_stdout, red_stderr.replace("left: 6", "left: 5"), 101, server, "server-red")))
check("wrong native return code is not red", lambda: refused(parse(red_stdout, red_stderr, 1, server, "server-red")))
check("extra panic is not red", lambda: refused(parse(red_stdout, red_stderr + panic("worker", "failed"), 101, server, "server-red")))
check("missing authority premise is not red", lambda: refused(parse(red_stdout, red_stderr.replace("revoked=true", "revoked=unknown"), 101, server, "server-red")))
check("duplicate selected case is rejected", lambda: refused(parse(red_stdout.replace(server[1], server[0]), red_stderr, 101, server, "server-red")))
check("ignored selected case is rejected", lambda: refused(parse(harness(server, True).replace("0 ignored", "1 ignored"), "", 0, server, "green")))
check("missing signed TCP ACK is not mutation red", lambda: refused(parse(mono_stdout, panic(mono[0], mono_marker), 101, mono, "mutation-red")))
check("wrong TCP observation is not mutation red", lambda: refused(parse(mono_stdout, mono_stderr.replace("connection_attempts: 1", "connection_attempts: 0"), 101, mono, "mutation-red")))
check("expired wall fixture is not mutation red", lambda: refused(parse(mono_stdout, mono_stderr + "fixture wall lease expired before the monotonic-only refusal could be assessed", 101, mono, "mutation-red")))
check("known source restores and unknown concurrent source survives", restore_controls)
print(json.dumps({"schema": "discovery-runner-synthetic-selftest-v1", "passed": True,
                  "native_commands_executed": 0, "native_results_claimed": False,
                  "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
                  "checks": checks}, indent=2))
