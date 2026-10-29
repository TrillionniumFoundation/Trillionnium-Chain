#!/usr/bin/env python3
"""Synthetic full-chain association controls, never native host/CPU evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_pure_pon_fixed_parent_v1 as reader
import test_run_pure_pon_fixed_parent_v1 as support
import test_check_pure_pon_receiver_owner_v1 as original

fixture = reader.fixture


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())


def load(path):
    return json.loads(path.read_bytes())


def raw_binding(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "error": None}


def replace_parent(value, pid):
    if isinstance(value, dict):
        return {key: pid if key == "parent_pid" and item == 90000 else replace_parent(item, pid)
                for key, item in value.items()}
    if isinstance(value, list):
        return [replace_parent(item, pid) for item in value]
    return value


def role(pid, group, start, end):
    return {"pid": pid, "cgroup": group, "expected_cgroup": group, "started_monotonic_ns": start,
            "ended_monotonic_ns": end, "descriptors": [{"fd": 1, "device": 7, "inode": 77}],
            "descriptor_errors": [], "descriptor_capture_complete": True, "matching_migration_descriptors": [],
            "capability_descriptor_absent": True, "threads": [{"tid": pid, "cgroup": group}], "membership_matches": True}


def kernel(expected):
    return {"schema": "public-host-kernel-binding-v1", "parent": str(fixture.PARENT), "boot_id": expected["boot_id"],
            "device": expected["parent_identity"]["device"], "inode": expected["parent_identity"]["inode"],
            "cpu_quota_usec": 25000, "cpu_period_usec": 100000, "cpu_burst_usec": 0,
            "memory_max_bytes": 2147483648, "memory_swap_max_bytes": 0, "pids_max": 256}


def kernel_sample(expected, cpu, periods, throttled):
    return {"schema": "public-host-kernel-bound-resource-sample-v1", "binding": kernel(expected),
            "resources": {"cpu_usage_usec": cpu, "cpu_nr_periods": periods, "cpu_nr_throttled": throttled,
                          "cpu_throttled_usec": throttled * 10, "memory_current_bytes": 1024, "pids_current": 2}}


def write_build(root, expected):
    source = {"schema": "trnm-ci-source-v1", "kind": "head", "candidate": expected["expected_head"],
              "tested_commit": expected["expected_head"], "tested_tree": expected["expected_tree"],
              "tracked_worktree_verified": True, "tests_executed_by_identity_check": False,
              "tracked_entries": 1, "tracked_bytes": 1}
    executable = b"\x7fELF\x02\x01" + b"synthetic, not an executable" * 3
    (root / "retained-binary").write_bytes(executable)
    binary = {"path": "/synthetic/target/release/deps/pure_pon_pressure_v2-abc", "bytes": len(executable),
              "sha256": hashlib.sha256(executable).hexdigest(), "test_harness": True,
              "profile": {"test": True, "opt_level": "3", "debug_assertions": False}}
    description = {"expected_head": expected["expected_head"], "expected_tree": expected["expected_tree"], "binary": binary}
    for base in (root, root / "build"):
        write(base / "source-before.json", source)
        write(base / "source-after.json", source)
        write(base / "native-binary.json", description)
    folder = root / "build"
    compiler_text = ("rustc 1.95.0 (abcdef012 2026-01-01)\nbinary: rustc\ncommit-hash: " + "abcdef012" + "0" * 31
                     + "\ncommit-date: 2026-01-01\nhost: x86_64-unknown-linux-gnu\nrelease: 1.95.0\nLLVM version: 22.0.0\n")
    cargo_text = ("cargo 1.95.0 (abcdef012 2026-01-01)\ncommit-hash: " + "abcdef012" + "0" * 31
                  + "\ncommit-date: 2026-01-01\nhost: x86_64-unknown-linux-gnu\nrelease: 1.95.0\n")
    write(folder / "toolchain-observation.json", reader.native.toolchain_identity(compiler_text, cargo_text, "x86_64"))
    resources = {"schema": "trnm.resource-observation.v1", "nice": 10, "cpu_affinity": [0, 1, 2, 3],
                 "limits": [{"cpu.max": "400000 100000", "memory.max": "17179869184"}]}
    write(folder / "resources-before.json", resources)
    write(folder / "resources-after.json", resources)
    prefix = ["/synthetic/cargo", "+1.95.0"]
    commands = [
        ["/synthetic/rustup", "run", "1.95.0", "rustc", "-Vv"], [*prefix, "-Vv"],
        [*prefix, "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "trillionnium/Cargo.toml"],
        [*prefix, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"],
        [*prefix, "clippy", "--release", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
         "--all-features", "-p", "trnm-pon-node", "--test", "pure_pon_pressure_v2", "--", "-D", "warnings"],
        [*prefix, "test", "--release", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
         "--all-features", "--no-run", "--message-format=json", "-p", "trnm-pon-node", "--test", "pure_pon_pressure_v2"],
        *([binary["path"], "--exact", selector, "--nocapture", "--test-threads=1"] for selector in fixture.CONTROL_SELECTORS.values())]
    build = (json.dumps({"reason": "compiler-artifact", "target": {"name": "pure_pon_pressure_v2", "kind": ["test"]},
                         "executable": binary["path"], "profile": binary["profile"]}) + "\n"
             + json.dumps({"reason": "build-finished", "success": True}) + "\n")
    terminal = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out; finished in 0.01s\n"
    streams = (compiler_text, cargo_text, "{}\n", "", "", build, terminal, terminal)
    steps, verdicts = [], []
    for name, command, timeout, stdout in zip(fixture.BUILD_STEPS, commands, (30, 30, 120, 180, 1800, 1800, 60, 60), streams):
        row = {"name": name, "command": command, "outer_stage_timeout_seconds": timeout,
               "returncode": 0, "error": None, "complete_success": True, "stdout_truncated": False, "stderr_truncated": False}
        for stream, raw in (("stdout", stdout.encode()), ("stderr", b"")):
            filename = name + "." + stream + ".log"
            (folder / filename).write_bytes(raw)
            row.update({stream: filename, stream + "_bytes": len(raw), stream + "_sha256": hashlib.sha256(raw).hexdigest()})
        write(folder / (name + ".step.json"), row)
        steps.append(row)
        if name in fixture.CONTROL_SELECTORS:
            verdict = reader.native.native_verdict(name, row, stdout)
            verdicts.append(verdict)
            write(folder / (name + ".native-verdict.json"), verdict)
    observations = []
    for prefix_only, prefix_hex, payload_hex in ((True, "000000", ""), (False, "00000005", "72")):
        observations.append({"prefix_only": prefix_only, "assertions_passed": True, "prefix_hex": prefix_hex,
                             "payload_hex": payload_hex, "error": "synthetic timeout", "deadline_allowance_ns": 100_000_000,
                             "started_monotonic_ns": 1, "ended_monotonic_ns": 100_000_001})
    write(folder / "ready-control.json", {"schema": "pon-receiver-ready-deadline-control-v1",
          "observations": observations, "original_ready_budget_seconds": 180, "qualification_budget_changed": False,
          "physical_authentication": False})
    write(folder / "results.json", {"schema": "pon-fixed-parent-build-v1", "expected_head": expected["expected_head"],
          "complete_success": True, "failure": None, "finalization_failures": [], "automatic_retries": 0, "toolchain": "1.95.0",
          "source_before": source, "source_after": source, "steps": steps, "binary": binary, "native_verdicts": verdicts,
          "physical_authentication": False, "original_campaign_qualification": False})
    return description


def refresh_receiver(location, phase_path):
    node = load(location / "receiver-report.json")
    phase = load(phase_path)
    phase.update({key: value for key, value in node.items() if key != "schema"})
    write(phase_path, phase)
    trace = load(location / "receiver-control-trace.json")
    stop = trace["exchanges"][-1]
    response = json.loads(bytes.fromhex(stop["response_hex"]))
    response["value"]["report"] = raw_binding(location / "receiver-report.json")
    encoded = json.dumps(response, separators=(",", ":"), sort_keys=True).encode()
    stop.update(response_hex=encoded.hex(), response_payload_hex=encoded.hex(),
                response_prefix_hex=len(encoded).to_bytes(4, "big").hex(),
                response_sha256=hashlib.sha256(encoded).hexdigest())
    trace["payload_bytes"] = sum(len(bytes.fromhex(row["request_hex"])) + len(bytes.fromhex(row["response_hex"]))
                                 for row in trace["exchanges"])
    write(location / "receiver-control-trace.json", trace)
    binding = load(location / "receiver-owner-binding-v1.json")
    binding["files"] = {name: raw_binding(location / name) for name in reader.receiver.FILES}
    binding["cost"] = load(location / "receiver-wait4.json")
    write(location / "receiver-owner-binding-v1.json", binding)
    probe = load(location / "receiver-child-ownership-binding-v1.json")
    probe["parent_cost_binding"] = raw_binding(location / "receiver-owner-binding-v1.json")
    write(location / "receiver-child-ownership-binding-v1.json", probe)


def rebind(root):
    path = root / "fixed-parent-binding-v1.json"
    if path.exists():
        path.unlink()
    fixture.bind_files(root, fixture.PHASES)


def write_fixture(root, *, paid_depletion=True):
    expected = support.context()
    write(root / "context.json", expected)
    description = write_build(root, expected)
    args = copy.deepcopy(original.fixture.fixture.campaign())
    for index, phase in enumerate(args[2]):
        phase["epoch_monotonic_ns"] = 1_000_000_000_000 + index * 100_000_000_000
        business = reader.pressure.preparation(args[1])
        for wrapper in phase["actors"]:
            actor = wrapper["report"]["result"]
            args[3][(phase["phase"], actor["actor"])] = original.fixture.fixture.cost_for(
                actor, phase["epoch_monotonic_ns"], business, "phase_closed_after_preparation")
        if not paid_depletion and phase["phase"] == "from-zero":
            sample = phase["samples"][2]
            sample["credit_freshness"] = original.fixture.fixture.fixture.credit_freshness(sample["flow"], 200_000_000)
            sample["depleted"] = False
            phase["rounds"][2]["depletion_observed_during_round"] = False
    native = root / "native"
    native.mkdir()
    original.write_supplement(native, args)
    common_hash = hashlib.sha256((native / "preparation.json").read_bytes()).hexdigest()
    context_hash = hashlib.sha256((root / "context.json").read_bytes()).hexdigest()
    executions = []
    for ordinal, name in enumerate(fixture.PHASES):
        location, phase_path = native / name, native / (name + ".json")
        parent_pid = 90000 + ordinal
        for path in [phase_path, *location.rglob("*.json")]:
            original_value = load(path)
            value = replace_parent(original_value, parent_pid)
            if value != original_value:
                write(path, value)
        phase = load(phase_path)
        epoch, receiver_pid = phase["epoch_monotonic_ns"], phase["receiver_pid"]
        cpu, periods, throttled = 1000 + ordinal * 10000, 100 + ordinal * 100, 5 + ordinal * 20
        before = support.snapshot(expected, start=epoch-2000, end=epoch-1500, cpu=cpu, periods=periods, throttled=throttled)
        after = support.snapshot(expected, start=epoch+reader.pressure.WINDOW+1200, end=epoch+reader.pressure.WINDOW+1300,
                                 cpu=cpu+1000, periods=periods+11, throttled=throttled+11)
        settled = copy.deepcopy(after)
        settled.update(started_monotonic_ns=epoch+reader.pressure.WINDOW+1000,
                       ended_monotonic_ns=epoch+reader.pressure.WINDOW+1001)
        execution = support.process_row(expected, name, description["binary"]["path"], parent_pid)
        execution.update(started_monotonic_ns=epoch-1000, ended_monotonic_ns=epoch+reader.pressure.WINDOW+1100,
                         before_parent_reap=settled, after=after)
        for stream in ("stdout", "stderr"):
            raw = b"synthetic controller terminal\n" if stream == "stdout" else b""
            (root / (name + "." + stream + ".log")).write_bytes(raw)
            execution.update({stream + "_bytes": len(raw), stream + "_sha256": hashlib.sha256(raw).hexdigest()})
        write(root / (name + "-kernel-before.json"), before)
        write(root / (name + "-kernel-after.json"), after)
        write(root / (name + "-process.json"), execution)
        executions.append(execution)
        descriptor = {**copy.deepcopy(expected["initial_root_open"]), "fd": 9, "filesystem_magic": 0x63677270,
                      "close_on_exec": True}
        controller = {"schema": "pon-fixed-parent-phase-controller-v1", "phase": name, "error": None,
                      "started_monotonic_ns": epoch-950, "ended_monotonic_ns": epoch+reader.pressure.WINDOW+900,
                      "common_preparation_sha256": common_hash, "placement": {"context_sha256": context_hash,
                      "controller_pid": parent_pid, "capability_consumed": True, "initial_descriptor": descriptor},
                      "all_rounds_confirmed": True, "original_campaign_qualification": False, "physical_authentication": False}
        write(native / (name + "-controller-v1.json"), controller)
        write(location / "fixed-parent-placement-v1.json", {"schema": "pon-fixed-parent-placement-v1",
              "context": expected, "context_sha256": context_hash, "controller_pid": parent_pid,
              "inherited_descriptor": descriptor, "kernel_enforced_write_zero_only": False, "physical_authentication": False})
        group = "0::" + expected["leaf_path"].removeprefix("/sys/fs/cgroup") + "\n"
        entry = {"schema": "pon-fixed-parent-receiver-entry-v1", "before_node_construction": True,
                 "context_sha256": context_hash, "controller_pid": parent_pid,
                 "role": role(receiver_pid, group, epoch-68, epoch-67),
                 "kernel": kernel_sample(expected, cpu+100, periods+1, throttled+1), "physical_authentication": False}
        write(location / "fixed-parent-receiver-entry-v1.json", entry)
        write(location / "fixed-parent-after-exec-v1.json", {"schema": "pon-fixed-parent-after-exec-v1",
              "context_sha256": context_hash, "controller": role(parent_pid, expected["outer_cgroup"], epoch-59, epoch-58),
              "receiver": role(receiver_pid, group, epoch-57, epoch-56), "physical_authentication": False})
        actors = []
        for index, wrapper in enumerate(phase["actors"]):
            actors.append(dict(role(wrapper["pid"], expected["outer_cgroup"], epoch-55+index*2, epoch-54+index*2), actor=index))
        write(location / "fixed-parent-actors-ready-v1.json", {"schema": "pon-fixed-parent-actors-ready-v1",
              "controller": role(parent_pid, expected["outer_cgroup"], epoch-6, epoch-5),
              "actors": actors, "physical_authentication": False})
        ready = json.dumps(load(location / "receiver-ready.json"), separators=(",", ":"), sort_keys=True).encode()
        write(location / "receiver-ready-exchange-v1.json", {"schema": "pon-receiver-ready-exchange-v1", "pid": receiver_pid,
              "started_monotonic_ns": epoch-66, "ended_monotonic_ns": epoch-60,
              "deadline_arm_before_monotonic_ns": epoch-69, "deadline_arm_after_monotonic_ns": epoch-68,
              "startup_budget_ns": 180_000_000_000, "original_owner_deadline": True,
              "timeout_restarted_between_reads": False, "prefix_hex": len(ready).to_bytes(4, "big").hex(),
              "payload_hex": ready.hex(), "error": None, "physical_authentication": False})
        node = load(location / "receiver-report.json")
        node["kernel_parent"].update(open_error=None,
            before={"Ok": kernel_sample(expected, cpu+200, periods+2, throttled+2)},
            after={"Ok": kernel_sample(expected, cpu+900, periods+10, throttled+10)},
            delta={"Ok": {"usage_usec": 700, "nr_periods": 8, "nr_throttled": 8, "throttled_usec": 80}})
        write(location / "receiver-report.json", node)
        refresh_receiver(location, phase_path)
        # Parent IDs changed in this synthetic fixture; bind actual rewritten
        # bytes in the same dependency order as the native observations.
        cost_path = location / reader.process.FILE
        cost = load(cost_path)
        cost["thread_cost_parent_binding"] = raw_binding(location / reader.actor.BINDING_FILE)
        for row in cost["actors"]:
            target = location / row["actor_directory"]
            row["files"] = {name: raw_binding(target / name) for name in row["files"]}
        write(cost_path, cost)
        probe_path = location / "attacker-child-ownership-binding-v1.json"
        probe = load(probe_path)
        probe["parent_cost_binding"] = raw_binding(cost_path)
        write(probe_path, probe)
    write(root / "host-capability.json", {"schema": "pon-fixed-parent-host-capability-v1", "euid": 0,
          "github_actions": "true", "runner_environment": "github-hosted", "fixed_parent_exists": False,
          "systemd_present": True, "cgroup_root_writable": True, "self_cgroup": expected["outer_cgroup"]})
    create = fixture.transient_unit_command(expected["manager_identity"]["Description"])
    manager_commands = (("absence-list-units", fixture.loaded_unit_absence_command(), ""),
                        ("absence-unit-files-by-patterns", fixture.unit_file_absence_command(), "a(ss) 0\n"),
                        ("create-owned-runtime-unit", create, ""),
                        ("stop-only-owned-runtime-unit", ["/usr/bin/systemctl", "stop", fixture.UNIT], ""))
    first_before = load(root / (fixture.PHASES[0] + "-kernel-before.json"))
    for index, (label, command, stdout) in enumerate(manager_commands, 1):
        started = (first_before["started_monotonic_ns"] - 1000 + index * 100
                   if index < 4 else executions[-1]["after"]["ended_monotonic_ns"] + 1000)
        write(root / ("manager-command-%02d.json" % index), {"label": label, "command": command,
              "returncode": 0, "error": None, "stdout": stdout, "stderr": "",
              "started_monotonic_ns": started, "ended_monotonic_ns": started + 10})
    cleanup_before = copy.deepcopy(executions[-1]["after"])
    cleanup_before["started_monotonic_ns"] += 200
    cleanup_before["ended_monotonic_ns"] += 200
    write(root / "results.json", {"schema": fixture.RESULT_SCHEMA, "expected_head": expected["expected_head"],
          "failure": None, "finalization_failures": [], "prior_failure": fixture.PRIOR_FAILURE,
          "phases": executions, "manager_command_files": ["manager-command-%02d.json" % i for i in range(1, 5)],
          "common_preparation_sha256": common_hash, "physical_authentication": False,
          "original_campaign_qualification": False, "cleanup": {"schema": "pon-fixed-parent-cleanup-v1",
          "attempted": True, "complete": True, "error": None, "forced_kernel_kill": False,
          "foreign_or_replaced_objects_touched": False, "before": cleanup_before, "manager_before": expected["manager_identity"]}})
    rebind(root)


class FixedParentControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        write_fixture(self.root)

    def mutate(self, relative, function, rebind_outer=True):
        path = self.root / relative
        value = load(path)
        function(value)
        write(path, value)
        if rebind_outer:
            rebind(self.root)

    def reject(self):
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            reader.check_directory(self.root)

    def test_complete_synthetic_chain_is_consistent_but_not_physical_evidence(self):
        value = reader.check_directory(self.root)
        self.assertTrue(value["host_fixture_qualified"])
        self.assertTrue(value["honest_service_qualified"])
        self.assertFalse(value["original_campaign_qualification"])
        self.assertFalse(value["physical_authentication"])
        self.assertEqual(len(value["host_phases"]), 3)

    def test_host_fixture_does_not_promote_failed_original_depletion(self):
        other = self.root / "separate-failed-depletion"
        other.mkdir()
        write_fixture(other, paid_depletion=False)
        value = reader.check_directory(other)
        self.assertTrue(value["host_fixture_qualified"])
        self.assertTrue(value["honest_service_qualified"])
        self.assertFalse(value["unchanged_paid_depletion_qualified"])
        self.assertFalse(value["unchanged_full_finite_predicate"])
        self.assertFalse(value["original_campaign_qualification"])
        self.assertFalse(value["prior_failure"]["supplement_from_zero_paid_depletion_qualified"])

    def test_raw_parent_binding_rejects_rewritten_root_result(self):
        self.mutate("results.json", lambda value: value.update(prior_failure={}), False)
        self.reject()

    def test_root_capture_also_binds_native_owner_receipts(self):
        self.mutate("native/baseline/receiver-owner-binding-v1.json",
                    lambda value: value.update(capture_source_comment="changed after root capture"), False)
        self.reject()

    def test_extra_manager_properties_are_not_silently_accepted(self):
        self.mutate("manager-command-03.json", lambda value: value["command"].extend(["TasksMax", "t", "4096"]))
        self.reject()

    def test_rebound_nonempty_or_untyped_unit_file_reply_is_rejected(self):
        path = self.root / "manager-command-02.json"
        original = load(path)
        for stdout in ("", "as 0\n", "a(ss) 0\nextra\n",
                       'a(ss) 1 "/etc/systemd/system/trnmponpublic.slice" "enabled"\n'):
            with self.subTest(stdout=stdout):
                write(path, {**original, "stdout": stdout})
                rebind(self.root)
                self.reject()

    def test_rebound_failed_unit_file_query_never_becomes_absence(self):
        path = self.root / "manager-command-02.json"
        original = load(path)
        for changes in ({"returncode": 1}, {"returncode": False}, {"error": "timeout"},
                        {"stderr": "Call failed: Unknown method\n"}):
            with self.subTest(changes=changes):
                write(path, {**original, **changes})
                rebind(self.root)
                self.reject()

    def test_rebound_wrong_absence_method_is_rejected(self):
        self.mutate("manager-command-02.json", lambda value: value.update(
            command=["/usr/bin/systemctl", "list-unit-files", fixture.UNIT]))
        self.reject()

    def test_rebound_loaded_unit_presence_is_rejected(self):
        self.mutate("manager-command-01.json", lambda value: value.update(
            stdout="trnmponpublic.slice loaded active active existing\n"))
        self.reject()

    def test_absence_queries_cannot_be_moved_after_creation(self):
        first = load(self.root / "manager-command-01.json")
        third = load(self.root / "manager-command-03.json")
        write(self.root / "manager-command-01.json", third)
        write(self.root / "manager-command-03.json", first)
        rebind(self.root)
        self.reject()

    def test_rebound_query_clock_after_create_is_rejected_despite_file_order(self):
        for index, (start, end) in enumerate(((100, 110), (500, 510), (300, 310), (600, 610)), 1):
            path = self.root / ("manager-command-%02d.json" % index)
            write(path, {**load(path), "started_monotonic_ns": start, "ended_monotonic_ns": end})
        rebind(self.root)
        with self.assertRaisesRegex(ValueError, "manager command sequence"):
            reader.check_directory(self.root)

    def test_rebound_missing_manager_clock_is_rejected(self):
        path = self.root / "manager-command-02.json"
        original = load(path)
        for field in ("started_monotonic_ns", "ended_monotonic_ns"):
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                del changed[field]
                write(path, changed)
                rebind(self.root)
                with self.assertRaisesRegex(ValueError, "manager command time bracket"):
                    reader.check_directory(self.root)

    def test_rebound_noninteger_or_negative_manager_clock_is_rejected(self):
        path = self.root / "manager-command-02.json"
        original = load(path)
        for field in ("started_monotonic_ns", "ended_monotonic_ns"):
            for invalid in (None, False, 0.0, "0", -1):
                with self.subTest(field=field, invalid=invalid):
                    write(path, {**original, field: invalid})
                    rebind(self.root)
                    with self.assertRaisesRegex(ValueError, "manager command time bracket"):
                        reader.check_directory(self.root)

    def test_rebound_reversed_manager_clock_bracket_is_rejected(self):
        path = self.root / "manager-command-02.json"
        original = load(path)
        write(path, {**original, "started_monotonic_ns": original["ended_monotonic_ns"] + 1})
        rebind(self.root)
        with self.assertRaisesRegex(ValueError, "manager command time bracket"):
            reader.check_directory(self.root)

    def test_sorted_manager_queries_and_create_after_phase_start_are_rejected(self):
        first = load(self.root / (fixture.PHASES[0] + "-kernel-before.json"))["started_monotonic_ns"]
        for index in range(1, 4):
            path = self.root / ("manager-command-%02d.json" % index)
            start = first + index * 100
            write(path, {**load(path), "started_monotonic_ns": start, "ended_monotonic_ns": start + 10})
        rebind(self.root)
        with self.assertRaisesRegex(ValueError, "creation must precede first phase"):
            reader.check_directory(self.root)

    def test_sorted_manager_stop_before_final_phase_end_is_rejected(self):
        final = load(self.root / (fixture.PHASES[-1] + "-kernel-after.json"))["ended_monotonic_ns"]
        path = self.root / "manager-command-04.json"
        write(path, {**load(path), "started_monotonic_ns": final - 20, "ended_monotonic_ns": final - 10})
        rebind(self.root)
        with self.assertRaisesRegex(ValueError, "stop preceded final phase"):
            reader.check_directory(self.root)

    def test_nonzero_controller_exit_cannot_be_host_success(self):
        self.mutate("baseline-process.json", lambda value: value.update(returncode=7))
        result = load(self.root / "results.json")
        result["phases"][0] = load(self.root / "baseline-process.json")
        write(self.root / "results.json", result)
        rebind(self.root)
        self.reject()

    def test_retained_actual_binary_mutation_is_rejected(self):
        path = self.root / "retained-binary"
        path.write_bytes(path.read_bytes() + b"x")
        self.reject()

    def test_actual_binary_path_cannot_be_selector_token(self):
        row = load(self.root / "baseline-process.json")
        row["command"][11] = "--exact"
        expected = load(self.root / "context.json")
        with self.assertRaises(ValueError):
            reader.check_process(row, expected, "baseline", "/synthetic/target/release/deps/pure_pon_pressure_v2-abc")

    def test_previous_lifetime_member_census_is_rejected(self):
        self.mutate("native/baseline/fixed-parent-receiver-entry-v1.json",
                    lambda value: value["role"].update(started_monotonic_ns=0, ended_monotonic_ns=1))
        self.reject()

    def test_actor_capability_fd_leak_is_recomputed(self):
        def mutate(value):
            forbidden = support.context()["migration_file_identity"]
            value["actors"][0]["descriptors"].append({"fd": 9, "device": forbidden["device"], "inode": forbidden["inode"]})
        self.mutate("native/from-zero/fixed-parent-actors-ready-v1.json", mutate)
        self.reject()

    def test_actor_mixed_receiver_cgroup_is_rejected(self):
        self.mutate("native/from-zero/fixed-parent-actors-ready-v1.json",
                    lambda value: value["actors"][0].update(cgroup="0::/trnmponpublic.slice/foreign\n"))
        self.reject()

    def test_missing_hierarchy_slash_is_rejected_after_rebinding(self):
        path = self.root / "native/baseline/fixed-parent-receiver-entry-v1.json"
        original = load(path)
        for target in ("expected", "observed"):
            with self.subTest(target=target):
                value = copy.deepcopy(original)
                role = value["role"]
                missing_slash = role["expected_cgroup"].replace("0::/", "0::", 1)
                if target == "expected":
                    role["expected_cgroup"] = missing_slash
                else:
                    role["cgroup"] = missing_slash
                    for thread in role["threads"]:
                        thread["cgroup"] = missing_slash
                # Even a claimed match plus newly computed outer hashes must
                # not normalize a wrong raw kernel/expected hierarchy path.
                role["membership_matches"] = True
                write(path, value)
                rebind(self.root)
                self.reject()

    def test_same_inner_wrong_inode_is_not_accepted(self):
        location = self.root / "native/baseline"
        node = load(location / "receiver-report.json")
        for endpoint in ("before", "after"):
            node["kernel_parent"][endpoint]["Ok"]["binding"]["inode"] += 1
        write(location / "receiver-report.json", node)
        refresh_receiver(location, self.root / "native/baseline.json")
        rebind(self.root)
        self.reject()

    def test_inner_cpu_counter_outside_outer_bracket_is_rejected(self):
        self.mutate("native/baseline/fixed-parent-receiver-entry-v1.json",
                    lambda value: value["kernel"]["resources"].update(cpu_usage_usec=1))
        self.reject()

    def test_counters_cannot_restart_between_phase_controllers(self):
        self.mutate("from-zero-kernel-before.json",
                    lambda value: value["parent"]["values"].update({"cpu.stat": "usage_usec 1\nnr_periods 1\nnr_throttled 1\nthrottled_usec 1\n"}))
        self.reject()

    def test_kernel_ceiling_and_identity_types_are_strict(self):
        expected = support.context()
        for key, value in (("cpu_quota_usec", 25001), ("cpu_burst_usec", False), ("inode", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                altered = kernel(expected)
                altered[key] = value
                reader.kernel_binding(altered, expected)

    def test_cleanup_cannot_follow_forced_kernel_kill_or_unknown(self):
        for key, value in (("forced_kernel_kill", True), ("complete", False), ("error", "unknown")):
            with self.subTest(key=key):
                original = load(self.root / "results.json")
                mutated = copy.deepcopy(original)
                mutated["cleanup"][key] = value
                write(self.root / "results.json", mutated)
                rebind(self.root)
                self.reject()
                write(self.root / "results.json", original)

    def test_original_failure_reference_cannot_be_erased(self):
        self.mutate("results.json", lambda value: value.update(prior_failure={}))
        self.reject()

    def test_source_hashes_cannot_be_relabelled(self):
        self.mutate("build/source-before.json", lambda value: value.update(tested_commit="9"*40))
        self.reject()

    def test_original_build_streams_are_read_not_only_verdicts(self):
        path = self.root / "build/ready-deadline.stdout.log"
        path.write_bytes(b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n")
        rebind(self.root)
        self.reject()

    def test_new_sidecar_authority_flags_cannot_be_promoted(self):
        for name in ("fixed-parent-receiver-entry-v1.json", "fixed-parent-after-exec-v1.json", "fixed-parent-actors-ready-v1.json"):
            with self.subTest(name=name):
                path = self.root / "native/baseline" / name
                value = load(path)
                original_value = copy.deepcopy(value)
                value["physical_authentication"] = True
                write(path, value)
                rebind(self.root)
                self.reject()
                write(path, original_value)

    def test_binding_unknown_paths_are_rejected_before_open(self):
        binding = load(self.root / "fixed-parent-binding-v1.json")
        binding["files"].append({"path": "unknown", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "error": None})
        with self.assertRaises(ValueError):
            reader.binding_rows(binding)

    def test_binding_total_and_boolean_sizes_are_rejected(self):
        binding = load(self.root / "fixed-parent-binding-v1.json")
        for row in binding["files"][:5]:
            row["bytes"] = fixture.FILE_LIMIT
        with self.assertRaises(ValueError):
            reader.binding_rows(binding)
        binding = load(self.root / "fixed-parent-binding-v1.json")
        binding["files"][0]["bytes"] = False
        with self.assertRaises(ValueError):
            reader.binding_rows(binding)

    def test_ready_real_framing_without_newline_is_valid_and_deadline_is_absolute(self):
        location = self.root / "native/baseline"
        value = load(location / "receiver-ready-exchange-v1.json")
        self.assertFalse(bytes.fromhex(value["payload_hex"]).endswith(b"\n"))
        cost = load(location / "receiver-wait4.json")
        ready = load(location / "receiver-ready.json")
        epoch = load(self.root / "native/baseline.json")["epoch_monotonic_ns"]
        reader.ready_exchange(value, ready, cost, epoch)
        value["deadline_arm_after_monotonic_ns"] = value["deadline_arm_before_monotonic_ns"] - 1
        with self.assertRaises(ValueError):
            reader.ready_exchange(value, ready, cost, epoch)


if __name__ == "__main__":
    unittest.main()
