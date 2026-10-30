#!/usr/bin/env python3
"""Independently read the three-controller fixed-parent fixture.

Host ownership/membership/counter observations, honest service and the unchanged
paid-credit depletion predicate are separate results. No old failure is replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import check_pure_pon_receiver_owner_v1 as receiver
import run_pure_pon_fixed_parent_v1 as fixture
import run_pure_pon_admission_daa_v2 as native

actor, process, pressure = receiver.actor, receiver.process, receiver.pressure
require, natural = actor.require, actor.natural
SCHEMA = "pon-fixed-parent-observation-v1"
FLAGS = ("physical_authentication", "public_fairness_qualified", "production_qualified",
         "work_hardness_qualified", "installation_authorized", "original_campaign_qualification",
         "kernel_enforced_write_zero_only")


def no_authority(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FLAGS:
                require(item is False, "fixed-parent observation authority")
            no_authority(item)
    elif isinstance(value, list):
        for item in value:
            no_authority(item)


def identity(value, directory):
    require(type(value) is dict and set(value) == {"device", "inode", "uid", "gid", "mode"}
            and all(natural(x) for x in value.values()) and value["inode"] > 0,
            "kernel identity fields")
    require(value["uid"] == 0 and value["mode"] & 0o022 == 0
            and (stat.S_ISDIR(value["mode"]) if directory else stat.S_ISREG(value["mode"])),
            "root-owned kernel object")


def context(value):
    require(value["schema"] == fixture.CONTEXT_SCHEMA and value["parent_path"] == str(fixture.PARENT)
            and re.fullmatch("[0-9a-f]{32}", value["owner_nonce"])
            and value["leaf_path"] == str(fixture.PARENT / ("owned-" + value["owner_nonce"] + ".group"))
            and value["limits"] == fixture.LIMITS and type(value["runner_uid"]) is int
            and value["runner_uid"] > 0 and type(value["runner_gid"]) is int and value["runner_gid"] > 0
            and natural(value["root_fixture_pid"]) and value["root_fixture_pid"] > 0,
            "exact fixed parent/context")
    require(re.fullmatch("[0-9a-f]{40}", value["expected_head"])
            and re.fullmatch("[0-9a-f]{40}", value["expected_tree"])
            and re.fullmatch("[0-9a-f-]{36}", value["boot_id"]), "context source/boot")
    require(value["outer_cgroup"].startswith("0::/system.slice/")
            and value["outer_cgroup"].endswith(".service\n")
            and "\n" not in value["outer_cgroup"][:-1]
            and "trnmponpublic.slice" not in value["outer_cgroup"], "separate controller cgroup")
    for key, directory in (("parent_identity", True), ("leaf_identity", True),
                           ("migration_file_identity", False)):
        identity(value[key], directory)
    opened = value["initial_root_open"]
    require(opened["identity"] == value["migration_file_identity"]
            and type(opened["opening_euid"]) is int and opened["opening_euid"] == 0
            and natural(opened["open_flags"]) and opened["open_flags"] & os.O_ACCMODE == os.O_WRONLY
            and natural(opened["descriptor_flags"]) and opened["descriptor_flags"] & 1 == 1,
            "root-opened capability observation")
    manager = value["manager_identity"]
    require(manager["Transient"] == "yes" and manager["ActiveState"] == "active"
            and manager["ControlGroup"] == "/trnmponpublic.slice"
            and manager["Description"] == "Owned PoN finite fixed-parent CI fixture " + value["owner_nonce"]
            and re.fullmatch("[0-9a-f]{32}", manager["InvocationID"]), "transient owner identity")
    no_authority(value)


def kernel_snapshot(value, expected, *, must_be_empty=True):
    require(value["schema"] == "pon-fixed-parent-kernel-snapshot-v1" and value["complete"] is True
            and value["errors"] == [] and value["boot_id"] == expected["boot_id"]
            and natural(value["started_monotonic_ns"]) and natural(value["ended_monotonic_ns"])
            and value["started_monotonic_ns"] <= value["ended_monotonic_ns"], "kernel snapshot completeness")
    totals = {}
    for name in ("parent", "leaf"):
        row = value[name]
        require(row["identity"] == expected[name + "_identity"], "kernel interval identity changed")
        raw = row["values"]
        require(raw["cgroup.type"] == "domain\n", "kernel domain changed")
        if name == "parent":
            require(all(raw[key].strip() == text for key, text in fixture.LIMITS.items()), "kernel limits changed")
            require({"cpu", "memory", "pids"} <= set(raw["cgroup.subtree_control"].split()), "controller coverage")
        else:
            require(raw["cgroup.max.descendants"].strip() == "0", "unexpected delegated descendants")
        cpu = fixture.kernel_pairs(raw["cpu.stat"])
        require({"usage_usec", "nr_periods", "nr_throttled", "throttled_usec"} <= set(cpu), "kernel CPU counters")
        require(raw["pids.current"].strip().isdigit() and raw["memory.current"].strip().isdigit(),
                "kernel current counters")
        fixture.kernel_pairs(raw["memory.events"])
        events = fixture.kernel_pairs(raw["cgroup.events"])
        require(events.get("populated") in (0, 1), "kernel population counter")
        if must_be_empty:
            require(not raw["cgroup.procs"].strip() and not raw["cgroup.threads"].strip()
                    and raw["pids.current"].strip() == "0" and events["populated"] == 0,
                    "fixed parent retains processes/threads")
        totals[name] = cpu
    return totals


def role(value, pid, group, forbidden, after, before):
    require(type(value["pid"]) is int and value["pid"] == pid
            and value["cgroup"] == value["expected_cgroup"] == group
            and natural(value["started_monotonic_ns"]) and natural(value["ended_monotonic_ns"])
            and after <= value["started_monotonic_ns"] <= value["ended_monotonic_ns"] <= before,
            "role PID/group/time")
    rows, errors = value["descriptors"], value["descriptor_errors"]
    require(type(rows) is list and len(rows) <= 256 and type(errors) is list and not errors
            and value["descriptor_capture_complete"] is True, "descriptor census unknown")
    seen, matches = set(), []
    for item in rows:
        require(all(natural(item[k]) for k in ("fd", "device", "inode")) and item["fd"] not in seen,
                "descriptor census identity")
        seen.add(item["fd"])
        if (item["device"], item["inode"]) == (forbidden["device"], forbidden["inode"]):
            matches.append(item["fd"])
    require(value["matching_migration_descriptors"] == matches == []
            and value["capability_descriptor_absent"] is True, "migration capability leaked")
    threads = value["threads"]
    require(type(threads) is list and 0 < len(threads) <= 256
            and all(natural(t["tid"]) and t["tid"] > 0 and t["cgroup"] == group for t in threads)
            and len({t["tid"] for t in threads}) == len(threads)
            and value["membership_matches"] is True, "thread membership")
    no_authority(value)


def check_source(value, expected):
    require(value["schema"] == "trnm-ci-source-v1" and value["kind"] == "head"
            and value["candidate"] == value["tested_commit"] == expected["expected_head"]
            and value["tested_tree"] == expected["expected_tree"]
            and value["tracked_worktree_verified"] is True and value["tests_executed_by_identity_check"] is False
            and natural(value["tracked_entries"]) and value["tracked_entries"] > 0
            and natural(value["tracked_bytes"]) and value["tracked_bytes"] > 0,
            "exact source identity")


def check_process(value, expected, phase, executable_path):
    require(value["schema"] == "pon-fixed-parent-controller-process-v1" and value["phase"] == phase
            and fixture.process_complete(value), "controller terminal/reap/cleanup")
    require(natural(value["pid"]) and value["pid"] > 0 and natural(value["started_monotonic_ns"])
            and natural(value["ended_monotonic_ns"])
            and value["started_monotonic_ns"] <= value["ended_monotonic_ns"]
            and value["original_phase_window_ns"] == pressure.WINDOW
            and type(value["original_phase_window_ns"]) is int
            and value["original_call_deadline_ns"] == 2_000_000_000
            and type(value["original_call_deadline_ns"]) is int
            and value["outer_controller_limit_seconds"] == 600
            and type(value["outer_controller_limit_seconds"]) is int, "original controller budgets")
    prefix = ["/usr/bin/setpriv", "--reuid", str(expected["runner_uid"]), "--regid",
              str(expected["runner_gid"]), "--clear-groups", "--no-new-privs", "--bounding-set=-all",
              "--inh-caps=-all", "--ambient-caps=-all", "--"]
    require(type(value["command"]) is list and value["command"][:len(prefix)] == prefix
            and value["command"][len(prefix)] == executable_path
            and value["command"][len(prefix)+1:] == ["--exact", "fixed_parent::fixed_parent_receiver_phase_v1",
                "--ignored", "--nocapture", "--test-threads=1"], "unprivileged exact native selector")
    opened = value["inherited_descriptor"]
    require(opened["identity"] == expected["migration_file_identity"]
            and opened["opening_euid"] == 0 and type(opened["opening_euid"]) is int
            and natural(opened["descriptor_flags"]) and opened["descriptor_flags"] & 1 == 1
            and natural(opened["open_flags"]) and opened["open_flags"] & os.O_ACCMODE == os.O_WRONLY,
            "phase descriptor provenance")


def kernel_binding(value, expected):
    require(value["schema"] == "public-host-kernel-binding-v1"
            and value["parent"] == str(fixture.PARENT) and value["boot_id"] == expected["boot_id"],
            "native fixed-parent guard namespace")
    fields = {"device": expected["parent_identity"]["device"], "inode": expected["parent_identity"]["inode"],
              "cpu_quota_usec": 25000, "cpu_period_usec": 100000, "cpu_burst_usec": 0,
              "memory_max_bytes": 2147483648, "memory_swap_max_bytes": 0, "pids_max": 256}
    require(all(natural(value[key]) and value[key] == target for key, target in fields.items()),
            "native fixed-parent guard identity/limits")


def ready_exchange(value, ready, cost, epoch):
    require(value["schema"] == "pon-receiver-ready-exchange-v1" and value["pid"] == cost["pid"]
            and type(value["pid"]) is int and value["error"] is None
            and value["original_owner_deadline"] is True and value["timeout_restarted_between_reads"] is False
            and value["physical_authentication"] is False, "ready observation identity/deadline")
    require(natural(value["started_monotonic_ns"]) and natural(value["ended_monotonic_ns"])
            and natural(value["deadline_arm_before_monotonic_ns"])
            and natural(value["deadline_arm_after_monotonic_ns"])
            and type(value["startup_budget_ns"]) is int and value["startup_budget_ns"] == 180_000_000_000
            and cost["spawn_finished_monotonic_ns"] <= value["deadline_arm_before_monotonic_ns"]
            <= value["deadline_arm_after_monotonic_ns"] <= value["started_monotonic_ns"]
            <= value["ended_monotonic_ns"] <= epoch
            and value["ended_monotonic_ns"] <= value["deadline_arm_after_monotonic_ns"] + value["startup_budget_ns"],
            "ready receive exceeded original absolute startup budget")
    prefix, payload = bytes.fromhex(value["prefix_hex"]), bytes.fromhex(value["payload_hex"])
    require(len(prefix) == 4 and int.from_bytes(prefix, "big") == len(payload) <= receiver.FRAME_LIMIT
            and actor.parse_raw(payload + b"\n", receiver.FRAME_LIMIT + 1) == ready, "ready raw framing/contents")


def binding_rows(value):
    """Reject attacker-selected paths/counts/aggregate sizes before reading files."""
    require(value["schema"] == "pon-fixed-parent-parent-binding-v1" and value["complete"] is True
            and value["physical_authentication"] is False, "root parent byte binding")
    allowed = set(fixture.core_binding_paths()) | {"manager-command-%02d.json" % i for i in range(1, 33)}
    rows, seen, total = value["files"], set(), 0
    require(type(rows) is list and 0 < len(rows) <= len(allowed), "root binding file-count bound")
    for item in rows:
        path = item["path"]
        require(type(path) is str and path in allowed and path not in seen and item["error"] is None
                and natural(item["bytes"]) and item["bytes"] <= fixture.FILE_LIMIT
                and re.fullmatch("[0-9a-f]{64}", item["sha256"]), "root binding row")
        seen.add(path)
        total += item["bytes"]
        require(total <= fixture.CAPTURE_LIMIT, "root binding aggregate byte bound")
    return rows


def check_build(get, bound, expected, binary):
    result = get("build/results.json")
    require(result["schema"] == "pon-fixed-parent-build-v1" and result["expected_head"] == expected["expected_head"]
            and result["complete_success"] is True and result["failure"] is None
            and result["finalization_failures"] == [] and type(result["automatic_retries"]) is int
            and result["automatic_retries"] == 0 and result["toolchain"] == native.TOOLCHAIN,
            "original build/control failure")
    no_authority(result)
    for key in ("source-before.json", "source-after.json"):
        source = get("build/" + key)
        check_source(source, expected)
        require(source == get(key) == result[key.split(".")[0].replace("-", "_")], "build/source association")
    require(get("build/native-binary.json") == binary and result["binary"] == binary["binary"], "build/binary association")
    steps = result["steps"]
    require(type(steps) is list and tuple(s["name"] for s in steps) == fixture.BUILD_STEPS, "complete build step coverage")
    cargo = steps[1]["command"][0]
    require(type(cargo) is str and Path(cargo).is_absolute() and Path(cargo).name == "cargo", "compiler executable path")
    prefix = [cargo, "+" + native.TOOLCHAIN]
    expected_commands = {
        "rustc-version": [str(Path(cargo).parent / "rustup"), "run", native.TOOLCHAIN, "rustc", "-Vv"],
        "cargo-version": [*prefix, "-Vv"],
        "locked-graph": [*prefix, "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "trillionnium/Cargo.toml"],
        "format": [*prefix, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"],
        "strict-pressure": [*prefix, "clippy", "--release", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
                            "--all-features", "-p", "trnm-pon-node", "--test", "pure_pon_pressure_v2", "--", "-D", "warnings"],
        "build-pressure": [*prefix, "test", "--release", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
                           "--all-features", "--no-run", "--message-format=json", "-p", "trnm-pon-node", "--test", "pure_pon_pressure_v2"],
        **{name: [binary["binary"]["path"], "--exact", selector, "--nocapture", "--test-threads=1"]
           for name, selector in fixture.CONTROL_SELECTORS.items()}}
    timeouts = (30, 30, 120, 180, 1800, 1800, 60, 60)
    for step, timeout in zip(steps, timeouts):
        name = step["name"]
        require(step == get("build/" + name + ".step.json") and step["command"] == expected_commands[name]
                and step["complete_success"] is True and step["returncode"] == 0
                and type(step["returncode"]) is int and step["error"] is None
                and step["stdout_truncated"] is step["stderr_truncated"] is False
                and type(step["outer_stage_timeout_seconds"]) is int and step["outer_stage_timeout_seconds"] == timeout,
                "complete original build/control terminal")
        for stream in ("stdout", "stderr"):
            filename = name + "." + stream + ".log"
            raw = bound["build/" + filename]
            require(step[stream] == filename and natural(step[stream + "_bytes"])
                    and len(raw) == step[stream + "_bytes"]
                    and hashlib.sha256(raw).hexdigest() == step[stream + "_sha256"], "complete build/control streams")
    compiler = get("build/toolchain-observation.json")
    require(compiler == native.toolchain_identity(bound["build/rustc-version.stdout.log"].decode(),
                bound["build/cargo-version.stdout.log"].decode(), compiler["native_machine"]), "native compiler identity")
    for name in ("resources-before.json", "resources-after.json"):
        native.bounds.validate_resources(get("build/" + name), 10)
    records = [actor.parse_raw(line, fixture.FILE_LIMIT)
               for line in bound["build/build-pressure.stdout.log"].splitlines(keepends=True)]
    require([r.get("success") for r in records if r.get("reason") == "build-finished"] == [True],
            "Cargo build terminal")
    artifacts = [r for r in records if r.get("reason") == "compiler-artifact"
                 and r.get("target", {}).get("name") == "pure_pon_pressure_v2" and r.get("executable")]
    require(len(artifacts) == 1 and artifacts[0]["executable"] == binary["binary"]["path"]
            and artifacts[0]["profile"] == binary["binary"]["profile"]
            and artifacts[0]["target"]["kind"] == ["test"], "Cargo native artifact identity")
    require(len(result["native_verdicts"]) == 2, "complete native control verdicts")
    for step, original in zip(steps[-2:], result["native_verdicts"]):
        name = step["name"]
        recomputed = native.native_verdict(name, step, bound["build/" + step["stdout"]].decode())
        require(original == get("build/" + name + ".native-verdict.json") == recomputed
                and recomputed["qualified"] is True and recomputed["terminal_summary"]["passed"] == 1,
                "nonempty original native controls")
    control = get("build/ready-control.json")
    require(control["schema"] == "pon-receiver-ready-deadline-control-v1"
            and type(control["original_ready_budget_seconds"]) is int and control["original_ready_budget_seconds"] == 180
            and control["qualification_budget_changed"] is control["physical_authentication"] is False
            and [r["prefix_only"] for r in control["observations"]] == [True, False], "native readiness controls")
    for row, prefix_hex, payload_hex in zip(control["observations"], ("000000", "00000005"), ("", "72")):
        require(row["assertions_passed"] is True and row["prefix_hex"] == prefix_hex and row["payload_hex"] == payload_hex
                and type(row["error"]) is str and row["error"] and type(row["deadline_allowance_ns"]) is int
                and row["deadline_allowance_ns"] == 100_000_000
                and natural(row["started_monotonic_ns"]) and natural(row["ended_monotonic_ns"])
                and row["started_monotonic_ns"] < row["ended_monotonic_ns"], "native partial-read deadline control")


def check_directory(directory):
    held = actor.open_directory(directory)
    try:
        deadline = time.monotonic() + 60
        read = lambda parts, limit=fixture.FILE_LIMIT: actor.safe_read(held, tuple(parts), limit, deadline)
        load = lambda parts, limit=fixture.FILE_LIMIT: actor.parse_raw(read(parts, limit), limit)
        binding = load(("fixed-parent-binding-v1.json",), 1024 * 1024)
        bound = {}
        for item in binding_rows(binding):
            path = item["path"]
            raw = read(path.split("/"))
            require(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"],
                    "root-bound raw bytes changed")
            bound[path] = raw
        get = lambda name: actor.parse_raw(bound[name], fixture.FILE_LIMIT)
        expected = get("context.json")
        context(expected)
        context_hash = hashlib.sha256(bound["context.json"]).hexdigest()
        result = get("results.json")
        require(result["schema"] == fixture.RESULT_SCHEMA and result["expected_head"] == expected["expected_head"]
                and result["failure"] is None and result["finalization_failures"] == []
                and result["prior_failure"] == fixture.PRIOR_FAILURE, "fixture failure/source/history")
        no_authority(result)
        require([p["phase"] for p in result["phases"]] == list(fixture.PHASES), "complete three-phase fixture")
        check_source(get("source-before.json"), expected)
        check_source(get("source-after.json"), expected)
        require(bound["source-before.json"] == bound["source-after.json"], "source changed")
        manager_names = result["manager_command_files"]
        require(type(manager_names) is list and 1 <= len(manager_names) <= 32
                and manager_names == ["manager-command-%02d.json" % i for i in range(1, len(manager_names)+1)],
                "manager command coverage")
        required_names = set(fixture.core_binding_paths()) | set(manager_names)
        require(set(bound) == required_names, "root binding coverage")
        commands = [get(name) for name in manager_names]
        require(all(c["returncode"] == 0 and type(c["returncode"]) is int and c["error"] is None
                    for c in commands), "manager operation failed")
        previous_command_end = None
        for command in commands:
            start, end = command.get("started_monotonic_ns"), command.get("ended_monotonic_ns")
            require(natural(start) and natural(end) and start <= end, "manager command time bracket")
            require(previous_command_end is None or previous_command_end <= start,
                    "manager command sequence contradicts monotonic times")
            previous_command_end = end
        starts = [c for c in commands if c["label"] == "create-owned-runtime-unit"]
        stops = [c for c in commands if c["label"] == "stop-only-owned-runtime-unit"]
        require(len(starts) == len(stops) == 1 and starts[0]["command"] ==
                fixture.transient_unit_command(expected["manager_identity"]["Description"])
                and stops[0]["command"] == ["/usr/bin/systemctl", "stop", fixture.UNIT],
                "owned runtime unit lifecycle")
        loaded = [c for c in commands if c["label"] == "absence-list-units"]
        unit_files = [c for c in commands if c["label"] == "absence-unit-files-by-patterns"]
        require(len(loaded) == len(unit_files) == 1 and commands[:3] == [loaded[0], unit_files[0], starts[0]],
                "unit absence must be observed before creation")
        require(loaded[0]["command"] == fixture.loaded_unit_absence_command()
                and type(loaded[0].get("stdout")) is str and not loaded[0]["stdout"].strip(),
                "loaded unit absence")
        fixture.require_unit_file_absence(unit_files[0])
        capability = get("host-capability.json")
        require(capability["schema"] == "pon-fixed-parent-host-capability-v1" and capability["euid"] == 0
                and type(capability["euid"]) is int and capability["github_actions"] == "true"
                and capability["runner_environment"] == "github-hosted"
                and capability["fixed_parent_exists"] is False and capability["systemd_present"] is True
                and capability["cgroup_root_writable"] is True
                and capability["self_cgroup"] == expected["outer_cgroup"], "original host capability")
        binary = get("native-binary.json")
        require(binary["expected_head"] == expected["expected_head"] and binary["expected_tree"] == expected["expected_tree"],
                "binary source binding")
        executable = binary["binary"]
        check_build(get, bound, expected, binary)
        raw_binary = read(("retained-binary",))
        require(natural(executable["bytes"]) and 0 < executable["bytes"] == len(raw_binary)
                and hashlib.sha256(raw_binary).hexdigest() == executable["sha256"]
                and raw_binary[:6] == b"\x7fELF\x02\x01"
                and executable["profile"]["opt_level"] == "3"
                and executable["profile"]["debug_assertions"] is False
                and executable["test_harness"] is executable["profile"]["test"] is True,
                "retained actual native binary")
        common = get("native/preparation.json")
        common_hash = hashlib.sha256(bound["native/preparation.json"]).hexdigest()
        require(common_hash == result["common_preparation_sha256"], "immutable common input bytes")
        reports, phases, sidecars, cost_bindings, captured, host_phases, declaration = [], [], {}, {}, {}, [], []
        previous_after = None
        receiver_group = "0::" + expected["leaf_path"].removeprefix("/sys/fs/cgroup") + "\n"
        for ordinal, name in enumerate(fixture.PHASES):
            phase = get("native/" + name + ".json")
            require(phase["schema"] == receiver.PHASE_SCHEMA and phase["phase"] == name, "native phase namespace/order")
            controller = get("native/" + name + "-controller-v1.json")
            execution = get(name + "-process.json")
            require(execution == result["phases"][ordinal], "root/native process association")
            check_process(execution, expected, name, executable["path"])
            require(controller["schema"] == "pon-fixed-parent-phase-controller-v1" and controller["phase"] == name
                    and controller["error"] is None and controller["common_preparation_sha256"] == common_hash
                    and controller["placement"]["context_sha256"] == context_hash
                    and controller["placement"]["controller_pid"] == phase["parent_pid"] == execution["pid"]
                    and controller["placement"]["capability_consumed"] is True,
                    "phase controller/common input binding")
            no_authority(controller)
            before, after = get(name + "-kernel-before.json"), get(name + "-kernel-after.json")
            require(after == execution["after"], "outer final kernel observation changed")
            b, a = kernel_snapshot(before, expected), kernel_snapshot(after, expected)
            settled = execution["before_parent_reap"]
            s = kernel_snapshot(settled, expected)
            require(before["ended_monotonic_ns"] <= execution["started_monotonic_ns"]
                    <= controller["started_monotonic_ns"] <= controller["ended_monotonic_ns"]
                    <= settled["started_monotonic_ns"] <= settled["ended_monotonic_ns"]
                    <= execution["ended_monotonic_ns"] <= after["started_monotonic_ns"], "phase owner time brackets")
            if previous_after is not None:
                require(previous_after["ended_monotonic_ns"] <= before["started_monotonic_ns"], "phase overlap")
                prior = kernel_snapshot(previous_after, expected)
                require(all(b[scope][key] >= prior[scope][key] for scope in ("parent", "leaf")
                            for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")),
                        "parent/leaf counters reset between controllers")
            else:
                require(starts[0]["ended_monotonic_ns"] <= before["started_monotonic_ns"],
                        "fixture creation must precede first phase observation")
            previous_after = after
            for scope in ("parent", "leaf"):
                require(all(b[scope][key] <= s[scope][key] <= a[scope][key]
                            for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")), "kernel counter rewind")
            for stream in ("stdout", "stderr"):
                raw = bound[name + "." + stream + ".log"]
                require(len(raw) == execution[stream + "_bytes"]
                        and hashlib.sha256(raw).hexdigest() == execution[stream + "_sha256"], "complete native streams")
            prefix = "native/" + name + "/"
            placement = get(prefix + "fixed-parent-placement-v1.json")
            require(placement["schema"] == "pon-fixed-parent-placement-v1" and placement["context"] == expected
                    and placement["context_sha256"] == context_hash
                    and placement["controller_pid"] == execution["pid"], "receiver migration context")
            descriptor = placement["inherited_descriptor"]
            require(descriptor == controller["placement"]["initial_descriptor"]
                    and descriptor["identity"] == expected["migration_file_identity"]
                    and natural(descriptor["fd"]) and descriptor["fd"] >= 3
                    and descriptor["filesystem_magic"] == 0x63677270
                    and type(descriptor["filesystem_magic"]) is int
                    and descriptor["close_on_exec"] is True
                    and natural(descriptor["descriptor_flags"]) and descriptor["descriptor_flags"] & 1 == 1
                    and natural(descriptor["open_flags"]) and descriptor["open_flags"] & os.O_ACCMODE == os.O_WRONLY,
                    "native capability descriptor identity")
            no_authority(placement)
            cost = load(("native", name, "receiver-wait4.json"), process.LOG_LIMIT)
            ready_packet = load(("native", name, "receiver-ready.json"), process.LOG_LIMIT)
            readiness = get(prefix + "receiver-ready-exchange-v1.json")
            ready_exchange(readiness, ready_packet, cost, phase["epoch_monotonic_ns"])
            entered = get(prefix + "fixed-parent-receiver-entry-v1.json")
            no_authority(entered)
            require(entered["schema"] == "pon-fixed-parent-receiver-entry-v1"
                    and entered["before_node_construction"] is True and entered["context_sha256"] == context_hash
                    and entered["controller_pid"] == execution["pid"], "receiver pre-Node migration")
            role(entered["role"], phase["receiver_pid"], receiver_group,
                 expected["migration_file_identity"], cost["spawn_started_monotonic_ns"],
                 readiness["ended_monotonic_ns"])
            kernel = entered["kernel"]["binding"]
            kernel_binding(kernel, expected)
            after_exec = get(prefix + "fixed-parent-after-exec-v1.json")
            no_authority(after_exec)
            require(after_exec["schema"] == "pon-fixed-parent-after-exec-v1"
                    and after_exec["context_sha256"] == context_hash, "post-exec observation namespace")
            role(after_exec["controller"], execution["pid"], expected["outer_cgroup"],
                 expected["migration_file_identity"], readiness["ended_monotonic_ns"], phase["epoch_monotonic_ns"])
            role(after_exec["receiver"], phase["receiver_pid"], receiver_group,
                 expected["migration_file_identity"], after_exec["controller"]["ended_monotonic_ns"],
                 phase["epoch_monotonic_ns"])
            ready = get(prefix + "fixed-parent-actors-ready-v1.json")
            no_authority(ready)
            require(ready["schema"] == "pon-fixed-parent-actors-ready-v1", "actor placement namespace")
            role(ready["controller"], execution["pid"], expected["outer_cgroup"],
                 expected["migration_file_identity"], after_exec["receiver"]["ended_monotonic_ns"],
                 phase["epoch_monotonic_ns"])
            population = 0 if name == "baseline" else pressure.ATTACKERS
            require(len(ready["actors"]) == len(phase["actors"]) == population, "actor placement population")
            process_cost = load(("native", name, process.FILE), actor.BINDING_LIMIT)
            require(process_cost["parent_pid"] == execution["pid"], "actor process owner mismatch")
            for index, value in enumerate(ready["actors"]):
                require(type(value["actor"]) is int and value["actor"] == index, "actor placement index")
                actor_cost = process_cost["actors"][index]["cost"]
                role(value, phase["actors"][index]["pid"], expected["outer_cgroup"],
                     expected["migration_file_identity"], max(actor_cost["spawn_finished_monotonic_ns"],
                         after_exec["receiver"]["ended_monotonic_ns"]), ready["controller"]["started_monotonic_ns"])
            # Reuse the unchanged ownership and finite-service predicates only
            # after the new fixture/context/byte bindings were checked.
            reports.append(receiver.check_receiver(phase, common,
                lambda file, limit: read(("native", name, file), limit)))
            require(reports[-1]["fixed_parent_interval_observed"] is True, "receiver fixed interval unknown")
            samples = [entered["kernel"], phase["kernel_parent"]["before"]["Ok"],
                       phase["kernel_parent"]["after"]["Ok"]]
            for sample in samples:
                require(sample["schema"] == "public-host-kernel-bound-resource-sample-v1"
                        and sample["binding"] == kernel, "receiver kernel endpoint owner mismatch")
                require(all(natural(v) for v in sample["resources"].values()), "native kernel counter type")
            for short, full in (("usage_usec", "cpu_usage_usec"), ("nr_periods", "cpu_nr_periods"),
                                ("nr_throttled", "cpu_nr_throttled"), ("throttled_usec", "cpu_throttled_usec")):
                amounts = [b["parent"][short], *(sample["resources"][full] for sample in samples), a["parent"][short]]
                require(amounts == sorted(amounts), "native kernel counters outside root observation interval")
            phases.append(phase)
            declaration.append({"phase": name, "file": name + ".json",
                                "all_rounds_confirmed": controller["all_rounds_confirmed"], "error": None})
            cost_bindings[name] = load(("native", name, actor.BINDING_FILE), actor.BINDING_LIMIT)
            require(cost_bindings[name]["parent_pid"] == execution["pid"], "actor preparation owner mismatch")
            for index in range(population):
                key = (name, index)
                captured[key] = {file: read(("native", name, "actor-" + str(index), file), limit)
                                 for file, limit in (("report.json", actor.REPORT_LIMIT), (actor.FILE, actor.COST_LIMIT))}
                sidecars[key] = actor.parse_raw(captured[key][actor.FILE], actor.COST_LIMIT)
            delta = {key: a["parent"][key] - b["parent"][key]
                     for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")}
            require(delta["usage_usec"] > 0, "no actual receiver kernel CPU observed")
            host_phases.append({"phase": name, "controller_pid": execution["pid"], "receiver_pid": phase["receiver_pid"],
                                "parent_cpu_delta": delta, "receiver_wait4_cpu_ns": reports[-1]["total_cpu_ns"],
                                "kernel_throttling_observed": delta["nr_throttled"] > 0 and delta["throttled_usec"] > 0})
        require(len({p["controller_pid"] for p in host_phases}) == 3, "separate phase controller identities")
        manifest = {"schema": pressure.SCHEMA, "window_ns": pressure.WINDOW, "attackers": pressure.ATTACKERS,
                    "actor_call_cap": pressure.CALL_CAP, "rounds": pressure.ROUNDS, "policy": phases[0]["policy"],
                    "phases": declaration, "public_fairness_qualified": False, "production_qualified": False,
                    "work_hardness_qualified": False, "installation_authorized": False}
        view_phases = [dict(p, schema=pressure.SCHEMA) for p in phases]
        semantics = pressure.check(manifest, common, view_phases)
        nested = actor.check(manifest, common, view_phases, sidecars, cost_bindings, captured)
        actor_processes = process.check_process_directory(directory / "native", nested, {p["phase"]: p for p in phases})
        cleanup = result["cleanup"]
        require(cleanup["schema"] == "pon-fixed-parent-cleanup-v1" and cleanup["attempted"] is True
                and cleanup["complete"] is True and cleanup["error"] is None
                and cleanup["forced_kernel_kill"] is False
                and cleanup["foreign_or_replaced_objects_touched"] is False, "owned-unit cleanup incomplete")
        cleaned = kernel_snapshot(cleanup["before"], expected)
        require(previous_after["ended_monotonic_ns"] <= cleanup["before"]["started_monotonic_ns"],
                "cleanup preceded final receiver observation")
        require(previous_after["ended_monotonic_ns"] <= stops[0]["started_monotonic_ns"],
                "fixture stop preceded final phase observation")
        require(all(cleaned[scope][key] >= a[scope][key] for scope in ("parent", "leaf")
                    for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")),
                "cleanup counters rewound")
        require(cleanup["manager_before"] == expected["manager_identity"], "cleanup unit identity changed")
        throttled = any(p["kernel_throttling_observed"] for p in host_phases)
        costs = all(r["cpu_observed"] and r["descendants_quiescent_observed"] for r in reports)
        costs &= actor_processes["cpu_observation_complete"] and actor_processes["descendants_quiescent_observed"]
        costs &= nested["cpu_observation_complete"]
        return {"schema": SCHEMA, "input_consistent": True, "parent_byte_bindings_verified": True,
                "host_fixture_qualified": bool(throttled and costs), "kernel_throttling_observed": throttled,
                "receiver_membership_observed": True, "capability_lifetime_observed": True,
                "cost_observation_complete": bool(costs), "common_preparation_sha256": common_hash,
                "honest_service_qualified": all(p["service_qualified"] for p in semantics["phases"]),
                "unchanged_paid_depletion_qualified": all(p["pressure_and_depletion_qualified"] for p in semantics["phases"]),
                "unchanged_full_finite_predicate": semantics["finite_qualification"],
                "host_phases": host_phases, "service_phases": semantics["phases"], "receiver_processes": reports,
                "actor_process_phases": actor_processes["phases"], "actor_preparation_phases": nested["phases"],
                "prior_failure": fixture.PRIOR_FAILURE, "physical_authentication": False,
                "public_fairness_qualified": False, "production_qualified": False, "work_hardness_qualified": False,
                "original_campaign_qualification": False, "installation_authorized": False,
                "scope": "New fixed-parent fixture only. Three independent external phase controllers, one unchanged parent and leaf, original 30s/2s/24-actor profile. Host correctness does not require or imply honest-service or paid-depletion qualification.",
                "cost_scope": "Kernel intervals include receiver migration-through-exit and descendants. Fork/pre-migration work remains outside that cgroup and inside wait4. Controller preparation, clients, actors, sampling and root observation are outside. Nested totals are not added; memory/task counters are point samples."}
    finally:
        os.close(held)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-host-fixture", action="store_true")
    parser.add_argument("--require-service", action="store_true")
    parser.add_argument("--require-paid-depletion", action="store_true")
    args = parser.parse_args()
    try:
        result = check_directory(args.directory)
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        result = {"schema": SCHEMA, "input_consistent": False, "host_fixture_qualified": False,
                  "honest_service_qualified": False, "unchanged_paid_depletion_qualified": False,
                  "unchanged_full_finite_predicate": False, "original_campaign_qualification": False,
                  "error": str(error), "prior_failure": fixture.PRIOR_FAILURE,
                  "physical_authentication": False, "production_qualified": False, "public_fairness_qualified": False}
    raw = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x") as output:
            output.write(raw)
    print(raw, end="")
    success = result["input_consistent"]
    success &= not args.require_host_fixture or result["host_fixture_qualified"]
    success &= not args.require_service or result["honest_service_qualified"]
    success &= not args.require_paid_depletion or result["unchanged_paid_depletion_qualified"]
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
