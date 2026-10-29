#!/usr/bin/env python3
"""Read actual owner-death evidence; synthetic controls never qualify a native run."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re

from read_native_history_verifier import (
    COUNTERS, LIMITS, PARENT, digest, integer, native_hash, parent_identity, read, require,
)

SMALL_PREFIX = "history_verifier::lifeline::linux::tests::"
SMALL_METHODS = (
    "prequeued_capability_survives_exec_and_allows_normal_exit",
    "eof_terminates_helper_while_controller_process_is_still_alive",
    "actual_owner_death_terminates_all_threads_despite_retained_stream_peer",
    "already_dead_owner_is_refused_before_the_scope_starts",
    "wrong_or_missing_kernel_descriptor_refuses_before_scope",
    "unexpected_data_after_arming_cannot_keep_the_helper_running",
)
CASES = (
    ("after-node-open-before-seed", "controller_death_after_actual_node_open_removes_verifier"),
    ("after-public-import-before-response", "controller_death_after_actual_public_import_removes_verifier"),
    ("after-node-close-before-report", "controller_death_after_run_return_before_report_removes_verifier"),
)
NATIVE_PREFIX = "history_verifier::lifeline_native::"
TOTAL_SECONDS = 600
SMALL_SECONDS = 60
CASE_SECONDS = 180
DEATH_NS = 5_000_000_000


def hash_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "retained regular file required")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def text_file(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            "bounded retained text required")
    raw = path.read_bytes()
    require(len(raw) <= maximum, "retained text grew past bound")
    return raw.decode("utf-8")


def absent(path):
    require(not os.path.lexists(path), "forbidden post-boundary output exists: " + str(path))


def source_identity(value, head, tree):
    require(value["schema"] == "trnm-ci-source-v1" and value["kind"] == "head"
            and value["tested_commit"] == value["candidate"] == head
            and value["tested_tree"] == tree
            and value["base"] is None and value["prospective_merge"] is None
            and value["tracked_worktree_verified"] is True
            and value["tests_executed_by_identity_check"] is False,
            "exact fully verified candidate source required")
    require(integer(value["tracked_entries"]) > 0 and integer(value["tracked_bytes"]) > 0,
            "full original tracked-byte observation required")


def baseline_binary(directory, head, tree):
    """Reuse an actual release build even if its separate original campaign failed."""
    directory = Path(directory)
    record, _ = read(directory / "binary-before.json")
    sources = [read(directory / name)[0] for name in
               ("source-before-build.json", "source-before-campaigns.json")]
    for source in sources:
        source_identity(source, head, tree)
    require(sources[0] == sources[1], "build and retained executable source differ")
    profile = record["actual_compiler_artifact_profile"]
    require(profile["opt_level"] == "3" and profile["debug_assertions"] is False
            and profile["test"] is True, "actual optimized release test artifact required")
    require(record["retained"] == "public_v3_multiprocess.bin"
            and record["build_separate_from_measured_campaign"] is True,
            "the original retained campaign executable required")
    binary = directory / record["retained"]
    require(integer(record["bytes"]) > 0 and binary.stat().st_size == record["bytes"]
            and hash_file(binary) == digest(record["sha256_before"]),
            "original ELF bytes and SHA256 differ")
    require(os.access(binary, os.X_OK), "retained test ELF must already be executable")
    with binary.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "actual retained Linux ELF required")
    build, _ = read(directory / "build.step.json")
    validate_step(directory, build, "build", maximum=1800)
    rows = []
    import json
    for line in text_file(directory / build["stdout"]).splitlines():
        row = json.loads(line)
        if (row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == "public_v3_multiprocess"
                and row.get("profile", {}).get("test") is True and row.get("executable")):
            rows.append(row)
    require(len(rows) == 1 and rows[0]["profile"] == profile
            and rows[0]["executable"] == record["build_artifact"],
            "retained binary must bind to the one actual compiler artifact")
    result, _ = read(directory / "results.json")
    # All selected campaigns retain the same actual compiler-artifact target. This permits
    # independent strict owner-death controls after either campaign failed;
    # it never transfers the campaign's result or the N8 execution policy.
    profiles = {
        "pon-original-native-campaign-ci-v1": (
            "strict-every-native-checkpoint-v1",
            "separate_process_work_and_signed_confirmation_campaign"),
        "pon-history-graph-resource-fence-campaign-ci-v1": (
            "history-account-graph-resource-fence-v1",
            "separate_process_graph_resource_fence_v1_work_and_signed_confirmation_campaign"),
    }
    if result["schema"] == "pon-pure-history-raw-joint-ci-v1":
        pure_selectors = {
            "strict-every-native-checkpoint-v1":
                "separate_process_pure_history_raw_strict_campaign",
            "history-account-graph-resource-fence-v1":
                "separate_process_pure_history_raw_graph_fence_campaign",
        }
        selected = result.get("history_resource_profile")
        require(selected in pure_selectors, "explicit pure History resource profile required")
        require(result.get("work_profile") == "pure-history-raw-v1"
                and type(result.get("admission_search_budget")) is int
                and result["admission_search_budget"] == 0
                and result.get("expected_public_policy_id") ==
                    "bf409dae237253a2ce14152c54198ed06e824e709763946e9c84e68e894eee58",
                "exact zero-search raw History source required")
        profiles[result["schema"]] = (selected, pure_selectors[selected])
    require(result["schema"] in profiles, "recognized actual campaign source observation required")
    expected_profile, expected_selector = profiles[result["schema"]]
    expected_fields = {
        "history_resource_profile": expected_profile, "native_selector": expected_selector,
        "strict_profile_result_is_separate": True,
    }
    # The original strict schema predates these profile fields. Preserve its
    # existing build-reader contract; if supplied, their values cannot conflict.
    required = result["schema"] != "pon-original-native-campaign-ci-v1"
    require(all((not required and key not in result)
                or (result.get(key) == value and type(result.get(key)) is type(value))
                for key, value in expected_fields.items()),
            "exact campaign profile and selector required; strict lifeline remains separate")
    require(result["expected_head"] == head and result["expected_tree"] == tree
            and result["profile"] == "release" and result["toolchain"] == "1.95.0"
            and result["binary"]["sha256_before"] == record["sha256_before"]
            and result["binary"]["sha256_after"] == record["sha256_before"]
            and result["binary"]["bytes"] == record["bytes"],
            "original final source/binary observation required")
    source_identity(result["source_after"], head, tree)
    return binary, record


def validate_step(directory, step, name, maximum):
    require(step["name"] == name and step["returncode"] == 0 and step["error"] is None
            and step["complete_success"] is True
            and step["stdout_truncated"] is False and step["stderr_truncated"] is False,
            "actual untruncated successful command required")
    require(type(step["outer_stage_timeout_seconds"]) in (int, float)
            and 0 < step["outer_stage_timeout_seconds"] <= maximum,
            "original command deadline may not increase")
    integer(step["elapsed_ns"])
    for channel in ("stdout", "stderr"):
        filename = step[channel]
        require(type(filename) is str and Path(filename).name == filename,
                "one local exact command stream required")
        path = Path(directory) / filename
        require(path.stat().st_size == integer(step[channel + "_bytes"])
                and hash_file(path) == digest(step[channel + "_sha256"]),
                "actual command raw stream hash/size mismatch")


def test_terminal(log, selectors, ignored):
    actual = re.findall(r"^test ([^\n]+?) \.\.\. ([^\n]+)$", log, re.M)
    require(all(status == "ok" or status == "ignored" or status.startswith("ignored, ")
                for _, status in actual), "failed or unknown actual test outcome refused")
    passed = [name for name, status in actual if status == "ok"]
    skipped = [name for name, status in actual if status.startswith("ignored")]
    require(set(passed) == set(selectors) and len(passed) == len(selectors)
            and set(skipped) == set(ignored) and len(skipped) == len(ignored),
            "exact native method roster and outcomes required")
    terminal = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out;[^\n]*$", log, re.M)
    require(len(terminal) == 1 and tuple(map(int, terminal[0][:4]))
            == (len(selectors), 0, len(ignored), 0),
            "one exact native completion terminal required")


def validate_roster(listed, ignored):
    expected = {SMALL_PREFIX + name for name in SMALL_METHODS} | {SMALL_PREFIX + "helper_entry"}
    def names(value):
        rows = re.findall(r"^(.+): test$", value, re.M)
        require(len(rows) == len(set(rows)), "duplicate listed test")
        return set(rows)
    require(names(listed) == expected
            and names(ignored) == {SMALL_PREFIX + "helper_entry"},
            "six required methods and one parent-driven helper required")


def validate_small(directory, log):
    test_terminal(log, [SMALL_PREFIX + name for name in SMALL_METHODS],
                  [SMALL_PREFIX + "helper_entry"])
    modes = ("normal", "eof", "owner-death", "already-dead", "unexpected-data",
             "regular-file-right", "missing-right", "ordinary-stdin", "multiple-rights",
             "truncated-rights", "wrong-preface", "named-socket")
    found = {}
    for path in Path(directory).iterdir():
        require(path.is_dir() and not path.is_symlink(), "real retained small-control directory")
        matches = [mode for mode in modes if re.fullmatch(
            r"history-lifeline-" + re.escape(mode) + r"-[1-9][0-9]*-[1-9][0-9]*-[0-9]+", path.name)]
        require(len(matches) == 1 and matches[0] not in found, "one actual small control per mode")
        found[matches[0]] = path
        absent(path / "late-worker-side-effect")
    require(set(found) == set(modes), "all actual small-control observations required")
    for mode in ("normal", "eof", "owner-death", "unexpected-data"):
        owner, _ = read(found[mode] / "entered-scope")
        require(set(owner) == {"peer_pid", "peer_uid", "peer_gid"}
                and integer(owner["peer_pid"]) > 1, "actual armed peer observation required")
        for field in ("peer_uid", "peer_gid"):
            require(integer(owner[field]) <= 0xffffffff, "actual peer credential required")
    require("watcher remains armed" in text_file(found["normal"] / "normal-return"),
            "normal return must retain whole-process watch")
    for mode in ("eof", "owner-death", "unexpected-data"):
        text_file(found[mode] / "watch-ready")
        text_file(found[mode] / "termination-trigger")
    for mode in modes[3:]:
        if mode != "unexpected-data":
            absent(found[mode] / "entered-scope")
    for mode in ("owner-death", "already-dead"):
        require(text_file(found[mode] / "controller-ready") == "prequeued-self-pidfd\n",
                "actual brokered self-pidfd controller required")
    for mode in modes:
        text_file(found[mode] / ("normal.log" if mode == "normal" else "watch.log"))
    require("named or abstract owner listener refused" in text_file(found["named-socket"] / "watch.log"),
            "named endpoint must fail at the actual anonymous-capability boundary")
    text_file(found["named-socket"] / "actual-named-socket")
    for mode in ("multiple-rights", "truncated-rights", "wrong-preface"):
        require("one exact prequeued pidfd capability required" in text_file(found[mode] / "watch.log"),
                "actual ancillary/preface rejection required")
    return {"required_methods": 6, "parent_driven_helpers": 1, "actual_control_modes": list(modes),
            "raw_controls_read": True, "systemd_node_qualification": False}


def validate_case(directory, stage, binary_sha256, outer_cgroup):
    require(stage in {item[0] for item in CASES}, "explicit native boundary required")
    directory = Path(directory)
    verifier = directory / "verifier"
    files = {}
    def get(path):
        value, value_sha = read(directory / path)
        files[path] = value_sha
        return value
    result = get("result.json")
    before = get("before-owner-death.json")
    control = get("control.json")
    cleanup = get("cleanup.json")
    launch = get("verifier/launch.json")
    job = get("verifier/job.json")
    boundary = get("verifier/owner-death-boundary.json")
    digest(binary_sha256)
    require(result["schema"] == "native-history-owner-death-result-v1"
            and control["schema"] == "native-history-owner-death-control-v1"
            and boundary["schema"] == "native-history-owner-death-boundary-v1"
            and launch["schema"] == "native-history-verifier-launch-v1",
            "exact native owner-death schemas required")
    require(all(item["stage"] == stage for item in (result, control, boundary))
            and job["owner_death_control"] == launch["owner_death_control"] == stage,
            "actual requested boundary must match every record")
    require(all(item["binary_sha256"] == binary_sha256
                for item in (result, before, control, launch, job, boundary)),
            "all actual observations must bind the executed ELF")
    owner = job["controller_observation"]
    require(type(owner) is dict and set(owner) == {"pid", "uid", "gid"}, "exact owner observation")
    controller = integer(owner["pid"])
    actor = integer(result["actor_pid"])
    require(controller > 1 and actor > 1 and actor != controller
            and all(integer(owner[key]) <= 0xffffffff for key in ("uid", "gid")),
            "actual distinct process and credential observations required")
    require(result["controller_pid"] == before["controller_pid"] == launch["controller_pid"] == controller
            and before["actor_pid"] == boundary["pid"] == actor
            and boundary["controller_observation"] == owner,
            "actual controller, actor and boundary observations must agree")
    unit = result["unit"]
    require(type(unit) is str and re.fullmatch(
        r"trnm-campaign-verifier-" + str(controller) + r"-[1-9][0-9]*\.service", unit),
        "only the actual owned verifier unit may be observed or cleaned")
    cgroup = "/trnmponpublic.slice/" + unit
    require(type(outer_cgroup) is str and outer_cgroup.startswith("/")
            and not outer_cgroup.startswith("/trnmponpublic.slice")
            and launch["original_outer_cgroup"] == outer_cgroup,
            "original outer controller resource domain must remain separate")
    require(launch["unit"] == unit and launch["parent"] == job["parent"] == PARENT
            and boundary["cgroup"] == cgroup
            and launch["controller_capability_prequeued"] is True
            and launch["collect_on_exit"] is False
            and integer(launch["launcher_pid"]) > 1,
            "actual prequeued private capability and inspectable service required")
    require(launch["job_sha256"] == boundary["job_sha256"] == files["verifier/job.json"],
            "boundary/launch must bind exact original job bytes")
    require(before["launch"] == launch and before["boundary"] == boundary
            and result["actual_boundary"] == boundary
            and before["actual_systemd_unit"] == result["before"]
            and before["parent"] == result["parent_before_death"],
            "summary must reproduce the complete actual pre-death record")
    require(control["state_backend"] == job["backend"] == "authenticated-v1"
            and job["kind"] == "history-verifier" and job["seed"] == [],
            "separate real native control with zero synthetic seed packets")
    genesis, network, parameters = (digest(control[key]) for key in ("genesis", "network", "parameters"))
    require(result["controller_signal"] == 9
            and type(result["controller_signal"]) is int
            and result["completed_control"] is True
            and result["original_campaign_qualified"] is False
            and result["administrative_stop_before_observation"] is False
            and result["clean_completion_report_exists"] is False
            and integer(result["maximum_death_to_empty_ns"]) == DEATH_NS
            and 0 < integer(result["death_to_empty_ns"]) < DEATH_NS,
            "actual owned controller SIGKILL and bounded pre-cleanup self-exit required")
    pre, post = result["before"], result["after"]
    require(pre["LoadState"] == post["LoadState"] == "loaded"
            and pre["MainPID"] == str(actor) and pre["ActiveState"] == "active"
            and pre["ControlGroup"] == cgroup
            and post["MainPID"] == "0" and post["ActiveState"] == "failed"
            and post["ExecMainCode"] == "1" and post["ExecMainStatus"] == "137",
            "actual CLD_EXITED(137), not cleanup kill, timeout or panic required")
    points = [launch["parent_before_spawn"], boundary["parent"],
              result["parent_before_death"], result["parent_after_death"]]
    require(len({parent_identity(point) for point in points}) == 1,
            "same unchanged root-owned fixed parent required")
    require(points[0]["pids.current"] == 0
            and all(integer(point["pids.current"]) >= 2 for point in points[1:-1])
            and points[-1]["pids.current"] == 0,
            "actual watched helper threads then empty fixed parent before cleanup required")
    for older, newer in zip(points, points[1:]):
        require(all(older["cpu.stat"][key] <= newer["cpu.stat"][key] for key in COUNTERS),
                "actual parent counters must not rewind")
    require(points[-1]["cpu.stat"]["usage_usec"] > points[0]["cpu.stat"]["usage_usec"],
            "actual fixed-parent CPU consumption required")
    require(cleanup["schema"] == "native-history-owner-death-cleanup-v1"
            and cleanup["unit"] == unit
            and cleanup["assertions_completed_before_cleanup"] is True
            and cleanup["killed_owned_controller_during_cleanup"] is False,
            "cleanup may only follow the completed native death observation")
    require([command["action"] for command in cleanup["commands"]] == ["reset-failed"]
            and all(command["exit_success"] is True and "error" not in command
                    for command in cleanup["commands"]),
            "successful bounded cleanup of only the recorded unit required")
    absent(verifier / "report.json")
    absent(verifier / "report.pending")
    facts = boundary["facts"]
    requests = {path.name for path in verifier.glob("request-*.json")}
    responses = {path.name for path in verifier.glob("response-*.json")}
    if stage == CASES[0][0]:
        require(facts["actual_native_open_returned"] is True
                and native_hash(facts["active"][0]) == genesis
                and integer(facts["active"][1]) == 0 and len(facts["active"]) == 3,
                "actual original genesis Node open must precede death")
        absent(verifier / "ready.json")
        require(not requests and not responses, "pre-seed death cannot include completed IPC")
    else:
        ready = get("verifier/ready.json")
        require(ready["pid"] == actor and ready["binary_sha256"] == binary_sha256
                and ready["cgroup"] == cgroup and ready["calling_thread_cgroup"] == "0::" + cgroup
                and ready["public_host_kernel_checked"] is True and ready["wrong_parent_refused"] is True,
                "real original strict public host guard and thread membership required")
        line = ready["controller_lifeline"]
        require(line["schema"] == "native-history-controller-lifeline-v1"
                and line["controller"] == owner
                and line["capability"] == "anonymous-unix-stream+prequeued-self-pidfd"
                and line["armed_before_node_open"] is True and line["watch_until_process_exit"] is True,
                "same source-bound whole-process watch required")
        require(parent_identity(ready["parent"]) == parent_identity(points[0])
                and points[0]["cpu.stat"]["usage_usec"] <= ready["parent"]["cpu.stat"]["usage_usec"]
                <= points[1]["cpu.stat"]["usage_usec"]
                and integer(ready["setup_process_cpu_ns"]) > 0,
                "actual setup must precede the observed native death boundary")
        require(requests == {"request-000.json"}, "one actual pre-death operation required")
        request = get("verifier/request-000.json")
        require(type(request["sequence"]) is int and request["sequence"] == 0,
                "one exact native request sequence required")
        if stage == CASES[1][0]:
            original = get("original-packet.json")
            tip = digest(original["id"])
            require(facts["actual_strict_public_import_returned"] is True
                    and native_hash(facts["returned_value"]) == tip
                    and native_hash(facts["active"][0]) == tip
                    and integer(facts["active"][1]) == 1 and len(facts["active"]) == 3
                    and type(facts["sequence"]) is int and facts["sequence"] == 0
                    and facts["request_sha256"] == files["verifier/request-000.json"],
                    "actual strict public import and active native state required")
            require(request["operation"] == "import" and request["source"] == "127.0.0.1:1"
                    and native_hash(request["tip"]) == tip
                    and native_hash(request["after"]) == original["after"] == genesis,
                    "actual public import target and cursor required")
            page = request["page"]
            require(type(original["wire"]) is str and re.fullmatch(r"(?:[0-9a-f]{2})+", original["wire"])
                    and page["schema"] == "pon-native-history-v1"
                    and page["network"] == network and page["parameters"] == parameters
                    and page["genesis"] == page["after"] == genesis
                    and page["tip"] == page["next"] == tip
                    and page["packets"] == [original["wire"]] and page["complete"] is True,
                    "exact original admitted packet and native Page context required")
            require(not responses, "death occurred before the import response was published")
        else:
            require(all(facts[key] is True for key in
                        ("actual_node_close_returned", "actual_runner_returned", "clean_node_close"))
                    and facts["entry_schema"] == "native-public-history-verifier-entry-v2",
                    "real Node close and runner return before outer report required")
            require(request["operation"] == "finish" and responses == {"response-000.json"},
                    "actual ordinary finish response required")
            response = get("verifier/response-000.json")
            measurement = response["measurement"]
            require(response["sequence"] == measurement["sequence"] == 0
                    and type(response["sequence"]) is int and type(measurement["sequence"]) is int
                    and response["request_sha256"] == files["verifier/request-000.json"]
                    and response["binary_sha256"] == binary_sha256 and response["error"] is None
                    and response["value"]["closing_original_node"] is True
                    and measurement["process_id"] == actor
                    and measurement["thread_cpu_observation_available"] is True,
                    "exact actual finish measurement and response bytes required")
            for key in ("process_cpu_ns", "thread_cpu_ns", "process_wall_ns"):
                integer(measurement[key])
    for filename in ("controller.log", "verifier/actor.log"):
        text_file(directory / filename)
        files[filename] = hash_file(directory / filename)
    return {"stage": stage, "complete": True, "unit": unit, "controller_pid": controller,
            "actor_pid": actor, "death_to_empty_ns": result["death_to_empty_ns"],
            "actual_self_exit_before_admin_cleanup": True, "raw_files_sha256": files,
            "no_clean_settlement_fabricated": True, "original_campaign_qualified": False,
            "production_qualified": False}
