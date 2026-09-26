#!/usr/bin/env python3
"""Controlled orchestration regressions: no network, signing or LAN evidence."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import tomllib
import types
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import plan_topology as planner
import run_fault_restart_fleet_v1 as fleet
import run_fault_restart_fleet_v1_test as fixtures

SUMMARY = "poco_fault_selection_v1_test=passed closed_selections=3 default_all_unchanged=true pre_effect_rejection=true controlled_execute=true exact_fault_labels=true source_anchor=true reduced_resources=true external_lease=true mac_paths=true fixture_only=true fault_matrix_completed=false"


def reject(action, text):
    try:
        action()
    except (ValueError, RuntimeError, SystemExit) as error:
        assert text in str(error), str(error)
    else:
        raise AssertionError("negative control unexpectedly passed")


def topology_and_processes(root, placement):
    with (HERE / "inventory.toml").open("rb") as source:
        inventory = tomllib.load(source)
    topology = planner.build_topology(inventory, 7, "equal", placement)
    routes = {host["host_id"]: host["management"] for host in topology["participants"]}
    aliases = {validator_id: f"v{index:03d}" for index, validator_id in enumerate(sorted(row["validator_id"] for row in topology["validators"]))}
    rows = [fleet.base.ValidatorProcess(
        validator_id=row["validator_id"], host_id=row["host_id"], management=routes[row["host_id"]],
        deployment=root / row["validator_id"],
        config_relative=pathlib.PurePosixPath(f"public/configs/{row['validator_id']}.json"),
        runtime_alias=aliases[row["validator_id"]],
    ) for index, row in enumerate(topology["validators"])]
    return topology, rows


def terminal_rows(processes):
    # This is a mocked Mac verifier boundary. Real crypto remains required by
    # collect_terminal_evidence; these values only exercise runner control flow.
    return [{
        "validator_id": row.validator_id, "host_id": row.host_id, "restarted": False,
        "fleet_start_certificate_sha256": "41" * 32,
        "observer_final_state_verification": {
            "finalized_height": 9, "finalized_ordinary_block_count": 6,
            "finalized_block_id": "42" * 32, "finalized_state_root": "43" * 32,
            "finalized_chain_root": "44" * 32,
        },
        "observer_fleet_start_certificate_verification": {
            "selected_validator_id": row.validator_id, "validator_count": 7,
            "fleet_start_certificate_sha256": "41" * 32,
            "fleet_start_certificate_digest": "45" * 32,
            "ready_set_sha256": "46" * 32, "context_sha256": "47" * 32,
        },
    } for row in processes]


def test_exact_raw_fault_join():
    verified = fixtures.journal_summary(False, 1)
    fields = ("run_id", "validator_id", "coordinator_manifest_sha256", "candidate_source_sha256",
              "binary_sha256", "config_sha256", "validator_set_sha256")
    events = []
    for index, (kind, subject) in enumerate([
        ("fault_applied", "leader_loss"), ("fault_recovered", "leader_loss"), ("clean_stop", "")
    ]):
        events.append({**{field: verified[field] for field in fields}, "sequence": index,
                       "kind": kind, "subject": subject, "event_sha256": "51" * 32})
    verified.update(event_count=3, runtime_event_sequence=2, runtime_event_sha256="51" * 32)
    encode = lambda rows: b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    fleet.exact_selected_journal_faults_v1(encode(events), verified, {"leader_loss"})
    for mutate, reason in [
        (lambda rows: rows[0].update(subject="host_loss"), "unexpected"),
        (lambda rows: rows[1].update(subject="asymmetric_partition"), "unmatched"),
        (lambda rows: rows[1].update(kind="proposal"), "labels/tip"),
        (lambda rows: rows[1].update(kind="fault_applied"), "duplicate"),
        (lambda rows: rows[0].update(candidate_source_sha256="52" * 32), "identity/sequence"),
        (lambda rows: rows[-1].update(event_sha256="53" * 32), "labels/tip"),
    ]:
        rows = copy.deepcopy(events)
        mutate(rows)
        reject(lambda: fleet.exact_selected_journal_faults_v1(encode(rows), verified, {"leader_loss"}), reason)


def test_control_pre_start():
    status = fixtures.status()
    for phase, ready in (("preparing", ""), ("ready", "54" * 32)):
        value = fixtures.response(status, nonce=1, verb="status")
        value.update(barrier_phase=phase, fleet_ready_set_sha256=ready, fleet_start_certificate_sha256="")
        fleet.exact_response(value, status=status, nonce=1, verb="status", allow_pre_start=True)
        reject(lambda: fleet.exact_response(value, status=status, nonce=1, verb="status"), "exact context")
        reject(lambda: fleet.exact_response(value, status=status, nonce=1, verb="expect_fault", allow_pre_start=True), "only available")
    value["fleet_start_certificate_sha256"] = "55" * 32
    reject(lambda: fleet.exact_response(value, status=status, nonce=1, verb="status", allow_pre_start=True), "exact context")


def test_launch_and_mac_paths(root):
    processes = fixtures.processes()
    for process in processes[:2]:  # Actual local and SSH argv builders.
        stage = fleet.base.HostStage(process.host_id, process.management,
                                    "/tmp/tp3-0123456789abcdef0123", None)
        capture_root = root / process.host_id
        capture_root.mkdir()
        calls = []
        with mock.patch.object(fleet.subprocess, "Popen", lambda argv, **kwargs: calls.append(argv) or object()):
            runtime = fleet.launch_runtime(
                process=process, stage=stage, binary="/tmp/tp3-0123456789abcdef0123/bin/validator",
                duration_seconds=120, max_blocks=8, process_io=capture_root, process_instance=1,
                peer_lease_socket="/tmp/tp3-0123456789abcdef0123/bin/peer-lease.sock",
            )
        try:
            rendered = " ".join(calls[0])
            assert "--peer-lease-socket /tmp/tp3-0123456789abcdef0123/bin/peer-lease.sock" in rendered
            if stage.remote:
                assert calls[0][0] == "ssh" and 'if wait "$child"' in rendered
        finally:
            fleet.base.close_process_capture(runtime.capture)
    stage = fleet.base.HostStage("mac", "p4-mac", "/tmp/tp3-0123456789abcdef0123", None)
    calls = []
    def command(arguments, **kwargs):
        calls.append(arguments)
        return types.SimpleNamespace(stdout=b"{}\n")
    with mock.patch.object(fleet, "run_file_backed", command):
        fleet.observer_verify(
            process=processes[0], source=root / "journal.jsonl", kind="runtime-journal",
            mac_binary="/tmp/tp3-0123456789abcdef0123/bin/validator",
            observer_root="/tmp/tp3-0123456789abcdef0123/observer-public", observer_stage=stage,
            coordinator_anchor="31" * 32, run_id="fixture", io_root=root, label="fixture",
        )
    assert calls[0][0] == "scp" and ":/private/tmp/tp3-" in calls[0][-1]
    assert calls[1][-1].startswith("chmod 600 /private/tmp/tp3-")
    assert "verify-runtime-journal" in calls[2][-1] and "/private/tmp/tp3-" in calls[2][-1]


def exercise(root, campaign="connectivity", failure=None, mutate_plan=None, placement=None):
    root.mkdir()
    placement = placement or fleet.base.REDUCED_PLACEMENT
    topology, processes = topology_and_processes(root, placement)
    manifest = {"run_id": "poco-g3-7-20260814T000000Z-deadbeef", "candidate": {
        "source_tree_sha256": "31" * 32, "linux_x86_64_sha256": "32" * 32,
        "macos_arm64_sha256": "33" * 32,
    }}
    (root / "manifest.json").write_bytes(fleet.base.canonical_json(manifest))
    anchor = fleet.consensus.checked_coordinator_anchor(root, fleet.base.sha256_file(root / "manifest.json"))
    driver = root / "driver.py"
    # Actual bounded child executable emits COMMAND data only. No event/signature
    # is created here. All simulated runtime observations use explicit mocks.
    driver.write_text("#!/usr/bin/env python3\nimport json,sys\na=dict(zip(sys.argv[1::2],sys.argv[2::2]))\nprint(json.dumps(dict(schema_version=1,phase=a['--phase'],kind=a['--kind'],target_validator_id=a['--target-validator-id'],status=('applied' if a['--phase']=='apply' else 'restored'),effect_id='61'*32,production_activation=False),separators=(',',':')))\n")
    driver.chmod(0o700)
    plan = fleet.campaign_plan(
        manifest=manifest, processes=processes, coordinator_anchor=anchor.sha256,
        driver_sha256=fleet.base.sha256_file(driver), duration_seconds=120, max_blocks=8,
        fault_window_seconds=2, campaign=campaign, topology=topology,
    )
    original_plan = copy.deepcopy(plan)
    if mutate_plan:
        mutate_plan(plan)
    output = root / "output"
    stages = fleet.base.preflight_runtime_layout(processes, manifest["run_id"], output)
    calls = []
    timestamps = iter(f"2026-09-22T00:00:{second:02d}Z" for second in range(10))
    state = {row.validator_id: {"expected": "", "active": set(), "recovered": set()} for row in processes}
    original_driver = fleet.invoke_fault_driver

    def probe(rows, count, *, placement_profile):
        assert rows == processes and count == 7 and placement_profile == placement
        calls.append("resources")
        return {"fixture_only": True, "placement_profile": placement_profile}

    def create(stage_plan, **kwargs):
        calls.append("stages")
        return stage_plan

    def lease(*args):
        calls.append("leases-start")
        return ({host: types.SimpleNamespace(socket=f"{stage.root}/bin/peer-lease.sock") for host, stage in stages.items() if host != "mac"}, ["fixture-daemon"])

    def launch(**kwargs):
        assert kwargs["peer_lease_socket"] == f"{stages[kwargs['process'].host_id].root}/bin/peer-lease.sock"
        calls.append("launch")
        return types.SimpleNamespace(process=kwargs["process"])

    def locator(**kwargs):
        value = fixtures.status()
        value.update(validator_id=kwargs["process"].validator_id, run_id=manifest["run_id"])
        return value

    def control(**kwargs):
        record = state[kwargs["process"].validator_id]
        verb, kind = kwargs["verb"], kwargs["fault"]
        if verb == "expect_fault":
            assert calls.count("started") == 7
            record["expected"] = kind
        elif verb == "clear_fault_expectation":
            assert kind in record["recovered"]
            record["expected"] = ""
        elif kwargs.get("allow_pre_start"):
            calls.append("started")
        value = fixtures.response(kwargs["status"], nonce=kwargs["nonce"], verb=verb,
                                  expected_fault=record["expected"], active=sorted(record["active"]), recovered=sorted(record["recovered"]))
        if failure == "halted" and verb == "status" and record["expected"]:
            value["safety_halted"] = True
        return fleet.exact_response(value, status=kwargs["status"], nonce=kwargs["nonce"], verb=verb, allow_pre_start=kwargs.get("allow_pre_start", False))

    def invoke(**kwargs):
        result = original_driver(**kwargs)
        kind, phase = kwargs["step"].kind, kwargs["phase"]
        calls.append(f"driver:{phase}:{kind}")
        record = state[kwargs["process"].validator_id]
        if failure == "restore" and phase == "restore":
            raise RuntimeError("controlled restoration failure")
        if phase == "apply":
            record["active"].add(kind)
            if failure == "partial-apply":
                raise RuntimeError("controlled partial apply failure")
        else:
            record["active"].discard(kind)
            record["recovered"].add(kind)
            if failure == "effect-mismatch":
                result[0]["effect_id"] = "62" * 32
        return result

    def collect(**kwargs):
        assert kwargs["restarted_validator_id"] is None
        selected = fleet.selected_fault_plan(processes, campaign)
        for process in processes:
            assert kwargs["expected_faults"][process.validator_id] == {step.kind for step in selected if step.target_validator_id == process.validator_id}
        calls.append("mac-collect-seven")
        if failure == "signature":
            raise RuntimeError("controlled Mac signature rejection")
        results = terminal_rows(processes)
        if failure == "divergence":
            results[-1]["observer_final_state_verification"]["finalized_block_id"] = "71" * 32
        return results

    with contextlib.ExitStack() as stack:
        for owner, name, replacement in (
            (fleet, "utc_now", lambda: next(timestamps)),
            (fleet.mesh_resources, "preflight_mesh_fleet_resources_v1", probe),
            (fleet.base, "create_stages", create),
            (fleet.base, "deploy", lambda *a: ({host: "/fixture/validator" for host in stages if host != "mac"}, "/fixture/mac-validator", f"{stages['mac'].root}/observer-public")),
            (fleet.consensus, "start_peer_lease_daemons", lease),
            (fleet.consensus, "stop_peer_lease_daemons", lambda daemons: calls.append("leases-stop") or []),
            (fleet, "launch_runtime", launch), (fleet, "wait_control_status", locator),
            (fleet, "send_control", control), (fleet, "invoke_fault_driver", invoke),
            (fleet, "collect_terminal_evidence", collect),
            (fleet, "stop_runtime", lambda runtime: calls.append("validator-stop")),
            (fleet.base, "clean_stages", lambda stages: calls.append("stages-clean") or []),
        ):
            stack.enter_context(mock.patch.object(owner, name, replacement))
        args = dict(coordinator=root, deployments=root, manifest=manifest, processes=processes,
                    linux_binary=driver, macos_binary=driver, fault_driver=driver, output=output,
                    duration_seconds=120, max_blocks=8, fault_window_seconds=2, plan=plan, stage_plan=stages,
                    campaign=campaign, topology=topology, anchor_snapshot=anchor)
        if campaign == "all":
            reject(lambda: fleet.execute_campaign(**args), "no fault effect was applied")
            assert calls == [] and not output.exists()
            return
        if mutate_plan:
            reject(lambda: fleet.execute_campaign(**args), "plan differs")
            assert calls == [] and not output.exists()
            return
        with contextlib.redirect_stdout(io.StringIO()):
            if failure:
                reject(lambda: fleet.execute_campaign(**args), "campaign failed")
            else:
                fleet.execute_campaign(**args)
    summary = json.loads((output / "fault-restart-run-summary.json").read_bytes())
    assert summary["selected_campaign_completed"] is (failure is None)
    assert summary["restart_count"] == 0 and summary["restarted_validator_id"] is None
    assert summary["candidate"] == manifest["candidate"] and summary["coordinator_manifest_sha256"] == anchor.sha256
    assert summary["fault_order"] == list(fleet.fault_semantics.campaign_faults(campaign))
    assert summary["profile"] == fleet.SELECTED_PROFILE and summary["schema_version"] == 2
    for field in ("fault_restart_profile_completed", "fault_matrix_completed", "validator_run_completed", "g3_lan_multihost_evidence", "production_activation", "performance_evidence", "whole_host_failure_tolerance"):
        assert summary[field] is False
    assert calls.index("resources") < calls.index("stages") < calls.index("leases-start") < calls.index("launch")
    assert calls[-9:] == ["validator-stop"] * 7 + ["leases-stop", "stages-clean"]
    assert summary["prestart_plan_sha256"] == fleet.base.sha256_file(output / "prestart-plan.json")
    if placement == fleet.base.REDUCED_PLACEMENT:
        assert summary["validator_host_allocations"] == {"desktop": 4, "rog": 3}
        assert summary["linux_validator_host_count"] == 2
    if failure is None:
        assert summary["participant_host_count"] == summary["planned_participant_host_count"]
        assert len(summary["validators"]) == 7
        assert len(summary["faults"]) == len(original_plan["fault_order"])
        for fault in summary["faults"]:
            schedules = list((output / "faults").glob(f"*-{fault['kind']}.schedule.json"))
            assert len(schedules) == 1 and fleet.base.sha256_file(schedules[0]) == fault["schedule_sha256"]
    else:
        assert summary["failure"] or summary["cleanup_failures"]
        if failure in {"partial-apply", "halted", "effect-mismatch"}:
            assert "driver:restore:leader_loss" in calls
    return calls


def main():
    test_exact_raw_fault_join()
    test_control_pre_start()
    legacy = fleet.campaign_plan(
        manifest={"run_id": "poco-g3-7-20260814T000000Z-deadbeef"}, processes=fixtures.processes(),
        coordinator_anchor="31" * 32, driver_sha256="32" * 32,
        duration_seconds=16, max_blocks=3, fault_window_seconds=2,
    )
    # Generated from committed09cc94d2 before this change; no Git/network needed.
    assert hashlib.sha256(fleet.base.canonical_json(legacy)).hexdigest() == "240c710abb05f9648b6765b93e6fe56453207a81d357d653dc5e29078fa496e9"
    for name in ("", "host_loss", "validator_process_kill", "leader_loss,asymmetric_partition", "ALL", "full", "bounded_delay_loss"):
        reject(lambda: fleet.fault_semantics.campaign_faults(name), "unknown closed")
    reject(fleet.fault_semantics.require_bundle_assembly_supported, "fail-closed")
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        test_launch_and_mac_paths(root)
        for name in ("all", "leader_loss", "asymmetric_partition", "connectivity"):
            exercise(root / name, name)
        exercise(root / "canonical", "connectivity", placement=fleet.base.CANONICAL_PLACEMENT)
        for failure in ("halted", "restore", "signature", "divergence", "partial-apply", "effect-mismatch"):
            exercise(root / failure, failure=failure)
        for index, mutate in enumerate((
            lambda plan: plan.update(campaign="leader_loss"),
            lambda plan: plan.update(fault_matrix_completed=True),
            lambda plan: plan.update(restart_count=False),
            lambda plan: plan["fault_order"][0].update(target_host_id="local"),
            lambda plan: plan["candidate"].update(source_tree_sha256="99" * 32),
        )):
            exercise(root / f"mutant-{index}", mutate_plan=mutate)
    print(SUMMARY)


if __name__ == "__main__":
    main()
