#!/usr/bin/env python3
"""Research owner-cancel observations around one real fresh W1 generation.

`start` launches the original target exactly once and returns only after a live
fixed r0vm is observed in the first new prove stage. That return is NOT proof
completion. The Rust owner must durably authorize cancellation separately.
`reconcile` performs no cancellation, dispatch, signing, payment or verification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

SCHEMA = "TRNM-W1-OWNER-CANCELLATION-RUNTIME1"
PLAN = "TRNM-W1-OWNER-CANCEL-PLAN1"


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("non-finite JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def plan(c):
    p = c.get("owner_cancellation")
    require(type(p) is dict and set(p) == {"schema", "authority", "trigger", "reason_sha256", "native_task_action"},
            "explicit complete owner cancellation plan required")
    require(p["schema"] == PLAN and p["authority"] == "development-owner-0"
            and p["trigger"] == "live-first-prove-r0vm"
            and p["native_task_action"] in ("retain-reserved", "cancel-reserved"), "owner cancellation plan")
    reason = p["reason_sha256"]
    require(type(reason) is str and len(reason) == 64 and reason != "0" * 64
            and all(x in "0123456789abcdef" for x in reason), "explicit nonzero cancellation reason")
    require(c.get("provider", {}).get("kind") != "kaggle-cli", "this cancellation entry owns a local child cgroup only")
    return p


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def process_state(target, selected):
    if selected.get("boot_id") != target.boot_id():
        return {"state": "UNKNOWN", "execution_terminal": False, "wait_reaped": None}
    try:
        current = target.process_identity(selected["pid"])
        raw = Path(f"/proc/{selected['pid']}/stat").read_text()
    except FileNotFoundError:
        return {"state": "ABSENT", "execution_terminal": True, "wait_reaped": None}
    except (OSError, ValueError, KeyError):
        return {"state": "UNKNOWN", "execution_terminal": False, "wait_reaped": None}
    if current != selected:
        return {"state": "ORIGINAL_IDENTITY_ABSENT", "execution_terminal": True, "wait_reaped": None}
    state = raw[raw.rfind(")") + 2:].split()[0]
    return {"state": "EXITED_UNREAPED" if state == "Z" else "PRESENT",
            "execution_terminal": state == "Z", "wait_reaped": False if state == "Z" else None}


def original_request(rt, target, c, path):
    request = rt.obj(path, 65536)
    require(request["operation"] == c["provider_operation"] and request["target_instance"] == c["target_instance"],
            "original operation or target changed")
    require(request["deadline_monotonic_ns"] == c["original_deadline_ns"]
            and request["clock_domain"] == target.clock_domain(c["target_instance"])
            and request["containment"] == "cgroup-v2", "original local deadline/containment changed")
    require(request["target_backend_sha256"] == c["target"]["sha256"], "original target source changed")
    return request


def live_first_prover(rt, target, c, request, group, expected_group):
    cp = Path(c["out"]) / "proof/checkpoint"
    manifest_path = cp / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = rt.obj(manifest_path)
    native = rt.obj(Path(c["out"]) / "native-winner/result.json")
    require(manifest["schema"] == "TRNM-W1-STAGED-PROOF2"
            and manifest["source_commit"] == c["expected_commit"]
            and manifest["input_sha256"] == native["input_sha256"]
            and manifest["runner_sha256"] == c["runner"]["sha256"]
            and manifest["r0vm_sha256"] == c["r0vm"]["sha256"]
            and manifest["guest_sha256"] == c["guest"]["sha256"]
            and manifest["image_id"] == c["image_id"], "actual prepared full execution changed")
    workers = request["proof_plan"]["segment_workers"]
    require(type(workers) is int and 1 <= workers <= 4, "original segment worker plan")
    label = "prove-0000" if workers == 1 else "prove-batch-0000"
    stage = Path(c["out"]) / "proof/controller" / label
    if not (stage / "declaration.json").is_file():
        return None
    require(not (stage / "result.json").exists(), "first expensive stage finished before a live prover was observed")
    declaration = rt.obj(stage / "declaration.json")
    argv = declaration["command"]
    base = [c["runner"]["path"], "--r0vm", c["r0vm"]["path"]]
    expected_argv = ([*base, "prove", str(cp), "1"] if workers == 1
                     else [*base, "prove-parallel", str(cp), str(workers), str(workers)])
    require(argv == expected_argv, "exact original new-segment dispatch required")
    observed = target.cgroup_observation(group, expected_group)
    runner = None
    for pid in observed["members"]:
        try:
            current_argv = [x.decode() for x in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if x]
            if current_argv == argv and rt.sha(f"/proc/{pid}/exe") == c["runner"]["sha256"]:
                runner = {"identity": target.process_identity(pid), "cmdline": current_argv,
                          "executable_sha256": c["runner"]["sha256"]}
                break
        except FileNotFoundError:
            continue
    if runner is None:
        return None
    for pid in observed["members"]:
        try:
            selected = target.process_identity(pid)
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if b"--port" not in command or b"--version" in command:
                continue
            if rt.sha(f"/proc/{pid}/exe") != c["r0vm"]["sha256"]:
                continue
            require(target.process_identity(pid) == selected, "observed prover PID identity changed")
            current_members = target.cgroup_observation(group, expected_group)
            require(pid in current_members["members"], "observed prover left original child cgroup")
            require(process_state(target, selected)["state"] == "PRESENT", "prover no longer live")
            require(target.process_identity(runner["identity"]["pid"]) == runner["identity"]
                    and process_state(target, runner["identity"])["state"] == "PRESENT", "original stage runner no longer live")
            require(rt.identity(pid)["parent"] == runner["identity"]["pid"], "r0vm is not the selected prove runner's child")
            affinity = sorted(os.sched_getaffinity(pid))
            require(set(affinity) <= set(request["cpus"]), "prover affinity escaped original request")
            return {"stage": label, "stage_declaration_path": str(stage / "declaration.json"),
                    "stage_declaration_sha256": rt.sha(stage / "declaration.json"),
                    "prepared_manifest_path": str(manifest_path), "prepared_manifest_sha256": rt.sha(manifest_path),
                    "prover_identity": selected, "prover_executable_sha256": c["r0vm"]["sha256"],
                    "prover_cmdline": [x.decode() for x in command if x], "prover_affinity": affinity,
                    "stage_runner": runner,
                    "child_cgroup": current_members, "observed_monotonic_ns": time.monotonic_ns(),
                    "full_proof_verified": False}
        except FileNotFoundError:
            continue
    return None


def start(rt, target, c, request_path, directory):
    rt.original(c)
    scope = rt.Scope(c)
    request = original_request(rt, target, c, request_path)
    require(request["cgroup_parent"] == str(scope.path), "target must belong to this original owner job")
    require(not (Path(c["out"]) / "proof").exists(), "fresh proof directory already exists")
    db, _ = target.open_db(c["target_root"], c["target_instance"], True)
    try:
        require(db.execute("SELECT count(*) FROM operations WHERE operation=? OR task_scope=?",
                           (request["operation"], request["task_scope"])).fetchone() == (0,),
                "existing operation is reconciliation-only, never a new trial")
    finally:
        db.close()
    args = SimpleNamespace(root=c["target_root"], target=c["target_instance"], request=str(request_path))
    dispatch = target.dispatch(args)
    rt.write_new(directory / "target-dispatch.json", dispatch)
    db, _ = target.open_db(c["target_root"], c["target_instance"], False)
    group = scope.path / ("trnm-w1-generation-" + request["operation"])
    selected_group = None
    try:
        while True:
            rt.original(c)
            row = target.read_operation(db, request["operation"])
            require(not row["cancel"] and row["result"] is None, "target stopped before explicit owner cancellation trigger")
            if row["worker"] is not None and group.is_dir():
                if selected_group is None:
                    selected_group = target.cgroup_identity(group)
                trigger = live_first_prover(rt, target, c, request, group, selected_group)
                if trigger is not None:
                    return {"original_job": row["worker"], "target_readback": target.public_readback(db, request["operation"], c["target_instance"]),
                            "target_request_sha256": row["request_sha256"], "target_request_raw_sha256": rt.sha(request_path),
                            "trigger": trigger, "parent_cgroup": {"path": str(scope.path), "identity": target.cgroup_identity(scope.path)},
                            "owner_identity": target.process_identity(os.getppid()), "scope_before_dispatch": scope.before,
                            "fresh_generation_started": True, "full_proof_verified": False,
                            "generation_operation_complete": False, "owned_generation_still_active": True,
                            "owner_cancel_performed": False, "new_complete_proofs": 0}
            time.sleep(.05)
    finally:
        db.close()


class ContinuingScope:
    """Read-only whole-owner observation, excluding only living caller ancestors.

    It deliberately permits the retained original worker to be present. Unknown
    other members remain in `remaining`; this reader never signals any process.
    """
    def __init__(self, rt, target, c, retained):
        self.rt = rt
        self.path = Path(retained["parent_cgroup"]["path"])
        require(target.cgroup_identity(self.path) == retained["parent_cgroup"]["identity"], "original parent cgroup replaced")
        membership = Path("/proc/self/cgroup").read_text().strip()
        require(membership.startswith("0::/") and "\n" not in membership, "current cgroup membership unknown")
        self.relative = membership[3:]
        require(self.path == Path("/sys/fs/cgroup") / self.relative.lstrip("/")
                and "/hepta-runtime-job-" in self.relative and self.relative.endswith(".service"), "reconcile must remain in original owner job")
        self.ancestors = {}
        pid = os.getpid()
        while pid > 0:
            current = rt.identity(pid)
            self.ancestors[pid] = current
            pid = current["parent"]
        owner = retained["owner_identity"]
        require(owner["pid"] in self.ancestors and target.process_identity(owner["pid"]) == owner,
                "original live Rust owner identity required for terminal handoff")
        self.expected_parent = retained["parent_cgroup"]["identity"]
        self.target = target

    def observe(self):
        observation = self.target.cgroup_observation(self.path, self.expected_parent)
        remaining = []
        for pid in observation["members"]:
            if pid in self.ancestors:
                require(self.rt.identity(pid) == self.ancestors[pid], "caller ancestor identity changed")
            else:
                remaining.append(self.rt.identity(pid))
        return {"parent_cgroup": observation, "excluded_live_caller_ancestors": list(self.ancestors.values()),
                "remaining_noncaller_members": remaining,
                "scope_empty_except_live_caller_ancestors": not remaining, "all_descendants_reaped": None}


def reconcile(rt, target, c, request_path, start_path, seconds):
    require(type(seconds) is int and 1 <= seconds <= 30, "bounded read-only reconciliation budget")
    retained = rt.obj(start_path)
    request = original_request(rt, target, c, request_path)
    require(retained["schema"] == SCHEMA and retained["phase"] == "start"
            and retained["config_sha256"] == rt.sha(c["_config_path"])
            and retained["operation"] == request["operation"]
            and retained["target_request_raw_sha256"] == rt.sha(request_path), "original start observation changed")
    scope = ContinuingScope(rt, target, c, retained)
    selected = retained["trigger"]["child_cgroup"]
    db, _ = target.open_db(c["target_root"], c["target_instance"], False)
    deadline = time.monotonic_ns() + seconds * 1_000_000_000
    last = {"operation": request["operation"], "original_job": retained["original_job"],
            "target_request_sha256": retained["target_request_sha256"],
            "target_request_raw_sha256": retained["target_request_raw_sha256"],
            "original_child_cgroup": selected,
            "read_only_observation_deadline_ns": deadline}
    try:
        while True:
            last["observation_started_monotonic_ns"] = time.monotonic_ns()
            row = target.read_operation(db, request["operation"])
            last["target"] = target.public_readback(db, request["operation"], c["target_instance"])
            require(row["worker"] == retained["original_job"] and row["request_sha256"] == retained["target_request_sha256"],
                    "original provider operation/job changed")
            observed_group = target.cgroup_observation(Path(selected["path"]), selected["identity"])
            last["child_cgroup"] = observed_group
            owner_scope = scope.observe()
            last["owner_scope"] = owner_scope
            worker = process_state(target, row["worker"]["identity"])
            last["original_worker"] = worker
            last["observation_completed_monotonic_ns"] = time.monotonic_ns()
            if (row["result"] is not None and worker["execution_terminal"] and observed_group["recursive_empty"]
                    and owner_scope["scope_empty_except_live_caller_ancestors"]):
                result = row["result"]
                require(row["cancel"] and result["sticky_cancel"] and result["cause"] == "cancelled"
                        and result["exit_code"] is not None and result["exit_code"] != 0
                        and result["command_success"] is False and result["all_owned_processes_terminal"] is True
                        and result["direct_child_reaped"] is True and result["resources"]["gpu_ns"] is None,
                        "original target did not observe the requested running-generation cancellation")
                return {"observation": last, "owner_cancel_performed": False, "cancellation_observed": True,
                        "original_target_execution_terminal": True, "all_descendants_reaped": None,
                        "gpu_ns": None, "resource_reservation_must_remain": True, "can_authorize_refund": False,
                        "generation_operation_complete": False, "full_proof_verified": False,
                        "read_only_observation_deadline_ns": deadline, "original_proof_deadline_renewed": False}
            require(time.monotonic_ns() < deadline, "original target terminal/recursive scope observation remains UNKNOWN")
            time.sleep(.05)
    except BaseException as exc:
        # Preserve the last actual observations, including partial reads, even
        # when a subsequent binding/terminal check fails. This is a snapshot,
        # never inferred cleanup or a synthesized successful target receipt.
        exc.owner_cancel_observation = last
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("start", "reconcile"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--start")
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    raw = Path(args.config).read_bytes()
    require(len(raw) <= 131072, "config bound")
    c = strict_json(raw)
    plan(c)
    runtime_path = Path(c["runtime"]["path"])
    require(runtime_path.is_absolute() and not runtime_path.is_symlink()
            and hashlib.sha256(runtime_path.read_bytes()).hexdigest() == c["runtime"]["sha256"],
            "runtime source pin before import")
    rt = module(c["runtime"]["path"], "owner_cancel_original_runtime")
    rt.pinned(c["runtime"])
    require(Path(rt.pinned(c["owner_cancel_runtime"])).resolve() == Path(__file__).resolve(), "cancel runtime source pin")
    require(c["original_boot_id"] == rt.boot(), "original controller boot changed; no clock rebasing")
    source = rt.source(c)
    target = rt.load_target(c)
    c["_config_path"] = args.config
    out = Path(args.out)
    require(out.is_absolute() and out.parent.is_dir(), "new absolute observation directory")
    out.mkdir(exist_ok=False)
    intent = {"schema": SCHEMA, "phase": args.phase, "config_sha256": hashlib.sha256(raw).hexdigest(),
              "operation": c["provider_operation"], "original_deadline_ns": c["original_deadline_ns"],
              "original_boot_id": c["original_boot_id"], "started_monotonic_ns": time.monotonic_ns(),
              "source": source, "can_authorize_payment": False, "new_complete_proofs": 0}
    rt.write_new(out / "intent.json", intent)
    try:
        if args.phase == "start":
            require(args.start is None, "start cannot import a previous execution")
            result = start(rt, target, c, args.request, out)
        else:
            require(args.start is not None, "retained original start observation required")
            result = reconcile(rt, target, c, args.request, args.start, args.seconds)
        require(rt.source(c) == source, "source changed during observation")
        result.update(intent, phase_observation_complete=True, completed_monotonic_ns=time.monotonic_ns(),
                      completion_timestamp_scope="pre-handoff observation; caller must record actual exit/ACK")
        rt.write_new(out / "result.json", result)
        print(json.dumps({"schema": SCHEMA, "phase": args.phase, "phase_observation_complete": True,
                          "generation_operation_complete": False, "new_complete_proofs": 0,
                          "can_authorize_payment": False}), flush=True)
    except BaseException as exc:
        rt.write_new(out / "failure.json", {**intent, "phase_observation_complete": False,
                     "error": f"{type(exc).__name__}: {exc}", "owner_cancel_performed": False,
                     "last_actual_observation": getattr(exc, "owner_cancel_observation", None),
                     "may_dispatch_again": False, "resource_reservation_must_remain": True})
        raise


if __name__ == "__main__":
    main()
