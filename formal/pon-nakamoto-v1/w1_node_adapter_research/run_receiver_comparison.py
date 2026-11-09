#!/usr/bin/env python3
"""Eight benign, fresh-process native / proof-plus-native receiver observations.

The fixed order is NPPN twice for ONE retained packet and existing proof pair.
No proof is generated. Each receiver gets a new Node directory. The proof arm
uses the existing durable proof-start owner and unchanged native admission.
Owner provisioning/status are measured separately, never hidden in the samples.

This Linux-only standard-library harness measures fork through wait4, including
the same pre-exec kernel observation in both arms. It does not measure network
transport, a fresh prover, a live service, adversarial load, or production I/O.
Its PASS, if any, is only a complete, source-stable local receiver comparison.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import time


SCHEMA = "trnm-w1-local-receiver-comparison-v1"
ORDER = tuple("NPPNNPPN")
PHASES = {
    "N": (
        "output_directory_create", "native_input_read_binding", "node_open_recovery",
        "node_current_context_and_before_observation", "native_admission",
        "native_activation", "native_readback",
    ),
    "P": (
        "proof_start_owner_open_and_reserve", "output_directory_create",
        "proof_input_read_binding", "proof_bundle_persistence", "complete_proof_verification",
        "node_open_recovery", "node_before_observation", "node_admission_activation_readback",
        "post_admission_readback", "proof_start_owner_snapshot",
    ),
}
LIMIT_FILES = (
    "cpu.max", "cpu.max.burst", "memory.max", "memory.swap.max",
    "pids.max", "cpuset.cpus.effective",
)
OBSERVATION_FILES = (
    "cpu.stat", "memory.current", "memory.peak", "memory.events",
    "memory.swap.current", "pids.current", "pids.peak",
)
PUBLIC_BYTES = 377_290
QUALIFICATION = "HOLD_NO_GO"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("non-finite JSON value: " + value)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def read_optional(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def kernel_snapshot():
    """Read the caller's real cgroup and every visible ancestor, without edits."""
    result = {
        "monotonic_ns": time.monotonic_ns(), "unix_ns": time.time_ns(),
        "pid": os.getpid(), "affinity": sorted(os.sched_getaffinity(0)),
        "loadavg": read_optional("/proc/loadavg"),
        "cpu_pressure": read_optional("/proc/pressure/cpu"),
        "memory_pressure": read_optional("/proc/pressure/memory"),
        "cgroup_text": read_optional("/proc/self/cgroup"),
        "cgroup_relative": None, "lineage": [], "errors": [],
    }
    try:
        text = result["cgroup_text"]
        require(text is not None, "missing /proc/self/cgroup")
        rows = [line[3:] for line in text.splitlines() if line.startswith("0::")]
        require(len(rows) == 1, "one cgroup-v2 membership required")
        relative = rows[0]
        require(relative.startswith("/") and ".." not in Path(relative).parts,
                "cgroup path is not visible within this namespace")
        root = Path("/sys/fs/cgroup").resolve(strict=True)
        current = (root / relative.lstrip("/")).resolve(strict=True)
        require(current == root or root in current.parents, "cgroup mount boundary")
        result["cgroup_relative"] = relative
        while True:
            result["lineage"].append({
                "path": str(current),
                "limits": {name: read_optional(current / name) for name in LIMIT_FILES},
                "observations": {
                    name: read_optional(current / name) for name in OBSERVATION_FILES
                },
            })
            if current == root:
                break
            current = current.parent
        for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max"):
            require(result["lineage"][0]["limits"][name] is not None,
                    "missing kernel readback: " + name)
    except (OSError, ValueError) as error:
        result["errors"].append(str(error))
    return result


def resource_signature(snapshot):
    require(isinstance(snapshot, dict) and not snapshot.get("errors"),
            "kernel readback is incomplete")
    require(snapshot.get("cgroup_relative") is not None and snapshot.get("lineage"),
            "kernel membership is missing")
    return {
        "cgroup_relative": snapshot["cgroup_relative"],
        "affinity": snapshot["affinity"],
        "lineage": [{"path": row["path"], "limits": row["limits"]}
                    for row in snapshot["lineage"]],
    }


def source_snapshot(repo, binary, inputs):
    adapter = Path(__file__).resolve().parent
    backend = adapter.parent / "w1_public_stark_research"
    sources = {Path(__file__).resolve(), adapter / "tests/test_receiver_comparison.py"}
    for crate in (adapter, backend):
        sources.update((crate / "src").rglob("*.rs"))
        sources.update((crate / "Cargo.toml", crate / "Cargo.lock"))
    diff = subprocess.check_output(
        ["git", "diff", "--no-ext-diff", "HEAD", "--binary"], cwd=repo)
    return {
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "tracked_diff_is_empty": not diff,
        "source_scope": "adapter and proof-backend Rust/Cargo plus comparison harness/tests; "
                        "complete source/dependency qualification is separate",
        "source_files": {str(path.relative_to(repo)): sha(path) for path in sorted(sources)},
        "binary": {"path": str(binary), "sha256": sha(binary)},
        "inputs": {name: {"path": str(path), "bytes": path.stat().st_size,
                          "sha256": sha(path)} for name, path in sorted(inputs.items())},
    }


def final_receipt(path):
    require(path.stat().st_size <= 1_048_576, "stdout exceeds receipt parsing bound")
    lines = [line for line in path.read_text().splitlines() if line.strip()]
    require(bool(lines), "no final stdout receipt")
    value = strict_json(lines[-1])
    require(isinstance(value, dict) and isinstance(value.get("result"), dict),
            "final stdout receipt has no result object")
    require(valid_number(value.get("outer_seconds")), "invalid Rust outer_seconds")
    return value


def valid_number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def kill_owned_child(pid):
    """Only for this harness's forked child, before wait4 releases its PID."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        # A deadline can fire before the child reaches setsid(). Its unreaped
        # PID is still ours, so terminate that child instead of waiting forever
        # for a process group which does not yet exist.
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def measure(argv, directory, env, cwd, timeout_seconds):
    """Direct fork/exec with exact child's wait4 rusage and retained raw streams."""
    require(valid_number(timeout_seconds) and timeout_seconds > 0,
            "positive finite child timeout required")
    directory.mkdir(parents=True, exist_ok=False)
    before = kernel_snapshot()
    stdout_path, stderr_path = directory / "stdout.jsonl", directory / "stderr.txt"
    child_readback = directory / "child-before-exec.json"
    started_ns = time.monotonic_ns()
    started_unix_ns = time.time_ns()
    timed_out = False
    timeout_request_ns = None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                os.dup2(stdout.fileno(), 1)
                os.dup2(stderr.fileno(), 2)
                os.chdir(cwd)
                snapshot = kernel_snapshot()
                snapshot["before_exec_monotonic_ns"] = time.monotonic_ns()
                save(child_readback, snapshot)
                os.execve(str(argv[0]), [str(value) for value in argv], env)
            except BaseException as error:
                os.write(2, ("harness child setup/exec error: " + repr(error) + "\n").encode())
                os._exit(127)

        def alarm_handler(_signum, _frame):
            nonlocal timed_out, timeout_request_ns
            timed_out = True
            timeout_request_ns = time.monotonic_ns()
            kill_owned_child(pid)

        previous_handler = signal.signal(signal.SIGALRM, alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
        try:
            waited, status, usage = os.wait4(pid, 0)
            require(waited == pid, "wait4 returned a different process")
        except BaseException:
            # The measured child has its own session. Do not orphan it when the
            # controller itself is interrupted while waiting.
            kill_owned_child(pid)
            try:
                os.wait4(pid, 0)
            except ChildProcessError:
                pass
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
    ended_ns = time.monotonic_ns()
    after = kernel_snapshot()
    record = {
        "argv": [str(value) for value in argv], "pid": pid,
        "started_unix_ns": started_unix_ns,
        "started_monotonic_ns": started_ns, "ended_monotonic_ns": ended_ns,
        "wall_seconds": (ended_ns - started_ns) / 1e9,
        "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
        "cpu_seconds": usage.ru_utime + usage.ru_stime,
        "peak_rss_kib": usage.ru_maxrss,
        "input_blocks": usage.ru_inblock, "output_blocks": usage.ru_oublock,
        "exit_code": os.waitstatus_to_exitcode(status), "timed_out": timed_out,
        "timeout_seconds": timeout_seconds, "timeout_request_monotonic_ns": timeout_request_ns,
        "timeout_cleanup_seconds": ((ended_ns - timeout_request_ns) / 1e9
                                    if timeout_request_ns is not None else None),
        "measurement_boundary": "fork through wait4, including same pre-exec kernel "
                                "readback, exec, receiver, and process teardown",
        "kernel_before": before, "kernel_after": after,
        "kernel_child_before_exec": None, "child_readback_error": None,
        "stdout": {"path": str(stdout_path), "bytes": stdout_path.stat().st_size,
                   "sha256": sha(stdout_path)},
        "stderr": {"path": str(stderr_path), "bytes": stderr_path.stat().st_size,
                   "sha256": sha(stderr_path)},
        "receipt": None, "receipt_error": None,
    }
    try:
        record["kernel_child_before_exec"] = strict_json(child_readback.read_text())
    except (OSError, ValueError) as error:
        record["child_readback_error"] = str(error)
    try:
        record["receipt"] = final_receipt(stdout_path)
    except (OSError, ValueError) as error:
        record["receipt_error"] = str(error)
    save(directory / "measurement.json", record)
    return record


def check_process(record):
    require(record.get("exit_code") == 0 and record.get("timed_out") is False,
            "process did not complete successfully")
    require(record.get("receipt_error") is None and isinstance(record.get("receipt"), dict),
            "missing complete process receipt")
    require(valid_number(record["receipt"].get("outer_seconds")), "invalid Rust outer_seconds")
    for field in ("wall_seconds", "user_seconds", "system_seconds", "cpu_seconds", "peak_rss_kib"):
        require(valid_number(record.get(field)), "invalid process metric: " + field)


def validate_receiver(row, plan):
    errors = []
    try:
        require(row.get("fresh_output_directory") is True, "receiver directory was not fresh")
        record = row["measurement"]
        check_process(record)
        result = record["receipt"]["result"]
        require(result.get("qualification") == QUALIFICATION
                and result.get("production_activation") is False, "qualification changed")
        require(result.get("input_identity") == plan["input_identity"], "input identity changed")
        metrics = result.get("metrics", {})
        variant = row["variant"]
        require(variant in ("N", "P"), "unknown receiver arm")
        require(metrics.get("schema") == "trnm-w1-receiver-metrics-v1", "receiver metrics schema")
        require(metrics.get("mode") == ("native" if variant == "N" else "proof-plus-native"),
                "receiver metrics mode")
        require(metrics.get("payload_bytes") == plan["application_payload_bytes"][variant],
                "receiver application payload differs from actual file lengths")
        require(metrics.get("phases_are_disjoint") is True, "receiver phase accounting")
        phases = metrics.get("phases")
        require(isinstance(phases, list) and phases, "receiver phase observations missing")
        require(tuple(phase.get("stage") for phase in phases) == PHASES[variant],
                "receiver phase roster is missing, duplicated, or reordered")
        require(all(phase.get("outcome") == "ok" and valid_number(phase.get("wall_seconds"))
                    for phase in phases), "incomplete receiver phase")
        phase_seconds = math.fsum(phase["wall_seconds"] for phase in phases)
        rust_seconds = record["receipt"]["outer_seconds"]
        # One microsecond only covers floating-point/clock representation. Event
        # output, final serialization, fsync and teardown remain paid overhead;
        # disjoint stage totals are deliberately not equated with process time.
        require(phase_seconds <= rust_seconds + 0.000001,
                "disjoint phases exceed Rust process clock")
        require(rust_seconds <= record["wall_seconds"] + 0.000001,
                "Rust process clock exceeds external process clock")
        if variant == "N":
            require(result.get("schema") == "trnm-w1-node-native-admit-v1", "native receipt schema")
            outcome = result
            require(outcome.get("both_real_proofs_verified") is False, "native arm claims proof checks")
        else:
            require(result.get("schema") == "trnm-w1-node-adapter-exercise-v2", "proof receipt schema")
            require(result.get("error") is None and isinstance(result.get("outcome"), dict),
                    "exercise exit zero is not proof admission success")
            require(result.get("requested_cancellation") == "none", "unexpected cancellation")
            outcome = result["outcome"]
            require(outcome.get("schema") == "trnm-w1-node-adapter-admission-v3", "admission receipt schema")
            require(outcome.get("both_real_proofs_verified") is True, "both real proofs not verified")
            proof_start = result.get("proof_start", {})
            require(proof_start.get("slot") == row["expected_proof_slot"]
                    and proof_start.get("purpose") == "admission"
                    and proof_start.get("reserved_before_work") is True,
                    "durable proof start not charged")
            require(outcome.get("proof_start") == proof_start, "proof reservation mismatch")
            owner = result.get("proof_start_owner_snapshot") or {}
            require(owner.get("occupied_slots") == row["expected_proof_slot"]
                    and result.get("proof_start_owner_snapshot_error") is None,
                    "proof-start owner observation missing or inconsistent")
        require(result.get("node_opened") is True, "Node was not opened")
        require(outcome.get("native_admitted") is True
                and outcome.get("native_admission_path_invoked") is True,
                "original native admission did not succeed")
        require(outcome.get("activation_requested") is True
                and outcome.get("activation_error") is None
                and outcome.get("late_cancellation") is None, "activation did not complete")
        require(outcome.get("active_before") == plan["genesis"]
                and outcome.get("generation_before") == 0, "Node was not at fresh genesis")
        observation = outcome.get("native_observation") or {}
        require(observation.get("stored_exact") is True
                and observation.get("active_chain_member") is True
                and outcome.get("native_observation_error") is None,
                "current exact packet admission/activation not observed")
        require(isinstance(outcome.get("block"), str) and len(outcome["block"]) == 64,
                "native block identity missing")
        require(valid_number(outcome.get("native_admission_seconds")), "missing native admission timing")
    except (KeyError, TypeError, ValueError) as error:
        errors.append(str(error))
    return errors


def summarize(manifest):
    """Recompute from every planned observation; never select only successful rows."""
    errors = list(manifest.get("fatal_errors", []))
    plan = manifest["plan"]
    rows = manifest["receivers"]
    expected_order = [{"index": index, "variant": variant} for index, variant in enumerate(ORDER)]
    if plan.get("planned_order") != expected_order:
        errors.append("planned order is not the fixed eight-run NPPNNPPN contract")
    if [{"index": row.get("index"), "variant": row.get("variant")} for row in rows] != expected_order:
        errors.append("planned receiver attempts are missing, duplicated, or reordered")
    for row in rows:
        errors.extend("receiver %s: %s" % (row.get("index"), error)
                      for error in validate_receiver(row, plan))
    if manifest.get("source_before") is None or manifest.get("source_before") != manifest.get("source_after"):
        errors.append("source, binary, harness, or inputs changed / final source capture missing")
    provision = manifest.get("owner_init")
    status = manifest.get("owner_status")
    for label, record, expected_slots in (("owner-init", provision, 0), ("owner-status", status, 4)):
        try:
            require(isinstance(record, dict), "owner observation missing")
            check_process(record)
            value = record["receipt"]["result"]
            owner = value.get("owner", {})
            require(value.get("qualification") == QUALIFICATION
                    and value.get("production_activation") is False, "owner qualification changed")
            require(owner.get("occupied_slots") == expected_slots
                    and owner.get("maximum_starts") == 4
                    and owner.get("exhausted") is (expected_slots == 4), "owner charge count")
            require(owner.get("owner_id") == plan["proof_start_policy"]["owner_id"], "owner identity changed")
        except (KeyError, TypeError, ValueError) as error:
            errors.append(label + ": " + str(error))
    resource_errors = []
    signatures = []
    for row in rows:
        try:
            record = row["measurement"]
            for field in ("kernel_before", "kernel_child_before_exec", "kernel_after"):
                signature = resource_signature(record[field])
                signatures.append(signature)
                leaf = signature["lineage"][0]["limits"]
                for name, expected in plan.get("expected_kernel_limits", {}).items():
                    require(leaf.get(name) == expected, "requested kernel readback differs: " + name)
                require(signature["affinity"] == plan["cpu_affinity"], "CPU affinity changed")
        except (KeyError, TypeError, ValueError) as error:
            resource_errors.append("receiver %s: %s" % (row.get("index"), error))
    if len(signatures) != 24 or any(value != signatures[0] for value in signatures[1:]):
        resource_errors.append("all before/child/after resource signatures must match")
    errors.extend(resource_errors)
    blocks = set()
    for row in rows:
        if not validate_receiver(row, plan):
            value = row["measurement"]["receipt"]["result"]
            blocks.add(value["block"] if row["variant"] == "N" else value["outcome"]["block"])
    if len(blocks) != 1:
        errors.append("receiver arms did not confirm exactly the same native block")
    medians = None
    changes = None
    if not errors:
        medians = {}
        for variant in ("N", "P"):
            selected = [row["measurement"] for row in rows if row["variant"] == variant]
            medians[variant] = {name: statistics.median(row[name] for row in selected)
                                for name in ("wall_seconds", "user_seconds", "system_seconds",
                                             "cpu_seconds", "peak_rss_kib")}
            medians[variant]["application_payload_bytes"] = plan["application_payload_bytes"][variant]
            medians[variant]["fresh_receiver_processes"] = len(selected)
        changes = {}
        for name in ("wall_seconds", "cpu_seconds", "peak_rss_kib", "application_payload_bytes"):
            native, proof = medians["N"][name], medians["P"][name]
            changes[name] = {"proof_minus_native": proof - native,
                             "change_percent": 100 * (proof / native - 1) if native > 0 else None}
    return {
        "schema": SCHEMA,
        "local_receiver_comparison": "PASS" if not errors else "INCOMPLETE_OR_INCOMPARABLE",
        "errors": errors, "planned_receiver_processes": 8,
        "recorded_receiver_processes": len(rows), "new_complete_proofs": 0,
        "distinct_input_tasks": 1, "existing_proof_replays_planned": 4,
        "owner_provisioning_and_status_separately_measured": True,
        "owner_costs": {label: ({key: record.get(key) for key in
                         ("wall_seconds", "user_seconds", "system_seconds", "cpu_seconds", "peak_rss_kib")}
                         if isinstance(record, dict) else None)
                       for label, record in (("provisioning", provision), ("final_status", status))},
        "medians": medians, "proof_vs_native_observed_changes": changes,
        "median_scope": "whole receiver processes; never sums of phase medians",
        "os_caches_flushed": False, "host_exclusive": False,
        "network_transport_measured": False, "fresh_prover_cost_measured": False,
        "end_to_end_benefit": "NOT_MEASURED", "receiver_count_break_even": None,
        "production_service_qualification": "NOT_ESTABLISHED",
        "production_activation": False, "qualification": QUALIFICATION,
    }


def run(args):
    require(sys.platform.startswith("linux"), "Linux wait4 / cgroup-v2 harness required")
    require(valid_number(args.timeout_seconds) and args.timeout_seconds > 0, "positive finite timeout required")
    require(args.rayon_threads > 0 and args.cpu_count > 0, "positive thread/CPU counts required")
    repo = args.repo.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    fixture, proof = args.fixture.resolve(strict=True), args.proof.resolve(strict=True)
    require(len(args.expected_binary_sha256) == 64
            and sha(binary) == args.expected_binary_sha256, "expected binary hash mismatch")
    available = sorted(os.sched_getaffinity(0))
    require(len(available) >= args.cpu_count, "insufficient allowed CPU affinities")
    cpus = available[:args.cpu_count]
    os.sched_setaffinity(0, cpus)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    output = args.output.resolve(strict=True)
    inputs = {
        "packet": fixture / "packet.bin", "statement": fixture / "statement.bin",
        "operator_plan": fixture / "operator-plan.json", "sha_proof": proof / "sha.proof.bin",
        "arithmetic_proof": proof / "arith.proof.bin",
    }
    if args.source_receipt is not None:
        inputs["external_source_receipt"] = args.source_receipt.resolve(strict=True)
    operator = strict_json(inputs["operator_plan"].read_text())
    policy = {
        "schema": "trnm-w1-proof-start-owner-policy-v1",
        "owner_id": hashlib.sha256(b"trnm-w1-receiver-comparison-owner-v1\0" + str(output).encode()).hexdigest(),
        "profile": operator["profile"], "network": operator["network"],
        "parameters": operator["parameters"], "genesis": operator["genesis"], "maximum_starts": 4,
    }
    policy_path, owner_path = output / "independent-owner-policy.json", output / "proof-start-owner"
    save(policy_path, policy)
    inputs["owner_policy"] = policy_path
    packet_bytes = inputs["packet"].stat().st_size
    require(inputs["statement"].stat().st_size == PUBLIC_BYTES, "unexpected complete statement length")
    plan = {
        "schema": SCHEMA, "planned_order": [{"index": i, "variant": v} for i, v in enumerate(ORDER)],
        "binary": str(binary), "expected_binary_sha256": args.expected_binary_sha256,
        "input_identity": {"packet_sha256": sha(inputs["packet"]),
                           "operator_plan_sha256": sha(inputs["operator_plan"]), "packet_bytes": packet_bytes},
        "application_payload_bytes": {
            "N": packet_bytes,
            "P": sum(inputs[name].stat().st_size for name in
                     ("packet", "statement", "sha_proof", "arithmetic_proof")),
        },
        "payload_scope": "actual application input files; proof arm retains the native packet; "
                         "independent operator plan/policy are provisioned separately; no measured network framing",
        "shared_operator_plan_bytes": inputs["operator_plan"].stat().st_size,
        "genesis": operator["genesis"], "proof_start_policy": policy,
        "cpu_affinity": cpus, "rayon_num_threads": args.rayon_threads,
        "expected_kernel_limits": {name: value for name, value in (
            ("cpu.max", args.expected_cpu_max), ("memory.max", args.expected_memory_max),
            ("memory.swap.max", args.expected_memory_swap_max), ("pids.max", args.expected_pids_max),
        ) if value is not None},
        "per_process_timeout_seconds": args.timeout_seconds,
        "platform": platform.platform(), "python_version": platform.python_version(),
        "fresh_node_directories": True, "new_complete_proofs": 0,
        "distinct_input_tasks": 1, "network_transport_measured": False,
        "fresh_prover_cost_measured": False, "production_activation": False,
        "qualification": QUALIFICATION,
    }
    manifest = {"plan": plan, "source_before": None, "source_after": None,
                "owner_init": None, "owner_status": None, "receivers": [], "fatal_errors": []}
    save(output / "plan.json", plan)
    save(output / "manifest.json", manifest)
    env = dict(os.environ, RAYON_NUM_THREADS=str(args.rayon_threads))
    try:
        manifest["source_before"] = source_snapshot(repo, binary, inputs)
        save(output / "manifest.json", manifest)
        manifest["owner_init"] = measure(
            [binary, "owner-init", policy_path, owner_path], output / "owner-init",
            env, repo, args.timeout_seconds)
        save(output / "manifest.json", manifest)
        check_process(manifest["owner_init"])
        slot = 0
        for index, variant in enumerate(ORDER):
            receiver_output = output / ("receiver-%02d-%s" % (index, variant))
            require(not os.path.lexists(receiver_output), "receiver output path already exists")
            if variant == "N":
                argv = [binary, "native-admit", fixture, receiver_output]
            else:
                slot += 1
                argv = [binary, "exercise", fixture, proof, receiver_output, "none", owner_path, policy_path]
            record = measure(argv, output / ("process-%02d-%s" % (index, variant)),
                             env, repo, args.timeout_seconds)
            row = {"index": index, "variant": variant, "fresh_output_directory": True,
                   "output_directory": str(receiver_output), "expected_proof_slot": slot if variant == "P" else None,
                   "measurement": record}
            row["validation_errors"] = validate_receiver(row, plan)
            manifest["receivers"].append(row)
            save(output / "manifest.json", manifest)
            print(json.dumps({"index": index, "variant": variant, "wall_seconds": record["wall_seconds"],
                              "cpu_seconds": record["cpu_seconds"], "exit_code": record["exit_code"],
                              "errors": row["validation_errors"]}), flush=True)
        manifest["owner_status"] = measure(
            [binary, "owner-status", policy_path, owner_path], output / "owner-status",
            env, repo, args.timeout_seconds)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        manifest["fatal_errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        try:
            manifest["source_after"] = source_snapshot(repo, binary, inputs)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            manifest["fatal_errors"].append("final source capture: " + str(error))
        save(output / "manifest.json", manifest)
        summary = summarize(manifest)
        summary["manifest_sha256"] = sha(output / "manifest.json")
        save(output / "summary.json", summary)
    print(json.dumps(summary, allow_nan=False), flush=True)
    return 0 if summary["local_receiver_comparison"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "binary", "fixture", "proof", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument("--cpu-count", type=int, default=8)
    parser.add_argument("--rayon-threads", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--expected-cpu-max")
    parser.add_argument("--expected-memory-max")
    parser.add_argument("--expected-memory-swap-max")
    parser.add_argument("--expected-pids-max")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
