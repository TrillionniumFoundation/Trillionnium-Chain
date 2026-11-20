"""Independent readback of actual deadline/refusal controls, including failures."""
from pathlib import Path
import re
import signal
import sys

from scripts import w1_owned_process_collector_v1 as owned
from hia.platform.peer_lease_unix.readback import processes
from .contract import ROOT, HERE, capture, document, identity, need
from .readback import check_identity, file_identity

ACTUAL = {
    "test_actual_normal_owned_child": ("normal", 10),
    "test_actual_escaped_descendant_is_reaped": ("descendant", 10),
    "test_actual_escaped_descendant_times_out": ("deadline", 1),
    "test_actual_native_owner_times_out": ("native-blocked", 1),
    "test_actual_public_close_has_one_cleanup_window": ("public-close", 10),
    "test_actual_stopped_trace_child_cleanup": ("ptrace-cleanup", 10),
}


def actual_controls(root, output):
    root, output = Path(root), Path(output)
    result = {}
    for name, (mode, seconds) in ACTUAL.items():
        directory = root / name
        proc = directory / "processes/control"
        row = document(proc / "receipt.json")
        need(document(directory / "processes/stages.json") == [row]
             and row["name"] == "control" and row["cwd"] == str(ROOT)
             and row["wall_limit_seconds"] == seconds and row["cleanup_limit_seconds"] == 3
             and row["max_process_observations"] == 4096 and row["started"] is True
             and row["cleanup_errors"] == [], "Actual control process/limits changed")
        argv = [sys.executable, "-B", "-m", "hia.platform.peer_payload.qualification.control_worker",
                "--mode", mode, "--output", str(directory / "actual"),
                "--native", str(output / "native/payload-owner.elf")]
        specification = document(proc / "command.json")
        need(row["argv"] == specification["argv"] == argv and specification["cwd"] == str(ROOT)
             and set(specification["environment"]) == {"PATH"}, "Actual control command was substituted")
        check_identity(proc / "command.json", row["command"])
        check_identity(Path(specification["executable"]), specification["executable_identity"])
        for stream in ("stdout", "stderr"):
            check_identity(proc / (stream + ".raw"), row[stream])
            need(capture(proc / (stream + ".raw")) == capture(proc / "owned" / (stream + ".log")),
                 "Actual control raw output changed")
        check_identity(proc / "owned/intent.json", row["intent"])
        value = owned.read_result(proc / "owned", row["collector_exit_code"],
            observed_boot_id=row["original_boot_id"], observed_completed_monotonic_ns=row["observed_completed_monotonic_ns"],
            expected_intent_sha256=row["intent"]["sha256"])
        need(value == row["collector_readback"] and value["collector_wait_domain_reaped"] is True,
             "Actual control family was not independently reaped")
        intent = document(proc / "owned/intent.json")
        python = Path(sys.executable).resolve(strict=True)
        command = [str(python), "-B", "-m", "hia.platform.peer_lease_unix.process", "--execute",
                   str(proc / "command.json"), "--sha256", row["command"]["sha256"]]
        need(intent["original_deadline_monotonic_ns"] == row["original_deadline_monotonic_ns"]
             and intent["original_boot_id"] == row["original_boot_id"] and intent["command"] == command
             and intent["executable_sha256"] == file_identity(python)["sha256"]
             and intent["max_log_bytes_per_stream"] == 16 * 1024 * 1024
             and intent["cleanup_grace_seconds"] == 3 and intent["max_process_records"] == 4096,
             "Actual control renewed its deadline or cleanup budget")
        actual = document(directory / "actual/control.json")
        need(actual["mode"] == mode and actual["native"] == str(output / "native/payload-owner.elf")
             and actual["native_identity"] == file_identity(output / "native/payload-owner.elf")
             and actual["product_failure_claimed"] is False
             and type(actual["parent_pid"]) is int and actual["parent_pid"] > 0,
             "Control did not bind the actual native image or claims a product failure")
        need(type(row["elapsed_ns"]) is int and 0 < row["elapsed_ns"] <= (seconds + 3) * 1_000_000_000,
             "Actual control elapsed time is unbounded")
        if mode in {"deadline", "native-blocked"}:
            need(row["timed_out"] is True and row["failure"] is not None
                 and value["deadline_qualified"] is False and value["command_success"] is False
                 and value["result"]["cause"] == "original-deadline"
                 and actual["status"] == "EXPECTED_TIMEOUT_PENDING"
                 and not (directory / "actual/descendant-finished.json").exists(),
                 "An actual timeout was promoted to a successful run")
        else:
            processes(directory / "processes", [row])
        if mode in {"descendant", "deadline", "native-blocked"}:
            waits = value["result"]["wait4_records"]
            need(any(item["identity_before_reap"]["pid"] == actual["child_pid"] for item in waits),
                 "The control's actual descendant was not waited")
        if mode == "normal":
            need(actual["status"] == "PASS_ACTUAL_NORMAL" and actual["observer_injection"] is None
                 and capture(proc / "stdout.raw").startswith(b"actual-normal\n"), "Normal control did not actually execute")
        elif mode == "descendant":
            need(actual["status"] == "PASS_PARENT_EXIT_BEFORE_DESCENDANT"
                 and document(directory / "actual/descendant-finished.json") == {"pid": actual["child_pid"], "finished": True}
                 and b"actual-descendant-finished\n" in capture(proc / "stdout.raw"), "Escaped descendant never completed")
        elif mode == "native-blocked":
            need(actual["observer_injection"] == "hold-open-input-without-a-request"
                 and capture(directory / "actual/native.stdout.raw") == capture(directory / "actual/native.stderr.raw") == b"",
                 "Native blocking fixture emitted an unobserved response")
        elif mode == "public-close":
            receipt = document(directory / "actual/actual-public-child/process.json")
            need(actual["status"] == "PASS_ACTUAL_OBSERVER_FAILURE_RETAINED"
                 and actual["observer_injection"] == "suppress-stdin-EOF-before-public-close"
                 and actual["complete_failure_cleanup_claimed"] is False and actual["receipt"] == receipt
                 and receipt["timed_out"] is True and receipt["failure"] is not None
                 and receipt["cleanup_windows"] == 1 and receipt["cleanup_limit_seconds"] == 3
                 and type(receipt["cleanup_elapsed_ns"]) is int and 3_000_000_000 <= receipt["cleanup_elapsed_ns"] < 6_000_000_000,
                 "Public close renewed its exhausted three-second cleanup window")
            # A scheduling overrun remains an explicit failed cleanup receipt;
            # only the outer owned collector's complete family reap is success.
        elif mode == "ptrace-cleanup":
            trace = document(directory / "actual/trace/trace.json")
            check_identity(directory / "actual/trace/trace.json", actual["trace_identity"])
            cleanup = trace["supervisor_cleanup"]
            need(actual["status"] == "PASS_ACTUAL_STOPPED_CHILD_CLEANUP"
                 and actual["observer_injection"] == "after-actual-TRACEME-stop-before-PTRACE_SETOPTIONS"
                 and trace["status"] == "FAIL" and "deliberate-control-before-PTRACE_SETOPTIONS" in trace["failure"]
                 and trace["actions"] == [] and len(trace["events"]) == 1
                 and trace["events"][0]["kind"] == "initial-wait"
                 and cleanup["signal"] == "SIGKILL" and cleanup["windows"] == 1
                 and cleanup["limit_seconds"] == 3 and cleanup["complete"] is True
                 and type(cleanup["elapsed_ns"]) is int and 0 <= cleanup["elapsed_ns"] <= 3_000_000_000,
                 "Stopped-child failure cleanup was not actually observed")
        result[mode] = {"actual_status": actual["status"], "wall_limit_seconds": seconds,
                        "timed_out": row["timed_out"], "family_reaped": True,
                        "receipt": file_identity(proc / "receipt.json"),
                        "elapsed_ns": row["elapsed_ns"], "observer_injection": actual["observer_injection"]}
    for directory in root.iterdir():
        if directory.name in ACTUAL:
            continue
        refusal = document(directory / "refusal.json")
        need(refusal.get("status") == "PASS_ACTUAL_READER_REFUSAL"
             and refusal.get("execution_claimed") is False and type(refusal.get("error")) is str
             and type(refusal.get("required_error")) is str
             and re.search(refusal["required_error"], refusal["error"]),
             "Reader refusal evidence is absent or does not contain the intended rejection")
        if "input" in refusal:
            check_identity(directory / "mutated-input.json", refusal["input"])
    return result
