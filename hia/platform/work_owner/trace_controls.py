"""Adversarial observations against complete actual same-worker syscall traces."""
from __future__ import annotations
import hashlib
import lzma
from pathlib import Path
from .build import digest, need, write_json
from .native_io import decode
from .trace_audit import audit_trace, complete_calls, arguments, io_fields

def run_controls(text, stdin, stdout, output):
    output = Path(output); output.mkdir(mode=0o700)
    baseline = audit_trace(text, stdin, stdout)
    calls, signals, exits = complete_calls(text)
    need(not signals and not exits, "Use an actual -qq successful baseline without signal/exit decorations")
    header = decode(stdout)["header"]; main = header["main_tid"]; worker = header["worker_tid"]
    need(header["domain"] == 0, "Successful actual baseline required")
    lines = text.splitlines(True)
    birth = next(c for c in calls if c["name"] == "clone")
    death = next(c for c in calls if c["name"] == "exit")
    terminal = next(c for c in calls if c["name"] == "exit_group")
    def insert(number, value):
        return "".join(lines[:number]) + value + "".join(lines[number:])
    def replace(old, new):
        need(old in text and old != new, "Trace control did not alter an actual token")
        return text.replace(old, new, 1)
    def changed(call, old, new):
        need(call["start"] == call["end"], "Control needs a complete actual line")
        line = lines[call["start"] - 1]
        need(old in line, "Expected actual syscall token missing")
        return "".join(lines[:call["start"] - 1]) + line.replace(old, new, 1) + "".join(lines[call["end"]:])
    def remove(call):
        selected = {call["start"] - 1, call["end"] - 1}
        return "".join(line for i, line in enumerate(lines) if i not in selected)
    def alter_read(prefix, offset, value):
        call = next(c for c in calls if c["name"] == "read" and c["start"] == c["end"]
                    and c["value"] is not None and c["value"] > 0
                    and io_fields(c)[1].startswith(prefix))
        old_data = io_fields(call)[1]
        data = bytearray(old_data); data[offset] = value
        rendered = '"' + "".join("\\x" + format(b, "02x") for b in data) + '"'
        return changed(call, arguments(call["args"])[1], rendered)
    notice_w = f"{worker} +++ exited with 0 +++\n"
    notice_m = f"{main} +++ exited with 0 +++\n"
    rows = [
        ("baseline-no-notifications", text, stdout, True),
        ("optional-worker-notification", insert(death["end"], notice_w), stdout, True),
        ("optional-main-notification", text + notice_m, stdout, True),
        ("optional-both-notifications", insert(death["end"], notice_w) + notice_m, stdout, True),
        ("unknown-tid-notification", text + f"{max(main, worker) + 1000000} +++ exited with 0 +++\n", stdout, False),
        ("worker-notification-before-birth", insert(birth["start"] - 1, notice_w), stdout, False),
        ("main-notification-before-exit", insert(terminal["start"] - 1, notice_m), stdout, False),
        ("duplicate-worker-notification", insert(death["end"], notice_w * 2), stdout, False),
        ("wrong-worker-notification-code", insert(death["end"], notice_w.replace("with 0", "with 1")), stdout, False),
        ("worker-call-before-birth", insert(birth["start"] - 1, f"{worker} gettid() = {worker}\n"), stdout, False),
        ("worker-call-after-exit", insert(death["end"], f"{worker} gettid() = {worker}\n"), stdout, False),
        ("unknown-thread-syscall", text + f"{max(main, worker) + 1000000} gettid() = {max(main, worker) + 1000000}\n", stdout, False),
        ("main-observation-before-worker-exit", insert(death["start"] - 1, f"{main} gettid() = {main}\n"), stdout, False),
        ("remove-clear-tid-clone-flag", replace("|CLONE_CHILD_CLEARTID", ""), stdout, False),
        ("replace-clone-parent-tid", replace(f"parent_tid=[{worker}]", f"parent_tid=[{main}]"), stdout, False),
        ("join-private-instead-of-shared", replace(f"FUTEX_WAIT, {worker}, NULL", f"FUTEX_WAIT_PRIVATE, {worker}, NULL"), stdout, False),
        ("boot-read-byte-substitution", alter_read(b"boot-identity\n", 11, ord("x")), stdout, False),
        ("limit-read-byte-substitution", alter_read(b"25000 100000\n", 4, ord("1")), stdout, False),
        ("counter-read-byte-substitution", alter_read(b"usage_usec 10\n", 12, ord("1")), stdout, False),
        ("parent-open-loses-nofollow", replace("O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH", "O_RDONLY|O_CLOEXEC|O_PATH"), stdout, False),
        ("missing-actual-worker-exit", remove(death), stdout, False),
        ("output-byte-substitution", text, stdout[:-1] + bytes([stdout[-1] ^ 1]), False),
        ("main-call-after-terminal", text + f"{main} gettid() = {main}\n", stdout, False),
    ]
    clock = next(c for c in calls if c["tid"] == worker and c["name"] == "clock_gettime" and c["start"] == c["end"])
    rows.append(("worker-wrong-clock", changed(clock, "CLOCK_MONOTONIC", "CLOCK_THREAD_CPUTIME_ID"), stdout, False))
    read = next(c for c in calls if c["tid"] == worker and c["name"] == "read"
                and c["start"] == c["end"] and c["value"] == 0)
    rows.append(("remove-resource-eof", remove(read), stdout, False))
    rows.append(("extra-resource-eof", insert(read["end"], lines[read["start"] - 1]), stdout, False))
    # PID field padding is a strace rendering detail. Neither spelling is a
    # different worker identity or a reason to drop otherwise complete calls.
    import re
    padded = re.sub(r"^(\d+)\s+", r"\1  ", text, flags=re.M)
    rows.append(("two-space-pid-rendering", padded, stdout, True))
    observations = []
    for name, raw, frame, accepted in rows:
        try:
            result = audit_trace(raw, stdin, frame)
            actual = True; failure = None
        except (ValueError, KeyError, IndexError, StopIteration) as error:
            actual = False; failure = repr(error)
        packed = lzma.compress(raw.encode(), preset=3)
        (output / (name + ".trace.xz")).write_bytes(packed)
        if frame != stdout: (output / (name + ".stdout.raw")).write_bytes(frame)
        row = {"name": name, "expected_acceptance": accepted, "actual_acceptance": actual,
               "status": "PASS" if actual == accepted else "FAIL", "failure": failure,
               "trace": {"bytes": len(raw.encode()), "sha256": digest(raw.encode())},
               "compressed_trace": {"bytes": len(packed), "sha256": digest(packed)},
               "stdout": {"bytes": len(frame), "sha256": digest(frame)}}
        observations.append(row)
    report = {"schema": "trnm.hia.work-owner-trace-controls.v1",
              "status": "PASS" if all(r["status"] == "PASS" for r in observations) else "FAIL",
              "count": len(observations), "positive": sum(r["expected_acceptance"] for r in observations),
              "negative": sum(not r["expected_acceptance"] for r in observations),
              "actual_baseline": baseline, "rows": observations, "new_native_execution": False,
              "empty_qq_exit_notification_roster_is_legal": True}
    write_json(output / "report.json", report)
    need(report["status"] == "PASS", "Actual trace qualification admitted a concrete corrupt observation")
    return report

def run_signal_controls(text, stdin, stdout, output):
    """Replay a real signal trace plus explicit derived gate interleavings."""
    output = Path(output); output.mkdir(mode=0o700)
    baseline = audit_trace(text, stdin, stdout, expected_signal=1)
    calls, signals, exits = complete_calls(text)
    header = decode(stdout)["header"]; worker = header["worker_tid"]; main = header["main_tid"]
    need(header["domain"] == 2 and header["code"] == 1 and len(signals) == 1,
         "Actual late-cancel SIGUSR1 trace required")
    writes = [c for c in calls if c["tid"] == worker and c["name"] == "write"
              and io_fields(c)[0] == 3]
    reads = [c for c in calls if c["tid"] == worker and c["name"] == "read"
             and io_fields(c)[0] == 4]
    returns = [c for c in calls if c["name"] == "rt_sigreturn"]
    need(len(writes) == len(returns) == 1 and reads, "Actual single gate/signal extent differs")
    gate = writes[0]; returned = returns[0]
    omitted = {signals[0]["line"] - 1, returned["start"] - 1, returned["end"] - 1}
    for call in reads: omitted.update((call["start"] - 1, call["end"] - 1))
    lines = text.splitlines(True)
    delivered = str(worker) + " " + signals[0]["text"] + "\n"
    ack = f'{worker} read(4, "\\x01", 1) = 1\n'
    done = f"{worker} rt_sigreturn({{mask=[]}}) = 1\n"
    before_read = f"{worker} rt_sigreturn({{mask=[]}}) = 32\n"
    def arranged(block, extra=""):
        rows = []
        for i, line in enumerate(lines):
            if i not in omitted: rows.append(line)
            if i + 1 == gate["end"]: rows.append(block)
        return "".join(rows) + extra
    normal = ack + delivered + done
    rows = [
        ("actual-signal-baseline", text, True, "unchanged actual trace"),
        ("signal-after-successful-ack", arranged(normal), True, "derived gate scheduling"),
        ("signal-before-ack-read", arranged(delivered + before_read + ack), True, "derived gate scheduling"),
        ("missing-signal-return", arranged(ack + delivered), False, "derived corrupt observation"),
        ("duplicate-signal-return", arranged(normal + done), False, "derived corrupt observation"),
        ("signal-return-wrong-tid", arranged(ack + delivered + done.replace(str(worker), str(main), 1)),
         False, "derived corrupt observation"),
        ("signal-delivery-wrong-tid", arranged(ack + delivered.replace(str(worker), str(main), 1) + done),
         False, "derived corrupt observation"),
        ("signal-return-wrong-mask", arranged(normal.replace("{mask=[]}", "{mask=[USR1]}")),
         False, "derived corrupt observation"),
        ("wrong-signal-name", arranged(normal.replace("SIGUSR1", "SIGUSR2")),
         False, "derived corrupt observation"),
        ("return-before-delivery", arranged(ack + done + delivered), False, "derived corrupt observation"),
        ("work-before-signal-return", arranged(ack + delivered + f"{worker} gettid() = {worker}\n" + done),
         False, "derived corrupt observation"),
        ("signal-return-after-lifetime", arranged(ack + delivered, done), False, "derived corrupt observation"),
        ("injected-signal-return", arranged(ack + delivered + done.replace("= 1\n", "= 1 (INJECTED)\n")),
         False, "derived corrupt observation"),
        ("eintr-without-interrupted-read", arranged(ack + delivered
             + f"{worker} rt_sigreturn({{mask=[]}}) = -1 EINTR (Interrupted system call)\n"),
         False, "derived corrupt observation"),
    ]
    observations = []
    for name, raw, accepted, origin in rows:
        try:
            audit_trace(raw, stdin, stdout, expected_signal=1); actual = True; failure = None
        except (ValueError, KeyError, IndexError, StopIteration) as error:
            actual = False; failure = repr(error)
        packed = lzma.compress(raw.encode(), preset=3)
        (output / (name + ".trace.xz")).write_bytes(packed)
        observations.append({"name": name, "expected_acceptance": accepted, "actual_acceptance": actual,
            "status": "PASS" if actual == accepted else "FAIL", "failure": failure, "origin": origin,
            "trace": {"bytes": len(raw.encode()), "sha256": digest(raw.encode())},
            "compressed_trace": {"bytes": len(packed), "sha256": digest(packed)},
            "stdout": {"bytes": len(stdout), "sha256": digest(stdout)}})
    report = {"schema": "trnm.hia.work-owner-signal-trace-controls.v1",
              "status": "PASS" if all(r["status"] == "PASS" for r in observations) else "FAIL",
              "count": len(observations), "positive": sum(r["expected_acceptance"] for r in observations),
              "negative": sum(not r["expected_acceptance"] for r in observations),
              "actual_baseline": baseline, "rows": observations, "new_native_execution": False,
              "syscall_signal_returns_must_be_paired_inside_own_gate": True}
    write_json(output / "report.json", report)
    need(report["status"] == "PASS", "Signal trace controls admitted a corrupt observation")
    return report
