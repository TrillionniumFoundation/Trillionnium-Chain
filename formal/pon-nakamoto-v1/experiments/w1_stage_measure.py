#!/usr/bin/env python3
"""Bound an actual prover stage and preserve failed and canceled observations.

This observer owns a new process session. Kernel wait4 usage includes only the
child and descendants it reaped; /proc snapshots are sampled lower bounds. No
aggregate memory peak, host isolation, or consensus qualification is inferred.
"""
from contextlib import contextmanager
import argparse
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time

MAX_LOG_BYTES = 4 * 1024 * 1024
TERMINATION_GRACE_SECONDS = 5


class Canceled(BaseException):
    def __init__(self, signum):
        self.signum = signum
        super().__init__(f"observer received signal {signum}")


@contextmanager
def cancel_on_signals():
    def cancel(signum, _frame):
        raise Canceled(signum)

    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def failure_record(error, operation, path):
    return {"operation": operation, "path": str(path), "type": type(error).__name__,
            "errno": getattr(error, "errno", None), "message": str(error)}


def read_proc_member(path, namespace, namespace_depth, session):
    status = {line.split(":", 1)[0]: line.split(":", 1)[1].split()
              for line in (path / "status").read_text().splitlines() if ":" in line}
    pids = [int(value) for value in status["NSpid"]]
    # An ancestor-namespace process cannot belong to this inner session. Read
    # session IDs before following namespace links for unrelated processes.
    if len(pids) < namespace_depth:
        return None
    sessions = [int(value) for value in status["NSsid"]]
    if sessions[namespace_depth - 1] != session:
        return None
    if os.readlink(path / "ns/pid") != namespace:
        return None
    groups = [int(value) for value in status["NSpgid"]]
    if len(pids) != namespace_depth or len(groups) != len(pids) or len(sessions) != len(pids):
        raise ValueError("inconsistent process namespace ID lengths")
    if pids[-1] <= 0 or groups[-1] <= 0 or pids[0] != int(path.name):
        raise ValueError("invalid process/group identity")
    text = (path / "stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    if int(fields[2]) != groups[0] or int(fields[3]) != sessions[0]:
        raise ValueError("process group/session changed during proc read")
    return {"pid": pids[-1], "proc_pid": int(path.name), "start_ticks": int(fields[19]),
            "pid_namespace": namespace, "state": fields[0], "proc_parent_pid": int(fields[1]),
            "process_group": groups[-1], "session": session,
            "proc_process_group": int(fields[2]), "proc_session": int(fields[3]),
            "user_ticks": int(fields[11]), "system_ticks": int(fields[12]),
            "reaped_child_user_ticks": int(fields[13]), "reaped_child_system_ticks": int(fields[14]),
            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}


def session_snapshot(session):
    """An unreadable process is unknown membership, not an empty session."""
    result = {"members": [], "errors": [], "disappearance_races": []}
    try:
        namespace = os.readlink("/proc/self/ns/pid")
        own_status = Path("/proc/self/status").read_text().splitlines()
        namespace_depth = len(next(line for line in own_status if line.startswith("NSpid:")).split()) - 1
        if namespace_depth <= 0:
            raise ValueError("observer namespace depth unavailable")
        paths = list(Path("/proc").iterdir())
    except Exception as error:
        result["errors"].append(failure_record(error, "read_observer_namespace_or_list_proc", "/proc"))
        return result
    for path in paths:
        if not path.name.isdecimal():
            continue
        try:
            member = read_proc_member(path, namespace, namespace_depth, session)
            if member is not None:
                result["members"].append(member)
        except OSError as error:
            record = failure_record(error, "read_proc_member", path)
            if error.errno in (errno.ENOENT, errno.ESRCH):
                result["disappearance_races"].append(record)
            else:
                result["errors"].append(record)
        except Exception as error:
            result["errors"].append(failure_record(error, "parse_proc_member", path))
    result["members"].sort(key=lambda row: row["pid"])
    return result


def probe_groups(groups):
    results = []
    for group in sorted(groups):
        try:
            os.killpg(group, 0)
            results.append({"group": group, "state": "PRESENT"})
        except ProcessLookupError:
            results.append({"group": group, "state": "ABSENT"})
        except Exception as error:
            results.append({"group": group, "state": "UNKNOWN",
                            "error": failure_record(error, "killpg_probe", group)})
    return results


def signal_groups(groups, signum):
    results = []
    for group in sorted(groups):
        try:
            os.killpg(group, signum)
            results.append({"group": group, "signal": signum, "outcome": "SENT"})
        except ProcessLookupError:
            results.append({"group": group, "signal": signum, "outcome": "ALREADY_ABSENT"})
        except Exception as error:
            results.append({"group": group, "signal": signum, "outcome": "FAILED",
                            "error": failure_record(error, "killpg_signal", group)})
    return results


def measure(command, out, wall_seconds, *, deadline=None):
    """Use the earlier stage/overall deadline; settlement never adds proof budget."""
    if not command or not math.isfinite(wall_seconds) or not 0 < wall_seconds <= 7200:
        raise ValueError("explicit command and wall bound in (0,7200] required")
    if deadline is not None and not math.isfinite(deadline):
        raise ValueError("finite monotonic deadline required")
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    effective_deadline = min(started + wall_seconds, deadline) if deadline is not None else started + wall_seconds
    declared = {
        "schema": "TRNM-W1-STAGE-MEASUREMENT2", "command": list(map(str, command)),
        "cwd": str(Path.cwd()), "wall_limit_seconds": wall_seconds,
        "effective_remaining_seconds": max(0, effective_deadline - started),
        "termination_grace_seconds": TERMINATION_GRACE_SECONDS,
        "started_unix_ns": time.time_ns(), "started_monotonic": started,
        "effective_deadline_monotonic": effective_deadline,
        "max_bytes_per_output_log": MAX_LOG_BYTES,
        "environment": {key: os.environ.get(key) for key in ("RAYON_NUM_THREADS", "RUST_LOG", "RISC0_HOME")},
        "resource_scope": "wait4 direct child including descendants it reaped; killed-stage CPU can be a lower bound; maxrss is largest single process, not aggregate peak",
        "proc_scope": "sampled members of the owned new session; missed short-lived or escaped-session descendants remain unmeasured; PID plus birth ticks identifies samples",
        "proc_clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "shared_cgroup": {name: Path("/sys/fs/cgroup", name).read_text().strip()
                          for name in ("cpu.max", "memory.max") if Path("/sys/fs/cgroup", name).is_file()},
    }
    write_new(out / "declaration.json", declared)
    child, usage, returncode = None, None, None
    reasons, error, remaining_after_exit, final_members = [], None, [], []
    observed_before_deadline = False
    sample_truncated, sample_rss = False, 0
    known_groups, proc_errors, proc_races, group_errors, signal_attempts = set(), [], [], [], []
    final_probes, cleanup_errors = [], []
    group_remaining_after_exit = False

    def reason(value):
        if value not in reasons:
            reasons.append(value)

    def observe(phase):
        try:
            snapshot = session_snapshot(child.pid)
        except Exception as failure:
            snapshot = {"members": [], "disappearance_races": [],
                        "errors": [failure_record(failure, "session_snapshot", "/proc")]}
        known_groups.update(row["process_group"] for row in snapshot["members"])
        proc_errors.extend({"phase": phase, **row} for row in snapshot["errors"])
        proc_races.extend({"phase": phase, **row} for row in snapshot["disappearance_races"])
        if snapshot["errors"]:
            reason("PROC_STATE_UNKNOWN")
        probes = probe_groups(known_groups)
        group_errors.extend({"phase": phase, **row} for row in probes if row["state"] == "UNKNOWN")
        if any(row["state"] == "UNKNOWN" for row in probes):
            reason("GROUP_STATE_UNKNOWN")
        return snapshot, probes

    def reap_nonblocking():
        nonlocal usage, returncode
        if child.returncode is None:
            pid, status, found_usage = os.wait4(child.pid, os.WNOHANG)
            if pid:
                usage = found_usage
                returncode = child.returncode = os.waitstatus_to_exitcode(status)

    def known_groups_settled(snapshot, probes):
        if child.returncode is None:
            return False
        if all(row["state"] == "ABSENT" for row in probes):
            return True
        if snapshot["errors"] or any(row["state"] == "UNKNOWN" for row in probes):
            return False
        members = snapshot["members"]
        zombie_groups = {row["process_group"] for row in members if row["state"] == "Z"}
        return (bool(members) and all(row["state"] == "Z" for row in members)
                and {row["group"] for row in probes if row["state"] == "PRESENT"} <= zombie_groups)

    def send(signum):
        attempts = signal_groups(known_groups, signum)
        signal_attempts.extend(attempts)
        if any(row["outcome"] == "FAILED" for row in attempts):
            reason("OWNED_GROUP_SIGNAL_FAILED")

    with (out / "stdout.log").open("xb") as stdout, (out / "stderr.log").open("xb") as stderr, \
            (out / "process-samples.jsonl").open("x", encoding="utf-8") as samples:
        try:
            if time.monotonic() >= effective_deadline:
                reasons.append("DEADLINE_EXHAUSTED_BEFORE_SPAWN")
            else:
                child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                known_groups.add(child.pid)
                next_sample = 0
                while True:
                    now = time.monotonic()
                    if now >= next_sample:
                        snapshot, probes = observe("running")
                        members = snapshot["members"]
                        sample_rss = max([sample_rss, *(row["rss_bytes"] for row in members)])
                        if samples.tell() < MAX_LOG_BYTES:
                            samples.write(json.dumps({"monotonic": now, "unix_ns": time.time_ns(),
                                          **snapshot, "group_probes": probes}) + "\n")
                            samples.flush()
                        else:
                            sample_truncated = True
                        next_sample = now + 1
                        if snapshot["errors"] or any(row["state"] == "UNKNOWN" for row in probes):
                            break
                    pid, status, found_usage = os.wait4(child.pid, os.WNOHANG)
                    if pid:
                        usage = found_usage
                        returncode = child.returncode = os.waitstatus_to_exitcode(status)
                        observed_before_deadline = time.monotonic() < effective_deadline
                        if not observed_before_deadline:
                            reasons.append("COMPLETION_NOT_OBSERVED_BEFORE_DEADLINE")
                        break
                    if time.monotonic() >= effective_deadline:
                        reasons.append("TIMEOUT")
                        break
                    if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_LOG_BYTES:
                        reasons.append("OUTPUT_LIMIT")
                        break
                    time.sleep(.05)
        except (Canceled, KeyboardInterrupt) as failure:
            reasons.append(f"CANCELED_SIGNAL_{getattr(failure, 'signum', signal.SIGINT)}")
            error = str(failure)
        except Exception as failure:
            reasons.append(f"OBSERVER_OR_SPAWN_FAILURE:{type(failure).__name__}")
            error = str(failure)
        finally:
            # Ignore repeated cancellation only while settling our owned session.
            previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                if child:
                    snapshot, probes = observe("settlement_entry")
                    if child.returncode is not None:
                        remaining_after_exit = snapshot["members"]
                        group_remaining_after_exit = bool(remaining_after_exit) or any(
                            row["state"] != "ABSENT" for row in probes)
                        if group_remaining_after_exit:
                            reason("DESCENDANTS_REMAINED_AFTER_CHILD_EXIT")
                        if any(row["state"] == "PRESENT" for row in probes) and not remaining_after_exit:
                            reason("GROUP_PRESENT_WITHOUT_VISIBLE_MEMBER")
                    if child.returncode is None or group_remaining_after_exit or proc_errors or group_errors:
                        send(signal.SIGTERM)
                        settlement_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
                        while time.monotonic() < settlement_deadline:
                            reap_nonblocking()
                            snapshot, probes = observe("settling")
                            if known_groups_settled(snapshot, probes):
                                break
                            time.sleep(.05)
                        if not known_groups_settled(snapshot, probes) or proc_errors or group_errors:
                            send(signal.SIGKILL)
                            reason("SIGKILL_DURING_SETTLEMENT")
                        if child.returncode is None:
                            reap_deadline = time.monotonic() + 1
                            while time.monotonic() < reap_deadline:
                                reap_nonblocking()
                                if child.returncode is not None:
                                    break
                                time.sleep(.01)
                            if child.returncode is None:
                                # Uninterruptible kernel waits cannot be made
                                # killable by a userspace wall-clock budget.
                                reason("UNREAPED_CHILD_AFTER_SIGKILL")
                    snapshot, final_probes = observe("final")
                    final_members = snapshot["members"]
                    if snapshot["errors"] or any(row["state"] == "UNKNOWN" for row in final_probes):
                        # A failed final read must not bypass cleanup or erase
                        # the known original session/group ownership.
                        send(signal.SIGTERM)
                        send(signal.SIGKILL)
                    if not known_groups_settled(snapshot, final_probes):
                        reason("OWNED_GROUP_SETTLEMENT_NOT_ESTABLISHED")
                if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_LOG_BYTES and "OUTPUT_LIMIT" not in reasons:
                    reasons.append("OUTPUT_LIMIT")
            except Exception as failure:
                cleanup_errors.append(failure_record(failure, "settle_owned_session", child.pid if child else None))
                reason("CLEANUP_FAILURE")
                if child:
                    send(signal.SIGTERM)
                    send(signal.SIGKILL)
                    try:
                        reap_nonblocking()
                    except Exception as reap_error:
                        cleanup_errors.append(failure_record(reap_error, "cleanup_wait4", child.pid))
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
    result = {
        **declared, "finished_unix_ns": time.time_ns(), "wall_seconds": time.monotonic() - started,
        "pid": child.pid if child else None, "returncode": returncode,
        "timed_out": any("DEADLINE" in reason or reason == "TIMEOUT" for reason in reasons),
        "termination_reasons": reasons, "error": error,
        "completion_observed_before_deadline": observed_before_deadline,
        "process_group_remaining_after_child_exit": group_remaining_after_exit,
        "members_after_child_exit": remaining_after_exit, "final_owned_session_members": final_members,
        "proc_scan_errors": proc_errors, "proc_disappearance_races": proc_races,
        "group_probe_errors": group_errors, "known_owned_groups": sorted(known_groups),
        "final_known_group_probes": final_probes, "signal_attempts": signal_attempts,
        "cleanup_errors": cleanup_errors,
        "owned_session_observation_complete": (not proc_errors and not group_errors and not cleanup_errors
                                               and "GROUP_PRESENT_WITHOUT_VISIBLE_MEMBER" not in reasons
                                               and "OWNED_GROUP_SETTLEMENT_NOT_ESTABLISHED" not in reasons),
        "sample_log_truncated": sample_truncated, "sampled_max_single_process_rss_bytes": sample_rss,
        "aggregate_process_tree_peak_rss_bytes": None,
        "rusage": {"user_seconds": usage.ru_utime if usage else None,
                   "system_seconds": usage.ru_stime if usage else None,
                   "max_single_process_rss_bytes": usage.ru_maxrss * 1024 if usage else None,
                   "minor_faults": usage.ru_minflt if usage else None,
                   "major_faults": usage.ru_majflt if usage else None,
                   "voluntary_context_switches": usage.ru_nvcsw if usage else None,
                   "involuntary_context_switches": usage.ru_nivcsw if usage else None},
        "stdout_sha256": sha(out / "stdout.log"), "stderr_sha256": sha(out / "stderr.log"),
        "stage_process_complete": returncode == 0 and observed_before_deadline and not reasons,
        "prover_resource_completeness_established": False, "complete_proof_claim": False,
        "note": "Stage exit 0 is not full proof success. Saved Succinct verification against the fixed image and external statement remains the cryptographic authority.",
    }
    write_new(out / "result.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wall-seconds", type=float, required=True)
    parser.add_argument("--deadline-monotonic", type=float)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    with cancel_on_signals():
        result = measure(command, args.out, args.wall_seconds, deadline=args.deadline_monotonic)
    print(json.dumps(result))
    return 0 if result["stage_process_complete"] else 124 if result["timed_out"] else result["returncode"] or 1


if __name__ == "__main__":
    raise SystemExit(main())
