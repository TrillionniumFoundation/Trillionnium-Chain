#!/usr/bin/env python3
"""Bound an actual prover stage and preserve failed and canceled observations.

This observer owns a new process session. Kernel wait4 usage includes only the
child and descendants it reaped; /proc snapshots are sampled lower bounds. No
aggregate memory peak, host isolation, or consensus qualification is inferred.
"""
from contextlib import ExitStack, contextmanager
import argparse
import collections
import copy
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

MAX_LOG_BYTES = 4 * 1024 * 1024
TERMINATION_GRACE_SECONDS = 5
MAX_TERMINATION_GRACE_SECONDS = 30


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


CANCEL_SIGNALS = (signal.SIGINT, signal.SIGTERM)
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
STAGE_SCHEMA = "TRNM-W1-STAGE-MEASUREMENT3"
CANCELLATION_SCHEMA = "TRNM-W1-CANCELLATION-HANDOFF1"
SNAPSHOT_SCHEMA = "TRNM-W1-OBSERVED-SNAPSHOT1"


def local_boot_id():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if str(uuid.UUID(value)) != value:
        raise ValueError("noncanonical local Linux boot ID")
    return value


def cancellation_signal(failure):
    """Only an actual local exception supplies cancellation; never parse text."""
    if isinstance(failure, KeyboardInterrupt):
        return int(signal.SIGINT)
    if isinstance(failure, Canceled):
        value = failure.signum
        if (isinstance(value, int) and not isinstance(value, bool)
                and value in CANCEL_SIGNALS):
            return int(value)
        raise ValueError("noncanonical actual cancellation signal")
    raise TypeError("actual Canceled or KeyboardInterrupt required")


def cancellation_details(failure, phase):
    signum = cancellation_signal(failure)
    previous = getattr(failure, "cancellation_event", None)
    if type(previous) is dict and previous.get("schema") == CANCELLATION_SCHEMA:
        event = copy.deepcopy(previous)
    else:
        event = {"schema": CANCELLATION_SCHEMA, "first_canceled_signal": signum,
                 "origin_phase": phase, "origin_exception": type(failure).__name__,
                 "handoffs": []}
    return event


def snapshot_identity(snapshot):
    if snapshot is None:
        return None
    return {key: snapshot[key] for key in ("schema", "kind", "path", "sha256")}


class DeferredCancellation:
    """Latch cancellation while cleanup and immutable observation writes settle.

    This is a local Linux/main-thread handoff, not a signal-delivery guarantee.
    The handler only changes its own latch, never a snapshot being serialized.
    A published snapshot remains a fact if cancellation is observed afterwards;
    the caller must also account for the actual return or raised cancellation.
    Restoring the enclosing cancel_on_signals handler is the handoff boundary.
    """
    def __init__(self, prior_cancellation=None, *, phase, live_deadline=None):
        if prior_cancellation is not None:
            cancellation_signal(prior_cancellation)
        if live_deadline is not None and not (
                type(live_deadline) is tuple and len(live_deadline) == 2
                and type(live_deadline[0]) in (int, float) and math.isfinite(live_deadline[0])
                and type(live_deadline[1]) is str and live_deadline[1]):
            raise ValueError("live deadline requires absolute seconds and explicit local boot ID")
        self.prior_cancellation = prior_cancellation
        self.phase = phase
        # Only an active caller supplies this context. Never reconstruct it by
        # parsing a historical saved observation or claimed cancellation text.
        self._live_deadline_context = (None if live_deadline is None else {
            "deadline_monotonic": live_deadline[0], "boot_id": live_deadline[1],
            "observer_pid": os.getpid()})
        self._latch = {}
        self._deferred_events = collections.deque(maxlen=64)
        self._deferred_events_truncated = False
        self._previous_handlers = {}
        self._previous_mask = None
        # Registered snapshots are immutable; only replace this reference.
        # Do not perform a potentially long copy before installing the guard.
        self.observed_snapshot = getattr(prior_cancellation, "observed_snapshot", None)
        self.observation_errors = []

    def _capture(self, signum, _frame):
        # setdefault preserves the first recorded signal even with reentrancy.
        event = {"signal": int(signum), "phase": self.phase,
                 "observed_monotonic_ns": time.monotonic_ns()}
        self._latch.setdefault("first", event)
        if len(self._deferred_events) == self._deferred_events.maxlen:
            self._deferred_events_truncated = True
        self._deferred_events.append(event)

    @property
    def canceled_signal(self):
        if self.prior_cancellation is not None:
            return cancellation_signal(self.prior_cancellation)
        first = self._latch.get("first")
        return first["signal"] if first is not None else None

    def pending_event(self):
        failure = self.prior_cancellation
        first = self._latch.get("first")
        if failure is None and first is not None:
            failure = Canceled(first["signal"])
        if failure is None:
            return None
        event = cancellation_details(failure, self.phase)
        event["deferred_at_snapshot"] = copy.deepcopy(first)
        event["deferred_events_at_snapshot"] = copy.deepcopy(list(self._deferred_events))
        event["deferred_events_truncated"] = self._deferred_events_truncated
        return event

    def record_error(self, kind, failure):
        self.observation_errors.append({"kind": kind, "phase": self.phase,
            "type": type(failure).__name__, "errno": getattr(failure, "errno", None),
            "message": str(failure)})

    def published_snapshot(self, kind, path):
        # Call only after write_new has returned following its successful fsync.
        # A readback failure must not promote an in-memory object to saved data.
        with path.open("rb") as stream:
            raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise ValueError("observation snapshot exceeds readback bound")
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError("observation snapshot must be a JSON object")
        self.observed_snapshot = {"schema": SNAPSHOT_SCHEMA, "kind": kind,
            "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "value": value}

    def __enter__(self):
        # Both installation and restoration protect the pair, not one handler.
        self._previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
        try:
            self._previous_handlers = {sig: signal.getsignal(sig) for sig in CANCEL_SIGNALS}
            for sig in CANCEL_SIGNALS:
                signal.signal(sig, self._capture)
        except BaseException as failure:
            restored = self._restore()
            self._raise_cancellation(failure, restored)
            raise
        signal.pthread_sigmask(signal.SIG_SETMASK, self._previous_mask)
        return self

    def _restore(self):
        failures = []
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
        except BaseException as failure:
            failures.append(failure)
        for sig, handler in self._previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except BaseException as failure:
                failures.append(failure)
        try:
            # Unmasking can synchronously run the restored enclosing handler.
            signal.pthread_sigmask(signal.SIG_SETMASK, self._previous_mask)
        except BaseException as failure:
            failures.append(failure)
        return failures

    def _raise_cancellation(self, active_error, restored):
        first = self._latch.get("first")
        restored_cancels = [failure for failure in restored
                            if isinstance(failure, (Canceled, KeyboardInterrupt))]
        # A second signal delivered during unmask must not replace the first.
        chosen = self.prior_cancellation
        if chosen is None and first is not None:
            chosen = Canceled(first["signal"])
        if chosen is None and isinstance(active_error, (Canceled, KeyboardInterrupt)):
            chosen = active_error
        if chosen is None and restored_cancels:
            chosen = restored_cancels[0]
        if chosen is None:
            return
        event = cancellation_details(chosen, self.phase)
        handoff = {"phase": self.phase,
            "prior_canceled_signal": (cancellation_signal(self.prior_cancellation)
                                      if self.prior_cancellation is not None else None),
            "first_deferred": copy.deepcopy(first),
            "deferred_events": copy.deepcopy(list(self._deferred_events)),
            "deferred_events_truncated": self._deferred_events_truncated,
            "restored_handler_cancellations": [
                {"signal": cancellation_signal(failure), "type": type(failure).__name__}
                for failure in restored_cancels],
            "observed_snapshot": snapshot_identity(self.observed_snapshot),
            "observation_errors": copy.deepcopy(self.observation_errors)}
        if active_error is not None and active_error is not chosen:
            handoff["interrupted_error"] = {
                "type": type(active_error).__name__, "errno": getattr(active_error, "errno", None),
                "message": str(active_error)}
        handoff["restoration_errors"] = [
            {"type": type(failure).__name__, "errno": getattr(failure, "errno", None),
             "message": str(failure)} for failure in restored
            if not isinstance(failure, (Canceled, KeyboardInterrupt))]
        event["handoffs"].append(handoff)
        chosen.cancellation_event = event
        if self.observed_snapshot is not None:
            chosen.observed_snapshot = self.observed_snapshot
        if self._live_deadline_context is not None:
            chosen._live_deadline_context = dict(self._live_deadline_context)
        # F1: a caught cancellation stays primary even if no second signal
        # arrives and persistence fails with an ordinary I/O exception.
        if active_error is not None and active_error is not chosen:
            raise chosen from active_error
        if restored and restored[0] is not chosen:
            raise chosen from restored[0]
        raise chosen

    def __exit__(self, _kind, active_error, _traceback):
        restored = self._restore()
        self._raise_cancellation(active_error, restored)
        if restored:
            raise restored[0] from active_error
        return False


def publish_cancellation(path, failure, scope):
    """Record operation cancellation separately; never rewrite a saved snapshot.

    This helper deliberately re-raises the same primary cancellation after its
    write, including when the write fails. A caller never receives success here.
    """
    with DeferredCancellation(failure, phase=f"{scope}-cancellation-record") as handoff:
        event = {"schema": "TRNM-W1-OPERATION-CANCELLATION1", "scope": scope,
                 "canceled_signal": cancellation_signal(failure),
                 "cancellation_event": cancellation_details(failure, scope),
                 "observed_snapshot": snapshot_identity(handoff.observed_snapshot),
                 "operation_canceled": True}
        write_new(path, event)


def run_cli(entrypoint):
    try:
        return entrypoint()
    except (Canceled, KeyboardInterrupt) as failure:
        snapshot = getattr(failure, "observed_snapshot", None)
        value = snapshot.get("value") if type(snapshot) is dict else None
        deadline_exhausted = (type(value) is dict
            and (value.get("timed_out") is True
                 or value.get("deadline_exhausted_at_snapshot") is True))
        event = cancellation_details(failure, "cli-handoff")
        live = getattr(failure, "_live_deadline_context", None)
        check = {"status": "NO_LIVE_CONTEXT"}
        if (type(live) is dict and live.get("observer_pid") == os.getpid()
                and type(live.get("deadline_monotonic")) in (int, float)
                and math.isfinite(live["deadline_monotonic"])):
            try:
                if live.get("boot_id") == local_boot_id():
                    now = time.monotonic()
                    expired = now >= live["deadline_monotonic"]
                    deadline_exhausted = deadline_exhausted or expired
                    check = {"status": "EXHAUSTED" if expired else "WITHIN_DEADLINE",
                             **live, "observed_monotonic": now}
                else:
                    check = {"status": "DIFFERENT_BOOT"}
            except (OSError, ValueError) as read_error:
                check = {"status": "UNKNOWN", "type": type(read_error).__name__}
        event["live_deadline_check_at_handoff"] = check
        event["exit_disposition"] = "TIMED_OUT" if deadline_exhausted else "CANCELED"
        try:
            print(json.dumps(event, sort_keys=True, allow_nan=False), file=sys.stderr, flush=True)
        except OSError as output_error:
            raise failure from output_error
        return 124 if deadline_exhausted else 128 + cancellation_signal(failure)



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


def measure(command, out, wall_seconds, *, deadline=None, environment_overrides=None,
            termination_grace_seconds=TERMINATION_GRACE_SECONDS):
    """Use the earlier proof deadline and a separately bounded cleanup grace.

    A supervisor of another supervisor must allow that child's own settlement
    and report handoff to finish. Cleanup grace never extends effective_deadline.
    """
    if not command or not math.isfinite(wall_seconds) or not 0 < wall_seconds <= 7200:
        raise ValueError("explicit command and wall bound in (0,7200] required")
    if deadline is not None and not math.isfinite(deadline):
        raise ValueError("finite monotonic deadline required")
    if environment_overrides is not None and not (
            type(environment_overrides) is dict
            and all(type(key) is str and key and "=" not in key and "\0" not in key
                    and type(value) is str and "\0" not in value
                    for key, value in environment_overrides.items())):
        raise ValueError("explicit environment overrides must be string pairs")
    if (type(termination_grace_seconds) not in (int, float)
            or not math.isfinite(termination_grace_seconds)
            or not 0 < termination_grace_seconds <= MAX_TERMINATION_GRACE_SECONDS):
        raise ValueError("finite termination grace in (0,30] seconds required")
    child_environment = os.environ.copy()
    child_environment.update(environment_overrides or {})
    boot_id = local_boot_id()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    effective_deadline = min(started + wall_seconds, deadline) if deadline is not None else started + wall_seconds
    declared = {
        "schema": STAGE_SCHEMA, "cancellation_schema": CANCELLATION_SCHEMA,
        "result_is_pre_handoff_snapshot": True, "command": list(map(str, command)),
        "cwd": str(Path.cwd()), "wall_limit_seconds": wall_seconds,
        "effective_remaining_seconds": max(0, effective_deadline - started),
        "termination_grace_seconds": termination_grace_seconds,
        "started_unix_ns": time.time_ns(), "started_monotonic": started,
        "observer_boot_id": boot_id,
        "effective_deadline_monotonic": effective_deadline,
        "max_bytes_per_output_log": MAX_LOG_BYTES,
        "environment": {key: child_environment.get(key) for key in ("RAYON_NUM_THREADS", "RUST_LOG", "RISC0_HOME")},
        "explicit_environment_override_names": sorted(environment_overrides or {}),
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
    prior_cancellation = None
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

    with ExitStack() as handoffs:
        with (out / "stdout.log").open("xb") as stdout, (out / "stderr.log").open("xb") as stderr, \
                (out / "process-samples.jsonl").open("x", encoding="utf-8") as samples:
            try:
                if time.monotonic() >= effective_deadline:
                    reasons.append("DEADLINE_EXHAUSTED_BEFORE_SPAWN")
                else:
                    child = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                             env=child_environment, start_new_session=True)
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
                prior_cancellation = failure
                reasons.append(f"CANCELED_SIGNAL_{cancellation_signal(failure)}")
                error = str(failure)
            except Exception as failure:
                reasons.append(f"OBSERVER_OR_SPAWN_FAILURE:{type(failure).__name__}")
                error = str(failure)
            finally:
                cancellation_handoff = handoffs.enter_context(DeferredCancellation(
                    prior_cancellation, phase="stage-settlement",
                    live_deadline=(effective_deadline, boot_id)))
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
                            settlement_deadline = time.monotonic() + termination_grace_seconds
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
        cancellation_handoff.phase = "stage-snapshot"
        canceled_at_snapshot = cancellation_handoff.canceled_signal
        if canceled_at_snapshot is not None:
            reason(f"CANCELED_SIGNAL_{canceled_at_snapshot}")
            if error is None:
                error = "cancellation observed during stage settlement"
        result = {
            **declared, "finished_unix_ns": time.time_ns(), "wall_seconds": time.monotonic() - started,
            "pid": child.pid if child else None, "returncode": returncode,
            "timed_out": any("DEADLINE" in reason or reason == "TIMEOUT" for reason in reasons),
            "termination_reasons": reasons, "error": error,
            "canceled_signal": canceled_at_snapshot,
            "cancellation_event": cancellation_handoff.pending_event(),
            "completion_observed_before_deadline": observed_before_deadline,
            "deadline_exhausted_at_snapshot": time.monotonic() >= effective_deadline,
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
        result["deadline_exhausted_at_snapshot"] = time.monotonic() >= effective_deadline
        write_new(out / "result.json", result)
        cancellation_handoff.published_snapshot("stage", out / "result.json")
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
        try:
            result = measure(command, args.out, args.wall_seconds, deadline=args.deadline_monotonic)
        except (Canceled, KeyboardInterrupt) as failure:
            publish_cancellation(args.out / "cancellation.json", failure, "stage-cli")
            raise
    print(json.dumps(result))
    if (result["timed_out"] or result["deadline_exhausted_at_snapshot"]
            or time.monotonic() >= result["effective_deadline_monotonic"]):
        return 124
    return 0 if result["stage_process_complete"] else result["returncode"] or 1


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
