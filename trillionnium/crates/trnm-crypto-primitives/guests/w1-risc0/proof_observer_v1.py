#!/usr/bin/python3
"""Optional local proof diagnostics; neither a prover nor a proof qualifier.

The default entry accepts only the original prove/5400/po2=18 shape. An
explicit, separately named cost-only profile accepts exactly 14400 seconds;
its observations cannot qualify the original 5400-second budget.
The process owner borrows the reserved-leader/WNOWAIT/killpg-before-reap rule
from formal/pon-nakamoto-v1/bounded_process.py. It records actual wait4 rows,
not a subtraction of the observing parent's mixed RUSAGE_CHILDREN. A sampled
/proc tree is partial: fast children, escaped sessions and unavailable files
remain unknown. No total historical family CPU or hardware lower bound is made.
Preparation and live sampling/logging use the same work deadline. Cleanup and
final held-FD readback share the pre-existing separate five-second cooperative
allowance; final bounded JSON publication follows the recorded wall interval.
Blocking kernel I/O, spawn and signal delivery are not hard real-time guarantees.
"""
from __future__ import annotations
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

PHASES = ("host-enter", "input-native-check-enter", "input-native-check-return",
          "sdk-prove-enter", "sdk-prove-return", "strict-verify-enter",
          "strict-verify-return", "codec-enter", "codec-return",
          "receipt-write-enter", "receipt-write-return", "host-complete")
STREAM_CAPS = {"stdout": 1024 * 1024, "stderr": 1024 * 1024,
               "backend-stdout": 16 * 1024 * 1024, "backend-stderr": 4 * 1024 * 1024}
PHASE_CAP = 16 * 1024
SAMPLE_CAP = 16 * 1024 * 1024
IMAGE_CAP = 256 * 1024 * 1024
RUST_LOG = "risc0_zkvm::host::server::prove::prover_impl=debug"
ORIGINAL_PROFILE = "original-5400-v1"
COST_PROFILE = "cost-only-14400-v1"


class ObservationError(ValueError):
    pass


def require(value, code):
    if not value:
        raise ObservationError(code)


def profile_budget(profile):
    require(type(profile) is str and profile in (ORIGINAL_PROFILE, COST_PROFILE),
            "unknown-proof-profile")
    return 5400 if profile == ORIGINAL_PROFILE else 14400


def encoded_report(value):
    raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")
    require(len(raw) <= 256 * 1024, "observer-report-bound")
    return raw


def deadline_check(deadline):
    require(time.monotonic() < deadline, "work-timeout")


def identity(st):
    return {"device": st.st_dev, "inode": st.st_ino, "bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns, "mode": st.st_mode}


def fd_hash(fd, deadline, cap=IMAGE_CAP):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, "file-bound-or-type")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        deadline_check(deadline)
        data = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset)
        require(data, "file-short-read")
        digest.update(data)
        offset += len(data)
    require(identity(os.fstat(fd)) == identity(before), "file-changed-during-read")
    return dict(identity(before), sha256=digest.hexdigest())


def file_hash(path, deadline, cap=IMAGE_CAP):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return fd_hash(fd, deadline, cap)
    finally:
        os.close(fd)


def limited_read(path, cap):
    with open(path, "rb") as stream:
        value = stream.read(cap + 1)
    require(len(value) <= cap, "proc-read-limit")
    return value


def proc_stat(pid):
    raw = limited_read(f"/proc/{pid}/stat", 8192).decode("ascii")
    close = raw.rfind(")")
    require(close >= 0 and raw.split(" ", 1)[0] == str(pid), "proc-stat-shape")
    fields = raw[close + 2:].split()
    require(len(fields) >= 22, "proc-stat-shape")
    return {"pid": pid, "state": fields[0], "ppid": int(fields[1]),
            "process_group": int(fields[2]), "session": int(fields[3]),
            "user_ticks": int(fields[11]), "system_ticks": int(fields[12]),
            "starttime_ticks": int(fields[19]), "rss_pages": int(fields[21])}


def sample_family(leader, deadline, images):
    """Read-only census. Never signal a PID discovered through this snapshot."""
    queue = [os.getpid(), leader]
    seen = set()
    processes = []
    rows = []
    errors = []
    thread_budget = 256
    while queue:
        deadline_check(deadline)
        pid = queue.pop(0)
        if pid in seen:
            continue
        if len(seen) >= 128:
            errors.append({"scope": "process-bound"})
            break
        seen.add(pid)
        try:
            before = proc_stat(pid)
            tids_before = sorted(int(path.name) for path in Path(f"/proc/{pid}/task").iterdir())
            require(len(tids_before) <= thread_budget, "thread-bound")
            thread_budget -= len(tids_before)
            for tid in tids_before:
                try:
                    raw = limited_read(f"/proc/{pid}/task/{tid}/children", 16384)
                    children = [int(token) for token in raw.split()]
                    require(all(value > 0 for value in children), "children-shape")
                    rows.append({"pid": pid, "tid": tid, "children": children})
                    queue.extend(children)
                except (OSError, ValueError) as error:
                    errors.append({"scope": "children", "pid": pid, "tid": tid,
                                   "errno": getattr(error, "errno", None)})
            tids_after = sorted(int(path.name) for path in Path(f"/proc/{pid}/task").iterdir())
            if tids_before != tids_after:
                errors.append({"scope": "thread-census-changed", "pid": pid})
            if pid == os.getpid():
                continue  # observer costs are never described as worker costs
            try:
                cgroup = {"status": "read", "raw": limited_read(f"/proc/{pid}/cgroup", 16384).decode("utf-8"),
                          "errno": None, "effective_resource_limit_qualified": False}
            except (OSError, ValueError, UnicodeError) as error:
                cgroup = {"status": "unavailable", "raw": None, "errno": getattr(error, "errno", None),
                          "effective_resource_limit_qualified": False}
            executable = None
            try:
                fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
                try:
                    observed = identity(os.fstat(fd))
                    key = json.dumps(observed, sort_keys=True)
                    if key not in images:
                        require(len(images) < 16, "executable-image-bound")
                        images[key] = fd_hash(fd, deadline)
                    executable = images[key]
                finally:
                    os.close(fd)
            except (OSError, ValueError) as error:
                errors.append({"scope": "actual-executable", "pid": pid,
                               "errno": getattr(error, "errno", None)})
            after = proc_stat(pid)
            stable = before["starttime_ticks"] == after["starttime_ticks"]
            processes.append({"before": before, "after": after,
                              "stable_starttime": stable,
                              "cgroup_observation": cgroup if stable else None,
                              "actual_executable": executable if stable else None})
            if not stable:
                errors.append({"scope": "pid-reuse-or-race", "pid": pid})
        except (OSError, ValueError) as error:
            errors.append({"scope": "process", "pid": pid,
                           "errno": getattr(error, "errno", None)})
    return {"schema": "pon-w1-process-sample-v1", "monotonic_ns": time.monotonic_ns(),
            "processes": processes, "children_rows": rows, "errors": errors,
            "historical_family_complete": False, "observer_pid": os.getpid()}


def subreaper():
    result = {"requested": True, "enabled": False, "errno": None}
    library = ctypes.CDLL(None, use_errno=True)
    prctl = library.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:
        result["errno"] = ctypes.get_errno()
        return result
    observed = ctypes.c_int()
    if prctl(37, ctypes.addressof(observed), 0, 0, 0) != 0:
        result["errno"] = ctypes.get_errno()
    else:
        result["enabled"] = observed.value == 1
    return result


def wait4_row(pid, options):
    actual, status, usage = os.wait4(pid, options)
    if actual == 0:
        return None
    return {"pid": actual, "raw_wait_status": status,
            "starttime_ticks": None,
            "identity_scope": "kernel wait4 child event; sampled process identities are separate, not joined by PID alone",
            "returncode": os.waitstatus_to_exitcode(status),
            "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
            "max_rss_kib": usage.ru_maxrss,
            "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt,
            "voluntary_context_switches": usage.ru_nvcsw,
            "involuntary_context_switches": usage.ru_nivcsw,
            "observed_monotonic_ns": time.monotonic_ns()}


def phase_readback(path, leader):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), "phase-file-type")
            raw = os.read(fd, PHASE_CAP + 1)
            require(len(raw) <= PHASE_CAP, "phase-file-bound")
        finally:
            os.close(fd)
    except FileNotFoundError:
        return {"status": "missing", "events": [], "complete": False}
    events = []
    error = None
    elapsed = -1
    for line in raw.splitlines(keepends=True):
        try:
            require(len(line) <= 1024 and line.endswith(b"\n"), "phase-line-bound-or-partial")
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    require(key not in value, "phase-duplicate-key")
                    value[key] = item
                return value
            row = json.loads(line, object_pairs_hook=unique)
            require(set(row) == {"schema", "sequence", "pid", "elapsed_ns", "event", "consensus_authority"}, "phase-shape")
            require(row["schema"] == "pon-w1-host-phase-v1" and row["consensus_authority"] is False,
                    "phase-namespace")
            require(type(row["sequence"]) is int and row["sequence"] == len(events), "phase-sequence")
            require(type(row["pid"]) is int and row["pid"] == leader, "phase-pid")
            require(type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= 0
                    and row["elapsed_ns"] >= elapsed,
                    "phase-time")
            require(len(events) < len(PHASES), "phase-extra-event")
            require(row["event"] == PHASES[len(events)] or row["event"] == "host-failed", "phase-order")
            require(not events or events[-1]["event"] != "host-failed", "phase-after-failure")
            elapsed = row["elapsed_ns"]
            events.append(row)
        except (ValueError, TypeError) as caught:
            error = str(caught) if isinstance(caught, ObservationError) else "phase-invalid-json"
            break
    return {"status": "parsed" if error is None else "partial-or-invalid", "error": error,
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "events": events,
            "complete": error is None and [row["event"] for row in events] == list(PHASES),
            "scope": "host-relative Instant epoch; not subtractable from owner monotonic timestamps; not proof verification"}


def _shim(arguments):
    """Exact SDK v3.0.6 connector split. No child Popen, new session or log handshake."""
    version = arguments == ["--version"]
    port = (len(arguments) == 2 and arguments[0] == "--port"
            and arguments[1].isascii() and arguments[1].isdecimal()
            and str(int(arguments[1])) == arguments[1] and 1 <= int(arguments[1]) <= 65535)
    require(version or port, "shim-argv")
    backend = int(os.environ["TRNM_W1_BACKEND_FD"])
    require(os.pread(backend, 4, 0) == b"\x7fELF", "shim-real-backend-not-elf")
    if port:
        for name, destination in (("STDOUT", 1), ("STDERR", 2)):
            fd = int(os.environ["TRNM_W1_BACKEND_" + name + "_FD"])
            require(stat.S_ISFIFO(os.fstat(fd).st_mode), "shim-log-not-pipe")
            os.dup2(fd, destination)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("TRNM_W1_")}
    if port:
        environment["RUST_LOG"] = RUST_LOG
    # fexecve of a held regular ELF closes this descriptor on successful exec.
    # --version retains the SDK's original stdout protocol and stderr unchanged.
    os.set_inheritable(backend, False)
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2 and fd != backend:
            try:
                os.close(fd)
            except OSError:
                pass
    os.execve(backend, ["r0vm", *arguments], environment)


def run_observed(command, out, timeout, *, backend_index=None, require_phases=False,
                 stream_caps=None, sample_interval=5.0, proof_profile=ORIGINAL_PROFILE):
    """Internal owner; tests call this only in fresh, dedicated CLI processes."""
    require(sys.platform == "linux", "observer-linux-only")
    budget = profile_budget(proof_profile)
    if proof_profile == COST_PROFILE:
        require(type(timeout) is int and timeout == budget, "observer-cost-only-timeout")
        require(backend_index == 2 and require_phases is True and stream_caps is None
                and sample_interval == 5.0, "cost-only-fixed-observer-settings")
        validate_prove_call(command, out, "prove", timeout, proof_profile)
    else:
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= budget,
                "observer-timeout")
    require(not any(key.startswith("TRNM_W1_") for key in os.environ), "observer-environment-override")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + timeout
    caps = dict(STREAM_CAPS if stream_caps is None else stream_caps)
    require(set(caps) == set(STREAM_CAPS) and all(type(n) is int and n >= 0 for n in caps.values()), "observer-caps")
    report = {"schema": "pon-w1-proof-process-observer-v1", "command": list(command),
              "started_utc": datetime.now(timezone.utc).isoformat(), "timeout_seconds": timeout,
              "source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"), "returncode": 125,
              "timed_out": False, "failure": None, "secondary_failures": [],
              "direct_wait4": None, "adopted_wait4": [], "finite_cleanup_observed": False,
              "family_capture_complete": False, "complete_family_cpu_seconds": None,
              "family_scope": "observed direct/adopted wait4 and sampled proc; no historical family total",
              "wait4_scope": "each row can include descendants already waited by that child; do not add proc ticks",
              "consensus_authority": False, "proof_qualification": False,
              "stream_limits": caps, "sample_limit": SAMPLE_CAP,
              "work_deadline_monotonic": deadline, "cleanup_allowance_seconds": 5,
              "wall_scope": "owner entry through final readback, including setup/work/cleanup; bounded JSON publication follows",
              "blocking_kernel_operations_hard_bounded": False,
              "user_ticks_per_second": os.sysconf("SC_CLK_TCK")}
    if proof_profile == COST_PROFILE:
        report.update(schema="pon-w1-cost-proof-process-observer-v1",
                      proof_profile=COST_PROFILE, original_5400s_budget_passed=False)
    def failure(code, error=None):
        if report["failure"] is None:
            report["failure"] = code
        elif len(report["secondary_failures"]) < 32:
            report["secondary_failures"].append({"code": code, "errno": getattr(error, "errno", None)})

    def close_fd(fd):
        try:
            os.close(fd)
        except OSError as error:
            failure("descriptor-close-error", error)

    def close_stream(stream):
        try:
            stream.close()
        except OSError as error:
            failure("stream-close-error", error)
    files = {}
    read_fds = {}
    passed = []
    images = {}
    selector = selectors.DefaultSelector()
    child = None
    backend_fd = None
    executable_fd = None
    terminal_exit = None
    sample_bytes = 0
    sample_count = 0
    stream_sizes = {name: 0 for name in caps}
    truncations = {name: False for name in caps}
    env = dict(os.environ)
    effective = list(command)
    report_file = (out / "prove.observer.json").open("x")
    try:
        for name in caps:
            files[name] = (out / ("prove." + name + ".log")).open("x+b")
        files["samples"] = (out / "prove.process-samples.jsonl").open("x+b")
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "observer-sigchld-disposition")
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            pass
        else:
            raise ObservationError("observer-requires-fresh-childless-cli")
        report["subreaper"] = subreaper()
        # Keep source/executable identities separate: source hashes are local
        # observation bindings, not hardware attestation or compiler proof.
        report["observer_source"] = file_hash(__file__, deadline)
        executable_fd = os.open(command[0], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        require(os.pread(executable_fd, 4, 0) == b"\x7fELF", "host-not-elf")
        report["host_before"] = fd_hash(executable_fd, deadline)
        passed.append(executable_fd)
        if require_phases:
            env["TRNM_W1_PHASE_JOURNAL"] = str((out / "prove.host-phases.jsonl").resolve())
        if backend_index is not None:
            backend_fd = os.open(command[backend_index], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            require(os.pread(backend_fd, 4, 0) == b"\x7fELF", "backend-not-elf")
            report["backend_before"] = fd_hash(backend_fd, deadline)
            passed.append(backend_fd)
            shim = out / "prove.backend-shim.py"
            with shim.open("xb") as stream:
                stream.write(Path(__file__).read_bytes())
            shim.chmod(0o700)
            report["shim_source"] = file_hash(shim, deadline)
            effective[backend_index] = str(shim.resolve())
            env["TRNM_W1_SHIM"] = "1"
            env["TRNM_W1_BACKEND_FD"] = str(backend_fd)
            report["backend_pipes"] = {}
            for name in ("stdout", "stderr"):
                read, write = os.pipe2(os.O_CLOEXEC)
                passed.append(write)
                read_fds["backend-" + name] = read
                env["TRNM_W1_BACKEND_" + name.upper() + "_FD"] = str(write)
                report["backend_pipes"][name] = {"read": identity(os.fstat(read)),
                                                 "write": identity(os.fstat(write)),
                                                 "scope": "host also inherits write end; EOF alone is not backend exit"}
            report["backend_log_filter"] = RUST_LOG
        report["effective_command"] = effective
        deadline_check(deadline)
        child = subprocess.Popen(effective, executable="/proc/self/fd/" + str(executable_fd),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env, pass_fds=tuple(passed), start_new_session=True)
        report["leader_pid"] = child.pid
        report["spawn_returned_monotonic_ns"] = time.monotonic_ns()
        for fd in passed:
            if fd not in (backend_fd, executable_fd):
                os.close(fd)
        passed = [fd for fd in passed if fd in (backend_fd, executable_fd)]
        read_fds.update(stdout=child.stdout.fileno(), stderr=child.stderr.fileno())
        for name, fd in read_fds.items():
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, name)
        next_sample = time.monotonic()
        while True:
            deadline_check(deadline)
            if time.monotonic() >= next_sample:
                sample = sample_family(child.pid, deadline, images)
                raw = json.dumps(sample, separators=(",", ":"), allow_nan=False).encode() + b"\n"
                require(len(raw) <= 65536 and sample_bytes + len(raw) <= SAMPLE_CAP, "sample-output-limit")
                files["samples"].write(raw)
                files["samples"].flush()
                sample_bytes += len(raw)
                sample_count += 1
                next_sample = time.monotonic() + sample_interval
            status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                require(status.si_pid == child.pid and status.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),
                        "leader-waitid-identity")
                terminal_exit = {"pid": status.si_pid, "code": status.si_code,
                                 "status": status.si_status, "monotonic_ns": time.monotonic_ns()}
                break
            for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                name, fd = key.data, key.fd
                try:
                    data = os.read(fd, min(65536, caps[name] - stream_sizes[name] + 1))
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(fd)
                    continue
                available = caps[name] - stream_sizes[name]
                files[name].write(data[:available])
                stream_sizes[name] += min(len(data), available)
                if len(data) > available:
                    truncations[name] = True
                    raise ObservationError(name + "-output-limit")
    except (OSError, ValueError, KeyError) as error:
        report["failure"] = str(error) if isinstance(error, ObservationError) else "observer-system-error"
        report["failure_errno"] = getattr(error, "errno", None)
        report["timed_out"] = report["failure"] == "work-timeout"
    finally:
        cleanup_deadline = time.monotonic() + 5
        report["work_finished_monotonic_ns"] = time.monotonic_ns()
        report["leader_exit_observation"] = terminal_exit
        if child is not None:
            # Success also cleans our own group while its leader PID remains
            # reserved. No poll/wait/communicate before this final group signal.
            try:
                os.killpg(child.pid, signal.SIGKILL)
                report["final_group_signal"] = "SIGKILL"
            except ProcessLookupError:
                report["final_group_signal"] = "group-absent"
            except OSError as error:
                report["cleanup_errno"] = error.errno
                report["failure"] = report["failure"] or "group-cleanup-error"
            # Preserve buffered tails without extending the original work
            # deadline. A descendant that escaped the group cannot make this
            # drain unbounded, and EOF never certifies process-family exit.
            try:
                while selector.get_map() and time.monotonic() < cleanup_deadline:
                    for key, _ in selector.select(min(0.05, max(0, cleanup_deadline - time.monotonic()))):
                        name, fd = key.data, key.fd
                        try:
                            data = os.read(fd, min(65536, caps[name] - stream_sizes[name] + 1))
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(fd)
                            continue
                        available = caps[name] - stream_sizes[name]
                        files[name].write(data[:available])
                        stream_sizes[name] += min(len(data), available)
                        if len(data) > available:
                            truncations[name] = True
                            failure(name + "-output-limit")
                            selector.unregister(fd)
            except (OSError, ValueError) as error:
                failure("cleanup-drain-error", error)
            if selector.get_map():
                report["failure"] = report["failure"] or "cleanup-pipe-incomplete"
            try:
                while time.monotonic() < cleanup_deadline:
                    row = wait4_row(child.pid, os.WNOHANG)
                    if row is not None:
                        report["direct_wait4"] = row
                        child.returncode = row["returncode"]
                        break
                    time.sleep(0.005)
                if report["direct_wait4"] is None:
                    report["failure"] = report["failure"] or "direct-wait4-incomplete"
                report["adoption_probe"] = "unknown"
                while time.monotonic() < cleanup_deadline and len(report["adopted_wait4"]) < 128:
                    try:
                        row = wait4_row(-1, os.WNOHANG)
                    except ChildProcessError:
                        report["adoption_probe"] = "ECHILD-observed-not-full-family-certification"
                        break
                    if row is None:
                        report["adoption_probe"] = "live-or-not-yet-waitable-child"
                        time.sleep(0.005)
                        continue
                    report["adopted_wait4"].append(row)
                report["finite_cleanup_observed"] = (report["direct_wait4"] is not None
                    and report["adoption_probe"] == "ECHILD-observed-not-full-family-certification")
                if not report["finite_cleanup_observed"]:
                    failure("adopted-cleanup-incomplete")
            except OSError as error:
                report["wait4_errno"] = error.errno
                failure("wait4-error", error)
        try:
            selector.close()
        except OSError as error:
            failure("selector-close-error", error)
        for name, fd in read_fds.items():
            if name not in ("stdout", "stderr"):
                close_fd(fd)
        if child is not None:
            close_stream(child.stdout)
            close_stream(child.stderr)
        for fd in passed:
            if fd not in (backend_fd, executable_fd):
                close_fd(fd)
        # After hashes use the remaining cleanup allowance, never claim an
        # unchanged input if this check fails or has no time remaining.
        for label, fd in (("host", executable_fd), ("backend", backend_fd)):
            if fd is not None:
                try:
                    after = fd_hash(fd, cleanup_deadline)
                    report[label + "_after"] = after
                    if after != report.get(label + "_before"):
                        report["failure"] = report["failure"] or label + "-changed"
                except (OSError, ValueError):
                    report[label + "_after"] = None
                    report["failure"] = report["failure"] or label + "-after-unavailable"
                finally:
                    close_fd(fd)
        report["streams"] = {}
        report["samples"] = {"count": sample_count, "bytes": sample_bytes}
        # Only files created by this owner are read back; a refused existing
        # output is never reclassified as our captured bytes. Read held FDs and
        # bind their still-current path/inode, rather than following a new link.
        for name, stream in files.items():
            try:
                stream.flush()
                cap = SAMPLE_CAP if name == "samples" else caps[name]
                observed = fd_hash(stream.fileno(), cleanup_deadline, cap)
                path = out / ("prove.process-samples.jsonl" if name == "samples"
                              else "prove." + name + ".log")
                require(identity(os.lstat(path)) == identity(os.fstat(stream.fileno())), "captured-path-changed")
                require(observed["bytes"] == (sample_bytes if name == "samples" else stream_sizes[name]),
                        "captured-byte-count-changed")
                if name == "samples":
                    report["samples"]["sha256"] = observed["sha256"]
                else:
                    report["streams"][name] = dict(observed, truncated=truncations[name])
            except (OSError, ValueError):
                report["failure"] = report["failure"] or "capture-after-unavailable"
            finally:
                close_stream(stream)
        if require_phases:
            try:
                report["host_phases"] = phase_readback(out / "prove.host-phases.jsonl", report.get("leader_pid"))
            except (OSError, ValueError):
                report["host_phases"] = {"status": "unavailable-or-over-limit", "complete": False}
            if not report["host_phases"]["complete"]:
                report["failure"] = report["failure"] or "host-phases-incomplete"
        if child is not None and time.monotonic() >= cleanup_deadline:
            failure("cleanup-finalization-timeout")
        row = report["direct_wait4"]
        report["returncode"] = (124 if report["timed_out"] else 125 if report["failure"]
                                else row["returncode"] if row is not None else 125)
        report["wall_seconds"] = time.monotonic() - started
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        try:
            report_file.write(encoded_report(report).decode("utf-8"))
        finally:
            report_file.close()
    return report


def validate_prove_call(command, out, name, timeout, proof_profile):
    budget = profile_budget(proof_profile)
    require(name == "prove" and timeout == budget
            and (proof_profile == ORIGINAL_PROFILE or type(timeout) is int) and len(command) == 7
            and Path(command[0]).name == "trnm-w1-risc0-host"
            and command[1] == "prove" and command[5] == "18",
            "explicit-original-proof-profile" if proof_profile == ORIGINAL_PROFILE else "explicit-cost-only-proof-profile")
    out = Path(out)
    require(all(Path(command[index]).absolute() == (out / filename).absolute()
                for index, filename in ((3, "guest.bin"), (4, "input.bin"), (6, "receipt.bin"))),
            "explicit-workflow-input-output-paths")


def observed_prove(command, out, name, timeout, *, proof_profile=ORIGINAL_PROFILE):
    validate_prove_call(command, out, name, timeout, proof_profile)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "prove.process.json").open("x") as stream:
        observed = run_observed(command, out, timeout, backend_index=2, require_phases=True,
                                proof_profile=proof_profile)
        row = observed["direct_wait4"]
        legacy = {"schema": "pon-w1-observed-process-v2", "command": command,
                  "started_utc": observed["started_utc"], "finished_utc": observed["finished_utc"],
                  "timeout_seconds": timeout, "source_sha": observed["source_sha"],
                  "returncode": observed["returncode"], "timed_out": observed["timed_out"],
                  "wall_seconds": observed["wall_seconds"],
                  "user_cpu_seconds": None if row is None else row["user_cpu_seconds"],
                  "system_cpu_seconds": None if row is None else row["system_cpu_seconds"],
                  "max_waited_descendant_rss_kib": None if row is None else row["max_rss_kib"],
                  "rss_scope": "direct host wait4, potentially including descendants it waited; not whole-family peak",
                  "cpu_scope": "direct host wait4 only; adopted rows separate; total family unknown",
                  "supplement": "prove.observer.json",
                  "supplement_sha256": hashlib.sha256(encoded_report(observed)).hexdigest(),
                  "family_capture_complete": False, "complete_family_cpu_seconds": None,
                  "consensus_authority": False}
        if proof_profile == COST_PROFILE:
            legacy.update(schema="pon-w1-cost-observed-process-v1",
                          proof_profile=COST_PROFILE, original_5400s_budget_passed=False)
        json.dump(legacy, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps(legacy, indent=2))
    return observed["returncode"]


if __name__ == "__main__":
    if os.environ.get("TRNM_W1_SHIM") == "1":
        try:
            _shim(sys.argv[1:])
        except (OSError, ValueError, KeyError):
            os.write(2, b"proof observer shim rejected invocation\n")
            raise SystemExit(125)
    raise SystemExit("invoke the explicit --observe-proof option of measure_step.py")
