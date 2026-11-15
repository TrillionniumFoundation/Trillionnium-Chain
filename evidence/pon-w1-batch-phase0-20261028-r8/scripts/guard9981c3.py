#!/usr/bin/env python3
"""One command, one fresh output directory. Linux sampled resource supervisor.

CPU/RSS/disk checks are sampled stop triggers, NOT kernel hard limits. Short
peaks and blocked monitoring syscalls can escape detection. The caller may add
an external wall timeout with enough TERM grace for this supervisor's cleanup.
"""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time


INTERVAL, TERM_GRACE, KILL_GRACE = 0.5, 3.0, 3.0
HZ, PAGE = os.sysconf("SC_CLK_TCK"), os.sysconf("SC_PAGE_SIZE")


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def proc(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return dict(pid=pid, state=fields[0], ppid=int(fields[1]),
                    pgid=int(fields[2]), sid=int(fields[3]), birth=int(fields[19]),
                    cpu_ticks=sum(int(fields[i]) for i in (11, 12, 13, 14)),
                    rss_bytes=max(0, int(fields[21])) * PAGE)
    except (FileNotFoundError, ProcessLookupError):
        return None


def proc_fields(path):
    return dict(line.split(":", 1) for line in path.read_text().splitlines() if ":" in line)


def ns_ids(fields, key):
    return [int(value) for value in fields[key].split()]


def check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise RuntimeError("sampling exceeded its 0.4 second work allowance")


def allocated_bytes(target, deadline=None):
    """du-like allocated size; do not follow symlinks; deduplicate hard links."""
    pending, seen, total = [target], set(), 0
    while pending:
        check_deadline(deadline)
        path = pending.pop()
        try:
            info = path.lstat()
            key = (info.st_dev, info.st_ino)
            if key in seen:
                continue
            seen.add(key)
            total += info.st_blocks * 512
            if stat.S_ISDIR(info.st_mode):
                with os.scandir(path) as entries:
                    for entry in entries:
                        check_deadline(deadline)
                        pending.append(Path(entry.path))
        except (FileNotFoundError, NotADirectoryError):
            pass  # Concurrent removals/renames are normal in a build tree.
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--wall-seconds", type=float, required=True)
    parser.add_argument("--cpu-seconds", type=float, required=True)
    parser.add_argument("--rss-bytes", type=int, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-growth-bytes", type=int, required=True)
    parser.add_argument("--min-free-bytes", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    limits = {k: v for k, v in vars(args).items() if k not in ("out", "target", "command")}
    if not command or any(not math.isfinite(v) or v <= 0 for v in limits.values()):
        parser.error("a command and finite, strictly positive limits are required")
    out, target = Path(args.out).absolute(), Path(args.target).resolve()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    self_status = proc_fields(Path("/proc/self/status"))
    self_proc_pid = int(self_status["Pid"])
    self_nspids = ns_ids(self_status, "NSpid")
    ns_index = len(self_nspids) - 1
    self_pid_namespace = os.readlink("/proc/self/ns/pid")
    if self_nspids[-1] != os.getpid() or self_nspids[0] != self_proc_pid:
        raise RuntimeError("unverifiable supervisor PID namespace mapping; no command launched")
    started, child, root_code, root_proc_pid = None, None, None, None
    root_birth = proc(self_proc_pid)["birth"]
    known, seen, reaped, errors = {}, {}, [], []
    reaped_cpu, peak_cpu, peak_rss, peak_growth, wait4_peak_rss = 0.0, 0.0, 0, 0, 0
    stopped, reason, term_at, kill_at = False, None, None, None
    requested_signal, latest = [None], None
    samples = (out / "samples.jsonl").open("x", buffering=1)
    events = (out / "events.jsonl").open("x", buffering=1)

    def event(kind, **values):
        events.write(json.dumps(dict(kind=kind, monotonic=time.monotonic(), **values)) + "\n")

    def reap():
        nonlocal reaped_cpu, root_code, wait4_peak_rss
        while True:
            try:
                pid, status, usage = os.wait4(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                break
            item = dict(pid=pid, returncode=os.waitstatus_to_exitcode(status),
                        user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
                        maxrss_kib=usage.ru_maxrss)
            reaped.append(item)
            reaped_cpu += usage.ru_utime + usage.ru_stime
            wait4_peak_rss = max(wait4_peak_rss, usage.ru_maxrss * 1024)
            event("wait4", **item)
            if child is not None and pid == child.pid:
                root_code = child.returncode = item["returncode"]

    def capture(deadline):
        all_procs = {}
        for name in os.listdir("/proc"):
            check_deadline(deadline)
            if name.isdecimal():
                try:
                    item = proc(int(name))
                except PermissionError:
                    if int(name) in known:
                        raise
                    continue
                if item:
                    all_procs[item["pid"]] = item
        owned = {pid for pid, item in all_procs.items()
                 if (pid in known and item["birth"] == known[pid]["birth"])
                 or (item["ppid"] == self_proc_pid and item["birth"] >= root_birth)}
        changed = True
        while changed:
            before = len(owned)
            group_anchored = any(all_procs[p]["pgid"] == root_proc_pid and
                                 all_procs[p]["sid"] == root_proc_pid for p in owned)
            owned.update(pid for pid, item in all_procs.items()
                         if item["birth"] >= root_birth and
                         (item["ppid"] in owned or (group_anchored and
                          item["pgid"] == root_proc_pid and item["sid"] == root_proc_pid)))
            changed = len(owned) != before
        def depth(pid):
            lineage = set()
            while pid in owned and pid not in lineage:
                lineage.add(pid)
                pid = all_procs[pid]["ppid"]
            return len(lineage)
        current = {}
        # Parent-before-child rereads prevent adding an already reaped child's
        # /proc CPU to the same CPU newly transferred into its parent's cutime.
        for pid in sorted(owned, key=depth):
            check_deadline(deadline)
            item = proc(pid)
            if not item or item["birth"] != all_procs[pid]["birth"]:
                continue
            old = known.get(pid)
            if old and old["birth"] != item["birth"]:
                os.close(known.pop(pid)["fd"])
                old = None
            if old is None:
                try:
                    status = proc_fields(Path(f"/proc/{pid}/status"))
                    namespace = os.readlink(f"/proc/{pid}/ns/pid")
                    nspids = ns_ids(status, "NSpid")
                    local_pid = nspids[ns_index]
                    fd = os.pidfd_open(local_pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                verified = proc(pid)
                fdinfo = proc_fields(Path(f"/proc/self/fdinfo/{fd}"))
                if (not verified or verified["birth"] != item["birth"] or
                        int(fdinfo["Pid"]) != pid or ns_ids(fdinfo, "NSpid") != nspids):
                    os.close(fd)
                    if verified and verified["birth"] == item["birth"]:
                        raise RuntimeError(f"pidfd mapping verification failed for proc PID {pid}")
                    continue
                known[pid] = dict(birth=item["birth"], fd=fd, local_pid=local_pid)
                seen[f'{pid}:{item["birth"]}'] = dict(pid=pid, birth=item["birth"],
                                                    local_pid=local_pid, pid_namespace=namespace)
                if (namespace != self_pid_namespace or ns_ids(status, "NSpgid")[0] != item["pgid"]
                        or ns_ids(status, "NSsid")[0] != item["sid"]):
                    raise RuntimeError(f"owned PID {pid} changed namespace or process group during verification")
            item["local_pid"] = known[pid]["local_pid"]
            current[pid] = item
        for pid in list(known):
            if pid not in current:
                # Keep the pidfd until a fresh birth check proves this identity
                # no longer occupies /proc; pidfds never signal a reused PID.
                item = proc(pid)
                if item is None or item["birth"] != known[pid]["birth"]:
                    os.close(known.pop(pid)["fd"])
        return list(current.values())

    def send(sig):
        for pid, identity in list(known.items()):
            try:
                signal.pidfd_send_signal(identity["fd"], sig)
                event("signal", pid=pid, local_pid=identity["local_pid"], birth=identity["birth"], signal=sig)
            except ProcessLookupError:
                pass
            except OSError as exc:
                errors.append(f"signal {sig} to {pid}: {exc}")

    declaration = dict(schema=1, command=command, cwd=os.getcwd(), target=str(target),
                       limits=limits, interval_seconds=INTERVAL,
                       term_grace_seconds=TERM_GRACE, kill_reap_grace_seconds=KILL_GRACE,
                       source_path=str(Path(__file__).resolve()),
                       source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       clock_ticks_per_second=HZ, page_bytes=PAGE, supervisor_pid=os.getpid(),
                       supervisor_proc_pid=self_proc_pid, supervisor_nspids=self_nspids,
                       supervisor_pid_namespace=self_pid_namespace,
                       pid_fields="pid/ppid/pgid/sid are procfs-visible; local_pid is signal namespace PID",
                       guarantee="sampled detection and stop; not kernel CPU/RSS/disk hard limits",
                       ownership="one new session, tracked descendants, process-local subreaper, pidfds",
                       cpu_accounting="wait4 reaped subtrees plus live inclusive /proc ticks; monotone max",
                       rss_accounting="sum of sampled process RSS; shared pages may be counted repeatedly",
                       disk_accounting="allocated st_blocks, unique inodes, no intentional symlink following",
                       source_commit_freeze="caller responsibility; this file records only source hash")
    write_json(out / "declaration.json", declaration)
    try:
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise RuntimeError("Linux pidfd support is required")
        self_fd = os.pidfd_open(os.getpid())
        try:
            fdinfo = proc_fields(Path(f"/proc/self/fdinfo/{self_fd}"))
            if int(fdinfo["Pid"]) != self_proc_pid or ns_ids(fdinfo, "NSpid") != self_nspids:
                raise RuntimeError("pidfd/procfs namespace mapping is unverified; command not launched")
        finally:
            os.close(self_fd)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER; process-local, no root.
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
        baseline = allocated_bytes(target)
        disk_path = target
        while not disk_path.exists():
            disk_path = disk_path.parent
        initial_free = shutil.disk_usage(disk_path).free
        declaration.update(target_baseline_bytes=baseline, disk_probe_path=str(disk_path),
                           initial_free_bytes=initial_free)
        write_json(out / "declaration.json", declaration)
        if initial_free <= args.min_free_bytes:
            raise RuntimeError("initial disk free space is at/below floor; command not launched")
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, lambda number, frame: requested_signal.__setitem__(0, number))
        with (out / "stdout.log").open("xb", buffering=0) as stdout, \
             (out / "stderr.log").open("xb", buffering=0) as stderr:
            started = time.monotonic()
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, start_new_session=True, close_fds=True)
            root_fd = os.pidfd_open(child.pid)
            root_info = proc_fields(Path(f"/proc/self/fdinfo/{root_fd}"))
            root_proc_pid = int(root_info["Pid"])
            first = proc(root_proc_pid)
            if first is None:
                os.close(root_fd)
                raise RuntimeError("launched child identity unavailable")
            root_birth = first["birth"]
            known[root_proc_pid] = dict(birth=root_birth, fd=root_fd, local_pid=child.pid)
            seen[f"{root_proc_pid}:{root_birth}"] = dict(pid=root_proc_pid, birth=root_birth,
                                                       local_pid=child.pid, pid_namespace=self_pid_namespace)
            root_status = proc_fields(Path(f"/proc/{root_proc_pid}/status"))
            if (ns_ids(root_status, "NSpid") != ns_ids(root_info, "NSpid") or
                    ns_ids(root_info, "NSpid")[ns_index] != child.pid or
                    os.readlink(f"/proc/{root_proc_pid}/ns/pid") != self_pid_namespace or
                    ns_ids(root_status, "NSpgid")[ns_index] != child.pid or
                    ns_ids(root_status, "NSsid")[ns_index] != child.pid or
                    first["pgid"] != root_proc_pid or first["sid"] != root_proc_pid):
                raise RuntimeError("launched child namespace/session verification failed")
            declaration.update(root_pid=child.pid, root_proc_pid=root_proc_pid, root_birth=root_birth,
                               root_pgid=root_proc_pid, root_sid=root_proc_pid, started_monotonic=started)
            write_json(out / "declaration.json", declaration)
            while True:
                tick = time.monotonic()
                if stopped and kill_at is None and tick - term_at >= TERM_GRACE - INTERVAL:
                    kill_at = tick
                    send(signal.SIGKILL)
                reap()
                try:
                    members = capture(tick + 0.4)
                    cpu = reaped_cpu + sum(p["cpu_ticks"] for p in members) / HZ
                    rss = sum(p["rss_bytes"] for p in members)
                    free = shutil.disk_usage(disk_path).free
                    size = allocated_bytes(target, tick + 0.4)
                    elapsed = time.monotonic() - started
                    peak_cpu, peak_rss = max(peak_cpu, cpu), max(peak_rss, rss)
                    growth = max(0, size - baseline)
                    peak_growth = max(peak_growth, growth)
                    latest = dict(elapsed_seconds=elapsed, cpu_seconds=cpu, cpu_peak_seconds=peak_cpu,
                                  reaped_cpu_seconds=reaped_cpu, rss_bytes=rss, target_bytes=size,
                                  wait4_peak_process_rss_bytes=wait4_peak_rss,
                                  target_growth_bytes=growth, free_bytes=free, processes=members,
                                  scan_seconds=time.monotonic() - tick)
                    samples.write(json.dumps(latest) + "\n")
                    breaches = [name for name, yes in (
                        ("wall", elapsed >= args.wall_seconds), ("cpu", peak_cpu >= args.cpu_seconds),
                        ("rss", rss >= args.rss_bytes), ("wait4_rss", wait4_peak_rss >= args.rss_bytes),
                        ("target_growth", growth >= args.target_growth_bytes),
                        ("disk_floor", free <= args.min_free_bytes)) if yes]
                    if requested_signal[0]:
                        breaches.insert(0, f"supervisor_signal_{requested_signal[0]}")
                    if breaches and not stopped:
                        stopped, reason, term_at = True, ",".join(breaches), time.monotonic()
                        event("stop_requested", reason=reason)
                        send(signal.SIGTERM)
                except Exception as exc:
                    errors.append(repr(exc))
                    if not stopped:
                        stopped, reason, term_at = True, "monitor_error", time.monotonic()
                        event("stop_requested", reason=reason, error=repr(exc))
                        send(signal.SIGTERM)
                now = time.monotonic()
                if root_code is not None and not known:
                    break
                if stopped:
                    if kill_at is not None or now - term_at >= TERM_GRACE - INTERVAL:
                        if kill_at is None:
                            kill_at = now
                        send(signal.SIGKILL)
                    else:
                        send(signal.SIGTERM)  # Include newly discovered descendants.
                    if kill_at is not None and now - kill_at >= KILL_GRACE:
                        break
                time.sleep(max(0, INTERVAL - (time.monotonic() - tick)))
    except Exception as exc:
        errors.append(repr(exc))
        stopped, reason = True, "startup_or_supervisor_error"
        if child is not None:
            # Unexpected startup failures still clean up the launched identity.
            if root_code is None and root_proc_pid not in known:
                # This direct child has not been wait4-reaped, so its PID cannot
                # be reused even if establishing its initial pidfd failed.
                try:
                    os.kill(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            send(signal.SIGTERM)
            term_at = time.monotonic()
            until = term_at + TERM_GRACE - INTERVAL
            while time.monotonic() < until:
                reap()
                try:
                    capture(time.monotonic() + 0.4)
                except Exception as cleanup_exc:
                    errors.append(repr(cleanup_exc))
                send(signal.SIGTERM)
                if root_code is not None and not known:
                    break
                time.sleep(0.1)
            kill_at = time.monotonic()
            send(signal.SIGKILL)
            if root_code is None and root_proc_pid not in known:
                try:
                    os.kill(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            until = time.monotonic() + KILL_GRACE
            while time.monotonic() < until and (root_code is None or known):
                reap()
                try:
                    capture(time.monotonic() + 0.4)
                except Exception as cleanup_exc:
                    errors.append(repr(cleanup_exc))
                send(signal.SIGKILL)
                time.sleep(0.1)
    reap()
    for final_breach, breached in (("wait4_rss", wait4_peak_rss >= args.rss_bytes),
                                    ("cpu", reaped_cpu >= args.cpu_seconds)):
        if breached and final_breach not in (reason or "").split(","):
            stopped = True
            reason = ",".join(filter(None, (reason, final_breach)))
    remaining = []
    for pid, identity in known.items():
        try:
            item = proc(pid)
        except Exception as exc:
            errors.append(repr(exc))
            item = dict(pid=pid, birth=identity["birth"], identity_unreadable=True)
        if item and item["birth"] == identity["birth"]:
            remaining.append(item)
        os.close(identity["fd"])
    incomplete = bool(remaining) or (child is not None and root_code is None)
    status = ("cleanup_incomplete" if incomplete else "stopped" if stopped else
              "completed" if root_code == 0 else "command_failed")
    result = dict(status=status, stop_reason=reason, command_returncode=root_code,
                  elapsed_seconds=None if started is None else time.monotonic() - started,
                  cpu_peak_seconds=max(peak_cpu, reaped_cpu), sampled_peak_rss_bytes=peak_rss,
                  wait4_peak_process_rss_bytes=wait4_peak_rss,
                  sampled_peak_target_growth_bytes=peak_growth, remaining_owned_processes=remaining,
                  seen_identities=list(seen.values()), wait4_records=reaped, errors=errors,
                  term_monotonic=term_at, kill_monotonic=kill_at, last_sample=latest,
                  source_sha256=declaration["source_sha256"], declaration_file="declaration.json",
                  assessment="supervision result only; no build, cryptographic, or proof validity claim")
    write_json(out / "result.json", result)
    samples.close()
    events.close()
    print(json.dumps(dict(status=status, reason=reason, result=str(out / "result.json"))))
    return 126 if incomplete else 125 if errors else 124 if stopped else 0 if root_code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
