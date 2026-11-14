#!/usr/bin/env python3
"""Prospective Linux subreaper around one new owner/target command.

This executable is the sole wait4 owner of its own root and adopted children.
It must not be imported and activated inside an existing Popen owner. Internal
Popen waits in the wrapped command remain theirs. No existing operation is
resumed, redispatched, requalified or paid by this collector.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import select
import selectors
import signal
import stat
import sys
import time

SCHEMA = "TRNM-W1-OWNED-PROCESS-COLLECTOR1"
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
WAIT_ALL = 0x40000000  # Linux __WALL: include clone children, not only SIGCHLD.
CANCEL_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
MAX_JSON = 16 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def bounded(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular or kernel pseudo-file required")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "bounded read exceeded: " + str(path))
    return raw


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return fd_digest(fd)
    finally:
        os.close(fd)


def fd_digest(fd):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024 * 1024,
            "bounded regular file required for digest")
    value = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    size = 0
    for block in iter(lambda: os.read(fd, 65536), b""):
        size += len(block)
        require(size <= 512 * 1024 * 1024, "file grew beyond digest bound")
        value.update(block)
    after = os.fstat(fd)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "file changed during digest")
    os.lseek(fd, 0, os.SEEK_SET)
    return value.hexdigest()


def write_new(path, value):
    raw = canonical(value) + b"\n"
    require(len(raw) <= MAX_JSON, "bounded JSON output exceeded")
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"sha256": digest(raw), "bytes": len(raw)}


def boot_id():
    return bounded("/proc/sys/kernel/random/boot_id", 128).decode().strip()


def process_identity(pid, boot):
    raw = bounded(f"/proc/{pid}/stat", 8192).decode()
    tail = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "start_ticks": int(tail[19]), "boot_id": boot,
            "parent": int(tail[1]), "state": tail[0]}


def same_identity(a, b):
    return all(a.get(key) == b.get(key) for key in ("pid", "start_ticks", "boot_id"))


def stable_pidfd(who, boot):
    """Bind before/after birth identity around pidfd_open; never fall back to PID kill."""
    fd = os.pidfd_open(who["pid"])
    try:
        require(same_identity(who, process_identity(who["pid"], boot)), "PID birth changed while opening pidfd")
    except BaseException:
        os.close(fd)
        raise
    return fd


def fd_ready(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poll.poll(0))


def enable_subreaper():
    require(sys.platform == "linux", "Linux subreaper required; no successful fallback")
    for name in ("fork", "waitid", "wait4", "pidfd_open", "WNOWAIT", "P_ALL"):
        require(hasattr(os, name), "required Linux process API unavailable: " + name)
    require(hasattr(signal, "pidfd_send_signal") and os.execve in os.supports_fd,
            "pidfd signalling and fd-bound exec required")
    require(len(list(Path("/proc/self/task").iterdir())) == 1, "standalone single-threaded collector required")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    if result != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
    value = ctypes.c_int()
    result = libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(value), 0, 0, 0)
    require(result == 0 and value.value == 1, "subreaper readback failed")
    # Do not consume somebody else's child. This program must start with none.
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WAIT_ALL)
    except ChildProcessError:
        return
    raise ValueError("collector already owns a child; refuse to steal an existing wait status")


def cgroup_snapshot():
    """Read bounded shared scope counters; never use emptiness as wait/reap evidence."""
    result = {"monotonic_ns": time.monotonic_ns(), "snapshot_complete": False,
              "task_exclusive": False, "billing_qualified": False}
    try:
        membership = bounded("/proc/self/cgroup", 8192).decode().strip().splitlines()
        require(len(membership) == 1 and membership[0].startswith("0::/"), "unambiguous cgroup-v2 required")
        relative = membership[0][3:]
        require(".." not in Path(relative).parts, "unsafe cgroup path")
        mounts = [line.split() for line in bounded("/proc/self/mountinfo", 512 * 1024).decode().splitlines()
                  if " - cgroup2 " in line]
        require(len(mounts) == 1 and mounts[0][3] == "/" and mounts[0][4] == "/sys/fs/cgroup",
                "original cgroup mount not fully visible")
        root = Path("/sys/fs/cgroup") / relative.lstrip("/")
        info = root.stat()
        result.update(relative=relative, directory_device=info.st_dev, directory_inode=info.st_ino)
        groups = [root]
        records = []
        for group in groups:
            children = sorted(p for p in group.iterdir() if p.is_dir())
            require(len(groups) + len(children) <= 128, "cgroup subtree exceeds snapshot bound")
            groups.extend(children)
            members = bounded(group / "cgroup.procs")
            values = members.decode().split()
            require(len(values) <= 4096 and all(x.isdigit() for x in values), "cgroup member bound/format")
            item = {"relative": str(group.relative_to(root)), "direct_member_count": len(values),
                    "direct_members_sha256": digest(members),
                    "events": bounded(group / "cgroup.events", 4096).decode().strip()}
            for name in ("cpu.stat", "cpu.max", "memory.peak", "memory.max"):
                try:
                    item[name] = bounded(group / name, 4096).decode().strip()
                except FileNotFoundError:
                    item[name] = None
            records.append(item)
        after = root.stat()
        require((info.st_dev, info.st_ino) == (after.st_dev, after.st_ino), "cgroup root changed during snapshot")
        result.update(snapshot_complete=True, groups=records)
    except (OSError, ValueError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    return result


class Collector:
    def __init__(self, args):
        self.args = args
        self.out = args.out
        self.started = time.monotonic_ns()
        self.boot = boot_id()
        self.identity = process_identity(os.getpid(), self.boot)
        self.owner = process_identity(os.getppid(), self.boot)
        self.owner_fd = stable_pidfd(self.owner, self.boot)
        self.deadline = args.deadline_monotonic_ns
        self.signal_received = None
        self.cause = None
        self.error = None
        self.cleanup_started = None
        self.owned = {}
        self.observations = []
        self.reaped = []
        self.root = None
        self.root_pid = None
        self.root_returncode = None
        self.root_exec_released = False
        self.root_exec_gate_closed = False
        self.echild = None
        self.records_truncated = False
        self.events_count = 0
        self.events_bytes = 0
        self.events = (self.out / "events.jsonl").open("xb")
        self.selector = selectors.DefaultSelector()
        self.streams = {}
        self.exec_fd = None
        self.before = cgroup_snapshot()
        self.intent_pin = None
        self.discovery_mode = ("task-children" if Path(f"/proc/self/task/{os.getpid()}/children").is_file()
                               else "bounded-proc-stat-index")
        for sig in CANCEL_SIGNALS:
            signal.signal(sig, self.receive_signal)

    def receive_signal(self, signum, unused):
        if self.signal_received is None:
            self.signal_received = {"signal": signum, "monotonic_ns": time.monotonic_ns()}

    def emit(self, kind, value):
        if self.records_truncated:
            return
        raw = canonical({"sequence": self.events_count, "kind": kind,
                         "monotonic_ns": time.monotonic_ns(), "value": value}) + b"\n"
        if self.events_count >= self.args.max_processes * 12 + 64 or self.events_bytes + len(raw) > 4 * 1024 * 1024:
            self.records_truncated = True
            self.stop("observation-limit")
            return
        try:
            self.events.write(raw)
            self.events.flush()
            os.fsync(self.events.fileno())
        except OSError as error:
            self.records_truncated = True
            self.error = self.error or f"event publication failed: {error}"
            if self.cause is None:
                self.cause = "event-publication-failed"
                self.cleanup_started = time.monotonic_ns()
            return
        self.events_count += 1
        self.events_bytes += len(raw)

    def stop(self, cause):
        if self.cause is None:
            self.cause = cause
            self.cleanup_started = time.monotonic_ns()
            self.emit("cleanup-started", {"cause": cause, "original_deadline_monotonic_ns": self.deadline})

    def remember(self, who, source):
        key = (who["pid"], who["start_ticks"])
        if key in self.owned:
            return
        if len(self.observations) >= self.args.max_processes:
            self.records_truncated = True
            self.stop("process-observation-limit")
            return
        fd = stable_pidfd(who, self.boot)
        self.owned[key] = {"identity": who, "pidfd": fd, "signals": set()}
        item = {"identity": who, "first_observed_from": source,
                "observed_monotonic_ns": time.monotonic_ns()}
        self.observations.append(item)
        self.emit("process-observed", item)

    def discover(self):
        # Walk only our current descendant tree, including children of threads.
        index = None
        if self.discovery_mode == "bounded-proc-stat-index":
            # CONFIG_CHECKPOINT_RESTORE may omit /proc/.../children. The
            # fallback is explicit in the intent and never signals unrelated
            # processes: only ancestry-checked identities receive pidfds.
            paths = [path for path in Path("/proc").iterdir() if path.name.isdigit()]
            require(len(paths) <= 16384, "proc stat index bound")
            index = {}
            for path in paths:
                try:
                    who = process_identity(int(path.name), self.boot)
                    index.setdefault(who["parent"], []).append(who)
                except (FileNotFoundError, ProcessLookupError):
                    continue
        queue = [self.identity]
        visited = set()
        while queue:
            parent = queue.pop()
            key = (parent["pid"], parent["start_ticks"])
            if key in visited:
                continue
            visited.add(key)
            require(len(visited) <= self.args.max_processes + 1, "descendant traversal bound")
            try:
                current = process_identity(parent["pid"], self.boot)
                if not same_identity(parent, current):
                    continue  # Reused PID is not a descendant identity.
                child_pids = set()
                if index is not None:
                    child_pids.update(who["pid"] for who in index.get(parent["pid"], []))
                else:
                    tasks = list(Path(f"/proc/{parent['pid']}/task").iterdir())
                    require(len(tasks) <= 4096, "thread traversal bound")
                    for task in tasks:
                        try:
                            raw = bounded(task / "children", 65536).decode().split()
                            require(len(raw) <= self.args.max_processes, "child traversal bound")
                            child_pids.update(map(int, raw))
                        except FileNotFoundError:
                            continue
                for pid in child_pids:
                    try:
                        who = process_identity(pid, self.boot)
                        # PPID may already have changed to us after adoption.
                        if who["parent"] not in (parent["pid"], self.identity["pid"]):
                            continue
                        if who["parent"] != self.identity["pid"]:
                            require(same_identity(parent, process_identity(parent["pid"], self.boot)),
                                    "parent PID birth changed during descendant discovery")
                        self.remember(who, {"parent": parent["pid"], "kind": "proc-descendant"})
                        queue.append(who)
                    except (FileNotFoundError, ProcessLookupError):
                        continue
            except (FileNotFoundError, ProcessLookupError):
                continue
        for key, item in list(self.owned.items()):
            if fd_ready(item["pidfd"]):
                # A descendant reaped by its own parent need not be waitable here.
                # Keep its observed identity, but release the completed pidfd.
                os.close(item["pidfd"])
                del self.owned[key]

    def reap_available(self):
        for _ in range(self.args.max_processes + 1):
            try:
                info = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WAIT_ALL)
            except ChildProcessError:
                # This exact syscall is the recorded no-unwaited-child evidence.
                try:
                    os.wait4(-1, os.WNOHANG | WAIT_ALL)
                except ChildProcessError:
                    self.echild = {"syscall": "wait4(-1, WNOHANG | __WALL)", "errno": errno.ECHILD,
                                   "monotonic_ns": time.monotonic_ns(), "boot_id": self.boot}
                    return True
                raise RuntimeError("wait domain changed between waitid ECHILD and wait4")
            if info is None:
                return False
            who = process_identity(info.si_pid, self.boot)
            require(who["parent"] == os.getpid() and who["state"] in ("Z", "X"), "waitable child identity mismatch")
            fd = stable_pidfd(who, self.boot)
            try:
                # WNOWAIT retains the zombie and PID until this sole waiter reaps.
                require(same_identity(who, process_identity(info.si_pid, self.boot)), "waitid/wait4 birth mismatch")
                pid, status, usage = os.wait4(info.si_pid, os.WNOHANG | WAIT_ALL)
                require(pid == who["pid"] and (os.WIFEXITED(status) or os.WIFSIGNALED(status)), "wait4 terminal mismatch")
                code = os.waitstatus_to_exitcode(status)
                expected = info.si_status if info.si_code == os.CLD_EXITED else -info.si_status
                require(code == expected, "waitid/wait4 exit status mismatch")
            finally:
                os.close(fd)
            record = {"identity_before_reap": who, "waitid_si_code": info.si_code,
                      "waitid_si_status": info.si_status, "wait4_status": status, "returncode": code,
                      "reaped_monotonic_ns": time.monotonic_ns(),
                      "rusage": {"user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
                                 "max_single_process_rss_bytes": usage.ru_maxrss * 1024}}
            if len(self.reaped) < self.args.max_processes:
                self.reaped.append(record)
                self.emit("child-reaped", record)
            else:
                self.records_truncated = True
                self.stop("reaped-record-limit")
            if who["pid"] == self.root_pid:
                if self.root is None:
                    self.root = who
                require(same_identity(who, self.root), "root birth identity changed before reaping")
                self.root_returncode = code
            key = (who["pid"], who["start_ticks"])
            held = self.owned.pop(key, None)
            if held is not None:
                os.close(held["pidfd"])
        return False

    def signal_owned(self):
        elapsed = time.monotonic_ns() - self.cleanup_started
        sig = signal.SIGKILL if elapsed >= min(250_000_000, int(self.args.cleanup_grace_seconds * 500_000_000)) else signal.SIGTERM
        for item in list(self.owned.values()):
            # A closed, never-released exec gate already tells this root to exit
            # with 125. Do not race that refusal with TERM before it can read
            # EOF. The original KILL escalation and total cleanup bound remain.
            if (sig == signal.SIGTERM and self.root_exec_gate_closed
                    and not self.root_exec_released
                    and item["identity"]["pid"] == self.root_pid):
                continue
            if sig in item["signals"]:
                continue
            item["signals"].add(sig)
            try:
                signal.pidfd_send_signal(item["pidfd"], sig)
                outcome = "sent"
            except ProcessLookupError:
                outcome = "already-exited"
            self.emit("signal", {"identity": item["identity"], "signal": sig, "outcome": outcome,
                                 "binding": "retained pidfd; no kill(pid) or killpg fallback"})

    def drain(self, timeout=0):
        for key, unused in self.selector.select(timeout):
            stream = self.streams[key.data]
            for _ in range(8):
                try:
                    raw = os.read(key.fd, 65536)
                except BlockingIOError:
                    break
                if not raw:
                    self.selector.unregister(key.fd)
                    os.close(key.fd)
                    stream["eof"] = True
                    break
                stream["seen_bytes"] += len(raw)
                room = max(0, self.args.max_log_bytes - stream["stored_bytes"])
                kept = raw[:room]
                stream["file"].write(kept)
                stream["stored_bytes"] += len(kept)
                if len(kept) < len(raw):
                    stream["truncated"] = True
                    self.stop("output-limit")

    def launch(self):
        executable = Path(self.args.command[0])
        require(executable.is_absolute() and not executable.is_symlink(), "absolute regular ELF executable required")
        self.exec_fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(self.exec_fd)
        require(stat.S_ISREG(info.st_mode) and os.pread(self.exec_fd, 4, 0) == b"\x7fELF", "pinned ELF required; run scripts via pinned Python")
        require(fd_digest(self.exec_fd) == self.args.executable_sha256, "executable SHA-256 mismatch")
        self.executable_info = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
        for raw in self.args.env:
            key, separator, value = raw.partition("=")
            require(separator and key in {"PATH", "LANG", "LC_ALL", "TMPDIR", "RAYON_NUM_THREADS", "RUST_LOG", "RISC0_HOME", "PYTHONDONTWRITEBYTECODE"}
                    and "\x00" not in value and len(value) <= 4096, "explicit bounded environment key required")
            env[key] = value
        intent = {"schema": SCHEMA + "/intent", "collector_identity": self.identity, "owner_identity": self.owner,
                  "original_deadline_monotonic_ns": self.deadline, "original_boot_id": self.boot,
                  "started_monotonic_ns": self.started,
                  "command": self.args.command, "cwd": str(self.args.cwd), "environment": env,
                  "executable_sha256": self.args.executable_sha256, "executable_stat": list(self.executable_info),
                  "subreaper_readback": True, "initial_wait_domain_empty": True,
                  "process_discovery_mode": self.discovery_mode,
                  "max_log_bytes_per_stream": self.args.max_log_bytes, "max_process_records": self.args.max_processes,
                  "cleanup_grace_seconds": self.args.cleanup_grace_seconds, "cgroup_before": self.before,
                  "gpu_ns": None, "can_authorize_payment": False}
        self.intent_pin = write_new(self.out / "intent.json", intent)
        self.emit("intent", self.intent_pin)
        readers, writers = {}, {}
        for name in ("stdout", "stderr"):
            reader, writer = os.pipe2(os.O_CLOEXEC)
            readers[name], writers[name] = reader, writer
            os.set_blocking(reader, False)
            self.streams[name] = {"file": (self.out / (name + ".log")).open("xb"),
                                  "seen_bytes": 0, "stored_bytes": 0, "truncated": False, "eof": False}
            self.selector.register(reader, selectors.EVENT_READ, name)
        gate_reader, gate_writer = os.pipe2(os.O_CLOEXEC)
        require(time.monotonic_ns() < self.deadline and not fd_ready(self.owner_fd) and self.signal_received is None,
                "owner/deadline/cancel pre-exec gate failed")
        pid = os.fork()
        if pid == 0:
            try:
                for sig in (*CANCEL_SIGNALS, signal.SIGCHLD):
                    signal.signal(sig, signal.SIG_DFL)
                signal.signal(signal.SIGPIPE, signal.SIG_DFL)
                os.setsid()
                null = os.open("/dev/null", os.O_RDONLY)
                os.dup2(null, 0)
                os.dup2(writers["stdout"], 1)
                os.dup2(writers["stderr"], 2)
                keep = {0, 1, 2, self.exec_fd, gate_reader}
                for value in os.listdir("/proc/self/fd"):
                    fd = int(value)
                    if fd not in keep:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                if os.read(gate_reader, 1) != b"G":
                    os._exit(125)
                os.close(gate_reader)
                os.chdir(self.args.cwd)
                os.execve(self.exec_fd, self.args.command, env)
            except BaseException as error:
                os.write(2, (f"collector exec failed: {type(error).__name__}: {error}\n").encode()[:4096])
                os._exit(126)
        self.root_pid = pid
        os.close(gate_reader)
        for writer in writers.values():
            os.close(writer)
        try:
            self.root = process_identity(pid, self.boot)
            self.remember(self.root, {"kind": "fork-gated-root"})
            self.emit("root-created", self.root)
            if time.monotonic_ns() >= self.deadline or self.signal_received is not None or fd_ready(self.owner_fd):
                self.stop("pre-exec-gate-closed")
            else:
                os.write(gate_writer, b"G")
                self.root_exec_released = True
                self.emit("root-exec-released", {"identity": self.root})
        finally:
            os.close(gate_writer)
            self.root_exec_gate_closed = True

    def loop(self):
        while True:
            now = time.monotonic_ns()
            if self.signal_received is not None:
                self.stop("cancelled")
            if fd_ready(self.owner_fd):
                self.stop("owner-lost")
            if now >= self.deadline:
                self.stop("original-deadline")
            try:
                done = self.reap_available()
                if done:
                    self.emit("wait-domain-empty", self.echild)
                    break
                self.discover()
                if self.cause is not None:
                    self.signal_owned()
                self.drain(.02)
            except (OSError, ValueError, RuntimeError) as error:
                self.error = self.error or f"{type(error).__name__}: {error}"
                self.stop("collector-error")
                # Existing pidfds remain usable even when /proc traversal fails.
                self.signal_owned()
                self.drain(.02)
            if self.cleanup_started is not None and time.monotonic_ns() >= self.cleanup_started + int(self.args.cleanup_grace_seconds * 1e9):
                self.error = self.error or "cleanup grace exhausted without confirmed ECHILD"
                break
        # With ECHILD the finite command tree has closed its pipe ends. Do not
        # block on a pipe exported to an external process: drain is bounded.
        for _ in range(16):
            self.drain(0)
            if all(value["eof"] for value in self.streams.values()):
                break
        if not all(value["eof"] for value in self.streams.values()):
            self.error = self.error or "output EOF unavailable after bounded terminal drain"
            self.stop("output-closure-unknown")

    def finish(self):
        after = cgroup_snapshot()
        actual = os.fstat(self.exec_fd)
        observed = (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns, actual.st_ctime_ns)
        # Hash the opened inode, not a replacement at the pathname.
        os.lseek(self.exec_fd, 0, os.SEEK_SET)
        if observed != self.executable_info or fd_digest(self.exec_fd) != self.args.executable_sha256:
            self.error = self.error or "executed inode changed"
            self.stop("executable-changed")
        if self.signal_received is not None:
            self.stop("cancelled")
        if time.monotonic_ns() >= self.deadline and self.cause is None:
            self.stop("original-deadline")
        complete = (self.echild is not None and self.root_returncode is not None and self.error is None
                    and not self.records_truncated and boot_id() == self.boot)
        if self.cause == "original-deadline":
            wrapper_code = 124
        elif self.signal_received is not None:
            wrapper_code = 128 + self.signal_received["signal"]
        elif not complete or self.cause is not None:
            wrapper_code = 125
        elif self.root_returncode != 0:
            wrapper_code = self.root_returncode
        elif any(row["returncode"] != 0 for row in self.reaped):
            wrapper_code = 125
        else:
            wrapper_code = 0
        streams = {}
        for name, data in self.streams.items():
            data["file"].flush()
            os.fsync(data["file"].fileno())
            streams[name] = {k: v for k, v in data.items() if k != "file"}
            streams[name]["sha256"] = file_digest(self.out / (name + ".log"))
        self.events.flush()
        os.fsync(self.events.fileno())
        if self.signal_received is not None:
            self.stop("cancelled")
            wrapper_code = 128 + self.signal_received["signal"]
        if time.monotonic_ns() >= self.deadline and self.cause is None:
            self.stop("original-deadline")
            wrapper_code = 124
        report = {"schema": SCHEMA + "/result", "intent": self.intent_pin,
                  "collector_identity": self.identity, "owner_identity": self.owner,
                  "process_discovery_mode": self.discovery_mode,
                  "root_identity": self.root, "root_exec_released": self.root_exec_released,
                  "root_returncode": self.root_returncode, "wrapper_returncode": wrapper_code,
                  "cause": self.cause, "error": self.error, "cancellation": self.signal_received,
                  "original_deadline_monotonic_ns": self.deadline, "original_boot_id": self.boot,
                  "completed_monotonic_ns": time.monotonic_ns(), "final_echild": self.echild,
                  "collector_wait_domain_reaped": complete,
                  "command_success_before_handoff": complete and wrapper_code == 0,
                  "process_observations": self.observations, "wait4_records": self.reaped,
                  "records_truncated": self.records_truncated, "streams": streams,
                  "events": {"sha256": file_digest(self.out / "events.jsonl"), "bytes": self.events_bytes,
                             "count": self.events_count},
                  "cgroup_before": self.before, "cgroup_after": after,
                  "historical_process_tree_reaping_established": False,
                  "all_historical_descendant_identities_enumerated": False,
                  "resource_billing_complete": False, "gpu_ns": None, "can_authorize_payment": False,
                  "may_dispatch_again": False, "result_is_pre_handoff_snapshot": True,
                  "scope": "only children owned/adopted by this surviving single-threaded subreaper in this invocation",
                  "resource_scope": "wait4 records include descendants reaped by each waited child; shared cgroup counters are separate and must not be added",
                  "limitations": ["No sandbox or proof of resistance to an external ptracer, hostile owner, or exported process handles.",
                                  "Descendants reaped by their own parents are not individually enumerated here.",
                                  "No final record after collector SIGKILL/crash means UNKNOWN, regardless of cgroup emptiness.",
                                  "A caller must bind this snapshot to the actual collector terminal status."]}
        write_new(self.out / "result.json", report)
        if self.signal_received is not None and report["cancellation"] is None:
            write_new(self.out / "late-cancellation.json", {"schema": SCHEMA + "/late-cancellation",
                                                          "cancellation": self.signal_received})
            wrapper_code = 128 + self.signal_received["signal"]
        return wrapper_code

    def close(self):
        for key in list(self.selector.get_map().values()):
            os.close(key.fd)
        self.selector.close()
        for stream in self.streams.values():
            stream["file"].close()
        for item in self.owned.values():
            os.close(item["pidfd"])
        self.owned.clear()
        if self.exec_fd is not None:
            os.close(self.exec_fd)
        os.close(self.owner_fd)
        self.events.close()


def parse_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def number(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite JSON number")
        return value
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=number,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    require(type(value) is dict, "collector JSON object required")
    return value


def read_json(path):
    return parse_json(bounded(path, MAX_JSON))


def exact(a, b):
    return canonical(a) == canonical(b)


def valid_identity(value, boot):
    require(type(value) is dict and type(value.get("pid")) is int and value["pid"] > 0
            and type(value.get("start_ticks")) is int and value["start_ticks"] > 0
            and type(value.get("parent")) is int and value["parent"] >= 0
            and value.get("boot_id") == boot and type(value.get("state")) is str
            and value["state"] in {"R", "S", "D", "Z", "X", "T", "t", "I", "W", "P"},
            "strict PID birth identity required")


def read_result(directory, observed_returncode=None, *, observed_boot_id=None,
                observed_completed_monotonic_ns=None, expected_intent_sha256=None):
    """Confirm a surviving collector's wait domain, never a payment or old task.

    Both actual terminal code and the caller's original-clock completion time
    are necessary for command_success. Missing time leaves deadline eligibility
    false even if the recorded wait domain was fully reaped.
    """
    root = Path(directory)
    unknown = {"schema": SCHEMA + "/readback", "terminal_state": "unknown",
               "collector_wait_domain_reaped": False, "command_success": False,
               "deadline_qualified": False, "gpu_ns": None, "resource_billing_complete": False,
               "can_authorize_payment": False}
    if not (root / "result.json").exists():
        return {**unknown, "reason": "no terminal collector record; never infer reaping from absent processes"}
    result = read_json(root / "result.json")
    require(result.get("schema") == SCHEMA + "/result", "collector result namespace")
    pins = {}
    for name, filename, limit in (("intent", "intent.json", MAX_JSON), ("events", "events.jsonl", 4 * 1024 * 1024)):
        raw = bounded(root / filename, limit)
        pin = result.get(name)
        require(type(pin) is dict and type(pin.get("bytes")) is int and pin["bytes"] == len(raw)
                and pin.get("sha256") == digest(raw), "collector raw record digest/length mismatch")
        pins[name] = raw
    if expected_intent_sha256 is not None:
        require(type(expected_intent_sha256) is str and len(expected_intent_sha256) == 64
                and digest(pins["intent"]) == expected_intent_sha256, "caller intent pin mismatch")
    intent = parse_json(pins["intent"])
    require(intent.get("schema") == SCHEMA + "/intent" and intent.get("subreaper_readback") is True
            and intent.get("initial_wait_domain_empty") is True, "collector original intent required")
    boot = intent.get("original_boot_id")
    started = intent.get("started_monotonic_ns")
    deadline = intent.get("original_deadline_monotonic_ns")
    completed = result.get("completed_monotonic_ns")
    require(type(boot) is str and boot and type(started) is int and started > 0
            and type(deadline) is int and deadline > started and type(completed) is int and completed >= started,
            "strict original monotonic clock values required")
    require(result.get("original_boot_id") == boot and type(result.get("original_deadline_monotonic_ns")) is int
            and result["original_deadline_monotonic_ns"] == deadline, "collector original clock changed")
    for name in ("collector_identity", "owner_identity"):
        valid_identity(intent.get(name), boot)
        valid_identity(result.get(name), boot)
        require(exact(intent[name], result[name]), "collector/owner identity differs from original intent")
    valid_identity(result.get("root_identity"), boot)
    collector_pid = result["collector_identity"]["pid"]
    require(result["root_identity"]["parent"] == collector_pid, "root has wrong collector parent")
    for key in ("records_truncated", "root_exec_released", "collector_wait_domain_reaped", "command_success_before_handoff"):
        require(type(result.get(key)) is bool, "strict collector boolean required: " + key)
    for key in ("historical_process_tree_reaping_established", "all_historical_descendant_identities_enumerated",
                "resource_billing_complete", "can_authorize_payment", "may_dispatch_again"):
        require(result.get(key) is False, "unsupported collector qualification: " + key)
    require(result.get("gpu_ns") is None and result.get("result_is_pre_handoff_snapshot") is True,
            "unknown GPU and pre-handoff scope required")
    for key in ("root_returncode", "wrapper_returncode"):
        require(type(result.get(key)) is int and -64 <= result[key] <= 255,
                "strict root/wrapper exit code required")
    require(result.get("error") is None or type(result["error"]) is str,
            "collector error must be null or text")
    require(result.get("cause") is None or type(result["cause"]) is str,
            "collector cause must be null or text")
    cancellation = result.get("cancellation")
    if cancellation is not None:
        require(type(cancellation) is dict and type(cancellation.get("signal")) is int
                and cancellation["signal"] in CANCEL_SIGNALS
                and type(cancellation.get("monotonic_ns")) is int
                and started <= cancellation["monotonic_ns"] <= completed, "strict cancellation observation required")
    rows = result.get("wait4_records")
    max_records = intent.get("max_process_records")
    require(type(max_records) is int and 4 <= max_records <= 4096 and type(rows) is list
            and 1 <= len(rows) <= max_records, "bounded nonempty wait4 records required")
    last = started
    identities = set()
    root_rows = []
    for row in rows:
        require(type(row) is dict, "wait4 row required")
        who = row.get("identity_before_reap")
        valid_identity(who, boot)
        key = (who["pid"], who["start_ticks"])
        require(key not in identities and who["parent"] == collector_pid and who["state"] in {"Z", "X"},
                "duplicate/non-child wait4 identity")
        identities.add(key)
        for name in ("wait4_status", "waitid_si_code", "waitid_si_status", "returncode", "reaped_monotonic_ns"):
            require(type(row.get(name)) is int, "strict wait4 integer required")
        status = row["wait4_status"]
        require(status >= 0 and (os.WIFEXITED(status) or os.WIFSIGNALED(status)), "terminal wait4 status required")
        code = os.waitstatus_to_exitcode(status)
        require(code == row["returncode"] and row["waitid_si_code"] in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}
                and code == (row["waitid_si_status"] if row["waitid_si_code"] == os.CLD_EXITED else -row["waitid_si_status"]),
                "waitid/wait4/root status mismatch")
        require(last <= row["reaped_monotonic_ns"] <= completed, "wait4 monotonic order mismatch")
        last = row["reaped_monotonic_ns"]
        usage = row.get("rusage")
        require(type(usage) is dict and type(usage.get("max_single_process_rss_bytes")) is int
                and usage["max_single_process_rss_bytes"] >= 0
                and all(type(usage.get(k)) in (int, float) and math.isfinite(usage[k]) and usage[k] >= 0
                        for k in ("user_seconds", "system_seconds")), "finite wait4 resource values required")
        if same_identity(who, result["root_identity"]):
            root_rows.append(row)
    require(len(root_rows) == 1 and root_rows[0]["returncode"] == result["root_returncode"], "unique original root wait status required")
    events = [parse_json(line) for line in pins["events"].splitlines()]
    require(type(result["events"].get("count")) is int and result["events"]["count"] == len(events)
            and len(events) <= max_records * 12 + 64, "event count bound/mismatch")
    previous = started
    for index, event in enumerate(events):
        require(type(event.get("sequence")) is int and event["sequence"] == index
                and type(event.get("monotonic_ns")) is int and previous <= event["monotonic_ns"] <= completed,
                "event sequence/clock mismatch")
        previous = event["monotonic_ns"]
    if result["records_truncated"] is False:
        require(exact([e["value"] for e in events if e.get("kind") == "child-reaped"], rows),
                "wait4 rows differ from retained events")
        created = [e["value"] for e in events if e.get("kind") == "root-created"]
        require((len(created) == 1 and exact(created[0], result["root_identity"]))
                or (created == [] and result["error"] is not None and result["root_exec_released"] is False),
                "original root creation event mismatch")
        released = [e for e in events if e.get("kind") == "root-exec-released"]
        require(bool(released) is result["root_exec_released"] and len(released) <= 1,
                "root exec release event mismatch")
    echild = result.get("final_echild")
    if echild is not None:
        require(type(echild) is dict and type(echild.get("errno")) is int and echild["errno"] == errno.ECHILD
                and echild.get("syscall") == "wait4(-1, WNOHANG | __WALL)" and echild.get("boot_id") == boot
                and type(echild.get("monotonic_ns")) is int and last <= echild["monotonic_ns"] <= completed,
                "strict final ECHILD/identity/clock required")
        if result["records_truncated"] is False:
            require(exact([e["value"] for e in events if e.get("kind") == "wait-domain-empty"], [echild]),
                    "final ECHILD differs from retained events")
    derived_complete = echild is not None and result["error"] is None and not result["records_truncated"]
    require(result["collector_wait_domain_reaped"] is derived_complete, "collector reaping boolean inconsistent with raw record")
    if result["cause"] == "original-deadline":
        expected_code = 124
    elif cancellation is not None:
        expected_code = 128 + cancellation["signal"]
    elif not derived_complete or result["cause"] is not None:
        expected_code = 125
    elif result["root_returncode"] != 0:
        expected_code = result["root_returncode"]
    elif any(r["returncode"] != 0 for r in rows):
        expected_code = 125
    else:
        expected_code = 0
    require(result["wrapper_returncode"] == expected_code
            and result["command_success_before_handoff"] is (derived_complete and expected_code == 0),
            "wrapper/success does not follow preserved root and intervention status")
    if result["command_success_before_handoff"]:
        require(completed < deadline, "pre-handoff command snapshot missed original deadline")
    max_log = intent.get("max_log_bytes_per_stream")
    require(type(max_log) is int and 1024 <= max_log <= 16 * 1024 * 1024, "bounded original output cap required")
    for name in ("stdout", "stderr"):
        raw = bounded(root / (name + ".log"), max_log)
        data = result.get("streams", {}).get(name)
        require(type(data) is dict and type(data.get("stored_bytes")) is int and data["stored_bytes"] == len(raw)
                and type(data.get("seen_bytes")) is int and data["seen_bytes"] >= len(raw)
                and type(data.get("eof")) is bool and type(data.get("truncated")) is bool
                and data["truncated"] is (data["seen_bytes"] > len(raw)) and data.get("sha256") == digest(raw),
                "strict retained output identity/count mismatch")
    if observed_returncode is None:
        return {**unknown, "reason": "actual collector terminal status not supplied"}
    require(type(observed_returncode) is int, "actual collector returncode must be an integer, not bool")
    if expected_code != observed_returncode:
        return {**unknown, "reason": "actual collector exit/signal differs from retained snapshot"}
    if os.path.lexists(root / "late-cancellation.json"):
        return {**unknown, "reason": "late cancellation after result snapshot"}
    handoff = False
    if observed_boot_id is not None or observed_completed_monotonic_ns is not None:
        require(type(observed_boot_id) is str and type(observed_completed_monotonic_ns) is int,
                "caller completion clock must be supplied together with strict types")
        if observed_boot_id != boot or observed_completed_monotonic_ns < completed:
            return {**unknown, "reason": "caller terminal observation uses a different or earlier clock"}
        handoff = observed_completed_monotonic_ns < deadline
    return {**unknown, "terminal_state": "observed", "collector_wait_domain_reaped": derived_complete,
            "command_success": result["command_success_before_handoff"] and handoff,
            "deadline_qualified": handoff, "result": result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--deadline-monotonic-ns", type=int, required=True)
    parser.add_argument("--deadline-boot-id", required=True)
    parser.add_argument("--cleanup-grace-seconds", type=float, default=3)
    parser.add_argument("--executable-sha256", required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--max-log-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-processes", type=int, default=256)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    require(args.command and len(args.command) <= 512 and sum(len(x) for x in args.command) <= 65536, "bounded command required")
    require(args.out.is_absolute() and args.cwd.is_absolute() and args.cwd.is_dir(), "absolute new output/cwd required")
    require(math.isfinite(args.cleanup_grace_seconds) and .1 <= args.cleanup_grace_seconds <= 30, "bounded cleanup grace required")
    require(1024 <= args.max_log_bytes <= 16 * 1024 * 1024 and 4 <= args.max_processes <= 4096, "bounded log/process limits required")
    args.out.mkdir(parents=False, exist_ok=False)
    collector = None
    try:
        enable_subreaper()
        # This dedicated executable owns no pre-existing children or useful
        # inherited descriptors. Never keep caller capabilities alive in it.
        for value in os.listdir("/proc/self/fd"):
            fd = int(value)
            if fd > 2:
                try:
                    os.close(fd)
                except OSError:
                    pass
        require(boot_id() == args.deadline_boot_id and time.monotonic_ns() < args.deadline_monotonic_ns,
                "original boot/deadline mismatch; no deadline rebasing")
        # Independent executable: discard every inherited non-stdio descriptor.
        for value in os.listdir("/proc/self/fd"):
            fd = int(value)
            if fd > 2:
                try:
                    os.close(fd)
                except OSError:
                    pass
        collector = Collector(args)
        try:
            collector.launch()
        except BaseException as error:
            collector.error = f"{type(error).__name__}: {error}"
            if collector.root_pid is None:
                raise
            collector.stop("launch-error")
        collector.loop()
        return collector.finish()
    except BaseException as error:
        write_new(args.out / "collector-failure.json", {"schema": SCHEMA + "/failure", "error": f"{type(error).__name__}: {error}",
                                                       "collector_wait_domain_reaped": False, "gpu_ns": None,
                                                       "can_authorize_payment": False, "may_dispatch_again": False})
        return 125
    finally:
        if collector is not None:
            collector.close()


if __name__ == "__main__":
    code = main()
    if code < 0:
        # Preserve a naturally signalled root as the caller's negative Popen code.
        sig = -code
        if sig not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
        os._exit(128 + sig)
    raise SystemExit(code)
