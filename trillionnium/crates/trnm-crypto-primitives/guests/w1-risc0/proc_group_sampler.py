"""Best-effort Linux observations of only a newly created child process group.

This is resource evidence, not accounting completeness or proof verification.
Filter numeric PIDs with getpgid/getsid before reading any process resource file,
never cmdline or environ. Processes that disappear between samples can be missed.
"""
from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

INTERVAL_SECONDS = 15.0
MAX_IDENTITIES = 4096


def parse_stat(data):
    """Extract only numeric identity, group and SELF-resource fields from stat."""
    prefix = data.find(b" (")
    end = data.rfind(b") ")
    if prefix <= 0 or end <= prefix:
        raise ValueError("invalid proc stat framing")
    pid = int(data[:prefix])
    # comm can contain spaces, parentheses and newlines; it is discarded.
    fields = data[end + 2:].split()
    if len(fields) < 22:
        raise ValueError("truncated proc stat")
    value = {"pid": pid, "process_group_id": int(fields[2]),
             "session_id": int(fields[3]), "user_ticks": int(fields[11]),
             "system_ticks": int(fields[12]), "start_ticks": int(fields[19]),
             "rss_pages": int(fields[21])}
    if pid <= 0 or any(number < 0 for number in value.values()):
        raise ValueError("negative proc stat value")
    # fields[13]/[14] are child CPU ticks and must never be added here.
    return value


def parse_hwm(data):
    for line in data.splitlines():
        if line.startswith(b"VmHWM:"):
            fields = line.split()
            if len(fields) != 3 or fields[2] != b"kB":
                raise ValueError("unexpected VmHWM unit")
            value = int(fields[1])
            if value < 0:
                raise ValueError("negative VmHWM")
            return value * 1024
    return None  # A missing field, including an exited process, is not zero.


class ProcGroupSampler:
    def __init__(self, group_id, stream, *, proc_root=Path("/proc"),
                 ticks_per_second=None, page_bytes=None,
                 group_lookup=os.getpgid, session_lookup=os.getsid):
        self.group_id = group_id
        self.stream = stream
        self.root = Path(proc_root)
        self.group_lookup = group_lookup
        self.session_lookup = session_lookup
        self.ticks = ticks_per_second or os.sysconf("SC_CLK_TCK")
        self.page_bytes = page_bytes or os.sysconf("SC_PAGE_SIZE")
        self.started = time.monotonic()
        self.sequence = 0
        self.records = {}
        self.errors = 0
        self.truncated = False
        self.maximum_sampled_sum_rss = None
        self.last_sample = None
        self.leader_start = None
        self.proc_self_identity_verified = False
        self.namespace_unavailable_reason = None
        # A mounted procfs can expose a different PID namespace from os.*.
        # Check only our own proc entry before any numeric target resource read.
        try:
            with (self.root / "self" / "stat").open("rb") as source:
                own = parse_stat(source.read(16384))
            self.proc_self_identity_verified = (
                own["pid"] == os.getpid()
                and own["process_group_id"] == os.getpgid(0)
                and own["session_id"] == os.getsid(0)
            )
            if not self.proc_self_identity_verified:
                self.namespace_unavailable_reason = "proc_self_identity_mismatch"
                return
        except (OSError, ValueError):
            self.errors += 1
            self.namespace_unavailable_reason = "proc_self_stat_unavailable_or_invalid"
            return
        try:
            if (self.group_lookup(group_id) != group_id
                    or self.session_lookup(group_id) != group_id):
                return
            leader = self._stat(group_id)
            if self._belongs(leader):
                self.leader_start = leader["start_ticks"]
        except (OSError, ValueError):
            self.errors += 1

    def _stat(self, pid):
        with (self.root / str(pid) / "stat").open("rb") as source:
            value = parse_stat(source.read(16384))
        if value["pid"] != pid:
            raise ValueError("proc pid mismatch")
        return value

    def _belongs(self, value):
        return (value["process_group_id"] == self.group_id
                and value["session_id"] == self.group_id)

    def _same_leader(self):
        if self.leader_start is None:
            return False
        try:
            if (self.group_lookup(self.group_id) != self.group_id
                    or self.session_lookup(self.group_id) != self.group_id):
                return False
            value = self._stat(self.group_id)
            return self._belongs(value) and value["start_ticks"] == self.leader_start
        except (OSError, ValueError):
            return False

    def _candidate_members(self):
        # Some Linux builds omit /proc/PID/task/TID/children. Enumerate only PID
        # names and query group/session IDs; do not read other groups' stat or
        # status files. Require the original leader identity before and after.
        if not self._same_leader():
            return []
        members = []
        try:
            for entry in self.root.iterdir():
                if not entry.name.isdecimal():
                    continue
                pid = int(entry.name)
                try:
                    if (self.group_lookup(pid) == self.group_id
                            and self.session_lookup(pid) == self.group_id):
                        if len(members) >= MAX_IDENTITIES:
                            self.truncated = True
                            break
                        members.append(pid)
                except (OSError, ValueError):
                    continue
        except OSError:
            self.errors += 1
        return members if self._same_leader() else []

    def sample(self, event, *, after_exit=False):
        observations = []
        # Start from identities previously observed, even if now orphaned.
        pending = deque((pid, start, False) for pid, start in self.records)
        if self.leader_start is not None:
            pending.appendleft((self.group_id, self.leader_start, False))
        if not after_exit:
            pending.extend((pid, None, True) for pid in self._candidate_members())
        seen = set()
        while pending and len(seen) < MAX_IDENTITIES:
            pid, expected_start, newly_discovered = pending.popleft()
            if pid <= 0:
                continue
            try:
                if (self.group_lookup(pid) != self.group_id
                        or self.session_lookup(pid) != self.group_id):
                    continue
                first = self._stat(pid)
                if not self._belongs(first) or first["start_ticks"] < self.leader_start:
                    continue
                if expected_start is not None and first["start_ticks"] != expected_start:
                    continue  # Reused PID is not the previously observed process.
                key = (pid, first["start_ticks"])
                if key in seen:
                    continue
                seen.add(key)
                if after_exit and newly_discovered:
                    continue
                try:
                    with (self.root / str(pid) / "status").open("rb") as source:
                        hwm = parse_hwm(source.read(65536))
                except (OSError, ValueError):
                    self.errors += 1
                    hwm = None
                second = self._stat(pid)
                if (second["start_ticks"] != first["start_ticks"]
                        or not self._belongs(second)):
                    continue  # Identity changed during this non-atomic sample.
                key = (pid, second["start_ticks"])
                if key not in self.records and len(self.records) >= MAX_IDENTITIES:
                    self.truncated = True
                    continue
                second["rss_bytes"] = second.pop("rss_pages") * self.page_bytes
                second["vm_hwm_bytes"] = hwm
                second["last_seen_sample"] = self.sequence
                old = self.records.get(key)
                if old is not None:
                    second["maximum_observed_user_ticks"] = max(old["maximum_observed_user_ticks"], second["user_ticks"])
                    second["maximum_observed_system_ticks"] = max(old["maximum_observed_system_ticks"], second["system_ticks"])
                    values = [value for value in [old["maximum_observed_vm_hwm_bytes"], hwm] if value is not None]
                    second["maximum_observed_vm_hwm_bytes"] = max(values) if values else None
                else:
                    second["maximum_observed_user_ticks"] = second["user_ticks"]
                    second["maximum_observed_system_ticks"] = second["system_ticks"]
                    second["maximum_observed_vm_hwm_bytes"] = hwm
                self.records[key] = second
                observations.append(second)
            except (OSError, ValueError):
                self.errors += 1
        if pending:
            self.truncated = True
        rss_sum = sum(value["rss_bytes"] for value in observations) if observations else None
        if rss_sum is not None:
            self.maximum_sampled_sum_rss = max(self.maximum_sampled_sum_rss or 0, rss_sum)
        sample = {"schema": "pon-w1-proc-group-sample-v1", "event": event,
                  "sequence": self.sequence, "sampled_utc": datetime.now(timezone.utc).isoformat(),
                  "elapsed_seconds": time.monotonic() - self.started,
                  "process_group_id": self.group_id, "leader_start_ticks": self.leader_start,
                  "proc_self_identity_verified": self.proc_self_identity_verified,
                  "namespace_unavailable_reason": self.namespace_unavailable_reason,
                  "observations": observations, "sampled_sum_rss_bytes": rss_sum,
                  "partial_read_errors_so_far": self.errors,
                  "tracking_was_truncated": self.truncated}
        self.stream.write(json.dumps(sample) + "\n")
        self.stream.flush()
        self.last_sample = sample
        self.sequence += 1
        return sample

    def summary(self):
        records = list(self.records.values())
        return {"schema": "pon-w1-proc-group-summary-v1", "interval_seconds": INTERVAL_SECONDS,
                "process_group_id": self.group_id, "leader_start_ticks": self.leader_start,
                "proc_self_identity_verified": self.proc_self_identity_verified,
                "namespace_unavailable_reason": self.namespace_unavailable_reason,
                "leader_identity_available": self.leader_start is not None,
                "clock_ticks_per_second": self.ticks, "page_bytes": self.page_bytes,
                "samples_written": self.sequence, "observed_process_identities": len(records),
                "observed_self_user_cpu_seconds_lower_bound": sum(value["maximum_observed_user_ticks"] for value in records) / self.ticks if records else None,
                "observed_self_system_cpu_seconds_lower_bound": sum(value["maximum_observed_system_ticks"] for value in records) / self.ticks if records else None,
                "maximum_sampled_sum_rss_bytes": self.maximum_sampled_sum_rss,
                "last_observed_processes": records, "last_sample": self.last_sample,
                "partial_read_errors": self.errors, "tracking_was_truncated": self.truncated,
                "cpu_scope": "sum of maximum observed SELF ticks for distinct PID/start-time identities, never child ticks; a sampling lower bound, not complete accounting",
                "memory_scope": "sum RSS can double-count shared pages and miss between-sample peaks; it is not physical memory usage or a group peak. Per-process VmHWM values are not summed.",
                "coverage_scope": "only this new process group/session, after /proc/self/stat PID/group/session match os identity; numeric PIDs are filtered by getpgid/getsid before resource files are read. New identities require the original leader PID/start time to remain live. Short-lived, unseen-after-leader-exit or escaped descendants can be missed. Final records retain last actual observations, not synthetic zero/completion.",
                "consensus_authority": False}
