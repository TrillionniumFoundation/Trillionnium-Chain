"""Best-effort Linux observations of only a newly created child process group.

This is resource evidence, not accounting completeness or proof verification.
Discover descendants through known members' task/children lists, never through
cmdline or environ. Processes that disappear between samples can be missed.
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
                 ticks_per_second=None, page_bytes=None):
        self.group_id = group_id
        self.stream = stream
        self.root = Path(proc_root)
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
        try:
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

    def _children(self, pid):
        children = set()
        for task in (self.root / str(pid) / "task").iterdir():
            if not task.name.isdecimal():
                continue
            try:
                with (task / "children").open("rb") as source:
                    data = source.read(65537)
                if len(data) > 65536:
                    self.truncated = True
                    continue
                children.update(int(value) for value in data.split())
            except (OSError, ValueError):
                self.errors += 1
        return children

    def sample(self, event, *, after_exit=False):
        observations = []
        # Start from identities previously observed, even if now orphaned.
        pending = deque((pid, start, False) for pid, start in self.records)
        if self.leader_start is not None:
            pending.appendleft((self.group_id, self.leader_start, False))
        seen = set()
        while pending and len(seen) < MAX_IDENTITIES:
            pid, expected_start, newly_discovered = pending.popleft()
            if pid <= 0:
                continue
            try:
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
                if not after_exit:
                    # Only inspect children listed by a verified owned member.
                    for child in self._children(pid):
                        if len(pending) >= MAX_IDENTITIES:
                            self.truncated = True
                            break
                        pending.append((child, None, True))
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
                "coverage_scope": "only members discovered from owned process descendants and verified to retain this new group/session; short-lived, unseen orphaned or escaped descendants can be missed. Final records retain last actual observations after exit; no zero or synthetic completion is substituted.",
                "consensus_authority": False}
