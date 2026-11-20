"""Independent full-byte audit of this owner's private original CLOCK observations."""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import os
import stat
import struct
from .build import need
from .primitive_evidence import decoded, raw_identity, same, unsigned

MARKER = b"HIA_WORK_OWNER_CLOCK:"
TEST = "host_kernel_parent::kernel_parent::resource_tests::hia_work_owner_oracle::clock_fault_observation::actual_controlled_clock"
COUNTERS = ("cpu.stat", "memory.current", "pids.current")
COUNTER_BYTES = (
    b"usage_usec 10\nnr_periods 20\nnr_throttled 3\nthrottled_usec 40\n", b"64\n", b"2\n")
LIMITS = ("cpu.max", "cpu.max.burst", "memory.max", "memory.swap.max", "pids.max")

def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)

class Capture:
    """Pin the complete four-file original observation directory throughout audit."""
    def __init__(self, root, *, exact_names=None):
        root = Path(root)
        need(root.is_absolute() and ".." not in root.parts, "Absolute original CLOCK evidence root required")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        self.fd = os.open("/", flags); self.stamps = {}
        try:
            for part in root.parts[1:]:
                child = os.open(part, flags, dir_fd=self.fd)
                os.close(self.fd); self.fd = child
            self.directory = stamp(os.fstat(self.fd)); self.names = set(os.listdir(self.fd))
            mandatory = {"report.json", "events.jsonl", "stdout.raw", "stderr.raw"}
            allowed = self.names in (mandatory, mandatory | {"audit.json"}) if exact_names is None else self.names == set(exact_names)
            need(allowed, "Original CLOCK directory omitted or added evidence")
        except BaseException:
            self.close(); raise

    def read(self, name, maximum):
        need(name in self.names and "/" not in name, "Unknown original CLOCK evidence file")
        named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        need(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_size <= maximum,
             "Original CLOCK evidence must be bounded single-link regular bytes")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = os.fstat(descriptor); need(stamp(before) == stamp(named), "CLOCK evidence replaced before read")
            parts = []; remaining = before.st_size
            while remaining:
                raw = os.read(descriptor, min(remaining, 1 << 20))
                need(raw, "CLOCK evidence truncated"); parts.append(raw); remaining -= len(raw)
            need(os.read(descriptor, 1) == b"" and stamp(os.fstat(descriptor)) == stamp(before)
                 == stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False)),
                 "CLOCK evidence changed during read")
            self.stamps[name] = stamp(before)
            return b"".join(parts)
        finally:
            os.close(descriptor)

    def fence(self):
        need(stamp(os.fstat(self.fd)) == self.directory and set(os.listdir(self.fd)) == self.names,
             "CLOCK evidence directory changed during audit")
        for name, saved in self.stamps.items():
            need(stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == saved,
                 "CLOCK evidence file changed after read")

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None

def i64(value):
    return type(value) is int and -(1 << 63) <= value < (1 << 63)

def hex_bytes(value, extent=None):
    need(type(value) is str and len(value) % 2 == 0, "Actual byte observation is not hex")
    raw = bytes.fromhex(value)
    need(raw.hex() == value and (extent is None or len(raw) == extent), "Noncanonical actual byte observation")
    return raw

def u32(value):
    return unsigned(value, (1 << 32) - 1)

def collect(events, stderr):
    need(type(events) is list and events, "No complete owned syscall event stream")
    execs = [row for row in events if row.get("kind") == "exec"]
    need(len(execs) == 1 and u32(execs[0].get("tid")) and execs[0]["tid"] > 0,
         "No unique actual original process exec")
    root = execs[0]["tid"]
    roster = {root: {"parent": None, "birth": 0}}
    pending = {}; entries = {}; exits = {}; terminal = {}; exit_stops = {}; births = {}
    roles = {}; joins = []; clocks = []; injections = []
    opened = {}; descriptor_history = {}; resource_fds = {}; resources = []; resource_parents = {}
    child_returns = set()
    allowed = {"exec", "birth", "syscall-entry", "syscall-exit", "terminal", "exit-stop",
               "actual-role", "actual-join", "signal", "child-initial-stop", "child-clone-return"}
    for number, row in enumerate(events, 1):
        need(type(row) is dict and type(row.get("sequence")) is int and row["sequence"] == number
             and row.get("kind") in allowed and u32(row.get("tid")) and row["tid"] > 0,
             "Original event identity/type/order differs")
        tid = row["tid"]; kind = row["kind"]
        need(tid in roster and tid not in terminal, "Original event lies outside actual owned thread lifetime")
        if kind == "exec":
            need(tid == root and row is execs[0] and row.get("actual_executable"),
                 "Unexpected owned child exec")
        elif kind == "birth":
            child = row.get("child"); call = pending.get(tid)
            need(u32(child) and child > 0 and child not in roster and type(row.get("ptrace_event")) is int and row["ptrace_event"] == 3
                 and call is not None and call["nr"] in (56, 435), "Birth lacks actual original clone")
            clone = call.get("actual_clone")
            need(type(clone) is dict and unsigned(clone.get("flags"))
                 and clone["flags"] & 0x350f00 == 0x350f00,
                 "Original scoped thread clone flags differ")
            address = clone.get("child_tid")
            need(unsigned(address) and address > 0 and address % 4 == 0
                 and clone.get("parent_tid") == address, "Original actual clear-TID address differs")
            roster[child] = {"parent": tid, "birth": number, "clone_entry": call["sequence"],
                             "child_tid_address": address}
            births[child] = row
        elif kind == "syscall-entry":
            need(tid not in pending and unsigned(row.get("nr")) and type(row.get("args")) is list
                 and len(row["args"]) == 6 and all(unsigned(x) for x in row["args"]),
                 "Original syscall entry is incomplete or overlaps")
            pending[tid] = row; entries[number] = row
            if row["nr"] in (2, 257):
                captured = row.get("actual_open")
                need(type(captured) is dict and set(captured) == {"path_hex", "flags", "dirfd"},
                     "Original open omitted complete actual pathname observation")
                hex_bytes(captured["path_hex"])
                need(type(captured["flags"]) is int and captured["flags"] ==
                     row["args"][1 if row["nr"] == 2 else 2], "Actual open flags differ")
                expected_dirfd = None if row["nr"] == 2 else (
                    row["args"][0] - (1 << 64) if row["args"][0] >> 63 else row["args"][0])
                need(same(captured["dirfd"], expected_dirfd), "Actual open directory descriptor differs")
            elif row["nr"] in (56, 435):
                clone = row.get("actual_clone"); need(type(clone) is dict, "Original clone bytes omitted")
                if row["nr"] == 56:
                    expected = {"abi": "clone", "flags": row["args"][0], "stack": row["args"][1],
                                "parent_tid": row["args"][2], "child_tid": row["args"][3], "tls": row["args"][4]}
                else:
                    raw = hex_bytes(clone.get("argument_hex"))
                    need(type(clone.get("argument_bytes")) is int and clone["argument_bytes"] ==
                         row["args"][1] == len(raw) and 64 <= len(raw) <= 88,
                         "Original clone3 argument bytes differ")
                    words = struct.unpack("<11Q", raw + bytes(88 - len(raw)))
                    expected = {"abi": "clone3", "argument_hex": raw.hex(), "argument_bytes": len(raw),
                        **dict(zip(("flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack",
                                   "stack_size", "tls", "set_tid", "set_tid_size", "cgroup"), words))}
                need(same(clone, expected), "Original clone descriptor differs from actual arguments")
                if "logical_clone_fallback" in row:
                    need(type(row["logical_clone_fallback"]) is bool
                         and type(row.get("role_spawn_ordinal")) is int and row["role_spawn_ordinal"] > 0,
                         "Original clone fallback/ordinal has another JSON type")
            elif row["nr"] == 202:
                need(row["args"][0] % 4 == 0 and u32(row.get("futex_word_before")),
                     "Actual futex word observation omitted")
        elif kind == "syscall-exit":
            entry = pending.pop(tid, None)
            need(entry is not None and type(row.get("entry")) is int and row["entry"] == entry["sequence"]
                 and type(row.get("nr")) is int and row["nr"] == entry["nr"]
                 and i64(row.get("result")) and i64(row.get("kernel_result_before_injection")),
                 "Original syscall completion does not match its actual entry")
            exits[entry["sequence"]] = row; result = row["result"]; nr = entry["nr"]; args = entry["args"]
            fault = entry.get("fault")
            if fault is None:
                need(result == row["kernel_result_before_injection"], "Unrecorded syscall-result substitution")
            else:
                need(nr == 228 and type(fault) is dict and set(fault) ==
                     {"kind", "error", "original_syscall_skipped"} and fault["kind"] == "clock"
                     and type(fault["error"]) is int and fault["error"] in (5, 22)
                     and fault["original_syscall_skipped"] is True
                     and row["kernel_result_before_injection"] == -38 and result == -fault["error"],
                     "Controlled CLOCK injection differs from actual skipped syscall")
                injections.append({"tid": tid, "role": entry.get("role"), "role_index": entry.get("role_index"),
                    "clock_id": entry.get("clock_id"), "clock_ordinal": entry.get("role_clock_ordinal"),
                    "spawn_ordinal": entry.get("role_spawn_ordinal"), "entry": entry["sequence"],
                    "rule": fault, "actual_skipped_result": -38, "injected_result": result})
            if nr in (2, 257) and result >= 0:
                need(result not in opened, "Original descriptor reused without close")
                opened[result] = entry; descriptor_history[entry["sequence"]] = {"entry": entry, "exit": row, "close": None}
                captured = entry["actual_open"]; name = hex_bytes(captured["path_hex"]).split(b"/")[-1]
                if name in tuple(x.encode() for x in COUNTERS) and captured["flags"] & 3 == 0 and not captured["flags"] & 0x200000:
                    parent = opened.get(captured["dirfd"])
                    need(nr == 257 and parent is not None and parent["sequence"] < entry["sequence"]
                         and hex_bytes(parent["actual_open"]["path_hex"]).endswith(b"/sys/fs/cgroup/trnmponpublic.slice"),
                         "Original counter read omitted live verified parent descriptor")
                    number_of_resource = len(resources); resource_fds[result] = number_of_resource
                    resource_parents[number_of_resource] = parent["sequence"]
                    resources.append({"fd": result, "opened_by_tid": tid, "counter": name.decode(),
                        "path_hex": captured["path_hex"], "dirfd": captured["dirfd"], "flags": captured["flags"],
                        "open_entry": entry["sequence"], "open_exit": row["sequence"], "reads": [], "close": None})
            if nr in (0, 3) and args[0] in resource_fds:
                index = resource_fds[args[0]]; captured = resources[index]
                need(type(entry.get("resource_interval")) is int and entry["resource_interval"] == index,
                     "Original resource descriptor annotation differs")
                if nr == 0:
                    read = row.get("actual_resource_read")
                    need(type(read) is dict and 0 <= result <= args[2] and result <= 65536 and args[2] > 0,
                         "Actual original resource read omitted bounded successful bytes")
                    raw = hex_bytes(read.get("data_hex"), result)
                    expected = {"tid": tid, "entry": entry["sequence"], "exit": row["sequence"],
                                "requested": args[2], "result": result, "data_hex": raw.hex()}
                    need(same(read, expected), "Original resource bytes/report differ")
                    captured["reads"].append(expected)
                else:
                    need(result == 0 and captured["close"] is None, "Original resource descriptor did not close")
                    captured["close"] = {"tid": tid, "entry": entry["sequence"], "exit": row["sequence"], "result": 0}
                    resource_fds.pop(args[0])
            else:
                need("resource_interval" not in entry and "actual_resource_read" not in row,
                     "Unbound extra resource observation")
            if nr == 3 and result == 0 and args[0] in opened:
                opened_entry = opened.pop(args[0]); descriptor_history[opened_entry["sequence"]]["close"] = row["sequence"]
            if nr == 202:
                need(u32(row.get("futex_word_after")), "Actual completed futex word observation omitted")
            if nr in (56, 435) and result > 0:
                need(result in roster and roster[result]["clone_entry"] == entry["sequence"],
                     "Original clone return did not match actual born thread")
                if entry["actual_clone"]["flags"] & 0x100000:
                    need(u32(row.get("parent_tid_word_after")) and row["parent_tid_word_after"] in (0, result),
                         "Original parent-settid word differs from born thread")
            if nr == 228:
                clock_id = args[0] - (1 << 64) if args[0] >> 63 else args[0]
                prior = sum(c["tid"] == tid for c in clocks)
                need(type(entry.get("clock_id")) is int and entry["clock_id"] == clock_id
                     and type(entry.get("clock_ordinal")) is int and entry["clock_ordinal"] == prior + 1,
                     "Actual clock identity or per-thread ordinal differs")
                clock = {"tid": tid, "ordinal": prior + 1, "clock_id": clock_id,
                    "entry": entry["sequence"], "exit": row["sequence"], "result": result,
                    "role": entry.get("role"), "role_index": entry.get("role_index"),
                    "role_clock_ordinal": entry.get("role_clock_ordinal"), "injected": fault}
                if result == 0:
                    raw = hex_bytes(row.get("actual_timespec_hex"), 16)
                    seconds, nanos = struct.unpack("<qq", raw)
                    need(0 <= nanos < 1_000_000_000, "Actual successful original timespec was invalid")
                    clock.update(timespec_hex=raw.hex(), seconds=seconds, nanoseconds=nanos)
                else:
                    need("actual_timespec_hex" not in row, "Failed original clock claimed returned time bytes")
                clocks.append(clock)
        elif kind == "actual-role":
            marker_entry = next((r for r in reversed(list(entries.values()))
                                 if r["tid"] == tid and "role_marker_hex" in r and r["sequence"] < number), None)
            need(marker_entry is not None and marker_entry["sequence"] in exits and tid not in roles,
                 "Private original role has no unique actual marker write")
            marker_exit = exits[marker_entry["sequence"]]
            raw = hex_bytes(marker_entry["role_marker_hex"], 32)
            declared, role, index = struct.unpack("<3Q", raw[8:])
            need(raw[:8] == b"PCROLE01" and declared == tid and role in (1, 3) and index == 0
                 and marker_entry["nr"] == 1 and marker_entry["args"][0] == 2
                 and marker_entry["args"][2] == marker_exit["result"] == 32 and raw in stderr,
                 "Private original role not bound to actual stderr bytes/TID")
            linked = [x for x in exits.values() if x["sequence"] == row.get("actual_thread_link_exit")]
            need(len(linked) == 1, "Role omitted actual own kernel thread link")
            linked_exit = linked[0]; linked_entry = entries[linked_exit["entry"]]
            need(linked_entry["tid"] == tid and linked_entry["nr"] in (89, 267)
                 and linked_entry.get("own_thread_link", {}).get("path") == "/proc/thread-self"
                 and hex_bytes(linked_exit.get("own_thread_link_result_hex")) ==
                 (str(root) + "/task/" + str(tid)).encode()
                 and linked_exit["sequence"] < marker_entry["sequence"],
                 "Role marker claimed another thread's identity")
            need(same(row, {"sequence": number, "kind": "actual-role", "tid": tid,
                            "role": role, "index": 0, "actual_thread_link_exit": linked_exit["sequence"]}),
                 "Private original role annotation differs")
            roles[tid] = {"role": role, "index": 0, "marker_entry": marker_entry["sequence"],
                          "marker_exit": marker_exit["sequence"], "clock_count": 0, "spawn_count": 0}
        elif kind == "actual-join":
            entry = entries.get(row.get("marker_entry")); returned = exits.get(row.get("marker_entry"))
            need(entry is not None and returned is not None and entry["tid"] == tid and entry["nr"] == 1
                 and entry["args"][0] == 2 and entry["args"][2] == returned["result"] == 32,
                 "Original join has no actual complete marker write")
            raw = hex_bytes(entry.get("join_marker_hex"), 32); main, worker, panicked = struct.unpack("<3Q", raw[8:])
            need(raw[:8] == b"PCJOIN01" and raw in stderr and main == tid and worker in roster
                 and roster[worker]["parent"] == tid and panicked in (0, 1)
                 and roles.get(tid, {}).get("role") == 1 and roles.get(worker, {}).get("role") == 3,
                 "Actual original join marker ownership differs")
            address = roster[worker]["child_tid_address"]
            need(type(entry.get("join_child_tid_address")) is int and entry["join_child_tid_address"] == address
                 and type(entry.get("join_child_tid_word")) is int and entry["join_child_tid_word"] == 0xFFFFFFFF
                 and worker in exit_stops and exit_stops[worker]["sequence"] < entry["sequence"],
                 "Original join marker preceded actual child exit or omitted the consumed glibc TID state")
            expected = {"sequence": number, "kind": "actual-join", "tid": tid, "worker_tid": worker,
                "panicked": bool(panicked), "marker_entry": entry["sequence"], "marker_exit": returned["sequence"],
                "actual_child_tid_address": address, "actual_child_tid_word": 0xFFFFFFFF}
            need(same(row, expected), "Original join annotation differs from actual marker")
            joins.append(expected)
        elif kind == "exit-stop":
            call = pending.get(tid)
            need(tid not in exit_stops and type(row.get("status")) is int and row["status"] == 0
                 and call is not None and call["nr"] in (60, 231) and call["args"][0] == 0,
                 "Original child/process did not execute normal actual exit")
            need((tid == root and call["nr"] == 231) or (tid != root and call["nr"] == 60),
                 "Worker used process-wide exit or root omitted exit_group")
            exit_stops[tid] = row
        elif kind == "terminal":
            need(tid in exit_stops and type(row.get("exit_code")) is int and row["exit_code"] == 0
                 and row.get("signal") is None, "Original process/thread terminal status differs")
            terminal[tid] = row; roster[tid]["terminal"] = row; pending.pop(tid)
        elif kind == "child-clone-return":
            need(tid != root and tid not in child_returns and type(row.get("result")) is int
                 and row["result"] == 0, "Original child clone return differs")
            child_returns.add(tid)
        elif kind == "child-initial-stop":
            need(tid != root, "Root initial stop was recorded as a born child")
        elif kind == "signal":
            need(type(row.get("signal")) is int and 0 < row["signal"] < 65, "Invalid actual signal")
    need(len(roster) == len(terminal) == len(exit_stops) == 3 and not pending
         and len(roles) == 2 and sorted(x["role"] for x in roles.values()) == [1, 3]
         and len(joins) == 1 and not resource_fds, "Original owned lifetime/roles/join/close roster incomplete")
    for tid, role in roles.items():
        for entry in entries.values():
            if entry["tid"] != tid or entry["sequence"] <= role["marker_exit"]: continue
            if entry["nr"] == 228:
                role["clock_count"] += 1
                need(type(entry.get("role")) is int and entry["role"] == role["role"]
                     and type(entry.get("role_index")) is int and entry["role_index"] == 0
                     and type(entry.get("role_clock_ordinal")) is int
                     and entry["role_clock_ordinal"] == role["clock_count"], "Clock role counter differs")
            if entry["nr"] in (56, 435):
                actual_previous = [old for old in entries.values()
                                   if old["tid"] == tid and old["nr"] in (56, 435)
                                   and role["marker_exit"] < old["sequence"] < entry["sequence"]]
                previous = actual_previous[-1] if actual_previous else None
                expected_fallback = bool(entry["nr"] == 56 and previous is not None
                                         and previous["nr"] == 435
                                         and exits.get(previous["sequence"], {}).get("result") == -38)
                need(same(entry.get("logical_clone_fallback"), expected_fallback),
                     "Original logical clone fallback differs from actual previous syscall")
                if not expected_fallback:
                    role["spawn_count"] += 1
                need(same(entry.get("role_spawn_ordinal"), role["spawn_count"])
                     and same(entry.get("role"), role["role"])
                     and same(entry.get("role_index"), 0), "Original clone role/count differs")
    return {"root": root, "roster": roster, "roles": roles, "joins": joins, "clocks": clocks,
            "injections": injections, "resources": resources, "resource_parents": resource_parents,
            "descriptor_history": descriptor_history, "entries": entries, "exits": exits,
            "exit_stops": exit_stops}

def original_constructor_clocks(ledger, main, first_resource, worker_birth):
    """Keep deadline, ListenerIntake creation and Paid budget watermark distinct."""
    rows = [row for row in ledger["clocks"] if row["tid"] == main and row["role"] == 1]
    need(len(rows) == 3
         and all(same(row["clock_id"], 1) and same(row["result"], 0)
                 and same(row["role"], 1) and same(row["role_index"], 0)
                 and same(row["role_clock_ordinal"], index)
                 and type(row["seconds"]) is int and row["seconds"] >= 0
                 and type(row["nanoseconds"]) is int and 0 <= row["nanoseconds"] < 1_000_000_000
                 for index, row in enumerate(rows, 1))
         and ledger["roles"][main]["marker_exit"] < rows[0]["entry"]
         and all(left["exit"] < right["entry"] for left, right in zip(rows, rows[1:]))
         and rows[-1]["exit"] < first_resource < worker_birth,
         "Actual original deadline, intake and Paid budget constructor clocks differ")
    times = [row["seconds"] * 1_000_000_000 + row["nanoseconds"] for row in rows]
    need(times == sorted(times), "Original constructors cannot replace or rewind the earlier deadline")
    return rows[0]

def clock_plan(profile, disable_vdso):
    """Enumerate source-bound Work and Paid calls, including real unwind cleanup."""
    from .faults import profiles
    need(type(disable_vdso) is bool and (disable_vdso or profile is None),
         "Controlled faults require the private raw-clock fixture")
    need(profile is None or any(same(profile, row) for row in profiles()),
         "Exact original Work CLOCK fault profile required")
    calls = []; ordinal = 0; stopped = False; checkpoints = 0
    def paid(kind):
        calls.extend(((kind + "-cpu", 3, None), (kind + "-wall", 1, None)))
    def work():
        nonlocal ordinal, stopped
        ordinal += 1
        calls.append(("work", 1, ordinal))
        stopped = profile is not None and ordinal == profile["ordinal"]
    paid("begin")
    work()
    if not stopped:
        paid("checkpoint"); checkpoints += 1
    for _ in range(1099):
        if stopped:
            break
        work()
        if not stopped:
            work()
        if not stopped:
            paid("checkpoint"); checkpoints += 1
    if not stopped:
        work()
    if stopped:
        paid("drop")
        calls.append(("drop-unavailable-wall", 1, None))
    else:
        paid("finish-checkpoint")
        paid("settlement")
    need(ordinal == (profile["ordinal"] if profile is not None else 2200),
         "Exact Work clock source sequence")
    if not disable_vdso:
        calls = [row for row in calls if row[1] == 3]
    return calls, checkpoints

def paid_clock_observation(value, worker_clocks, profile, disable_vdso):
    """Bind same-thread Paid facts to complete observed calls and retained values."""
    plan, checkpoints = clock_plan(profile, disable_vdso)
    need(len(worker_clocks) == len(plan), "Complete original Work/Paid clock roster differs")
    work = []; cpu = []; wall = []; paid_wall = []; expected_fault = None
    for index, (row, (kind, clock_id, logical)) in enumerate(zip(worker_clocks, plan, strict=True), 1):
        need(same(row.get("clock_id"), clock_id) and same(row.get("role"), 3)
             and same(row.get("role_index"), 0) and same(row.get("role_clock_ordinal"), index)
             and same(row.get("tid"), value.get("worker_tid")),
             "Original Work/Paid clock identity, order or role differs")
        injected = profile is not None and kind == "work" and logical == profile["ordinal"]
        if injected:
            error = 5 if profile["errno"] == "EIO" else 22
            need(same(row.get("result"), -error)
                 and same(row.get("injected"), {"kind": "clock", "error": error, "original_syscall_skipped": True}),
                 "Original Work CLOCK fault was moved, retried or omitted")
            expected_fault = {"clock_roles": [3], "clock_when": index, "clock_error": error}
        else:
            need(same(row.get("result"), 0) and row.get("injected") is None,
                 "Original Paid/Work successful clock was failed or injected")
            seconds, nanos = row.get("seconds"), row.get("nanoseconds")
            need(type(seconds) is int and seconds >= 0 and type(nanos) is int
                 and 0 <= nanos < 1_000_000_000, "Actual original successful clock extent")
            timestamp = seconds * 1_000_000_000 + nanos
            if clock_id == 3:
                need(timestamp < 1 << 64 and (not cpu or timestamp >= cpu[-1]),
                     "Original same-worker CPU timestamp overflow or rewind")
                cpu.append(timestamp)
            else:
                need(not wall or timestamp >= wall[-1], "Original monotonic timestamp rewound")
                wall.append(timestamp)
                if kind != "work":
                    paid_wall.append(timestamp)
        if kind == "work":
            work.append(row)
    need(type(value.get("paid_checkpoints")) is int and value["paid_checkpoints"] == checkpoints,
         "Original Paid checkpoint count differs from actual call sequence")
    panicked = profile is not None
    need(len(cpu) == checkpoints + (2 if panicked else 3), "Original Paid CPU lifetime is incomplete")
    charged = cpu[-1 if panicked else -2] - cpu[0]
    total = None if panicked else cpu[-1] - cpu[0]
    residual = None if panicked else cpu[-1] - cpu[-2]
    live = value.get("paid_live"); global_ = value.get("paid_global")
    need(same(live, {"poisoned": False, "unavailable": False, "refused": False,
                     "charged_ns": charged, "registered_threads": 0, "termination_reserved": False}),
         "Actual original Paid live account did not retire with measured charges")
    global_fields = {"poisoned", "unavailable", "in_flight", "credit_ns",
                     "termination_reserved_ns", "verified_completions", "flow"}
    need(type(global_) is dict and set(global_) == global_fields,
         "Complete original Paid global snapshot required")
    for key, expected in (("poisoned", False), ("unavailable", panicked), ("in_flight", 0),
                          ("termination_reserved_ns", 0), ("verified_completions", 0)):
        need(same(global_[key], expected), "Actual original Paid global lifecycle differs: " + key)
    def signed_credit(raw):
        need(type(raw) is str, "Original Paid credit must retain its decimal type")
        value_ = int(raw)
        need(str(value_) == raw and -(1 << 127) <= value_ < 1 << 127,
             "Original Paid credit is not canonical signed 128-bit")
        return value_
    credit = signed_credit(global_["credit_ns"]); flow = global_["flow"]
    flow_fields = {"initial_credit_ns", "credited_refill_ns", "discarded_refill_ns",
                   "booked_reservation_ns", "live_debited_cpu_ns", "settlement_residual_cpu_ns",
                   "settled_full_cpu_ns", "settlement_discard_ns"}
    need(type(flow) is dict and set(flow) == flow_fields, "Complete original Paid flow snapshot required")
    initial = signed_credit(flow["initial_credit_ns"])
    need(initial == 2_000_000_000, "Original standalone Paid initial credit changed")
    need(all(type(flow[k]) is int and 0 <= flow[k] < 1 << 64 for k in flow_fields - {"initial_credit_ns"}),
         "Original Paid flow counter type or extent differs")
    booked = 100_000_000 if panicked else 0
    expected_flow = {"booked_reservation_ns": booked, "live_debited_cpu_ns": charged,
                     "settlement_residual_cpu_ns": 0 if panicked else residual,
                     "settled_full_cpu_ns": 0 if panicked else total, "settlement_discard_ns": 0}
    need(all(same(flow[key], expected) for key, expected in expected_flow.items()),
         "Actual original Paid flow differs from same-thread clocks and unwind")
    need(credit == initial + flow["credited_refill_ns"] - booked - charged
         - flow["settlement_residual_cpu_ns"], "Original Paid flow does not conserve measured charge")
    if panicked:
        need(value.get("paid") is None, "Original panic invented a returned Paid settlement")
    else:
        expected = {"schema": "service-owner-scoped-thread-cpu-settlement-v1",
                    "owner_cpu_ns": total, "scoped_worker_cpu_ns": 0, "total_cpu_ns": total,
                    "live_paid_cpu_ns": charged, "residual_cpu_ns": residual,
                    "spawned_workers": 0, "started_workers": 0, "finished_workers": 0,
                    "known_workers": 0, "live_refused": False, "accounting_unavailable": False}
        need(same(value.get("paid"), expected), "Original Paid settlement differs from actual CPU intervals")
    return {"work_clocks": work, "expected_fault": expected_fault,
            "paid_checkpoints": checkpoints, "worker_clock1_calls": sum(row["clock_id"] == 1 for row in worker_clocks),
            "paid_cpu_calls": len(cpu), "paid_wall_calls": len(paid_wall),
            "actual_live_cpu_ns": charged, "actual_total_cpu_ns": total,
            "actual_residual_cpu_ns": residual, "cleanup": "drop" if panicked else "finish"}

def compare_observation(value, baseline, profile):
    need(type(value) is dict and value.get("schema") == "trnm.hia.work-owner-original-clock-observation.v2"
         and value.get("name") == baseline["name"]
         and value.get("input_sha256") == hashlib.sha256(bytes.fromhex(baseline["request_hex"])).hexdigest(),
         "Actual original CLOCK input observation differs")
    for field in ("actual_original_W1", "actual_original_Host_primitives",
                  "actual_original_task_alive_and_final_resource", "actual_original_std_scoped_spawn_and_join",
                  "actual_original_finite_paid_work_checkpoints",
                  "parent_retained_observation_after_actual_join", "joined"):
        need(value.get(field) is True, "Actual original CLOCK method/observation scope omitted")
    for field in ("production_fixed_parent_authority", "complete_Node_or_paid_checkpoint"):
        need(value.get(field) is False, "Private original CLOCK observation claimed production authority")
    need(type(value.get("original_deadline_seconds")) is int and value["original_deadline_seconds"] == 4,
         "Original four-second deadline changed")
    panicked = profile is not None
    need(value.get("worker_panicked") is panicked and value.get("ordinary_finish_returned") is (not panicked),
         "Original clock did not unwind at the expected point")
    progress = profile["progress"] if panicked else 1099
    calls = profile["worker_host_calls"] if panicked else 1101
    need(same(value.get("progress"), baseline["progress"][:progress]), "Actual retained original progress differs")
    for key, expected in (("host_calls", calls), ("host_checks", calls), ("before_checks", 3),
                          ("after_sample_attempts", 0 if panicked else 1),
                          ("after_checks", 0 if panicked else 5), ("work_code", 0)):
        need(same(value.get(key), expected), "Actual original CLOCK count/type differs: " + key)
    need(same(value.get("before_values"), [10, 20, 3, 40, 64, 2]), "Actual original initial counters differ")
    if panicked:
        need(type(value.get("panic_payload")) is str and value["panic_payload"],
             "Actual original panic payload missing after join")
        need(all(value.get(k) is None for k in ("after_values", "delta_values", "product_hex",
                                               "returned_domain", "returned_code")),
             "Original panic claimed a normal result or after-sampling")
    else:
        need(value.get("panic_payload") is None and same(value.get("returned_domain"), 0)
             and same(value.get("returned_code"), 0) and same(value.get("after_values"), [10, 20, 3, 40, 64, 2])
             and same(value.get("delta_values"), [0, 0, 0, 0]),
             "Original positive sample/result differs")
        product = hex_bytes(value.get("product_hex"), 16384)
        need(product.hex() == baseline["product_hex"], "Full actual original Work product differs")
    return {"panicked": panicked, "progress": progress, "host_calls": calls}

def audit(directory, *, argv, environment, executable, baseline, profile=None, disable_vdso=True):
    need(__debug__, "Original CLOCK readback refuses optimized Python")
    capture = Capture(Path(directory))
    try:
        raw_report = capture.read("report.json", 32 << 20)
        raw_events = capture.read("events.jsonl", 256 << 20)
        stdout = capture.read("stdout.raw", 2 << 20); stderr = capture.read("stderr.raw", 2 << 20)
        report = decoded(raw_report); events = [decoded(line) for line in raw_events.splitlines()]
        need(report.get("schema") == "trnm.hia.work-owner-original-clock-trace.v1" and report.get("status") == "PASS"
             and same(report.get("argv"), argv) and same(report.get("environment"), environment)
             and same(report.get("executable_before"), executable) and report.get("executable_after") == "MATCH"
             and report.get("complete_owned_process_reaped") is True
             and same(report.get("exit_code"), 0) and report.get("signal") is None
             and report.get("disable_vdso") is disable_vdso, "Actual original CLOCK process identity/status differs")
        for name, raw in (("events", raw_events), ("stdout", stdout), ("stderr", stderr)):
            need(same(report.get(name), raw_identity(raw)), "Actual complete CLOCK bytes differ: " + name)
        values = [decoded(line.split(MARKER, 1)[1]) for line in stdout.splitlines() if MARKER in line]
        need(len(values) == 1 and b"test result: ok. 1 passed; 0 failed;" in stdout,
             "Actual complete original CLOCK observer did not execute once")
        value = values[0]; observation = compare_observation(value, baseline, profile)
        ledger = collect(events, stderr)
        actual_exec = next(row for row in events if row["kind"] == "exec")
        need(actual_exec["actual_executable"] == argv[0]
             and same(actual_exec.get("auxv"), report.get("auxv")),
             "Original executed image/auxv differs from the complete exec event")
        main = value.get("main_tid"); worker = value.get("worker_tid")
        need(u32(main) and u32(worker) and main != worker and ledger["roles"].get(main, {}).get("role") == 1
             and ledger["roles"].get(worker, {}).get("role") == 3 and ledger["roster"][worker]["parent"] == main,
             "Original result uses another actual worker lifetime")
        need(same(report.get("roster"), {str(k): v for k, v in ledger["roster"].items()})
             and same(report.get("actual_roles"), {str(k): v for k, v in ledger["roles"].items()})
             and same(report.get("actual_joins"), ledger["joins"])
             and same(report.get("injections"), ledger["injections"])
             and same(report.get("actual_resource_intervals"), ledger["resources"]),
             "Original summary differs from complete event/descriptor/role ledger")
        joined = ledger["joins"][0]
        need(joined["tid"] == main and joined["worker_tid"] == worker
             and joined["panicked"] is observation["panicked"], "Original join result differs from actual child")
        # The actual child lifecycle and consumed source-bound join are mandatory.
        # glibc marks the joined TID -1 after its kernel-zero wait/read succeeds.
        # A futex wait may legitimately be absent if that same child already exited;
        # only an actual captured zero is reported as directly observed kernel clearing.
        waits = []
        for entry in ledger["entries"].values():
            if entry["tid"] == main and entry["nr"] == 202 and entry["args"][0] == joined["actual_child_tid_address"]:
                returned = ledger["exits"].get(entry["sequence"]); operation = entry["args"][1]
                need(operation & 128 == 0 and operation & 127 in (0, 9) and entry["args"][2] == worker
                     and entry["args"][3] == 0 and returned is not None and returned["result"] in (0, -11, -4),
                     "Actual original join futex wait differs")
                need(entry["sequence"] < returned["sequence"] < joined["marker_entry"],
                     "Join futex returned after claimed consumed join")
                waits.append({"entry": entry["sequence"], "exit": returned["sequence"],
                              "result": returned["result"], "clear_word": returned["futex_word_after"]})
        resources = ledger["resources"]; groups = 1 if profile is not None else 2
        need([row["counter"] for row in resources] == list(COUNTERS) * groups,
             "Original panic/positive actual counter-read roster differs")
        worker_birth = ledger["roster"][worker]["birth"]
        for group in range(groups):
            rows = resources[group * 3:(group + 1) * 3]
            parent_entries = {ledger["resource_parents"][group * 3 + j] for j in range(3)}
            need(len(parent_entries) == 1, "Original resource sample changed parent between its three reads")
            parent = ledger["descriptor_history"][next(iter(parent_entries))]
            need(parent["close"] is not None and parent["entry"]["sequence"] < rows[0]["open_entry"]
                 and parent["close"] > rows[-1]["close"]["exit"],
                 "Original sample did not keep verified parent descriptor across three reads")
            for j, row in enumerate(rows):
                need(row["opened_by_tid"] == main and row["flags"] == 690176
                     and hex_bytes(row["path_hex"]) == COUNTERS[j].encode() and row["close"] is not None,
                     "Original counter open flags/thread/name differ")
                remaining = 2049 if j == 0 else 65; payload = bytearray()
                need(row["reads"] and row["reads"][-1]["result"] == 0, "Original counter omitted actual EOF")
                for k, read in enumerate(row["reads"]):
                    need(read["tid"] == main and read["requested"] == remaining
                         and (read["result"] > 0 or k == len(row["reads"]) - 1),
                         "Original bounded counter-read request/order differs")
                    payload.extend(hex_bytes(read["data_hex"], read["result"])); remaining -= read["result"]
                need(bytes(payload) == COUNTER_BYTES[j], "Original actual counter bytes differ from fixed baseline")
                if group == 0:
                    need(row["close"]["exit"] < worker_birth, "Original before sample ran after worker birth")
                else:
                    need(row["open_entry"] > joined["marker_exit"], "Original after sample preceded actual consumed join")
        worker_clocks = [row for row in ledger["clocks"] if row["tid"] == worker and row["role"] == 3]
        pre_role_clocks = [row for row in ledger["clocks"]
                           if row["tid"] in (main, worker) and row["role"] is None]
        need(all(row["entry"] < ledger["roles"][row["tid"]]["marker_entry"]
                 and row["result"] == 0 and row["injected"] is None for row in pre_role_clocks),
             "A pre-role observer clock was substituted for a request clock")
        actual_clocks = report.get("actual_clock_calls")
        need(type(actual_clocks) is list and len(actual_clocks) == len(ledger["clocks"]),
             "Original actual complete clock roster differs")
        for derived, actual in zip(ledger["clocks"], actual_clocks, strict=True):
            need(same(actual, derived), "Original complete clock result/timespec differs")
        paid_clocks = paid_clock_observation(value, worker_clocks, profile, disable_vdso)
        expected_fault = paid_clocks["expected_fault"]
        need(len(ledger["injections"]) == (0 if profile is None else 1)
             and same(report.get("fault"), expected_fault),
             "Original requested Work fault and complete actual injection roster differ")
        auxv = report.get("auxv"); request_start = None
        if disable_vdso:
            need(type(auxv) is dict and auxv.get("private_platform_fixture") is True
                 and auxv.get("normal_vdso_behavior_claimed") is False
                 and unsigned(auxv.get("AT_SYSINFO_EHDR_before")) and auxv["AT_SYSINFO_EHDR_before"] > 0
                 and same(auxv.get("AT_SYSINFO_EHDR_after"), 0), "Original raw-clock fixture omitted actual auxv evidence")
            before = hex_bytes(auxv.get("auxv_before_hex")); after = hex_bytes(auxv.get("auxv_after_hex"))
            need(len(before) == len(after) and len(before) % 16 == 0, "Original auxv capture extent differs")
            old = list(struct.iter_unpack("<QQ", before)); new = list(struct.iter_unpack("<QQ", after))
            need(old[-1][0] == new[-1][0] == 0 and sum(k == 33 for k, _ in old) == 1
                 and next(v for k, v in old if k == 33) == auxv["AT_SYSINFO_EHDR_before"]
                 and new == [(k, 0 if k == 33 else v) for k, v in old],
                 "Private original fixture changed more than one actual AT_SYSINFO_EHDR word")
            request_start = original_constructor_clocks(ledger, main, resources[0]["open_entry"], worker_birth)
            start = request_start["seconds"] * 1_000_000_000 + request_start["nanoseconds"]
            deadline = start + 4_000_000_000
            need(all(row["result"] != 0 or row["seconds"] * 1_000_000_000 + row["nanoseconds"] < deadline
                     for row in paid_clocks["work_clocks"]),
                 "Original successful alive sample did not precede its actual four-second deadline")
        else:
            need(same(auxv, {"private_platform_fixture": False, "auxv_unchanged": True}),
                 "Normal original vDSO positive altered platform auxv")
        files = {}
        for entry in ledger["entries"].values():
            opened = entry.get("actual_open")
            if entry["tid"] != worker or opened is None or opened["flags"] & 3 != 0 or opened["flags"] & 0x200000: continue
            leaf = hex_bytes(opened["path_hex"]).split(b"/")[-1].decode()
            files[leaf] = files.get(leaf, 0) + 1
        for name in ("boot", "membership", *LIMITS):
            need(files.get(name) == observation["host_calls"],
                 "Actual original fresh Host file-read count differs: " + name)
        capture.fence()
        return {"schema": "trnm.hia.work-owner-original-clock-audit.v2", "status": "PASS",
            "observation": value, "profile": profile, "private_no_vdso": disable_vdso,
            "raw": {"report.json": raw_identity(raw_report), "events.jsonl": raw_identity(raw_events),
                    "stdout.raw": raw_identity(stdout), "stderr.raw": raw_identity(stderr)},
            "syscalls": len(ledger["entries"]), "actual_owned_threads": len(ledger["roster"]),
            "actual_join": joined, "actual_join_futex_waits": waits,
            "actual_post_join_tid_word": joined["actual_child_tid_word"],
            "kernel_clear_tid_zero_observed_at_wait_return": any(row["clear_word"] == 0 for row in waits),
            "actual_worker_CLOCK1_syscalls": paid_clocks["worker_clock1_calls"],
            "actual_Work_CLOCK1_syscalls": len(paid_clocks["work_clocks"]),
            "actual_Paid_CLOCK3_syscalls": paid_clocks["paid_cpu_calls"],
            "actual_Paid_CLOCK1_syscalls": paid_clocks["paid_wall_calls"],
            "paid_clock_observation": {key: item for key, item in paid_clocks.items() if key != "work_clocks"},
            "actual_counter_files": len(resources),
            "actual_request_deadline_start": request_start, "actual_pre_role_clock_calls": pre_role_clocks,
            "full_counter_bytes_and_verified_parent_fd_lifetime": True,
            "original_deadline_seconds": 4, "normal_vdso_fault_behavior_claimed": False,
            "production_fixed_parent_authority": False, "whole_Node_or_paid_checkpoint_closed": False}
    finally:
        capture.close()


# This observer gate has its own owned Python child. It cannot substitute for a
# Work, Paid, native or Rust execution. All complete raw bytes are reread here.
OBSERVER_SCOPE = {
    "business_native_or_original_Rust_executed": False,
    "full_source_qualification_claimed_by_these_controls": False,
    "production_fixed_parent_authority": False,
    "whole_Node_or_paid_checkpoint_closed": False,
    "original_4s_16_service_gate_closed": False,
}
OBSERVER_MEMORY_RAW = (
    "maps-before.raw", "maps-after.raw", "child-status.raw",
    "child-self-readback.raw", "owned-readonly-before.raw",
    "owned-readonly-after.raw", "memory-operations.jsonl", "kernel-transfer.json",
)
OBSERVER_READER_SPECS = (
    ("positive-actual-owned-memory", True),
    ("wrong-memory-schema", False),
    ("extra-memory-authority", False),
    ("foreign-source-inputs", False),
    ("boolean-owned-child", False),
    ("coherent-readonly-bytes", False),
    ("coherent-readonly-permissions", False),
    ("invented-full-kernel-read", False),
    ("missing-actual-EFAULT", False),
    ("omitted-memory-control", False),
    ("truncated-child-self-readback", False),
    ("positive-actual-restored-memory", True),
)

OBSERVER_READER_FAILURES = {
    "wrong-memory-schema": "Observer memory schema/status/scope differs",
    "extra-memory-authority": "Observer memory schema/status/scope differs",
    "foreign-source-inputs": "Observer memory source binding differs",
    "boolean-owned-child": "Observer owned child identity/lifecycle differs",
    "coherent-readonly-bytes": "Observer complete readonly memory differs",
    "coherent-readonly-permissions": "Observer readonly permissions changed",
    "invented-full-kernel-read": "Observer actual kernel short read differs",
    "missing-actual-EFAULT": "Observer memory operation differs: fully-unreadable-page",
    "omitted-memory-control": "Observer memory control roster differs",
    "truncated-child-self-readback": "Observer child self readback differs",
}

def observer_mutation(baseline, name):
    """Retain exact controlled byte deltas; this never decides acceptance."""
    need(name in {label for label, _ in OBSERVER_READER_SPECS},
         "Unknown observer raw memory mutation")
    raw = dict(baseline)
    if name.startswith("positive-"):
        return raw
    report = decoded(raw["report.json"])
    def encoded(value):
        return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    if name == "wrong-memory-schema":
        report["schema"] = "trnm.hia.unbound-observer.v1"
    elif name == "extra-memory-authority":
        report["production_authority"] = True
    elif name == "foreign-source-inputs":
        report["source_inputs"] = {}
    elif name == "boolean-owned-child":
        report["owned_child"]["pid"] = True
    elif name == "coherent-readonly-bytes":
        changed = bytes([raw["owned-readonly-before.raw"][0] ^ 1]) + raw["owned-readonly-before.raw"][1:]
        raw["owned-readonly-before.raw"] = raw["owned-readonly-after.raw"] = changed
        own = decoded(raw["child-self-readback.raw"])
        own["sha256"] = hashlib.sha256(changed).hexdigest()
        raw["child-self-readback.raw"] = encoded(own)
        rows = [decoded(line) for line in raw["memory-operations.jsonl"].splitlines()]
        rows[0]["old_PEEK_hex"] = rows[0]["new_bulk_hex"] = changed[:1].hex()
        raw["memory-operations.jsonl"] = b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows)
    elif name == "coherent-readonly-permissions":
        address = report["owned_child"]["address"]
        lines = raw["maps-before.raw"].decode("ascii").splitlines(keepends=True)
        selected = []
        for index, line in enumerate(lines):
            extent, mode, *_ = line.split()
            low, high = (int(value, 16) for value in extent.split("-"))
            if low <= address < high:
                need(mode == "r--p", "Observer baseline is not read-only")
                selected.append(index)
        need(len(selected) == 1, "Observer readonly mutant has no unique mapped page")
        lines[selected[0]] = lines[selected[0]].replace(" r--p ", " rw-p ", 1)
        changed = "".join(lines).encode()
        need(changed != raw["maps-before.raw"], "Observer permission mutant did not change bytes")
        raw["maps-before.raw"] = raw["maps-after.raw"] = changed
    elif name == "invented-full-kernel-read":
        value = decoded(raw["kernel-transfer.json"]); value["returned"] = 16
        raw["kernel-transfer.json"] = encoded(value)
    elif name in ("missing-actual-EFAULT", "omitted-memory-control"):
        rows = [decoded(line) for line in raw["memory-operations.jsonl"].splitlines()]
        if name == "missing-actual-EFAULT":
            next(row for row in rows if row["name"] == "fully-unreadable-page")["errno"] = 0
        else:
            rows.pop()
        raw["memory-operations.jsonl"] = b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows)
    elif name == "truncated-child-self-readback":
        raw["child-self-readback.raw"] = raw["child-self-readback.raw"][:-3]
    else:
        raise ValueError("Observer raw mutation implementation missing")
    report["raw"] = {file: raw_identity(raw[file]) for file in OBSERVER_MEMORY_RAW}
    raw["report.json"] = encoded(report)
    return raw

def observer_json(raw, message):
    try:
        value = decoded(raw)
    except (ValueError, UnicodeError):
        raise ValueError(message) from None
    return value

def observer_layout(page):
    need(type(page) is int and page == 4096, "Observer requires the qualified x86-64 page size")
    data = bytearray((i * 17 + 11) % 256 for i in range(page * 4))
    strings = (
        ("plain", 64, b"owned/read-only/path"),
        ("cross-page", page - 13, b"across-readable-pages/" + b"x" * 43),
        ("last-readable-byte-terminator", 2 * page - 23, b"z" * 22),
        ("empty-readonly", 3 * page + 64, b""),
    )
    for _, offset, value in strings:
        data[offset:offset + len(value) + 1] = value + b"\0"
    data[512:576] = b"q" * 64
    reads = ((0, 1), (1, 7), (7, 9), (63, 32), (257, 257), (page - 13, 80),
             (page - 1, 2), (page + 17, 513), (2 * page - 8, 8),
             (3 * page + 16, 128), (4 * page - 17, 17))
    return bytes(data), reads, strings

def observer_operations(pid, page):
    data, reads, strings = observer_layout(page)
    rows = []
    for offset, extent in reads:
        value = data[offset:offset + extent].hex()
        rows.append({"name": "complete-read-%d-%d" % (offset, extent), "pid": pid,
                     "offset": offset, "extent": extent, "old_PEEK_hex": value,
                     "new_bulk_hex": value, "status": "PASS"})
    for name, offset, value in strings:
        rows.append({"name": "cstring-" + name, "pid": pid, "offset": offset,
                     "limit": 4096, "old_PEEK_hex": value.hex(),
                     "new_bulk_hex": value.hex(), "status": "PASS"})
    negatives = (
        ("strict-actual-short-read", "bytes", 2 * page - 8, 16,
         "ValueError", None, "Actual owned memory read was incomplete"),
        ("fully-unreadable-page", "bytes", 2 * page, 16, "OSError", 14, None),
        ("cstring-unreadable-page", "cstring", 2 * page, 4096, "OSError", 14, None),
        ("cstring-no-terminator-in-bound", "cstring", 512, 32,
         "ValueError", None, "Actual C string omitted bounded terminator"),
        ("negative-memory-extent", "bytes", 0, -1,
         "ValueError", None, "Private bounded memory read"),
        ("oversized-memory-extent", "bytes", 0, 65537,
         "ValueError", None, "Private bounded memory read"),
        ("missing-nonempty-address", "null", 0, 1,
         "ValueError", None, "Actual memory read address absent"),
    )
    for name, operation, offset, extent, kind, errno, message in negatives:
        rows.append({"name": name, "pid": pid, "operation": operation,
                     "offset": offset, "extent": extent, "status": "PASS",
                     "rejected": True, "error_type": kind, "errno": errno,
                     "message": message})
    rows.append({"name": "zero-extent-no-read", "pid": pid, "status": "PASS",
                 "old_PEEK_hex": "", "new_bulk_hex": ""})
    return rows

def observer_permissions(raw, address, page):
    try:
        lines = raw.decode("ascii").splitlines()
        mappings = []
        for line in lines:
            fields = line.split()
            low, high = (int(value, 16) for value in fields[0].split("-"))
            need(low < high and len(fields) >= 5, "Observer map record differs")
            mappings.append((low, high, fields[1]))
        result = []
        for index in range(4):
            start = address + page * index
            covering = [(low, high, mode) for low, high, mode in mappings
                        if low <= start and high >= start + page]
            need(len(covering) == 1, "Observer memory page lacks one complete mapping")
            result.append(covering[0][2])
        return result
    except (ValueError, IndexError, UnicodeError):
        raise ValueError("Observer readonly permissions changed") from None

def validate_owned_memory(directory, *, source_inputs):
    """Reread the actual stopped-child memory controls without creating a child."""
    capture = Capture(Path(directory), exact_names=("report.json", *OBSERVER_MEMORY_RAW))
    try:
        report_raw = capture.read("report.json", 256 << 10)
        report = observer_json(report_raw, "Observer memory report is not complete JSON")
        keys = {"schema", "status", "source_inputs", "source_after", "control_count",
                "positive", "negative", "owned_child", "raw", *OBSERVER_SCOPE}
        need(type(report) is dict and set(report) == keys
             and report.get("schema") == "trnm.hia.work-owner-observer-owned-memory.v1"
             and report.get("status") == "PASS"
             and all(report.get(key) is False for key in OBSERVER_SCOPE),
             "Observer memory schema/status/scope differs")
        need(same(report["source_inputs"], source_inputs) and report["source_after"] == "MATCH",
             "Observer memory source binding differs")
        need(same([report["control_count"], report["positive"], report["negative"]], [23, 16, 7]),
             "Observer memory control counts differ")
        child = report["owned_child"]
        need(type(child) is dict and set(child) == {
            "pid", "parent_pid", "address", "page_bytes", "initial_wait_status",
            "terminal_wait_status", "exit_code", "reaped", "ptrace_exitkill"},
            "Observer owned child identity/lifecycle differs")
        pid = child["pid"]; parent = child["parent_pid"]; address = child["address"]; page = child["page_bytes"]
        need(u32(pid) and pid > 0 and u32(parent) and parent > 0 and parent != pid
             and unsigned(address) and address > 0 and type(page) is int and page == 4096
             and address % page == 0 and same(child["initial_wait_status"], (19 << 8) | 127)
             and same(child["terminal_wait_status"], 0) and same(child["exit_code"], 0)
             and child["reaped"] is True and child["ptrace_exitkill"] is True,
             "Observer owned child identity/lifecycle differs")
        raw = {name: capture.read(name, 2 << 20) for name in OBSERVER_MEMORY_RAW}
        need(same(report["raw"], {name: raw_identity(value) for name, value in raw.items()}),
             "Observer memory complete raw identities differ")
        try:
            fields = {}
            for line in raw["child-status.raw"].decode("ascii").splitlines():
                key, value = line.split(":", 1)
                need(key not in fields, "Observer child status repeated a field")
                fields[key] = value.strip()
            need(all(fields.get(name) == str(wanted) for name, wanted in (
                ("Pid", pid), ("Tgid", pid), ("PPid", parent), ("TracerPid", parent)))
                 and fields.get("State", "").split()[0] == "t",
                 "Observer child was not its parent's stopped owned process")
        except (ValueError, IndexError, UnicodeError):
            raise ValueError("Observer child was not its parent's stopped owned process") from None
        need(raw["maps-before.raw"] == raw["maps-after.raw"]
             and observer_permissions(raw["maps-before.raw"], address, page) ==
                 ["r--p", "r--p", "---p", "r--p"],
             "Observer readonly permissions changed")
        data, _, _ = observer_layout(page)
        expected = data[:2 * page] + data[3 * page:]
        need(raw["owned-readonly-before.raw"] == raw["owned-readonly-after.raw"] == expected,
             "Observer complete readonly memory differs")
        own = observer_json(raw["child-self-readback.raw"], "Observer child self readback differs")
        need(same(own, {"pid": pid, "bytes": len(expected),
                       "sha256": hashlib.sha256(expected).hexdigest()}),
             "Observer child self readback differs")
        partial = observer_json(raw["kernel-transfer.json"], "Observer actual kernel short read differs")
        need(same(partial, {"pid": pid, "offset": 2 * page - 8, "requested": 16,
                           "returned": 8, "errno": 0,
                           "retained_prefix_hex": data[2 * page - 8:2 * page].hex()}),
             "Observer actual kernel short read differs")
        rows = [observer_json(line, "Observer memory operation JSON differs")
                for line in raw["memory-operations.jsonl"].splitlines()]
        expected_rows = observer_operations(pid, page)
        need(len(rows) == 23 and all(type(row) is dict for row in rows)
             and [row.get("name") for row in rows] == [row["name"] for row in expected_rows],
             "Observer memory control roster differs")
        for actual, expected in zip(rows, expected_rows, strict=True):
            need(same(actual, expected), "Observer memory operation differs: " + expected["name"])
        capture.fence()
        return {"status": "PASS", "count": 23, "positive": 16, "negative": 7,
                "owned_children": 1, "memory_report": raw_identity(report_raw),
                "raw": {name: raw_identity(value) for name, value in raw.items()}}
    finally:
        capture.close()

def observer_clock_replays(clock_root, complete):
    """Compare old completed-clock scans and incremental counts on all real events."""
    from .faults import profiles
    roster = [("normal-vdso-positive", None), ("private-raw-positive", None)]
    roster += [(profile["name"], profile) for profile in profiles()]
    need(type(complete.get("rows")) is list and len(complete["rows"]) == 20
         and [row.get("name") for row in complete["rows"]] == [name for name, _ in roster],
         "Observer clock ordinal replay lacks the exact twenty original captures")
    results = []
    for (name, profile), admitted in zip(roster, complete["rows"], strict=True):
        capture = Capture(Path(clock_root) / name)
        try:
            raw = {file: capture.read(file, 256 << 20) for file in
                   ("report.json", "events.jsonl", "stdout.raw", "stderr.raw")}
            identities = {file: raw_identity(value) for file, value in raw.items()}
            need(same(admitted.get("audit", {}).get("raw"), identities),
                 "Observer ordinal replay has another admitted complete capture")
            report = observer_json(raw["report.json"], "Observer ordinal trace report differs")
            events = [decoded(line) for line in raw["events.jsonl"].splitlines()]
            ledger = collect(events, raw["stderr.raw"])
            need(same(report.get("actual_clock_calls"), ledger["clocks"])
                 and same(report.get("actual_roles"), {str(k): v for k, v in ledger["roles"].items()}),
                 "Observer ordinal replay differs from complete actual clocks and roles")
            for key, file in (("events", "events.jsonl"), ("stdout", "stdout.raw"), ("stderr", "stderr.raw")):
                need(same(report.get(key), identities[file]), "Observer ordinal raw identity differs")
            completed = []; counts = {}; roles = {}; pending = {}
            pre_role = 0; post_role = 0; selected = []
            for row in events:
                tid = row["tid"]
                if row["kind"] == "actual-role":
                    need(tid not in roles, "Observer role reset repeated")
                    roles[tid] = {"role": row["role"], "index": row["index"], "count": 0}
                elif row["kind"] == "syscall-entry" and row["nr"] == 228:
                    old = sum(value == tid for value in completed) + 1
                    current = counts.get(tid, 0) + 1
                    need(tid not in pending and old == current and same(row.get("clock_ordinal"), old),
                         "Observer completed-clock ordinal changed")
                    pending[tid] = (row, old)
                    if tid in roles:
                        role = roles[tid]; role["count"] += 1; post_role += 1
                        need(same([row.get("role"), row.get("role_index"), row.get("role_clock_ordinal")],
                                  [role["role"], role["index"], role["count"]]),
                             "Observer role ordinal reset or injection position changed")
                    else:
                        pre_role += 1
                        need(all(key not in row for key in ("role", "role_index", "role_clock_ordinal", "fault")),
                             "Observer pre-role clock gained request authority")
                    if "fault" in row:
                        need(profile is not None and row.get("role") == 3 and row.get("role_index") == 0
                             and same(row.get("role_clock_ordinal"), profile["clock_syscall_ordinal"])
                             and same(row.get("clock_id"), 1)
                             and same(row["fault"], {"kind": "clock",
                                "error": 5 if profile["errno"] == "EIO" else 22,
                                "original_syscall_skipped": True}),
                             "Observer Work injection position changed")
                        selected.append({"entry": row["sequence"], "tid": tid,
                            "completed_ordinal": old, "role_ordinal": row["role_clock_ordinal"],
                            "logical_Work_ordinal": profile["ordinal"], "clock_id": row["clock_id"]})
                elif row["kind"] == "syscall-exit" and row["nr"] == 228:
                    entry, ordinal = pending.pop(tid)
                    need(same(row["entry"], entry["sequence"]), "Observer clock completion changed")
                    completed.append(tid); counts[tid] = ordinal
            need(not pending and post_role > 0 and len(completed) == pre_role + post_role
                 and len(completed) == len(ledger["clocks"])
                 and len(selected) == (0 if profile is None else 1),
                 "Observer completed-clock replay omitted events or actual injection")
            clock_bytes = (json.dumps(ledger["clocks"], sort_keys=True, separators=(",", ":")) + "\n").encode()
            results.append({"name": name, "status": "PASS", "events": len(events),
                "clock_count": len(completed), "before_role": pre_role, "after_role": post_role,
                "per_tid_completed_counts": {str(k): v for k, v in sorted(counts.items())},
                "role_counts": {str(k): v for k, v in sorted(roles.items())},
                "actual_injection_positions": selected, "complete_clock_values": raw_identity(clock_bytes),
                "raw": identities})
            capture.fence()
        finally:
            capture.close()
    return results

def observer_control_outcome(directory, *, source_inputs):
    try:
        validate_owned_memory(directory, source_inputs=source_inputs)
        return True, None
    except (ValueError, OSError) as error:
        return False, str(error)

def validate_observer_reader_controls(directory, *, source_inputs, baseline):
    names = ("report.json", *(name for name, _ in OBSERVER_READER_SPECS))
    capture = Capture(Path(directory), exact_names=names)
    original = None
    try:
        original = Capture(Path(directory).parent / "memory", exact_names=("report.json", *OBSERVER_MEMORY_RAW))
        baseline_raw = {file: original.read(file, 2 << 20) for file in ("report.json", *OBSERVER_MEMORY_RAW)}
        need(same({file: raw_identity(value) for file, value in baseline_raw.items()}, baseline),
             "Observer reader baseline complete bytes differ")
        encoded = capture.read("report.json", 512 << 10)
        report = observer_json(encoded, "Observer memory reader report is incomplete")
        keys = {"schema", "status", "source_inputs", "source_after", "baseline_after",
                "baseline", "count", "positive", "negative", "rows",
                "actual_owned_children_executed_by_reader_controls", *OBSERVER_SCOPE}
        need(type(report) is dict and set(report) == keys
             and report.get("schema") == "trnm.hia.work-owner-observer-memory-reader-controls.v1"
             and report.get("status") == "PASS"
             and all(report.get(key) is False for key in OBSERVER_SCOPE)
             and same(report.get("source_inputs"), source_inputs)
             and report.get("source_after") == report.get("baseline_after") == "MATCH",
             "Observer memory reader schema/source/scope differs")
        need(same([report["count"], report["positive"], report["negative"],
                   report["actual_owned_children_executed_by_reader_controls"]], [12, 2, 10, 0])
             and same(report["baseline"], baseline),
             "Observer memory reader counts or baseline differ")
        need(type(report["rows"]) is list and len(report["rows"]) == 12
             and [row.get("name") for row in report["rows"]] == [name for name, _ in OBSERVER_READER_SPECS],
             "Observer memory reader control roster differs")
        for (name, expected), row in zip(OBSERVER_READER_SPECS, report["rows"], strict=True):
            child = Capture(Path(directory) / name, exact_names=("report.json", *OBSERVER_MEMORY_RAW))
            try:
                actual_raw = {file: raw_identity(child.read(file, 2 << 20))
                              for file in ("report.json", *OBSERVER_MEMORY_RAW)}
                child.fence()
            finally:
                child.close()
            expected_raw = observer_mutation(baseline_raw, name)
            need(same(actual_raw, {file: raw_identity(value) for file, value in expected_raw.items()}),
                 "Observer reader control changed outside its exact mutation: " + name)
            acceptance, failure = observer_control_outcome(Path(directory) / name, source_inputs=source_inputs)
            need(failure == OBSERVER_READER_FAILURES.get(name),
                 "Observer raw memory control refused for another reason: " + name)
            need(acceptance is expected and same(row, {
                "name": name, "status": "PASS", "expected_acceptance": expected,
                "actual_acceptance": acceptance, "actual_failure": failure, "raw": actual_raw}),
                 "Observer raw memory reader control did not independently reproduce: " + name)
            if expected:
                need(same(actual_raw, baseline), "Observer restored full memory baseline differs")
        capture.fence()
        original.fence()
        return raw_identity(encoded)
    finally:
        if original is not None: original.close()
        capture.close()

def validate_observer_controls(directory, *, source_inputs, clock_root, complete):
    need(__debug__, "Observer memory readback refuses optimized Python")
    directory = Path(directory); clock_root = Path(clock_root)
    need(directory == clock_root / "observer-memory-controls",
         "Observer controls are outside the admitted original clock root")
    capture = Capture(directory, exact_names=("report.json", "memory", "reader-controls"))
    try:
        raw = capture.read("report.json", 2 << 20)
        report = observer_json(raw, "Observer composite report is incomplete")
        keys = {"schema", "status", "source_inputs", "source_after", "memory",
                "memory_report", "reader_controls_report", "clock_ordinal_replays",
                "memory_count", "memory_positive", "memory_negative", "owned_children",
                "clock_ordinal_replay_count", "reader_count", "reader_positive", "reader_negative",
                *OBSERVER_SCOPE}
        need(type(report) is dict and set(report) == keys
             and report.get("schema") == "trnm.hia.work-owner-observer-controls.v1"
             and report.get("status") == "PASS"
             and all(report.get(key) is False for key in OBSERVER_SCOPE)
             and same(report.get("source_inputs"), source_inputs) and report.get("source_after") == "MATCH",
             "Observer composite schema/source/scope differs")
        need(same([report["memory_count"], report["memory_positive"], report["memory_negative"],
                   report["owned_children"], report["clock_ordinal_replay_count"],
                   report["reader_count"], report["reader_positive"], report["reader_negative"]],
                  [23, 16, 7, 1, 20, 12, 2, 10]),
             "Observer composite count types or values differ")
        memory = validate_owned_memory(directory / "memory", source_inputs=source_inputs)
        need(same(memory, report["memory"]) and same(memory["memory_report"], report["memory_report"]),
             "Observer complete memory report is disconnected")
        baseline = {"report.json": memory["memory_report"], **memory["raw"]}
        reader = validate_observer_reader_controls(directory / "reader-controls",
                                                   source_inputs=source_inputs, baseline=baseline)
        need(same(reader, report["reader_controls_report"]), "Observer raw reader report is disconnected")
        replays = observer_clock_replays(clock_root, complete)
        need(same(report["clock_ordinal_replays"], replays),
             "Observer complete original clock ordinal replay differs")
        need(same(complete.get("observer_memory_controls"), report)
             and same(complete.get("observer_memory_controls_report"), raw_identity(raw)),
             "Original clock report omits or disconnects observer memory controls")
        capture.fence()
        return {
            "original_observer_memory_controls": 23,
            "original_observer_memory_positive_controls": 16,
            "original_observer_memory_negative_controls": 7,
            "original_observer_owned_memory_children": 1,
            "original_observer_clock_ordinal_replays": 20,
            "original_observer_memory_raw_reader_controls": 12,
            "original_observer_memory_raw_positive_controls": 2,
            "original_observer_memory_raw_negative_controls": 10,
            "original_observer_memory_controls_status": "PASS",
            "original_observer_memory_control_report": raw_identity(raw),
            "original_observer_memory_raw_report": memory["memory_report"],
            "original_observer_memory_reader_report": reader,
        }
    finally:
        capture.close()
