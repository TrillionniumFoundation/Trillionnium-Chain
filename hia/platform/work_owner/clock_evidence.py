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
    def __init__(self, root):
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
            need(self.names in (mandatory, mandatory | {"audit.json"}),
                 "Original CLOCK directory omitted or added evidence")
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

def compare_observation(value, baseline, profile):
    need(type(value) is dict and value.get("schema") == "trnm.hia.work-owner-original-clock-observation.v1"
         and value.get("name") == baseline["name"]
         and value.get("input_sha256") == hashlib.sha256(bytes.fromhex(baseline["request_hex"])).hexdigest(),
         "Actual original CLOCK input observation differs")
    for field in ("actual_original_W1", "actual_original_Host_primitives",
                  "actual_original_task_alive_and_final_resource", "actual_original_std_scoped_spawn_and_join",
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
        expected_clock_count = (profile["ordinal"] if profile is not None else 2200) if disable_vdso else 0
        need(len(worker_clocks) == expected_clock_count
             and all(row["clock_id"] == 1 and row["role"] == 3 and row["role_index"] == 0 for row in worker_clocks),
             "Actual original CLOCK1 count/thread identity differs")
        expected_fault = None
        if profile is not None:
            error = 5 if profile["errno"] == "EIO" else 22
            expected_fault = {"clock_roles": [3], "clock_when": profile["ordinal"], "clock_error": error}
            need(len(ledger["injections"]) == 1 and worker_clocks[-1]["result"] == -error
                 and worker_clocks[-1]["role_clock_ordinal"] == profile["ordinal"]
                 and all(row["result"] == 0 for row in worker_clocks[:-1]),
                 "Original CLOCK fault was retried, moved, or not reached")
        else:
            need(not ledger["injections"] and all(row["result"] == 0 for row in worker_clocks),
                 "Positive original CLOCK run injected or failed a sample")
        need(same(report.get("fault"), expected_fault), "Original requested CLOCK fault profile differs")
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
            main_clocks = [row for row in ledger["clocks"] if row["tid"] == main and row["role"] == 1]
            need(len(main_clocks) == 1 and main_clocks[0]["clock_id"] == 1
                 and main_clocks[0]["result"] == 0 and main_clocks[0]["role_clock_ordinal"] == 1
                 and ledger["roles"][main]["marker_exit"] < main_clocks[0]["entry"]
                 and main_clocks[0]["exit"] < resources[0]["open_entry"] < worker_birth,
                 "Actual original deadline-start clock differs")
            request_start = main_clocks[0]
            start = request_start["seconds"] * 1_000_000_000 + request_start["nanoseconds"]
            deadline = start + 4_000_000_000
            need(all(row["result"] != 0 or row["seconds"] * 1_000_000_000 + row["nanoseconds"] < deadline
                     for row in worker_clocks),
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
        return {"schema": "trnm.hia.work-owner-original-clock-audit.v1", "status": "PASS",
            "observation": value, "profile": profile, "private_no_vdso": disable_vdso,
            "raw": {"report.json": raw_identity(raw_report), "events.jsonl": raw_identity(raw_events),
                    "stdout.raw": raw_identity(stdout), "stderr.raw": raw_identity(stderr)},
            "syscalls": len(ledger["entries"]), "actual_owned_threads": len(ledger["roster"]),
            "actual_join": joined, "actual_join_futex_waits": waits,
            "actual_post_join_tid_word": joined["actual_child_tid_word"],
            "kernel_clear_tid_zero_observed_at_wait_return": any(row["clear_word"] == 0 for row in waits),
            "actual_worker_CLOCK1_syscalls": len(worker_clocks), "actual_counter_files": len(resources),
            "actual_request_deadline_start": request_start, "actual_pre_role_clock_calls": pre_role_clocks,
            "full_counter_bytes_and_verified_parent_fd_lifetime": True,
            "original_deadline_seconds": 4, "normal_vdso_fault_behavior_claimed": False,
            "production_fixed_parent_authority": False, "whole_Node_or_paid_checkpoint_closed": False}
    finally:
        capture.close()
