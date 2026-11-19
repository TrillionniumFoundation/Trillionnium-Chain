"""Capture and independently read every byte around actual private flat calls.

These are test observations, not production authority or execution attestations.
The recorder stores complete original guarded buffers in content-addressed chunks;
the reader reconstructs them and checks the source-defined 177-control contract.
"""
from __future__ import annotations
from collections import OrderedDict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import time
import weakref

SCHEMA = "trnm.hia.work-owner-primitive-bytes.v1"
CHUNK_BYTES = 4096
MAX_BUFFER_BYTES = 270336 + 64
MAX_INDEX_BYTES = 128 << 20
MAX_PHYSICAL_BYTES = 256 << 20
HEX = re.compile(r"[0-9a-f]{64}\Z")
LEFT = b"\xa5" * 32
RIGHT = b"\x5a" * 32


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unsigned(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 <= value <= maximum


def same(first, second):
    if type(first) is not type(second):
        return False
    if type(first) is dict:
        return first.keys() == second.keys() and all(same(first[k], second[k]) for k in first)
    if type(first) is list:
        return len(first) == len(second) and all(same(a, b) for a, b in zip(first, second))
    return first == second


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "Duplicate primitive evidence JSON field")
        out[key] = value
    return out


def decoded(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite evidence number")))


def raw_identity(raw):
    return {"bytes": len(raw), "sha256": digest(raw)}


def identity_shape(value):
    return (type(value) is dict and set(value) == {"bytes", "sha256"}
            and unsigned(value["bytes"]) and type(value["sha256"]) is str
            and HEX.fullmatch(value["sha256"]) is not None)


def exact_keys(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label + " has unexpected fields")


def summary(index, manifest):
    return {
        "schema": SCHEMA,
        "manifest": raw_identity(manifest),
        "calls": index["calls"],
        "case_count": len(index["cases"]),
        "call_count": index["call_count"],
        "buffer_count": len(index["buffers"]),
        "snapshot_count": len(index["snapshots"]),
        "chunk_count": len(index["chunk_sizes"]),
        "logical_capture_bytes": index["logical_capture_bytes"],
        "physical_chunk_bytes": sum(index["chunk_sizes"].values()),
        "native_cpu_ns": index["native_cpu_ns"],
        "native_wall_ns": index["native_wall_ns"],
        "guards_and_complete_bodies_retained": True,
    }


class Recorder:
    """Only Flat.call invokes capture around its actual native function."""

    def __init__(self, directory):
        require(__debug__, "Primitive capture refuses optimized Python")
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        (self.directory / "chunks").mkdir(mode=0o700)
        self.calls = (self.directory / "calls.jsonl").open("xb")
        self.buffer_ids = weakref.WeakKeyDictionary()
        self.buffers = []
        self.snapshots = {}
        self.chunk_sizes = {}
        self.cases = []
        self.current = None
        self.call_count = 0
        self.logical_bytes = 0
        self.native_cpu_ns = 0
        self.native_wall_ns = 0
        self.last_cpu_ns = 0
        self.finished = False

    def begin(self, name, kind, image):
        require(not self.finished and type(name) is str and name, "Invalid primitive capture case")
        if self.current is not None:
            require(self.current["calls"] > 0, "Empty primitive capture case")
        self.current = {"name": name, "kind": kind, "image": image,
                        "first_call": self.call_count, "calls": 0}
        self.cases.append(self.current)

    def buffer(self, value):
        if value not in self.buffer_ids:
            require(unsigned(value.size, MAX_BUFFER_BYTES - 64), "Native buffer outside captured profile")
            number = len(self.buffers) + 1
            self.buffer_ids[value] = number
            self.buffers.append({"id": number, "body_bytes": value.size})
        return self.buffer_ids[value]

    def snapshot(self, raw):
        require(type(raw) is bytes and 64 <= len(raw) <= MAX_BUFFER_BYTES, "Invalid captured backing extent")
        self.logical_bytes += len(raw)
        key = digest(raw)
        if key not in self.snapshots:
            chunks = []
            for offset in range(0, len(raw), CHUNK_BYTES):
                chunk = raw[offset:offset + CHUNK_BYTES]
                chunk_key = digest(chunk)
                if chunk_key not in self.chunk_sizes:
                    path = self.directory / "chunks" / (chunk_key + ".bin")
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    try:
                        view = memoryview(chunk)
                        while view:
                            written = os.write(fd, view)
                            require(written > 0, "Captured chunk short write")
                            view = view[written:]
                    finally:
                        os.close(fd)
                    self.chunk_sizes[chunk_key] = len(chunk)
                else:
                    require(self.chunk_sizes[chunk_key] == len(chunk), "Captured chunk identity collision")
                chunks.append(chunk_key)
            self.snapshots[key] = {"bytes": len(raw), "chunks": chunks}
        else:
            require(self.snapshots[key]["bytes"] == len(raw), "Captured buffer identity collision")
        return key

    def invoke(self, image, function, values):
        require(not self.finished and self.current is not None and self.current["image"] == image,
                "Native call escaped its recorded primitive control")
        ids = [self.buffer(value) for value in values]
        before = [self.snapshot(value.value.raw) for value in values]
        cpu_before = time.thread_time_ns()
        wall_before = time.monotonic_ns()
        result = function(values[0].pointer, values[0].size, values[1].pointer, values[1].size,
                          values[2].pointer, values[2].size)
        wall_after = time.monotonic_ns()
        cpu_after = time.thread_time_ns()
        after = [self.snapshot(value.value.raw) for value in values]
        cpu = cpu_after - cpu_before
        wall = wall_after - wall_before
        require(unsigned(result, (1 << 32) - 1) and unsigned(cpu) and unsigned(wall),
                "Invalid actual native result or measured interval")
        call = {"case": self.current["name"], "image": image, "ordinal": self.current["calls"],
                "buffer_ids": ids, "before": before, "after": after, "return_code": result,
                "native_cpu_ns": cpu, "native_wall_ns": wall}
        self.calls.write(encoded(call))
        self.current["calls"] += 1
        self.call_count += 1
        self.native_cpu_ns += cpu
        self.native_wall_ns += wall
        self.last_cpu_ns = cpu
        return result

    def finish(self, images, status):
        require(not self.finished, "Primitive recorder already consumed")
        self.finished = True
        self.calls.flush()
        os.fsync(self.calls.fileno())
        self.calls.close()
        calls = (self.directory / "calls.jsonl").read_bytes()
        index = {
            "schema": SCHEMA, "status": status, "chunk_bytes": CHUNK_BYTES,
            "images": images, "calls": raw_identity(calls), "cases": self.cases,
            "buffers": self.buffers, "snapshots": self.snapshots, "chunk_sizes": self.chunk_sizes,
            "call_count": self.call_count, "logical_capture_bytes": self.logical_bytes,
            "native_cpu_ns": self.native_cpu_ns, "native_wall_ns": self.native_wall_ns,
            "production_authority": False,
        }
        raw = encoded(index)
        require(len(raw) <= MAX_INDEX_BYTES and sum(self.chunk_sizes.values()) <= MAX_PHYSICAL_BYTES,
                "Complete primitive evidence exceeds its explicit observation profile")
        with (self.directory / "manifest.json").open("xb") as stream:
            stream.write(raw)
        return summary(index, raw)


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            value.st_mode, value.st_nlink, value.st_uid, value.st_gid)


class SafeRoot:
    """Hold every directory by descriptor; never re-open through an ancestor path."""

    def __init__(self, root):
        path = Path(root)
        require(path.is_absolute() and str(path) == str(root) and ".." not in path.parts,
                "Absolute canonical primitive evidence root required")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        try:
            for component in path.parts[1:]:
                require(component not in ("", ".", ".."), "Invalid evidence ancestor")
                child = os.open(component, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            self.fd = fd
            fd = None
        finally:
            if fd is not None:
                os.close(fd)
        self.chunk_fd = None
        self.stamps = {}
        try:
            self.root_stamp = _stamp(os.fstat(self.fd))
            require(set(os.listdir(self.fd)) == {"manifest.json", "calls.jsonl", "chunks"},
                    "Primitive evidence root has missing or extra entries")
            self.chunk_fd = os.open("chunks", flags, dir_fd=self.fd)
            self.chunk_stamp = _stamp(os.fstat(self.chunk_fd))
            self.chunk_names = set(os.listdir(self.chunk_fd))
            require(all(type(name) is str and re.fullmatch(r"[0-9a-f]{64}\.bin", name)
                        for name in self.chunk_names), "Unexpected primitive chunk filename")
        except BaseException:
            self.close()
            raise

    def read(self, name, maximum):
        require(type(name) is str and unsigned(maximum), "Invalid primitive evidence read")
        if name.startswith("chunks/"):
            leaf = name[7:]
            require(re.fullmatch(r"[0-9a-f]{64}\.bin", leaf) is not None,
                    "Invalid chunk path")
            directory = self.chunk_fd
        else:
            require(name in ("manifest.json", "calls.jsonl"), "Unexpected primitive evidence file")
            leaf = name
            directory = self.fd
        before_name = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(before_name.st_mode) and before_name.st_nlink == 1,
                "Primitive evidence must be a single-link regular file")
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(_stamp(before) == _stamp(before_name) and before.st_size <= maximum,
                    "Primitive evidence changed before capture or exceeds extent")
            pieces = []
            remaining = before.st_size
            while remaining:
                part = os.read(fd, min(remaining, 1 << 20))
                require(part, "Truncated primitive evidence")
                pieces.append(part)
                remaining -= len(part)
            require(os.read(fd, 1) == b"", "Primitive evidence grew during capture")
            require(_stamp(os.fstat(fd)) == _stamp(before)
                    == _stamp(os.stat(leaf, dir_fd=directory, follow_symlinks=False)),
                    "Primitive evidence changed during capture")
            if name in self.stamps:
                require(self.stamps[name] == _stamp(before), "Previously captured evidence changed")
            self.stamps[name] = _stamp(before)
            return b"".join(pieces)
        finally:
            os.close(fd)

    def fence(self):
        require(_stamp(os.fstat(self.fd)) == self.root_stamp
                and _stamp(os.fstat(self.chunk_fd)) == self.chunk_stamp,
                "Primitive evidence directory changed")
        require(set(os.listdir(self.fd)) == {"manifest.json", "calls.jsonl", "chunks"}
                and set(os.listdir(self.chunk_fd)) == self.chunk_names,
                "Primitive evidence roster changed")
        for name, stamp in self.stamps.items():
            directory, leaf = (self.chunk_fd, name[7:]) if name.startswith("chunks/") else (self.fd, name)
            require(_stamp(os.stat(leaf, dir_fd=directory, follow_symlinks=False)) == stamp,
                    "Captured primitive evidence changed after reading")

    def close(self):
        if self.chunk_fd is not None:
            os.close(self.chunk_fd)
            self.chunk_fd = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Snapshots:
    def __init__(self, safe, index):
        self.safe = safe
        self.index = index
        self.chunks = {}
        self.cache = OrderedDict()
        self.used = set()
        chunk_sizes = index["chunk_sizes"]
        require(type(chunk_sizes) is dict and chunk_sizes, "Missing captured chunks")
        require(all(type(k) is str and HEX.fullmatch(k) and unsigned(v, CHUNK_BYTES) and v > 0
                    for k, v in chunk_sizes.items()), "Invalid primitive chunk identity or extent")
        require(sum(chunk_sizes.values()) <= MAX_PHYSICAL_BYTES, "Primitive chunk storage exceeds bound")
        require(safe.chunk_names == {key + ".bin" for key in chunk_sizes},
                "Missing or extra primitive chunk")
        for key, size in chunk_sizes.items():
            raw = safe.read("chunks/" + key + ".bin", size)
            require(len(raw) == size and digest(raw) == key, "Captured chunk bytes differ from identity")
            self.chunks[key] = raw
        snapshots = index["snapshots"]
        require(type(snapshots) is dict and snapshots, "Missing captured snapshots")
        referenced = set()
        for key, descriptor in snapshots.items():
            require(type(key) is str and HEX.fullmatch(key), "Invalid whole-buffer identity")
            exact_keys(descriptor, ("bytes", "chunks"), "Buffer snapshot")
            size = descriptor["bytes"]
            require(unsigned(size, MAX_BUFFER_BYTES) and size >= 64, "Invalid whole-buffer extent")
            parts = descriptor["chunks"]
            require(type(parts) is list and len(parts) == (size + CHUNK_BYTES - 1) // CHUNK_BYTES,
                    "Incomplete whole-buffer chunk sequence")
            for i, part in enumerate(parts):
                require(type(part) is str and part in self.chunks, "Unknown captured chunk")
                require(len(self.chunks[part]) == min(CHUNK_BYTES, size - i * CHUNK_BYTES),
                        "Chunk has the wrong position-dependent extent")
                referenced.add(part)
        require(referenced == set(self.chunks), "Unreferenced primitive chunk")

    def body(self, key, size):
        require(type(key) is str and key in self.index["snapshots"], "Unknown captured whole buffer")
        self.used.add(key)
        if key in self.cache:
            raw = self.cache.pop(key)
        else:
            descriptor = self.index["snapshots"][key]
            raw = b"".join(self.chunks[part] for part in descriptor["chunks"])
            require(len(raw) == descriptor["bytes"] and digest(raw) == key,
                    "Reconstructed whole-buffer bytes differ")
        self.cache[key] = raw
        if len(self.cache) > 8:
            self.cache.popitem(last=False)
        require(len(raw) == size + 64 and raw[:32] == LEFT and raw[-32:] == RIGHT,
                "Actual captured primitive guard or buffer extent differs")
        return raw[32:-32]


def owner_identity_initial():
    """Exact first worker issue before any supplied Paid completion or Host result."""
    event, command, state = bytearray(128), bytearray(4096), bytearray(65536)
    for offset in (16, 24, 32):
        struct.pack_into("<Q", event, offset, 1)
    for offset, value in ((0, 11), (8, 1), (64, 90)):
        struct.pack_into("<Q", command, offset, value)
    for offset, value in ((0, 90), (16, 1), (24, 1), (32, 1)):
        struct.pack_into("<Q", state, offset, value)
    return bytes(event), bytes(command), bytes(state)


def paid_constructor_steps(fixture):
    """Exact private standalone-constructor ABI observations, not a CPU model.

    Both entries use the original trusted-local standalone epoch. The fixture
    bit binds the entry identity only; it never changes that epoch's credit.
    The supplied clock and lock completions exist only inside this flat test.
    No supplied event is accepted by the production executable's stdin.
    """
    require(type(fixture) is bool, "Exact private constructor profile required")
    event, state, epoch = bytearray(640), bytearray(73728), bytearray(4096)

    def put(raw, values):
        for offset, value in values:
            struct.pack_into("<Q", raw, offset, value)

    def step(mode, code):
        return (bytes(event), mode, bytes(state), bytes(epoch), code)

    put(event, ((8, 11), (16, 1), (32, (1 << 64) - 1), (608, 1)))
    put(state, ((256, 3), (320, 910), (392, 11), (400, 1),
                (416, (1 << 64) - 1), (448, 102), (1600, 1),
                (1616, 1), (1672, int(fixture))))
    rows = [step(0, 0)]
    # A foreign actual-owner identity cannot continue the private constructor.
    put(event, ((8, 12), (56, 3), (64, 7), (72, 123)))
    rows.append(step(0, 1))
    put(event, ((8, 11),))
    put(state, ((256, 0), (320, 102), (1160, 7), (1168, 123)))
    rows.append(step(0, 0))
    put(event, ((56, 0),))
    put(state, ((256, 4), (264, 1), (320, 103)))
    rows.append(step(0, 0))
    put(event, ((56, 4), (80, 1)))
    put(state, ((256, 5), (320, 104)))
    put(epoch, ((0, int.from_bytes(b"PCPU0001", "little")),
                (16, 2_000_000_000), (32, 7), (40, 123), (72, 1),
                (80, 2_000_000_000)))
    rows.append(step(1, 0))
    put(event, ((56, 5), (80, 0)))
    put(state, ((1600, 0), (1624, 1),
                (4096, int.from_bytes(b"PCOWN001", "little")),
                (4104, (1 << 64) - 1), (4248, 1), (4256, 11), (4264, 1)))
    rows.append(step(0, 512))
    # Even a fresh method generation cannot remint this completed epoch.
    put(event, ((608, 2),))
    rows.append(step(0, 1))
    return rows


def _expected_roster(cases):
    lengths = list(range(130)) + [255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
        2047, 2048, 2049, 4095, 4096, 4097, 65535, 65536, 65537, 131135, 131136]
    rows = [("sha-" + str(n), "sha", "sha", 1, n) for n in lengths]
    rows += [("sha-" + name, "sha-bound", "sha", 1, sizes) for name, sizes in (
        ("input-bound", (131137, 32, 132256)), ("output-short", (3, 31, 132256)),
        ("output-long", (3, 33, 132256)), ("arena-short", (3, 32, 132255)))]
    math = cases[:4] + cases[52:]
    require(len(cases) == 61 and len(math) == 13, "Complete current primitive corpus required")
    rows += [(case["name"], "work", "work", len(case["progress"]) + 3, case) for case in math]
    rows += [(name, "work-bound", "work", 1, (sizes, code)) for name, sizes, code in (
        ("request-short", (49283, 64, 270336), 1), ("event-short", (49284, 63, 270336), 10),
        ("event-long", (49284, 65, 270336), 10), ("arena-short", (49284, 64, 270335), 10))]
    rows += [(name, "owner-identity", "owner", 2, (offset, value)) for name, offset, value in (
        ("foreign-tid", 24, 2), ("foreign-generation", 32, 2),
        ("foreign-role", 16, 0), ("out-of-order-phase", 112, 102))]
    rows += [(name + "-standalone-constructor", "paid-constructor", name, 7, fixture)
             for name, fixture in (("paid", False), ("paid-fixture", True))]
    require(len(rows) == 177 and len({r[0] for r in rows}) == 177, "Primitive control roster differs")
    return rows


def validate(directory, report, cases, images):
    """Read all raw bytes without executing or importing any artifact as code."""
    require(__debug__, "Primitive evidence reader refuses optimized Python")
    safe = SafeRoot(directory)
    try:
        raw = safe.read("manifest.json", MAX_INDEX_BYTES)
        index = decoded(raw)
        exact_keys(index, ("schema", "status", "chunk_bytes", "images", "calls", "cases",
                          "buffers", "snapshots", "chunk_sizes", "call_count", "logical_capture_bytes",
                          "native_cpu_ns", "native_wall_ns", "production_authority"), "Primitive manifest")
        require(index["schema"] == SCHEMA and index["status"] == "PASS"
                and type(index["chunk_bytes"]) is int and index["chunk_bytes"] == CHUNK_BYTES
                and index["production_authority"] is False, "Unsuccessful or wrong primitive capture")
        require(type(images) is dict and set(images) == {"sha", "work", "owner", "paid", "paid-fixture"}
                and all(identity_shape(v) for v in images.values())
                and same(index["images"], images), "Primitive image bindings differ")
        roster = _expected_roster(cases)
        total = sum(row[3] for row in roster)
        require(unsigned(index["call_count"]) and index["call_count"] == total,
                "Primitive actual call count differs")
        require(identity_shape(index["calls"]) and index["calls"]["bytes"] <= total * 2048,
                "Invalid primitive call-stream extent")
        calls_raw = safe.read("calls.jsonl", total * 2048)
        require(same(raw_identity(calls_raw), index["calls"]), "Complete primitive call stream differs")
        lines = calls_raw.splitlines(keepends=True)
        require(len(lines) == total and all(line.endswith(b"\n") for line in lines),
                "Missing or extra primitive call")
        call_rows = [decoded(line) for line in lines]
        require(type(index["cases"]) is list and len(index["cases"]) == 177,
                "Primitive captured case roster incomplete")
        require(type(index["buffers"]) is list, "Missing primitive buffer allocation roster")
        sizes = {}
        for number, buffer in enumerate(index["buffers"], 1):
            exact_keys(buffer, ("id", "body_bytes"), "Buffer allocation")
            require(type(buffer["id"]) is int and buffer["id"] == number
                    and unsigned(buffer["body_bytes"], MAX_BUFFER_BYTES - 64),
                    "Primitive buffer identity/extent differs")
            sizes[number] = buffer["body_bytes"]
        require(type(report) is dict and report.get("schema") == "trnm.hia.work-owner-primitives.v1"
                and report.get("status") == "PASS"
                and report.get("production_authority") is False and report.get("actual_original_Rust") is False
                and same(report.get("images"), images), "Primitive report scope or actual images differ")
        require(type(report.get("count")) is int and report["count"] == 177
                and type(report.get("rows")) is list and len(report["rows"]) == 177,
                "Primitive report is incomplete")
        for key, value in (("sha_vectors", 150), ("sha_bounds", 4), ("work_histories", 13),
                           ("work_bounds", 4), ("owner_identity_controls", 4),
                           ("paid_constructor_controls", 2)):
            require(type(report.get(key)) is int and report[key] == value, "Primitive category count differs")
        snapshots = Snapshots(safe, index)
        cursor = 0
        next_buffer = 1
        logical_bytes = 0
        cpu_sum = 0
        wall_sum = 0

        def pull(name, image, ordinal, ids, expected_before):
            nonlocal cursor, logical_bytes, cpu_sum, wall_sum
            row = call_rows[cursor]
            cursor += 1
            exact_keys(row, ("case", "image", "ordinal", "buffer_ids", "before", "after",
                             "return_code", "native_cpu_ns", "native_wall_ns"), "Actual native call")
            require(row["case"] == name and row["image"] == image
                    and type(row["ordinal"]) is int and row["ordinal"] == ordinal
                    and same(row["buffer_ids"], ids), "Primitive call order, image or buffer identity differs")
            require(unsigned(row["return_code"], (1 << 32) - 1)
                    and unsigned(row["native_cpu_ns"]) and unsigned(row["native_wall_ns"]),
                    "Invalid native result or timing type")
            require(type(row["before"]) is list and len(row["before"]) == 3
                    and type(row["after"]) is list and len(row["after"]) == 3,
                    "Incomplete before/after capture")
            before = [snapshots.body(key, sizes[number]) for key, number in zip(row["before"], ids)]
            after = [snapshots.body(key, sizes[number]) for key, number in zip(row["after"], ids)]
            require(before == expected_before, "Primitive before/after continuity or initial bytes differ")
            require(after[0] == before[0], "Actual read-only primitive input changed")
            logical_bytes += 2 * sum(sizes[number] + 64 for number in ids)
            cpu_sum += row["native_cpu_ns"]
            wall_sum += row["native_wall_ns"]
            return row, after

        for position, (name, kind, image, count, detail) in enumerate(roster):
            expected_case = {"name": name, "kind": kind, "image": image, "first_call": cursor, "calls": count}
            require(same(index["cases"][position], expected_case), "Captured primitive control sequence differs")
            observed = report["rows"][position]
            require(type(observed) is dict and observed.get("name") == name
                    and observed.get("kind") == kind and observed.get("status") == "PASS",
                    "Primitive semantic report order differs")
            ids = [next_buffer, next_buffer + 1, next_buffer + 2]
            next_buffer += 3
            if kind == "sha":
                length = detail
                data = bytes((i * 73 + length * 29 + 0xa5) & 255 for i in range(length))
                extents = (length, 32, 132256)
                expected = [data, bytes(32), bytes(132256)]
            elif kind == "sha-bound":
                extents = detail
                expected = [bytes(size) for size in extents]
            elif kind == "work":
                data = bytes.fromhex(detail["request_hex"])
                extents = (len(data), 64, 270336)
                expected = [data, bytes(64), bytes(270336)]
            elif kind == "work-bound":
                extents, return_code = detail
                data = bytes.fromhex(cases[0]["request_hex"])[:extents[0]]
                expected = [data, bytes(extents[1]), bytes(extents[2])]
            elif kind == "paid-constructor":
                extents = (640, 73728, 0)
                expected = [paid_constructor_steps(detail)[0][0], bytes(73728), b""]
            else:
                extents = (128, 4096, 65536)
                event = bytearray(128)
                for offset in (16, 24, 32):
                    struct.pack_into("<Q", event, offset, 1)
                expected = [bytes(event), bytes(4096), bytes(65536)]
            require(all(number in sizes and sizes[number] == size for number, size in zip(ids, extents)),
                    "Actual allocated primitive extent differs")
            if kind in ("sha", "sha-bound", "work-bound"):
                call, after = pull(name, image, 0, ids, expected)
                if kind == "sha":
                    exact_keys(observed, ("name", "kind", "status", "input", "digest"), "SHA report")
                    wanted = hashlib.sha256(data).digest()
                    require(call["return_code"] == 32 and after[1] == wanted
                            and same(observed["input"], raw_identity(data)) and observed["digest"] == wanted.hex(),
                            "Captured actual SHA result differs from independent SHA-256")
                else:
                    exact_keys(observed, ("name", "kind", "status"), "Extent report")
                    code = 4294967293 if kind == "sha-bound" else return_code
                    require(call["return_code"] == code and after == expected,
                            "Refused primitive extent changed captured memory")
            elif kind == "work":
                exact_keys(observed, ("name", "kind", "status", "return_code", "progress", "cpu_ns",
                                      "input", "product_sha256", "consumed_replay_and_cross_proof_rejected"),
                           "Work primitive report")
                measured = 0
                for ordinal, point in enumerate(detail["progress"]):
                    call, after = pull(name, image, ordinal, ids, expected)
                    require(call["return_code"] == point[0]
                            and list(struct.unpack("<8Q", after[1]))[:5] == point,
                            "Captured actual continuation progress differs")
                    measured += call["native_cpu_ns"]
                    expected = after
                terminal = len(detail["progress"])
                call, after = pull(name, image, terminal, ids, expected)
                measured += call["native_cpu_ns"]
                require(call["return_code"] == detail["code"], "Captured terminal Work result differs")
                if detail["code"] == 0:
                    require(after[2][205984:222368] == bytes.fromhex(detail["product_hex"]),
                            "Captured native product differs from independent A*B")
                product_sha = digest(after[2][205984:222368]) if detail["code"] == 0 else None
                require(type(observed["return_code"]) is int and observed["return_code"] == detail["code"]
                        and same(observed["progress"], detail["progress"])
                        and type(observed["cpu_ns"]) is int and observed["cpu_ns"] == measured
                        and same(observed["input"], raw_identity(data))
                        and observed["product_sha256"] == product_sha
                        and observed["consumed_replay_and_cross_proof_rejected"] is True,
                        "Work primitive report differs from complete captured calls")
                expected = after
                call, after = pull(name, image, terminal + 1, ids, expected)
                require(call["return_code"] == 11 and after == expected,
                        "Consumed continuation replay mutated or accepted")
                other = data[:-1] + bytes([data[-1] ^ 1])
                require(next_buffer in sizes and sizes[next_buffer] == len(data),
                        "Missing separate cross-proof input buffer")
                ids = [next_buffer, ids[1], ids[2]]
                next_buffer += 1
                expected = [other, expected[1], expected[2]]
                call, after = pull(name, image, terminal + 2, ids, expected)
                require(call["return_code"] == 11 and after == expected,
                        "Consumed continuation accepted or mutated another proof")
            elif kind == "paid-constructor":
                exact_keys(observed, ("name", "kind", "status", "initial_credit_ns",
                                      "foreign_tid_refused", "reinitialize_refused",
                                      "fixture_is_production_authority"), "Paid constructor report")
                require(type(observed["initial_credit_ns"]) is int
                        and observed["initial_credit_ns"] == 2_000_000_000
                        and observed["foreign_tid_refused"] is True
                        and observed["reinitialize_refused"] is True
                        and observed["fixture_is_production_authority"] is False,
                        "Private standalone constructor scope or initial credit differs")
                require(next_buffer in sizes and sizes[next_buffer] == 4096,
                        "Missing complete private Paid epoch buffer")
                epoch_id = next_buffer
                next_buffer += 1
                before_state, before_epoch = bytes(73728), bytes(4096)
                for ordinal, (event, mode, state, epoch, code) in enumerate(paid_constructor_steps(detail)):
                    call_ids = ids[:2] + [epoch_id if mode else ids[2]]
                    expected = [event, before_state, before_epoch if mode else b""]
                    call, after = pull(name, image, ordinal, call_ids, expected)
                    require(call["return_code"] == code
                            and after == [event, state, epoch if mode else b""],
                            "Actual standalone constructor complete bytes or refusal differs")
                    before_state, before_epoch = state, epoch
            else:
                exact_keys(observed, ("name", "kind", "status", "fixture_is_production_authority"),
                           "Owner identity report")
                require(observed["fixture_is_production_authority"] is False,
                        "Private owner event acquired production authority")
                call, after = pull(name, image, 0, ids, expected)
                require(call["return_code"] == 0 and tuple(after) == owner_identity_initial(),
                        "Actual private owner first Paid issue complete bytes differ")
                event = bytearray(after[0])
                struct.pack_into("<Q", event, 112, 90)
                struct.pack_into("<Q", event, detail[0], detail[1])
                expected = [bytes(event), after[1], after[2]]
                call, after = pull(name, image, 1, ids, expected)
                require(call["return_code"] == 88 and after == expected,
                        "Owner identity/phase substitution accepted or changed state")
        require(cursor == total and next_buffer == len(sizes) + 1
                and snapshots.used == set(index["snapshots"]), "Unconsumed primitive call, buffer or snapshot")
        for key, value in (("logical_capture_bytes", logical_bytes), ("native_cpu_ns", cpu_sum),
                           ("native_wall_ns", wall_sum)):
            require(type(index[key]) is int and index[key] == value, "Primitive capture accounting differs")
        expected_summary = summary(index, raw)
        require(same(report.get("raw_evidence"), expected_summary),
                "Primitive raw evidence binding or strict field type differs")
        safe.fence()
        return expected_summary
    finally:
        safe.close()


def read_file(path, maximum):
    """Read one descriptor-bound regular file without following any ancestor."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts and path.name not in ("", ".", ".."),
            "Absolute evidence file required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    file_fd = None
    try:
        for name in path.parent.parts[1:]:
            child = os.open(name, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_size <= maximum,
                "Bounded single-link regular evidence file required")
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                          dir_fd=directory)
        before = os.fstat(file_fd)
        require(_stamp(before) == _stamp(named), "Evidence file replaced before read")
        chunks = []
        remaining = before.st_size
        while remaining:
            raw = os.read(file_fd, min(remaining, 1 << 20))
            require(raw, "Evidence file truncated")
            chunks.append(raw)
            remaining -= len(raw)
        require(os.read(file_fd, 1) == b""
                and _stamp(os.fstat(file_fd)) == _stamp(before)
                == _stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)),
                "Evidence file changed during read")
        return b"".join(chunks)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory)


def main():
    import argparse
    import traceback
    from .build import ROOT, source_manifest, write_json
    from .bundle import canonical_root, overlap, validate_build
    from .cases import corpus
    require(__debug__, "Primitive evidence CLI refuses optimized Python")
    parser = argparse.ArgumentParser(description="Independently read the complete actual primitive buffer capture")
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--primitive-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    require(output.resolve() == output and not output.exists() and not output.is_symlink(),
            "Fresh canonical primitive readback output required")
    for protected in (ROOT, args.build.absolute(), args.capture.absolute(), args.primitive_report.absolute()):
        require(not overlap(output, protected), "Readback output overlaps source or captured evidence")
    output.mkdir(mode=0o700)
    result = {"schema": "trnm.hia.work-owner-primitive-byte-readback.v1", "status": "FAIL",
              "production_authority": False, "complete_native_or_original_qualification": False}
    before = None
    build_raw = None
    report_raw = None
    try:
        before = source_manifest()
        write_json(output / "source-before.json", before)
        build_root = canonical_root(args.build)
        require(build_root.name == "build", "Complete captured native build directory required")
        build_raw = read_file(build_root / "build.json", 32 << 20)
        built = decoded(build_raw)
        require(type(built) is dict and same(built.get("source_inputs"), before),
                "Primitive reader requires the exact current complete native source closure")
        validate_build(build_root.parent, {"source_inputs": before, "build": built})
        report_raw = read_file(args.primitive_report.absolute(), 32 << 20)
        primitive = decoded(report_raw)
        require(type(primitive) is dict and primitive.get("raw_readback") == "PASS",
                "No successful producer byte readback")
        images = {name: built["native_images"][name]
                  for name in ("sha", "work", "owner", "paid", "paid-fixture")}
        observed = validate(args.capture.absolute(), primitive, corpus(), images)
        result.update(status="PASS", raw_evidence=observed, build=raw_identity(build_raw),
                      primitive_report=raw_identity(report_raw), source_inputs=before)
    except BaseException as error:
        result.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        if before is not None:
            try:
                after = source_manifest()
                write_json(output / "source-after.json", after)
                require(same(before, after), "Primitive reader source changed")
                if build_raw is not None:
                    require(read_file(args.build.absolute() / "build.json", 32 << 20) == build_raw,
                            "Primitive build changed after reading")
                if report_raw is not None:
                    require(read_file(args.primitive_report.absolute(), 32 << 20) == report_raw,
                            "Primitive report changed after reading")
                result["source_after"] = "MATCH"
            except BaseException as error:
                result.update(status="FAIL", source_after="FAIL", final_fence_failure=repr(error))
        else:
            result["source_after"] = "ADMISSION_DID_NOT_COMPLETE"
        write_json(output / "report.json", result)
    print(json.dumps({key: result.get(key) for key in ("status", "source_after", "failure")}, sort_keys=True))
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
