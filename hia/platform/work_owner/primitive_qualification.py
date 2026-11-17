"""Execute private arithmetic/continuation controls against actual compiled HIA.

Only these tests map flat code into their own process. They do not emulate the
owner, supply production authority or replace the separate static ELF tests.
"""
from __future__ import annotations
import ctypes
import hashlib
import mmap
from pathlib import Path
import struct
from .build import digest, identity, need, write_json
from .primitive_evidence import Recorder, validate as validate_primitive_bytes

class Buffer:
    def __init__(self, size, raw=None):
        self.size = size
        self.value = ctypes.create_string_buffer(size + 64)
        ctypes.memset(ctypes.addressof(self.value), 0xa5, 32)
        ctypes.memset(ctypes.addressof(self.value) + 32 + size, 0x5a, 32)
        self.pointer = ctypes.addressof(self.value) + 32
        if raw is not None:
            need(len(raw) == size, "Private input buffer extent differs")
            ctypes.memmove(self.pointer, raw, size)

    def body(self):
        return ctypes.string_at(self.pointer, self.size)

    def check(self):
        need(self.value.raw[:32] == b"\xa5" * 32
             and self.value.raw[32 + self.size:] == b"\x5a" * 32,
             "Actual native flat call escaped a captured buffer")

    def word(self, offset, value):
        need(0 <= offset <= self.size - 8, "Private test word escaped buffer")
        ctypes.memmove(self.pointer + offset, struct.pack("<Q", value), 8)

class Flat:
    def __init__(self, path, recorder, name):
        self.recorder = recorder; self.name = name
        self.path = Path(path); self.identity = identity(self.path)
        raw = self.path.read_bytes()
        self.mapping = mmap.mmap(-1, len(raw), prot=mmap.PROT_READ | mmap.PROT_WRITE)
        self.mapping.write(raw)
        self.address = ctypes.addressof(ctypes.c_char.from_buffer(self.mapping))
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect.restype = ctypes.c_int
        need(libc.mprotect(self.address, len(raw), mmap.PROT_READ | mmap.PROT_EXEC) == 0,
             "Actual private native RX mapping failed")
        self.function = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.c_void_p, ctypes.c_size_t)(self.address)

    def call(self, first, second, third):
        result = self.recorder.invoke(self.name, self.function, (first, second, third))
        for value in (first, second, third): value.check()
        return result

    def close(self):
        need(identity(self.path) == self.identity, "Actual flat image changed during execution")
        self.function = None
        self.mapping.close()

def run(build_dir, cases, output):
    output = Path(output); output.mkdir(mode=0o700)
    rows = []; modules = {}
    recorder = Recorder(output / "raw-buffers")
    report = {"schema": "trnm.hia.work-owner-primitives.v1", "status": "FAIL",
              "rows": rows, "production_authority": False, "actual_original_Rust": False,
              "mapping_profile": "private RW capture then RX; no RWX mapping"}
    try:
        for name in ("sha", "work", "owner"):
            modules[name] = Flat(Path(build_dir) / (name + ".flat.bin"), recorder, name)
        lengths = list(range(130)) + [255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
            2047, 2048, 2049, 4095, 4096, 4097, 65535, 65536, 65537, 131135, 131136]
        need(len(lengths) == 150, "SHA coverage roster differs")
        for length in lengths:
            recorder.begin("sha-" + str(length), "sha", "sha")
            data = bytes((i * 73 + length * 29 + 0xa5) & 255 for i in range(length))
            inp, out, arena = Buffer(length, data), Buffer(32), Buffer(132256)
            status = modules["sha"].call(inp, out, arena)
            expected = hashlib.sha256(data).digest()
            need(status == 32 and out.body() == expected and inp.body() == data,
                 "Actual optimized HIA SHA differs from independent SHA-256")
            rows.append({"name": "sha-" + str(length), "kind": "sha", "status": "PASS",
                         "input": {"bytes": length, "sha256": digest(data)}, "digest": out.body().hex()})
        for name, sizes in (("input-bound", (131137, 32, 132256)),
                            ("output-short", (3, 31, 132256)),
                            ("output-long", (3, 33, 132256)),
                            ("arena-short", (3, 32, 132255))):
            recorder.begin("sha-" + name, "sha-bound", "sha")
            buffers = [Buffer(n) for n in sizes]
            before = [b.body() for b in buffers]
            need(modules["sha"].call(*buffers) == 4294967293
                 and [b.body() for b in buffers] == before, "SHA refused extent mutated captured data")
            rows.append({"name": "sha-" + name, "kind": "sha-bound", "status": "PASS"})
        mathematical = cases[:4] + cases[52:]
        need(len(mathematical) == 13, "Complete arithmetic correspondence roster differs")
        for case in mathematical:
            recorder.begin(case["name"], "work", "work")
            data = bytes.fromhex(case["request_hex"])
            inp, progress, arena = Buffer(len(data), data), Buffer(64), Buffer(270336)
            points = []; elapsed = 0
            for _ in range(1357):
                status = modules["work"].call(inp, progress, arena)
                elapsed += recorder.last_cpu_ns
                if status < 64: break
                values = list(struct.unpack("<8Q", progress.body()))
                need(64 <= status <= 69 and values[0] == status and values[4] == len(points) + 1,
                     "Actual W1 continuation emitted a malformed progress event")
                points.append(values[:5])
            else: raise ValueError("Actual W1 continuation exceeded its bounded progress profile")
            need(status == case["code"] and points == case["progress"] and inp.body() == data,
                 "Actual W1 continuation differs from independent complete progress/product expectation")
            if status == 0:
                need(arena.body()[205984:222368] == bytes.fromhex(case["product_hex"]),
                     "Actual native product differs from independently computed A*B")
            state = arena.body(); event = progress.body()
            need(modules["work"].call(inp, progress, arena) == 11
                 and arena.body() == state and progress.body() == event, "Consumed continuation replay accepted")
            other = Buffer(len(data), data[:-1] + bytes([data[-1] ^ 1]))
            need(modules["work"].call(other, progress, arena) == 11
                 and arena.body() == state and progress.body() == event,
                 "Consumed continuation accepted another proof")
            rows.append({"name": case["name"], "kind": "work", "status": "PASS",
                         "return_code": status, "progress": points, "cpu_ns": elapsed,
                         "input": {"bytes": len(data), "sha256": digest(data)},
                         "product_sha256": digest(arena.body()[205984:222368]) if status == 0 else None,
                         "consumed_replay_and_cross_proof_rejected": True})
        data = bytes.fromhex(cases[0]["request_hex"])
        for name, sizes, code in (("request-short", (49283, 64, 270336), 1),
                                  ("event-short", (49284, 63, 270336), 10),
                                  ("event-long", (49284, 65, 270336), 10),
                                  ("arena-short", (49284, 64, 270335), 10)):
            recorder.begin(name, "work-bound", "work")
            buffers = [Buffer(sizes[0], data[:sizes[0]]), Buffer(sizes[1]), Buffer(sizes[2])]
            before = [b.body() for b in buffers]
            need(modules["work"].call(*buffers) == code and [b.body() for b in buffers] == before,
                 "W1 extent refusal altered a buffer")
            rows.append({"name": name, "kind": "work-bound", "status": "PASS"})
        # These are intentionally private event fixtures. Production events
        # are generated by the native adapter, never accepted from stdin.
        for name, offset, value in (("foreign-tid", 24, 2), ("foreign-generation", 32, 2),
                                    ("foreign-role", 16, 0), ("out-of-order-phase", 112, 102)):
            recorder.begin(name, "owner-identity", "owner")
            event, command, state = Buffer(128), Buffer(4096), Buffer(65536)
            for offset0, value0 in ((16, 1), (24, 1), (32, 1)): event.word(offset0, value0)
            need(modules["owner"].call(event, command, state) == 0
                 and struct.unpack_from("<Q", state.body())[0] == 101
                 and struct.unpack_from("<Q", command.body())[0] == 3, "Private live-owner initial transition differs")
            event.word(112, 101); event.word(offset, value)
            before = (command.body(), state.body())
            need(modules["owner"].call(event, command, state) == 88
                 and (command.body(), state.body()) == before, "Owner continuation identity/phase substitution accepted")
            rows.append({"name": name, "kind": "owner-identity", "status": "PASS",
                         "fixture_is_production_authority": False})
        report.update(status="PASS", count=len(rows), sha_vectors=150, sha_bounds=4,
                      work_histories=13, work_bounds=4, owner_identity_controls=4,
                      images={name: module.identity for name, module in modules.items()})
    except BaseException as error:
        report["failure"] = repr(error)
        raise
    finally:
        failures = []
        for name, module in modules.items():
            try: module.close()
            except BaseException as error: failures.append({"name": name, "error": repr(error)})
        if failures: report.update(status="FAIL", final_fence_errors=failures)
        try:
            report["raw_evidence"] = recorder.finish(
                {name: module.identity for name, module in modules.items()}, report["status"])
            if report["status"] == "PASS":
                validate_primitive_bytes(output / "raw-buffers", report, cases, report["images"])
                report["raw_readback"] = "PASS"
        except BaseException as error:
            report.update(status="FAIL", raw_readback="FAIL", raw_evidence_failure=repr(error))
        write_json(output / "report.json", report)
    need(report["status"] == "PASS", "Primitive image fence failed")
    return report
