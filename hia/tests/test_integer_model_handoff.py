"""Actual held stock State and original Rust versus a single named HIA call."""
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.platform.integer_model_handoff.build import BODY, ENTRY, WORK, build, inspect_text
from hia.tests.test_integer_model_project import (
    FRAME, MARK, OPCODES, Session, create_state, digest, emit_existing_owner,
    original_with_projection, panel, request, snapshot_request,
)


def native_entry(library):
    holder = ctypes.CDLL(str(library))
    fun = getattr(holder, ENTRY)
    fun.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 3
    fun.restype = ctypes.c_uint64
    return fun


def invoke(fun, wire, output_cap=BODY + 13, work_cap=WORK + 29):
    source = ctypes.create_string_buffer(wire, max(1, len(wire)))
    output = ctypes.create_string_buffer(MARK * output_cap, max(1, output_cap))
    scratch = ctypes.create_string_buffer(b"W" * work_cap, max(1, work_cap))
    code = fun(source, len(wire), output, output_cap, scratch, work_cap)
    if source.raw[:len(wire)] != wire or scratch.raw[WORK:work_cap] != b"W" * max(work_cap - WORK, 0):
        raise ValueError("Held native handoff changed the immutable input or scratch suffix")
    return code, output.raw[:output_cap], scratch.raw[:work_cap]


class IntegerModelHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-model-handoff-")))
        cls.library, cls.build_proof = build(cls.work / "held")
        cls.entry = staticmethod(native_entry(cls.library))
        if digest(cls.library.read_bytes()) != cls.build_proof["artifact_sha256"]:
            raise ValueError("Held library changed before first use")

    def test_importless_single_export_and_rejected_owned_aliases(self):
        proof = self.build_proof
        self.assertEqual(proof["backend"], "selfhost-only")
        self.assertEqual(proof["dynamic"]["dynamic_exports"], [ENTRY])
        self.assertEqual(proof["dynamic"]["unresolved_imports"], [])
        self.assertEqual(proof["decoded"]["direct_calls"], ((206, 282), (247, 32701)))
        self.assertEqual(proof["decoded"]["system_instruction_count"], 0)
        self.assertFalse(proof["runtime_host_shuttle"])
        self.assertEqual(invoke(self.entry, request(struct.pack("<Q", 0), bytes(32), bytes(32)))[:2],
                         (2, MARK * (BODY + 13)))
        self.assertEqual(invoke(self.entry, b"Z" * 296017)[:2],
                         (100, MARK * (BODY + 13)))
        self.assertEqual(invoke(self.entry, b"Z", work_cap=WORK - 1)[:2],
                         (102, MARK * (BODY + 13)))

        # Only addresses of actual owned allocations are used. No real
        # service, fake high address, protected mapping or OS action.
        a = ctypes.create_string_buffer(b"x" * WORK, WORK)
        b = ctypes.create_string_buffer(b"y" * WORK, WORK)
        original = a.raw, b.raw
        self.assertEqual(self.entry(a, 80, a, BODY, b, WORK), 1 << 32)
        self.assertEqual(self.entry(a, 80, b, BODY, a, WORK), 1 << 32)
        self.assertEqual(self.entry(a, 80, b, BODY, b, WORK), 1 << 32)
        self.assertEqual((a.raw, b.raw), original)
        code = self.library.parent / "linked.raw"
        body = bytearray(code.read_bytes())
        body[206] ^= 1
        mutant = self.work / "unexpected-carrier.raw"
        mutant.write_bytes(body)
        with self.assertRaisesRegex(ValueError, "machine-text extent/hash differs"):
            inspect_text(mutant)

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT"),
                         "requires verified prebuilt locked Rust, not an approximated oracle")
    def test_original_full_stock_snapshots_using_one_named_call_each(self):
        stock = self.work / "stock"
        stock.mkdir()
        owner, owner_proof = emit_existing_owner(stock)
        self.owner_binding = owner_proof
        oracle_dir = self.work / "oracle"
        oracle_dir.mkdir()
        rust, proof = original_with_projection(oracle_dir)
        self.original_binding = proof
        self.assertEqual(proof["mode"], "verified-prebuilt-original-lock")
        self.handoff_observations = []
        for index, (artifact, family, rows, projected_status, downstream) in enumerate(panel()):
            with self.subTest(index=index):
                s = Session(owner, self.work / f"native-{index}", seconds=30)
                try:
                    state = create_state(s, rows)
                    view = s.request(OPCODES["view.new"], a=state)
                    self.assertEqual(view["status"], 0)
                    snapshot, counters = snapshot_request(s, state)
                    query = artifact + family + struct.pack("<I", len(snapshot)) + snapshot
                    result = subprocess.run([rust], input=query, capture_output=True, check=True,
                                            env={}, timeout=20)
                    self.assertEqual(result.stderr, b"")
                    reference = json.loads(result.stdout)
                    wire = request(snapshot, artifact, family)
                    expected_status = projected_status if downstream is None else downstream
                    body = bytes.fromhex(reference["loaded_body"]) if downstream == 0 else b""
                    if downstream is not None:
                        self.assertEqual(reference["original_load"], {
                            0: "OK", 3: "FACTOR_MODEL_METADATA",
                            4: "FACTOR_MODEL_CHUNK", 10: "FACTOR_MODEL_HASH",
                        }[downstream])
                    elif projected_status in (1, 2):
                        self.assertEqual(reference["status"], projected_status)
                    code, output, work = invoke(self.entry, wire)
                    self.assertEqual((code, output), (expected_status, body + MARK * (len(output) - len(body))))
                    if downstream is not None:
                        self.assertEqual(work[:FRAME], bytes.fromhex(reference["projected"]))
                    if downstream == 0:
                        self.assertIn(len(body), (BODY - 2, BODY))
                        self.assertEqual(invoke(self.entry, wire, output_cap=len(body), work_cap=WORK)[:2],
                                         (0, body))
                        self.assertEqual(invoke(self.entry, wire, output_cap=len(body)-1)[:2],
                                         (102, MARK * (len(body) - 1)))
                        # Adjacent ranges in the same actual allocation are
                        # legal: all three spans are exactly half-open.
                        joined = ctypes.create_string_buffer(wire + MARK * len(body) + b"W" * WORK)
                        base = ctypes.addressof(joined)
                        self.assertEqual(self.entry(base, len(wire), base + len(wire), len(body),
                                         base + len(wire) + len(body), WORK), 0)
                        self.assertEqual(joined.raw[:len(wire)+len(body)], wire + body)
                    self.assertEqual(snapshot_request(s, state), (snapshot, counters))
                    self.assertEqual(s.request(OPCODES["view.drop"], a=view["result"])["status"], 0)
                    end = s.request(OPCODES["close"])
                    self.assertEqual((end["status"], end["live_objects"], end["live_blocks"]), (0, 0, 0))
                finally:
                    receipt = s.finish(allow_failure=not s.closed)
                self.handoff_observations.append({
                    "case": index, "request_sha256": digest(wire), "snapshot_sha256": digest(snapshot),
                    "original_load": reference["original_load"], "status": code,
                    "output_sha256": digest(output), "output_extent": len(body),
                    "internal_projected_sha256": digest(work[:FRAME]) if downstream is not None else None,
                    "stock_owner_receipt": receipt,
                })
        self.assertEqual(digest(self.library.read_bytes()), self.build_proof["artifact_sha256"])
        self.assertEqual(len(self.handoff_observations), 24)
