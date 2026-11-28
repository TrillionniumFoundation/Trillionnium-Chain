"""Raw native State export to native IMD2 bytes and the unchanged named loader."""

import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.platform.integer_model_snapshot.build import ENTRY, build as named_loader
from hia.tests.native_support import NativeModule
from hia.tests.test_integer_model_select import (
    ROOT, STATE_REFERENCE, MARK, OPCODES, Session, create_state, digest,
    emit_existing_owner, frame as ims1_frame, model_rows, snapshot_request,
)
from hia.tests import integer_model_material_original as rust_source
from hia.tools.toolchain import pinned_toolchain

SRC = ROOT / "hia/src/state/integer_model_project.hepta"
SELECT = ROOT / "hia/src/state/integer_model_select.hepta"
SELECT_ADAPTER = Path(__file__).with_name("rust_integer_model_select_reference.rs")
FRAME = 18648
RESULT = 7790
WORK = 9014


def original_with_projection(work):
    target = os.environ.get("HIA_M06_ORACLE_PREBUILT")
    if not target:
        raise ValueError("no verified original M06 prebuilt dependency graph")
    combined = rust_source.caller_source()
    original_driver = rust_source.CALLER.read_bytes()
    assert combined.endswith(original_driver)
    original = combined.removesuffix(original_driver)
    a = original_driver.index(b"const ROW:")
    b = original_driver.index(b"const RESPONSE:")
    e = original_driver.index(b"fn encode_cell")
    f = original_driver.index(b"fn hash_arg", e)
    projector = original_driver[a:b] + original_driver[e:f]
    transport = STATE_REFERENCE.read_bytes()
    decoder = transport[transport.index(b"fn take<'a>"):transport.index(b"fn encode_node(")]
    adapter = SELECT_ADAPTER.read_bytes()
    bind = b'            "old_count": old.len(), "new_count": new.len(),\n'
    assert adapter.count(bind) == 1
    additions = b'''            "projected": project(&state, id, family).map(hex::encode),
            "loaded_body": loaded.as_ref().ok().map(|m|
                hex::encode([m.id().as_slice(), m.encode().as_slice()].concat())),
'''
    raw = original + b"\nuse std::io::Read;\n" + decoder + projector
    raw += adapter.replace(bind, bind + additions)
    binary, receipt = rust_source.verified_prebuilt(work, target, raw, linked=("-C", "strip=symbols"))
    return binary, {**receipt, "original_projector_sha256": digest(projector),
                    "original_load_capture_sha256": digest(original), "binary_sha256": digest(binary.read_bytes())}


def request(snapshot, artifact, family):
    return b"IMP1\0\0\0\0" + artifact + snapshot + family


def invoke_loader(library, frame):
    """Only move the exact native-projected owned bytes to the held old ABI."""
    method = getattr(ctypes.CDLL(str(library)), ENTRY)
    method.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 3
    method.restype = ctypes.c_uint64
    source = ctypes.create_string_buffer(frame, len(frame))
    result = ctypes.create_string_buffer(MARK * (RESULT + 13), RESULT + 13)
    scratch = ctypes.create_string_buffer(b"X" * (WORK + 11), WORK + 11)
    code = method(source, len(frame), result, len(result), scratch, len(scratch))
    if code >> 32 != 0 or source.raw != frame or scratch.raw[WORK:] != b"X" * 11:
        raise ValueError("held native loader violated the typed ABI")
    return code, result.raw


def panel():
    for artifact, family, rows, chosen, full in model_rows():
        downstream = {"OK": 0, "FACTOR_MODEL_METADATA": 3, "FACTOR_MODEL_CHUNK": 4}.get(full)
        if chosen:
            yield artifact, family, rows, chosen, None
        elif downstream == 0:
            yield artifact, family, rows, 0, 0
            for version in (2, 3):
                prefix = f"linear-model-v{version}:{artifact.hex()}:"
                if prefix + "meta" not in rows:
                    continue
                meta = rows[prefix + "meta"]
                yield artifact, family, {**rows, prefix + "meta": {**meta, "family": "f" * 64}}, 0, 3
                yield artifact, family, {**rows, prefix + "meta": {**meta, "bytes": 7}}, 0, 3
                chunk = rows[prefix + "00"]
                # Preserve the noncanonical byte; only old IMD2 owns rejection.
                yield artifact, family, {**rows, prefix + "00": "F" + chunk[1:]}, 0, 4
                almost = dict(rows)
                almost[prefix + "08"] = almost.pop(prefix + "07")
                yield artifact, family, almost, 104, None
                new_id = bytes([artifact[0] ^ 0x80]) + artifact[1:]
                replaced = f"linear-model-v{version}:{new_id.hex()}:"
                recoded = {replaced + k[len(prefix):] if k.startswith(prefix) else k: v
                           for k, v in rows.items()}
                yield new_id, family, recoded, 0, 10
        else:
            # Original metadata/chunk errors for shapes deliberately outside
            # our typed slot cap stay separately identified as private refuses.
            yield artifact, family, rows, 104, None


class IntegerModelProject(unittest.TestCase):
    def test_both_native_projectors_fail_closed_with_no_reference_process(self):
        wire = request(struct.pack("<Q", 0), bytes(32), bytes(32))
        cases = [
            (wire, FRAME, 2),
            (wire, FRAME-1, 102),
            (wire[:4] + b"\x01" + wire[5:], FRAME, 100),
            (wire[:-1], FRAME, 100),
        ]
        for mode in ("direct", "selfhost"):
            with NativeModule(SRC, backend=mode, byte_exports=("f0",)) as module:
                for source, count, status in cases:
                    got = module.call("f0", [source, MARK * FRAME, b"Z" * count])
                    got.require_returned()
                    self.assertEqual((got.value, got.arguments[:2]), (status, [source, MARK * FRAME]))

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT"), "requires the locked original M06 graph")
    def test_original_bytes_and_loader_through_genuine_stock_state(self):
        with tempfile.TemporaryDirectory(prefix="trnm-model-project-") as td:
            work = Path(td)
            pinned_toolchain()
            owner, owner_receipt = emit_existing_owner(work)
            rust_dir = work / "oracle"
            rust_dir.mkdir()
            rust, proof = original_with_projection(rust_dir)
            self.assertEqual(proof["mode"], "verified-prebuilt-original-lock")
            self.qualified_cases = []
            lib, bound = named_loader(work / "existing-loader")
            self.assertEqual(digest(lib.read_bytes()), bound["artifact_sha256"])
            with NativeModule(SELECT, backend="selfhost", byte_exports=("f0",)) as select, \
                 NativeModule(SRC, backend="direct", byte_exports=("f0",)) as direct, \
                 NativeModule(SRC, backend="selfhost", byte_exports=("f0",)) as selfhost:
                self.assertNotEqual(direct.artifact_sha256, selfhost.artifact_sha256)
                self.native_bindings = {
                    "owner": owner_receipt, "original_rust": proof, "named_imd2": bound,
                    "ims1": select.receipt, "imp1_direct": direct.receipt,
                    "imp1_selfhost": selfhost.receipt,
                }
                for index, (artifact, family, rows, status, downstream) in enumerate(panel()):
                    with self.subTest(index=index):
                        state_session = Session(owner, work / f"held-{index}", seconds=30)
                        try:
                            state = create_state(state_session, rows)
                            view = state_session.request(OPCODES["view.new"], a=state)
                            self.assertEqual(view["status"], 0)
                            snapshot, used = snapshot_request(state_session, state)
                            query = artifact + family + struct.pack("<I", len(snapshot)) + snapshot
                            raw = subprocess.run([rust], input=query, capture_output=True,
                                                 check=True, env={}, timeout=20)
                            self.assertEqual(raw.stderr, b"")
                            baseline = json.loads(raw.stdout)
                            observed = select.call("f0", [ims1_frame(snapshot, artifact), MARK * 32, b""])
                            observed.require_returned()
                            self.assertEqual(observed.value, baseline["status"])
                            packed = b"" if downstream is None else bytes.fromhex(baseline["projected"])
                            expect = packed + MARK * (FRAME + 7 - len(packed))
                            if packed:
                                self.assertEqual(len(packed), FRAME)
                            wire = request(snapshot, artifact, family)
                            for module in (direct, selfhost):
                                asked_work = b"S" * (FRAME + 19)
                                got = module.call("f0", [wire, MARK * (FRAME + 7), asked_work])
                                got.require_returned()
                                self.assertEqual((got.value, got.arguments[:2]), (status, [wire, expect]))
                                self.assertEqual(got.arguments[2][FRAME:], b"S" * 19)
                                if downstream is None:
                                    continue
                                real_frame = got.arguments[1][:FRAME]
                                code, result = invoke_loader(lib, real_frame)
                                self.assertEqual(code, downstream)
                                if downstream == 0:
                                    self.assertEqual(baseline["original_load"], "OK")
                                    want = bytes.fromhex(baseline["loaded_body"])
                                else:
                                    self.assertEqual(baseline["original_load"], {
                                        3: "FACTOR_MODEL_METADATA", 4: "FACTOR_MODEL_CHUNK",
                                        10: "FACTOR_MODEL_HASH"}[downstream])
                                    want = b""
                                self.assertEqual(result, want + MARK * (len(result) - len(want)))
                            if index == 0:
                                check_shape_controls(self, selfhost, wire)
                            self.assertEqual(snapshot_request(state_session, state), (snapshot, used))
                            self.assertEqual(state_session.request(
                                OPCODES["view.drop"], a=view["result"])["status"], 0)
                            end = state_session.request(OPCODES["close"])
                            self.assertEqual((end["status"], end["live_objects"], end["live_blocks"]),
                                             (0, 0, 0))
                        finally:
                            receipt = state_session.finish(allow_failure=not state_session.closed)
                        self.qualified_cases.append({
                            "case": index, "snapshot_sha256": digest(snapshot),
                            "request_sha256": digest(wire), "stock_owner_raw": receipt,
                            "projector_status": status, "old_ims1_status": observed.value,
                            "original_load_semantics": baseline["original_load"],
                            "native_loader_status": downstream,
                            "projected_frame_sha256": digest(packed) if packed else None,
                            "actual_loaded_sha256": digest(want) if downstream == 0 else None,
                        })
            self.assertEqual(digest(lib.read_bytes()), bound["artifact_sha256"])
            self.assertEqual(digest(owner), owner_receipt["owner_elf_sha256"])


def check_shape_controls(test, module, wire):
    for value, ks, ws, status in (
        (wire, FRAME - 1, FRAME, 102), (wire, FRAME, FRAME - 1, 102),
        (wire[:4] + b"\x01" + wire[5:], FRAME, FRAME, 100),
        (wire[:-33] + wire[-32:], FRAME, FRAME, 100),
        (wire[:-32] + b"x" + wire[-32:], FRAME, FRAME, 100),
    ):
        got = module.call("f0", [value, MARK * ks, b"Z" * ws]).require_returned()
        test.assertEqual((got.value, got.arguments[:2]), (status, [value, MARK * ks]))
