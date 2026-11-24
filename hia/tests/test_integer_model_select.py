"""Native-owned immutable State export through the M06 model namespace selector."""

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_integer_model_material import cases
from hia.tests import integer_model_material_original as rust_source
from hia.platform.execution_state import build as state_build
from hia.platform.execution_state.cases import tape
from hia.platform.execution_state.native_io import OPCODES, Session
from hia.platform.build import Build as PinnedBuild, inspect_executable

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "hia/src/state/integer_model_select.hepta"
ADAPTER = Path(__file__).with_name("rust_integer_model_select_reference.rs")
STATE_REFERENCE = ROOT / "hia/platform/execution_state/rust_reference.rs"
MARK, WORK = b"\xa5", b"unchanged-selector-work"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def emit_existing_owner(work):
    # Do not rebuild the original Rust owner or change the original HIA process
    # builder. Use its exact source closure, stage protocol and pinned emitter.
    # The original build's complete workspace Rust inventory is separate.
    composed, sources = state_build.compose()
    pin = PinnedBuild(work / "existing-native-stages")
    images = {name: pin.stage(pin.compiler, composed[name], "compile-" + name)
              for name in ("owner", "root", "linux_emitter")}
    joined = struct.pack("<QQ", len(images["owner"]), len(images["root"]))
    joined += images["owner"] + images["root"]
    elf = pin.stage(images["linux_emitter"], joined, "emit-owner")
    inspect_executable(elf)
    pin.check_pin()
    if not elf.endswith(images["owner"] + images["root"]) or state_build.compose()[1] != sources:
        raise ValueError("existing sealed State owner or source capture differs")
    return elf, {
        "owner_elf_sha256": digest(elf),
        "image_sha256": {name: digest(image) for name, image in images.items()},
        "source_inventory_sha256": state_build.digest(sources),
        "source_inventory": sources,
    }


def build_original(work):
    target = os.environ.get("HIA_M06_ORACLE_PREBUILT")
    if not target:
        raise ValueError("configure verified prebuilt exact Rust/Serde/Hex for original M06 parity")
    combined = rust_source.caller_source()
    old_driver = rust_source.CALLER.read_bytes()
    if not combined.endswith(old_driver):
        raise ValueError("original method extraction boundary changed")
    original = combined.removesuffix(old_driver)
    # Reuse the exact existing test decoder for our captured JVT1 payloads,
    # not a Python-side reconstruction/prior selection of the model rows.
    transport = STATE_REFERENCE.read_bytes()
    start = transport.index(b"fn take<'a>")
    stop = transport.index(b"fn encode_node(", start)
    decoder = transport[start:stop]
    raw = (original + b"\nuse std::io::Read;\n" + decoder
           + ADAPTER.read_bytes())
    binary, proof = rust_source.verified_prebuilt(
        work, target, raw, linked=("-C", "strip=symbols"))
    proof.update(methods_sha256=digest(original), source_sha256=digest(raw),
                 binary_sha256=digest(binary.read_bytes()),
                 cargo_lock_sha256=digest(rust_source.LOCK.read_bytes()))
    return binary, proof


def frame(snapshot, artifact):
    return b"IMS1\0\0\0\0" + artifact + snapshot


def model_rows():
    vectors = [row for row, _, code in cases() if code == 0]
    seen = set()
    for row in vectors:
        version = 3 if row["new"] else 2
        if version in seen:
            continue
        seen.add(version)
        artifact = bytes.fromhex(row["id"])
        other_id = bytes([artifact[0] ^ 1]) + artifact[1:]
        family = bytes.fromhex(row["family"])
        prefix = f"linear-model-v{version}:{artifact.hex()}:"
        rival = f"linear-model-v{5 - version}:{artifact.hex()}:"
        near = {
            "": 1, "prefix\0neighbor": None, "\U0010ffff": False,
            prefix[:-1]: "missing colon", prefix[:-1] + "!meta": {"other": [3, False]},
            f"linear-model-v{version}:{other_id.hex()}:meta": True,
            f"linear-model-v{version}:{artifact.hex().upper()}:meta": 8,
        }
        good = {**near, **{prefix + k: v for k, v in row["new" if version == 3 else "old"].items()}}
        yield artifact, family, good, 0, "OK"
        no_meta = {k: v for k, v in good.items() if k != prefix + "meta"}
        # Simultaneous nonempty namespaces must win even without either meta.
        yield artifact, family, {**no_meta, rival + "🧪": False}, 1, "FACTOR_MODEL_COLLISION"
        yield artifact, family, no_meta, 2, "FACTOR_MODEL_MISSING"
        # Presence is an observation of the key, not the validity of its value.
        yield artifact, family, {**good, prefix + "meta": None}, 0, "FACTOR_MODEL_METADATA"
        yield artifact, family, {**good, prefix + "07": [None]}, 0, "FACTOR_MODEL_CHUNK"
        yield artifact, family, {**good, prefix + "\0weird-suffix": "present"}, 0, "FACTOR_MODEL_METADATA"
        yield artifact, family, near, 2, "FACTOR_MODEL_MISSING"


def snapshot_request(session, state):
    reply = session.request(OPCODES["state.export"], a=state)
    if reply["status"] != 0:
        raise ValueError("actual State owner refused export")
    return bytes.fromhex(reply["data_hex"]), (reply["live_objects"], reply["live_blocks"])


def create_state(session, rows):
    make = session.request(OPCODES["state.new"])
    assert make["status"] == 0 and make["result"] > 0
    state = make["result"]
    # Insertion order differs from the lookup contract; the real native export
    # must impose the original UTF-8/BTreeMap order, reconstructed nowhere here.
    for key, value in rows.items():
        new = session.request(OPCODES["value.new"], data=tape(value))
        assert new["status"] == 0 and new["result"] > 0
        put = session.request(OPCODES["state.put"], a=state, b=new["result"], key=key.encode())
        assert put["status"] == 0 and put["result"] == 0
    return state


class IntegerModelSelect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-model-select-")))
        cls.modules = {mode: cls.enterClassContext(NativeModule(
            SRC, backend=mode, byte_exports=("f0",))) for mode in ("direct", "selfhost")}
        if len({module.artifact_sha256 for module in cls.modules.values()}) != 2:
            raise ValueError("direct and selfhost selectors must differ")
        cls.owner, cls.owner_proof = emit_existing_owner(cls.tmp)

    def calls(self, batches):
        for backend, module in self.modules.items():
            for i in range(0, len(batches), 4):
                group = batches[i:i+4]
                asks = [("f0", [wire, MARK * capacity, WORK])
                        for wire, capacity, _, _ in group]
                for got, case, ask in zip(module.call_many(asks), group, asks, strict=True):
                    with self.subTest(backend=backend):
                        got.require_returned()
                        wire, _, status, prefix = case
                        untouched = ask[1][1][len(prefix):]
                        self.assertEqual(got.value, status)
                        self.assertEqual(got.arguments, [wire, prefix + untouched, WORK])

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT"),
                         "full selector differential requires verified prebuilt Rust/Serde/Hex")
    def test_native_state_snapshot_same_bytes_to_original_and_both_native_selectors(self):
        rust, proof = build_original(self.tmp)
        self.assertEqual(proof["mode"], "verified-prebuilt-original-lock")
        for index, (artifact, family, rows, status, expected_load) in enumerate(model_rows()):
            with self.subTest(case=index):
                session = Session(self.owner, self.tmp / f"owned-{index}", seconds=30)
                try:
                    state = create_state(session, rows)
                    view = session.request(OPCODES["view.new"], a=state)
                    self.assertEqual(view["status"], 0)
                    snapshot, counts = snapshot_request(session, state)
                    query = artifact + family + struct.pack("<I", len(snapshot)) + snapshot
                    answer = subprocess.run([rust], input=query, capture_output=True, check=True,
                                            env={}, timeout=20)
                    self.assertEqual(answer.stderr, b"")
                    oracle = json.loads(answer.stdout)
                    self.assertEqual((oracle["status"], oracle["original_load"]), (status, expected_load))
                    payload = struct.pack("<4Q", *oracle["metadata"]) if status == 0 else b""
                    if payload:
                        old_n, new_n, at, length = oracle["metadata"]
                        self.assertGreater(old_n + new_n, 0)
                        self.assertEqual(snapshot[at:at+4], b"JVT1")
                        self.assertLessEqual(at + length, len(snapshot))
                    self.calls([(frame(snapshot, artifact), 43, status, payload)])
                    self.assertEqual(snapshot_request(session, state), (snapshot, counts))
                    self.assertEqual(session.request(OPCODES["view.drop"], a=view["result"])["status"], 0)
                    closed = session.request(OPCODES["close"])
                    self.assertEqual((closed["status"], closed["live_objects"], closed["live_blocks"]),
                                     (0, 0, 0))
                finally:
                    session.finish(allow_failure=not session.closed)

    def test_only_local_framing_and_capacity_errors_can_outrank_semantic_cases(self):
        artifact = bytes(range(32))
        prefix = f"linear-model-v2:{artifact.hex()}:"
        rows = {f"n-{i:02}": i for i in range(61)}
        rows["é" * 256] = "x" * 4087
        rows[prefix + "meta"] = None
        rows[prefix + "00"] = False
        session = Session(self.owner, self.tmp / "caps", seconds=30)
        try:
            state = create_state(session, rows)
            good, _ = snapshot_request(session, state)
            self.assertEqual(int.from_bytes(good[:8],"little"), 64)
            wire = frame(good, artifact)
            # The synthetic rows are valid original State; this test makes only
            # small local envelope mutations without exercising host services.
            duplicate = (struct.pack("<Q", 2) + struct.pack("<QQ", 1, 9)
                         + b"x" + b"JVT1" + bytes(5))
            duplicate += duplicate[8:]
            raw_meta_key = (prefix + "meta").encode()
            at = good.index(raw_meta_key) + len(raw_meta_key)
            self.assertEqual(good[at:at + 9], tape(None))
            selected = struct.pack("<4Q", 2, 0, at, 9)
            self.calls([(wire, 32, 0, selected),
                        (wire, 31, 102, b""),
                        (wire[:-1], 40, 100, b""),
                        (wire + b"x", 40, 100, b""),
                        (wire[:48] + struct.pack("<Q", 513) + wire[56:], 40, 100, b""),
                        (wire[:56] + struct.pack("<Q", 4097) + wire[64:], 40, 100, b""),
                        (wire[:4] + b"\x01" + wire[5:], 40, 100, b""),
                        (wire[:40] + struct.pack("<Q", 65) + wire[48:], 40, 100, b""),
                        (frame(duplicate, artifact), 40, 100, b""),
                        (frame(struct.pack("<QQQ", 1, 1, 9) + b"\xff" + b"JVT1" + bytes(5),
                               artifact), 40, 100, b""),
                        (frame(struct.pack("<QQQ", 1, 1, 9) + b"a" + b"JVT1" + b"\0\x02\0\0\0",
                               artifact), 40, 100, b"")])
            extra_value = session.request(OPCODES["value.new"], data=tape("extra"))
            self.assertEqual(extra_value["status"], 0)
            self.assertEqual(session.request(OPCODES["state.put"], a=state,
                                             b=extra_value["result"], key=b"new-row")["status"], 0)
            over, _ = snapshot_request(session, state)
            self.assertEqual(int.from_bytes(over[:8], "little"), 65)
            self.calls([(frame(over, artifact), 32, 100, b"")])
            next_state = create_state(session, {prefix + "meta": False,
                f"linear-model-v3:{artifact.hex()}:tiny": None})
            collision, _ = snapshot_request(session, next_state)
            self.calls([(frame(collision, artifact), 0, 1, b""),
                        (frame(collision[:-1], artifact), 32, 100, b"")])
            self.assertEqual(session.request(OPCODES["close"])["status"], 0)
        finally:
            session.finish(allow_failure=not session.closed)
