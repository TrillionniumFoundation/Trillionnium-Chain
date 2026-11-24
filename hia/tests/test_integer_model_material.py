"""Bounded pure model metadata and chunks, separate from model/ID admission."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.integer_model_material_original import build
from hia.tests.native_support import NativeModule
from hia.tests.test_integer_model_codec import COEFFICIENTS, canonical, values
from hia.tests.test_verification_profile_registry import ROOT

SRC = ROOT / "hia/src/state/integer_model_material.hepta"
MARK, SCRATCH = b"\xa5", b"\x49" * 13


def entry(key, tag, payload, capacity):
    key_bytes = key.encode("ascii")
    if len(key_bytes) > 8 or len(payload) > capacity:
        raise ValueError("outside bounded fixture shape")
    return key_bytes.ljust(8, b"\0") + struct.pack("<BH5x", tag, len(payload)) + payload.ljust(capacity, b"\0")


def field(key, value):
    if type(value) is int and 0 <= value < 1 << 64:
        return entry(key, 3, struct.pack("<Q", value), 64)
    if type(value) is str:
        return entry(key, 1, value.encode("utf-8"), 64)
    return entry(key, 0, b"", 64)


def row(key, value):
    if type(value) is dict:
        fields = [field(k, v) for k, v in sorted(value.items())]
        return entry(key, 2, bytes([len(fields)]) + b"".join(fields), 2048)
    if type(value) is str:
        return entry(key, 1, value.encode("utf-8"), 2048)
    return entry(key, 0, b"", 2048)


def native_frame(case):
    old, new = [case[k] for k in ("old", "new")]
    return (b"IMD1" + bytes([len(old), len(new), 0, 0]) + bytes.fromhex(case["family"]) +
            b"".join(row(k, v) for group in (old, new) for k, v in sorted(group.items())))


def native_case(raw, version, family):
    domain = f"integer-linear-model-artifact-v{version}".encode("ascii")
    digest = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(domain)) + domain +
                            struct.pack("<I", len(raw)) + raw).hexdigest()
    meta = {"schema": f"integer-model-chunks-v{version}", "family": family.hex(),
            "chunks": (len(raw) + 1023) // 1024, "bytes": len(raw)}
    selected = {"meta": meta}
    for i, start in enumerate(range(0, len(raw), 1024)):
        selected[f"{i:02}"] = raw[start:start+1024].hex()
    return dict(id=digest, family=family.hex(), old=selected if version == 2 else {},
                new=selected if version == 3 else {})


def cases():
    result = []
    rng = random.Random(73711)
    for version, namespace in ((2, "old"), (3, "new")):
        family = rng.randbytes(32)
        raw = canonical(version, family, values([rng.randint(-32767,32767) for _ in range(COEFFICIENTS)]),
                        active=7 if version == 3 else 0)
        complete = native_case(raw, version, family)
        def add(change, code, original=None, data=b""):
            value = deepcopy(complete)
            change(value, value[namespace])
            result.append((value, (code,data), code if original is None else original))

        add(lambda c,s: None, 0, data=raw)
        add(lambda c,s: c["new" if version == 2 else "old"].update(noise=None), 1)
        def both_missing(c,s):
            s.pop("meta")
            c["new" if version == 2 else "old"]["unused"] = {}
        add(both_missing, 1)
        add(lambda c,s: s.pop("meta"), 2)
        add(lambda c,s: s.update(meta=None), 3)
        add(lambda c,s: s.update(meta=3), 3)
        add(lambda c,s: s["meta"].update(bytes=float(len(raw))), 3)
        add(lambda c,s: s["meta"].update(bytes=-1), 3)
        add(lambda c,s: s["meta"].update(bytes="7756"), 3)
        add(lambda c,s: s["meta"].update(chunks=7), 3)
        add(lambda c,s: s["meta"].update(chunks="8"), 3)
        add(lambda c,s: s["meta"].pop("schema"), 3)
        add(lambda c,s: s["meta"].update(extra=0), 3)
        add(lambda c,s: s["meta"].update(schema="integer-model-chunks-v0"), 3)
        add(lambda c,s: s["meta"].update(family=family.hex().upper()), 3)
        add(lambda c,s: s["meta"].update(family="0"*64), 3)
        add(lambda c,s: s["meta"].update(family=42), 3)
        add(lambda c,s: s.update(excess=None), 3)
        add(lambda c,s: s.pop("07"), 3)
        def rename(c,s):
            s["08"] = s.pop("07")
        add(rename, 4)
        add(lambda c,s: s.update({"07": False}), 4)
        add(lambda c,s: s.update({"07": s["07"][:-2]}), 4)
        add(lambda c,s: s.update({"07": s["07"]+"00"}), 4)
        add(lambda c,s: s.update({"07": s["07"][:-1]+"F"}), 4)
        add(lambda c,s: s.update({"07": s["07"][:-1]+"g"}), 4)
        add(lambda c,s: s.update({"00": "F"+s["00"][1:]}), 4)
        add(lambda c,s: s.update({"00": "é"+s["00"][2:]}), 4)
        add(lambda c,s: c.update(id="0"*64), 0, original=10, data=raw)
        broken = b"X"+raw[1:]
        add(lambda c,s: s.update({"00": broken[:1024].hex()}), 0, original=6, data=broken)
        add(lambda c,s: s.update({"00": "00"*1024, "07": s["07"][:-1]+"F"}), 4)
        add(lambda c,s: s.clear(), 2)
    return result


class IntegerModelMaterial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {mode: cls.enterClassContext(NativeModule(SRC, backend=mode, byte_exports=("f0",)))
                       for mode in ("direct", "selfhost")}
        if len({v.artifact_sha256 for v in cls.modules.values()}) != 2:
            raise ValueError("distinct pinned artifacts required")

    def emitted(self, cases_raw, wanted, limits=None):
        if limits is None:
            limits = [len(p) + 17 for _, p in wanted]
        commands = [("f0", [data, MARK*lim, SCRATCH]) for data,lim in zip(cases_raw,limits,strict=True)]
        for backend, module in self.modules.items():
            for start in range(0,len(commands),10):
                batch = commands[start:start+10]
                expected = wanted[start:start+len(batch)]
                for n,(got, (_, args), (code, payload)) in enumerate(zip(
                        module.call_many(batch,timeout=40),batch,expected,strict=True)):
                    with self.subTest(backend=backend,index=start+n):
                        got.require_returned()
                        self.assertEqual(got.value,code)
                        self.assertEqual(got.arguments[0],args[0])
                        self.assertEqual(got.arguments[1],payload+args[1][len(payload):])
                        self.assertEqual(got.arguments[2],SCRATCH)

    def test_both_emitters_admit_typed_rows_and_materialize_atomically(self):
        rows = cases()
        self.emitted([native_frame(c) for c,_,_ in rows],[expect for _,expect,_ in rows])

    def test_private_extent_and_output_canaries(self):
        q, good, _ = cases()[0]
        valid = native_frame(q)
        short = len(good[1])-1
        out = len(good[1])
        controls = [
            (b"", (100,b""), 17), (valid[:39], (100,b""),17),
            (b"BAD!"+valid[4:], (100,b""),17),
            (valid[:-1], (100,b""), 17), (valid+b"x", (100,b""), 17),
            (valid[:6]+b"\x01"+valid[7:], (100,b""), 17),
            (valid[:4]+b"\x0b"+valid[5:], (100,b""), 17),
            (valid[:40]+valid[40+2064:40+2*2064]+valid[40:40+2064]+valid[40+2*2064:], (100,b""), 17),
            (valid[:40]+valid[40:40+2064]+valid[40:40+2064]+valid[40+2*2064:], (100,b""), 17),
            (valid, (102,b""),short), (valid,good,out),
        ]
        self.emitted([x[0] for x in controls],[x[1] for x in controls],[x[2] for x in controls])

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT") or
                         os.environ.get("HIA_M06_LOCKED_CARGO_ORACLE") == "1",
                         "requires configured verified genuine Rust/Serde oracle; core native tests always run")
    def test_original_exact_rust_typed_rows_and_explicit_stage_boundary(self):
        rows = cases()
        with tempfile.TemporaryDirectory(prefix="trnm-imd-") as d:
            binary, proof = build(Path(d))
            commands = b"".join(json.dumps(c).encode("ascii")+b"\n" for c,_,_ in rows)
            r = subprocess.run([binary],input=commands,check=True,capture_output=True,timeout=55)
            self.assertEqual(r.stderr,b"")
        self.assertIn(proof["mode"],["verified-prebuilt-original-lock","tiny-locked-offline-cargo"])
        data = r.stdout
        observed = []
        for c, expected, rust_code in rows:
            self.assertTrue(data)
            self.assertEqual(data[0],rust_code)
            width = 0 if rust_code else 7758 if c["new"] else 7756
            if not rust_code:
                outcome = (0, data[1:1+width])
                self.assertEqual(expected, outcome)
                observed.append(outcome)
            elif rust_code <= 4:
                outcome = (rust_code, b"")
                self.assertEqual(expected, outcome)
                observed.append(outcome)
            else:
                # Failure in the subsequent original ILM or identity stage is not materialization.
                self.assertEqual(expected[0],0)
                self.assertTrue(expected[1])
                observed.append(expected)
            data = data[1+width:]
        self.assertEqual(data,b"")
        self.emitted([native_frame(c) for c, _, _ in rows], observed)
