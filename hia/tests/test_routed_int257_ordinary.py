"""Pure bounded Int257 ordinary inference against unchanged original Rust."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule, unlinked_path

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "trillionnium"
MANIFEST = WORKSPACE / "Cargo.toml"
CRATE = WORKSPACE / "crates/trnm-crypto-primitives"
ORIGINAL = CRATE / "src/pon_routed_int257_grouped.rs"
PIN = "e9416457ee3df24cf5446ebffde6d7748a8eeff8f0f46e77b6ad9555e0ef6b0a"
SOURCE = ROOT / "hia/src/state/routed_int257_ordinary.hepta"
CALLER = Path(__file__).with_name("rust_routed_int257_ordinary_reference.rs")
DIM = 257
PARAMS = 5 * 3 * DIM
MAX_LOGIT = 134_737_904
OUTPUT = struct.Struct("<qqqBB")


def run(argv, *, data=None, env=None, timeout=180):
    result = subprocess.run(argv, cwd=ROOT, input=data, capture_output=True, env=env,
                            timeout=timeout, check=False)
    if result.returncode:
        raise ValueError(f"Original ordinary process failed: {result.stderr.decode(errors='replace')}")
    return result


def locked_ordinary(directory, raw):
    bound = (ORIGINAL, CRATE / "Cargo.toml", CRATE / "src/lib.rs", MANIFEST,
             WORKSPACE / "Cargo.lock", ROOT / "rust-toolchain.toml", CALLER)
    def ids():
        return [hashlib.sha256(path.read_bytes()).hexdigest() for path in bound]
    before = ids()
    if before[0] != PIN:
        raise ValueError("Original ordinary inference implementation differs")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if run([rustc, "--version"]).stdout.decode().split()[1] != pin:
        raise ValueError("Original ordinary requires pinned Rust")
    target = directory / "target"
    build = run([cargo, "build", "--locked", "--offline", "--manifest-path", str(MANIFEST),
                 "--package", "trnm-crypto-primitives", "--lib", "--target-dir", str(target),
                 "--message-format=json"], env={**os.environ, "RUSTC": rustc, "CARGO_INCREMENTAL": "0"})
    events = [json.loads(line) for line in build.stdout.splitlines()]
    if events[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("Original library did not build")
    [artifact] = [e for e in events if e.get("reason") == "compiler-artifact"
                  and e["target"]["name"] == "trnm_crypto_primitives" and not e["profile"]["test"]]
    [library] = [unlinked_path(s) for s in artifact["filenames"] if s.endswith(".rlib")]
    if (library != target / "debug/libtrnm_crypto_primitives.rlib"
            or Path(artifact["target"]["src_path"]) != CRATE / "src/lib.rs"
            or Path(artifact["manifest_path"]) != CRATE / "Cargo.toml"
            or artifact["features"] != ["default"]):
        raise ValueError("Original ordinary library source, features or artifact differs")
    binary = directory / "ordinary"
    run([rustc, "--edition=2021", "--extern", f"trnm_crypto_primitives={library}",
         "-L", f"dependency={target / 'debug/deps'}", str(CALLER), "-o", str(binary)], timeout=60)
    result = run([str(binary)], data=raw, timeout=30)
    if result.stderr or before != ids():
        raise ValueError("Original ordinary observations altered the tracked source or wrote stderr")
    return result.stdout


def frame(model, rows):
    return struct.pack("<I", len(rows)) + struct.pack(f"<{PARAMS}i", *model) + b"".join(
        struct.pack(f"<{DIM}i", *row) for row in rows)


def features(*items, bias=8):
    r = [0] * DIM
    for j, value in items:
        r[j] = value
    r[-1] = bias
    return r


def change(original, index, value):
    result = list(original)
    result[index] = value
    return result


def records(raw, count):
    at = 0
    for _ in range(count):
        status, length = struct.unpack_from("<BI", raw, at)
        at += 5
        data = raw[at:at+length]
        at += len(data)
        if status not in (0, 3, 4, 5) or len(data) != length or (status and length):
            raise ValueError("Invalid original ordinary result")
        yield status, data
    if at != len(raw):
        raise ValueError("Original ordinary produced trailing records")


class RoutedInt257Ordinary(unittest.TestCase):
    def test_genuine_original_and_stock_inference(self):
        zero = [0] * PARAMS
        model = [((i*13+i//DIM*11) % 29)-14 for i in range(PARAMS)]
        # Explicit distinct router coordinates force expert 0/1/2. Ties remain at 0.
        model[3*DIM:6*DIM] = [0]*(3*DIM)
        for j in range(3):
            model[(3+j)*DIM+j] = 19
        rows = [features((0, 8)), features((1, 8)), features((2, 8)),
                features((0, 5), (1, 5)), features((3, -8), (4, 7))]
        min_expert = [-32767]*PARAMS
        max_expert = [32767]*PARAMS
        ext = [8]*DIM
        neg_input = [-8]*(DIM-1)+[8]
        varied = [features((i%256, ((i*9)%17)-8), ((i+29)%256, 7)) for i in range(64)]
        panel = [
            (zero, [rows[0]], 0), (model, rows, 0),
            (max_expert, [ext], 0), (min_expert, [ext], 0),
            (min_expert, [neg_input], 0),
            (model, varied[:1], 0), (model, varied[:31], 0), (model, varied, 0),
            (model, [], 4), (model, varied+[rows[0]], 4),
            (change(model, 0, -32768), [], 3),
            (change(model, PARAMS-1, 32768), [rows[0]], 3),
            (change(model, PARAMS-2, -(1<<31)), [rows[0]], 3),
            (change(model, 2*DIM, (1<<31)-1), [features(bias=7)], 3),
            (model, [features(bias=7)], 5),
            (model, [features((0, -9))], 5),
            (model, [features((255, 9))], 5),
            (model, [*rows, features((0,-8),bias=-8)], 5),
            (model, [*varied[:-1], features((1, 9))], 5),
        ]
        frames = [frame(m, r) for m,r,_ in panel]
        data = b"".join(struct.pack("<I",len(f))+f for f in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-ordinary-original-") as tmp:
            exact = list(records(locked_ordinary(Path(tmp), data), len(panel)))
        self.assertEqual([s for s,_ in exact], [s for _,_,s in panel])
        self.assertEqual([len(out) for _,out in exact[:8]], [26,130,26,26,26,26,806,1664])
        self.assertEqual(OUTPUT.unpack(exact[0][1]), (0,0,0,0,0))
        self.assertEqual([r[3] for r in OUTPUT.iter_unpack(exact[1][1])], [0,1,2,0,0])
        self.assertEqual(OUTPUT.unpack(exact[2][1]), (MAX_LOGIT,)*3+(0,0))
        self.assertEqual(OUTPUT.unpack(exact[3][1]), (-MAX_LOGIT,)*3+(0,0))
        known = frames[0]
        probes = [(f,s,v,max(37,len(v)+7))
                  for f,(s,v) in zip(frames,exact,strict=True)] + [
            (b"",100,b"",0), (known[:-1],100,b"",40), (known+b"\0",100,b"",40),
            (b"\xff"*4+known[4:],100,b"",40), (known,102,b"",25),
            (known,0,exact[0][1],26), (frames[7],102,b"",1663),
            (frames[-1],5,b"",0), (frames[10],3,b"",0),
        ]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for start in range(0, len(probes), 5):
                    subset = probes[start:start+5]
                    arguments = [("f0",[raw,b"\xa5"*width,b"scratch unchanged"])
                                 for raw,_,_,width in subset]
                    actual = native.call_many(arguments, timeout=60)
                    for i, ((raw,s,value,width), observed) in enumerate(zip(subset,actual,strict=True), start):
                        self.assertEqual(observed.require_returned().value,s,i)
                        self.assertEqual(observed.arguments,
                                         [raw,value+b"\xa5"*(width-len(value)),b"scratch unchanged"],i)
