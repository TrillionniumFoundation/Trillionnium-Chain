"""All 15 held Cell lanes against exact isolated original signed Rust spans."""
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state/cell_scalar_products.hepta"
CALLER = Path(__file__).with_name("rust_cell_scalar_products_reference.rs")
MODEL = "trillionnium/crates/trnm-pon-node/src/cell_native_v1.rs"
WORK = "trillionnium/crates/trnm-pon-node/src/cell_native_v1/work.rs"
PREP = "trillionnium/crates/trnm-pon-node/src/cell_native_v1/source.rs"
DOT = "trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs"
PINS = {
    MODEL: "d807c924d7e9657d4126d9092d32585427fccba8144133066deb3ea7db54fe26",
    WORK: "deb160835dda7a0efacef8975ed55a2a31fd6e4372a635a601cbac9e0c8b672c",
    PREP: "8c27cdadece9f1f9c26bd20869a74318bb7490aea436e6dc0140684c20cf6c3e",
    DOT: "e9416457ee3df24cf5446ebffde6d7748a8eeff8f0f46e77b6ad9555e0ef6b0a",
    "rust-toolchain.toml": "24ef3b9d3edbd850aa386cb0a98e10450b0030991a4537cb359f54d49dbbb33a",
}
SCRATCH = b"unused Cell scalar product work loan"
BOUND = 32767
DIM = 257
FIXED = 15424


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def original_source():
    raw = {key: (ROOT / key).read_bytes() for key in PINS}
    if {key: digest(value) for key, value in raw.items()} != PINS:
        raise ValueError("Frozen isolated Cell scalar closure differs")
    def exact(content, pattern):
        matches = re.findall(pattern, content, flags=re.M | re.S)
        if len(matches) != 1:
            raise ValueError("Ambiguous frozen scalar span")
        return matches[0]
    dim = exact(raw[MODEL], rb"^pub const DIM:[^\n]+;")
    if dim != exact(raw[DOT], rb"^pub const DIM:[^\n]+;"):
        raise ValueError("Frozen Cell and routed dimensions differ")
    decls = [dim, exact(raw[MODEL], rb"^pub const MODEL_SCHEMA:[^\n]+;"),
             exact(raw[MODEL], rb"^type Matrix =[^\n]+;"),
             exact(raw[MODEL], rb"^pub struct Model \{.*?^\}")]
    parts = {
        b"// @CELL_CONSTANT_AND_TYPED_DECLARATIONS@": b"\n".join(decls),
        b"// @CELL_WEIGHTS_ORDER@": exact(raw[WORK], rb"^fn weights\([^\n]+\n.*?^\}"),
        b"// @PURE_ROUTED_DOT@": exact(raw[DOT], rb"^fn dot\([^\n]+\n.*?^\}"),
        b"// @CELL_SCALAR_EXPRESSION@": exact(raw[WORK], rb"^            (let scalar: i64 = [^\n]+;)"),
    }
    witness = CALLER.read_bytes()
    for marker, span in parts.items():
        if witness.count(marker) != 1:
            raise ValueError("Frozen scalar comparison marker moved")
        witness = witness.replace(marker, span)
    return witness, {k.decode(): digest(v) for k, v in parts.items()}


def run_original(stream):
    source, spans = original_source()
    compiler = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    version = subprocess.run([compiler, "--version", "--verbose"], check=True, capture_output=True,
                             timeout=10).stdout.decode()
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version.splitlines()[0].split()[1] != channel:
        raise ValueError("Wrong repository-pinned Rust compiler")
    with tempfile.TemporaryDirectory(prefix="trnm-cell-scalar-source-") as t:
        folder = Path(t)
        src = folder / "scalar-source.rs"
        src.write_bytes(source)
        elf = folder / "scalar-reference"
        subprocess.run([compiler, "--edition=2021", "--crate-name", "cell_scalar_reference",
                        "-C", "opt-level=2", "--remap-path-prefix", f"{folder}=/trnm-held-cell-scalar",
                        "-o", str(elf), str(src)],
                       cwd=folder, check=True, capture_output=True, timeout=45)
        image = elf.read_bytes()
        result = subprocess.run([str(elf)], cwd=folder, input=stream, capture_output=True,
                                check=True, timeout=20)
        if result.stderr or elf.read_bytes() != image or src.read_bytes() != source or original_source() != (source, spans):
            raise ValueError("Exact scalar reference or source witness changed")
    return result.stdout, dict(original_elf=digest(image), source_sha256=digest(source),
                               source_pins=PINS, frozen_spans=spans,
                               input_sha256=digest(stream), stdout_sha256=digest(result.stdout),
                               rust=version.splitlines()[0])


def frame(weights, features):
    assert len(weights) == 15 and all(len(row) == DIM for row in weights + features)
    return (struct.pack("<I", len(features)) +
            b"".join(struct.pack("<257i", *row) for row in weights + features))


def positive():
    # Coordinate 256 must be consumed for every lane, with unique signed output.
    bias = [[0] * 256 + [i - 7] for i in range(15)]
    yield bias, [[0] * 256 + [8]]
    # All 15 distinct lane signatures, including the non-selected deltas. Rows
    # cross the original tile boundaries without invoking any tiling/proof owner.
    locs = (0, 1, 62, 63, 64, 65, 126, 127, 128, 129, 191, 192, 254, 255, 256)
    weights = [[(-1 if g % 2 else 1) * (100 * g + j + 1) if j == locs[g] else i
                for j, i in enumerate([0] * DIM)] for g in range(15)]
    feature_rows = [[(8 if i % 2 else -8) if j == i else (8 if j == 256 else 0)
                     for j in range(DIM)] for i in locs[:-1]]
    yield weights, feature_rows
    exact_l1 = [8] * 128 + [0] * 128 + [8]
    tight = [[(BOUND if g % 2 == 0 else -BOUND)] * 257 for g in range(15)]
    yield tight, [exact_l1, [-x for x in exact_l1[:256]] + [8]]
    rng = random.Random(2515)
    for size in (1, 2, 3, 7, 8, 9, 15, 16, 31, 32, 33, 63, 64, 64):
        weights = [[rng.randint(-BOUND, BOUND) for _ in range(DIM)] for _ in range(15)]
        features = []
        for i in range(size):
            row = [0] * 256 + [8]
            for j in rng.sample(range(256), 12 + i % 100):
                row[j] = rng.randint(-8, 8)
            features.append(row)
        yield weights, features


class CellScalarProducts(unittest.TestCase):
    def test_all_fifteen_frozen_cell_product_lanes_with_both_stock_emitters(self):
        inputs = list(positive())
        stream = b"".join(struct.pack("<I", len(raw)) + raw
                          for raw in (frame(weights, feature) for weights, feature in inputs))
        original, proof = run_original(stream)
        offset = 0
        accepted = []
        for weights, features in inputs:
            n = 120 * len(features)
            want = original[offset:offset + n]
            accepted.append((frame(weights, features), b"X" * (n+17), 0, want))
            offset += n
        self.assertEqual(offset, len(original))
        self.assertEqual(struct.unpack("<15q", accepted[0][3]), tuple(range(-56, 57, 8)))
        self.assertEqual(struct.unpack_from("<qq", accepted[2][3]), (33815544, -33815544))
        weights, features = inputs[-1]
        frame_max, _, _, want_max = accepted[-1]
        self.assertEqual((len(frame_max), len(want_max)), (81216, 7680))
        def alter(s, pos, value):
            return s[:pos]+struct.pack("<i", value)+s[pos+4:]
        def bad(raw, code):
            return (raw, b"Z" * 7680, code, b"")
        w_end = FIXED - 4
        late = FIXED + 63 * 1028
        below = [8] * 127 + [7] + [0] * 128 + [8]
        over = [8] * 128 + [1] + [0] * 127 + [8]
        good_l1 = frame(weights, features[:-1]+[below])
        l1_ref, _ = run_original(struct.pack("<I", len(good_l1)) + good_l1)
        controls = [
            bad(b"",100), bad(frame_max[:-1],100), bad(frame_max+b"\0",100),
            bad(frame_max[:FIXED],100), bad(frame(weights, []),4), bad(frame(weights, features+[features[0]]),4),
            bad(alter(frame_max, w_end, BOUND+1),3), bad(alter(frame_max, w_end, -BOUND-1),3),
            bad(alter(frame_max, 4, -(1<<31)),3), bad(alter(frame_max, late, 9),5),
            bad(alter(frame_max, late+4, -9),5), bad(alter(frame_max, late+1024, 7),5),
            bad(frame(weights, features[:-1]+[over]),5),
            bad(alter(frame(weights, []),w_end,BOUND+1),3),
            (frame_max,b"Y"*7679,102,b""),(frame_max,b"",102,b""),
            (frame_max,b"Y"*7680,0,want_max),(good_l1,b"Y"*7680,0,l1_ref),
        ]
        print(json.dumps(dict(proof,test_cases=len(accepted)+1, request_rows=sum(len(f) for _,f in inputs)+64,
                              all_lanes=15, extra_l1_neighbor_output_sha256=digest(l1_ref)),sort_keys=True),flush=True)
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as native:
                cases=accepted+controls
                for j in range(0,len(cases),8):
                    segment=cases[j:j+8]
                    actual=native.call_many([("f0",[raw,out,SCRATCH]) for raw,out,_,_ in segment],timeout=30)
                    for i,((raw,out,code,value),result) in enumerate(zip(segment,actual,strict=True)):
                        self.assertEqual(result.require_returned().value,code,(backend,j+i))
                        self.assertEqual(result.arguments,[raw,value+out[len(value):],SCRATCH],(backend,j+i))
                print(json.dumps(dict(backend=backend,elf=native.artifact_sha256,
                                     original_frames=len(accepted)+1,private_controls=len(controls)-1),
                                 sort_keys=True),flush=True)
