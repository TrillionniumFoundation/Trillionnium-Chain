"""Actual locked public pure BEP52 outputs and both stock machine profiles."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import CHUNK, MAX_ROWS, wire
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/bep52_binding.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_bep52_binding_reference.rs"
BASE = 1760
OUTPUT = b"\xa5" * 241


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def locked_original(target, rows):
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    tracked = (LOCK, MANIFEST, REFERENCE, CRATE / "src/cell/bep52.rs", CRATE / "src/cell/manifest.rs")
    before = tuple(sha(x.read_bytes()) for x in tracked)
    version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True, text=True,
                             timeout=10).stdout
    if not version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("BEP52 qualification requires the exact frozen Rust")
    runner = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                             str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                             "--lib", "--target-dir", str(target), "--message-format=json"],
                            env=env, check=True, capture_output=True, text=True, timeout=180)
    builds = list(map(json.loads, runner.stdout.splitlines()))
    if not builds or builds[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("Missing actual original Cargo terminal success")
    [build] = [x for x in builds if x.get("reason") == "compiler-artifact"
               and x["target"]["name"] == "trnm_data_availability" and x["target"]["kind"] == ["lib"]]
    if build["features"] != ["default"] or Path(build["manifest_path"]) != MANIFEST:
        raise ValueError("Wrong original library target/profile")
    [library] = [Path(x) for x in build["filenames"] if x.endswith(".rlib")]
    library_sha = sha(library.read_bytes())
    binary = target / "bep52-original"
    subprocess.run([rustc, "--edition=2024", "-O", "-Dwarnings", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(binary)],
                   env=env, check=True, capture_output=True, timeout=35)
    data = b"".join(struct.pack("<I", len(sample)) + sample for sample, *_ in rows)
    result = subprocess.run([str(binary)], env=env, input=data, check=True, capture_output=True, timeout=45)
    if (result.stderr or not result.stdout or sha(library.read_bytes()) != library_sha
            or before != tuple(sha(x.read_bytes()) for x in tracked)):
        raise ValueError("Incomplete or changed frozen BEP52 original")
    answers = []
    pos = 0
    for _, wanted, _ in rows:
        status = result.stdout[pos]
        pos += 1
        if status != wanted:
            raise ValueError(f"External input disagrees with frozen status {status}, expected {wanted}")
        if status:
            answers.append(b"")
            continue
        n, = struct.unpack_from(">H", result.stdout, pos + 64)
        if not 1 <= n <= 256:
            raise ValueError("Invalid original canonical info length")
        end = pos + 66 + n
        answers.append(result.stdout[pos:end])
        pos = end
    if pos != len(result.stdout):
        raise ValueError("Incomplete original observation consumption")
    print(json.dumps({"original_inputs": dict(zip((x.name for x in tracked), before, strict=True)),
                      "original_rlib_sha256": library_sha, "original_elf_sha256": sha(binary.read_bytes()),
                      "input_sha256": sha(data), "stdout_sha256": sha(result.stdout),
                      "actual_rows": len(rows)}, sort_keys=True), flush=True)
    return answers


def overwrite(raw, at, value):
    return raw[:at] + value + raw[at + len(value):]


def declared(size, seed=0, piece=CHUNK, family=b"Declared.Bep52_v1"):
    encoded = bytearray(wire(size=size, chunk_bytes=piece, family=family, opaque=True))
    for i in range((size + piece - 1) // piece):
        at = 217 + len(family) + 36 * i
        encoded[at:at + 32] = hashlib.sha256(struct.pack(">II", seed, i)).digest()
    if size == 3:
        at = 217 + len(family)
        encoded[at:at+32] = hashlib.sha256(b"abc").digest()
    return bytes(encoded)


def request(manifest, expected=None, context=None):
    expected = expected if expected is not None else hashlib.sha256(b"trnm.cell-manifest.v1\0"+manifest).digest()
    context = context if context is not None else manifest[4:165 + manifest[4]]
    return b"BPB1" + expected + context + manifest


def corpus():
    rows = []
    for size in (1, 3, 9, 10, 11, 99, 100, 999, 1000, 9999, 10000, 16383, 16384, 16385, 32768, 32769,
                 49152, 49153, 65536, 65537, 81921, 131071, 131072, 131073, 163841,
                 1_000_000, 1_000_001, 16_777_217):
        count = (size + CHUNK - 1) // CHUNK
        rows.append((request(declared(size, size % 77)), 0, 1 << (count-1).bit_length()))
    for count, tail, seed in ((4095, 7, 11), (4097, 100, 9), (16383, 16384, 49), (MAX_ROWS, 16384, 5)):
        rows.append((request(declared((count-1)*CHUNK+tail, seed)), 0, 1 << (count-1).bit_length()))
    sample = declared(5*CHUNK+9)
    a = request(sample)
    family_n = sample[4]
    offset = 197 + family_n
    context = sample[4:165+family_n]
    wrong_p = overwrite(a, 4, bytes([a[4] ^ 1]))
    for i in (37, 37+family_n, 69+family_n, 101+family_n, 133+family_n, 165+family_n):
        rows += [(overwrite(a, i, bytes([a[i] ^ 1])), 14, 0)]
    rows += [(wrong_p, 15, 0), (overwrite(wrong_p,37,b"X"),14,0),
             (overwrite(wrong_p,offset,b"X"),3,0),
             (a[:offset]+sample[:-1],7,0),
             (a[:offset]+sample+b"\x00",7,0),
             (a[:offset]+sample[:3],2,0),
             (a[:offset]+overwrite(sample,4,b"\x00"),4,0),
             (a[:offset]+overwrite(sample,5,b"\xff"),5,0),
             (a[:offset]+overwrite(sample,5,b"!"),8,0),
             (a[:offset]+overwrite(sample,205+family_n,struct.pack(">I", 16385)),9,0),
             (a[:offset]+overwrite(sample,165+family_n,bytes(8)),10,0),
             (a[:offset]+overwrite(sample,209+family_n,bytes(4)),6,0),
             (a[:offset]+overwrite(sample,213+family_n,struct.pack(">I", CHUNK-1)),12,0)]
    for piece in (32768, 65536, 4_194_304):
        other = declared(piece+1, 2, piece)
        other_good = request(other)
        rows += [(other_good,16,0), (request(other, bytes(32)),15,0),
                 (request(other, bytes(32), overwrite(context,1,b"X")),14,0)]
    return rows


class DaBep52BindingValue(unittest.TestCase):
    def test_exact_frozen_declared_piece_tree_and_canonical_info_both_stock(self):
        rows = corpus()
        self.assertEqual(len(rows), 60)
        with tempfile.TemporaryDirectory(prefix="trnm-bep52-original-") as tmp:
            observed = locked_original(Path(tmp), rows)
        self.assertEqual(observed[1][:32], hashlib.sha256(b"abc").digest())
        self.assertTrue(any(pow_ == MAX_ROWS for _, _, pow_ in rows))
        for (sample, code, _), want in zip(rows, observed, strict=True):
            if code == 0:
                self.assertEqual(want[32:64], hashlib.sha256(want[66:]).digest())
                self.assertEqual(len(want[66:]), int.from_bytes(want[64:66], "big"))
                self.assertTrue(want[66:].endswith(b"12:piece lengthi16384ee"))
        checks = [(s, OUTPUT, b"\x79"*(BASE+32*pow_+13), code, answer, BASE+32*pow_ if pow_ else 1232)
                  for (s, code, pow_), answer in zip(rows, observed, strict=True)]
        one = checks[1]
        sample, _, _, _, answer, exact = one
        # Three ABI boundaries plus malformed envelope and protected output.
        checks += [(b"", OUTPUT, b"", 100, b"", 0),
                   (b"NOPE"+sample[4:], OUTPUT, b"\x79"*exact, 100, b"", 0),
                   (sample[:36]+b"\xff"+sample[37:200], OUTPUT, b"\x79"*exact, 100, b"", 0),
                   (sample, OUTPUT[:len(answer)-1], b"\x79"*exact, 102, b"", exact),
                   (sample, OUTPUT, b"\x79"*(exact-1), 102, b"", 1232),
                   (sample, OUTPUT, b"\x79"*1231, 102, b"", 0),
                   (sample, OUTPUT[:len(answer)], b"\x79"*exact, 0, answer, exact)]
        small = [x for x in checks if len(x[0]) < 10000]
        big = [x for x in checks if len(x[0]) >= 10000]
        batches = [small[i:i+12] for i in range(0,len(small),12)] + [[x] for x in big]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                for batch in batches:
                    results = native.call_many([("f0", [s, out, work]) for s,out,work,*_ in batch], timeout=60)
                    for (s,out,work,code,expected,guard), result in zip(batch, results, strict=True):
                        self.assertEqual(result.require_returned().value, code, (len(s),len(work)))
                        self.assertEqual(result.arguments[0], s)
                        self.assertEqual(result.arguments[1], expected + out[len(expected):])
                        self.assertEqual(result.arguments[2][guard:], work[guard:])
                print(json.dumps({"backend":backend, "native_elf":native.artifact_sha256,
                                  "original_matches":len(rows), "counts":Counter(code for _,code,_ in rows),
                                  "abi_controls":len(checks)-len(rows)}, sort_keys=True), flush=True)
