"""Run original Rust formatting and its original local example against two HIA images."""

import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "hia/src/verification/integer_linear_normal.hepta"
CRATE = ROOT / "trillionnium/crates/trnm-verification-profiles"
ORIGINAL = CRATE / "src/exact_integer_linear_v1.rs"
EXAMPLE = CRATE / "examples/integer_linear_normal_form.rs"
ADAPTER = Path(__file__).with_name("rust_integer_linear_normal_reference.rs")
SHA_ADAPTER = Path(__file__).with_name("rust_verification_challenge_reference.rs")
FAMILY = "89b918183308ee94cc4e45575ac12f74d5de704d385289dbe2752daa13a47cef"
SHAPE = struct.Struct("<771i")
FRAME = 40 + SHAPE.size
MIN_OUT, MAX_OUT = 1680, 5535
MARK, SCRATCH = b"\xa5", b"scratch-must-not-change"


def build_original(work):
    rust_pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], capture_output=True, check=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", rust_pin]:
        raise ValueError("integer-linear normal report requires pinned Rust")
    original = ORIGINAL.read_bytes()
    binding = b"use sha2::{Digest, Sha256};\n"
    if original.count(binding) != 1:
        raise ValueError("unexpected original SHA dependency")
    sha = SHA_ADAPTER.read_bytes()
    sha = sha[sha.index(b"use std::io"):sha.index(b"fn array")].replace(
        b"use std::io::{self, Read, Write};", b"use std::io::Write;")
    source = work / "original.rs"
    # Preserve the complete original Rust module and example. Only the existing
    # SHA library import is supplied by the independent sha256sum test adapter.
    source.write_bytes(b"pub mod exact_integer_linear_v1 {\n"
                       + original.replace(binding, sha) + ADAPTER.read_bytes() + b"}\n")
    reference = work / "typed.rs"
    reference.write_text("""
use std::io::{self, Read, Write};
use trnm_verification_profiles::exact_integer_linear_v1::{reporting_fixture, COLUMNS, ROWS};
fn main() -> io::Result<()> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    const REQUEST: usize = 33 + 4 * ROWS * COLUMNS;
    assert_eq!(data.len() % REQUEST, 0);
    let mut out = io::stdout().lock();
    for request in data.chunks_exact(REQUEST) {
        let delta = std::array::from_fn(|row| std::array::from_fn(|col| {
            let at = 33 + 4 * (row * COLUMNS + col);
            i32::from_le_bytes(request[at..at+4].try_into().unwrap())
        }));
        let report = reporting_fixture(request[..32].try_into().unwrap(), request[32], delta);
        out.write_all(&(report.len() as u32).to_le_bytes())?;
        out.write_all(&report)?;
    }
    Ok(())
}
""")
    workspace = tomllib.loads((ROOT / "trillionnium/Cargo.toml").read_text())["workspace"]
    edition = workspace["package"]["edition"]
    rust = ["rustc", f"--edition={edition}", "-Dwarnings", "-Cstrip=symbols"]
    lib = work / "libtrnm_verification_profiles.rlib"
    subprocess.run(rust + ["--crate-type=rlib", "--crate-name=trnm_verification_profiles",
                           source, "-o", lib], check=True, timeout=30)
    binaries = [work / "typed-reference", work / "integer_linear_normal_form"]
    for program, binary in zip((reference, EXAMPLE), binaries, strict=True):
        subprocess.run(rust + ["--extern", f"trnm_verification_profiles={lib}",
                               program, "-o", binary], check=True, timeout=30)
    return binaries


def framed(identity, coordinates):
    return b"ILN1\0\0\0\0" + identity + SHAPE.pack(*coordinates)


def run(program, *args, data=None):
    result = subprocess.run([program, *args], input=data, capture_output=True, check=True,
                            timeout=20)
    if result.stderr:
        raise ValueError(f"unexpected original diagnostic: {result.stderr!r}")
    return result.stdout


class IntegerLinearNormal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-iln-")))
        cls.reference, cls.example = build_original(cls.work)
        cls.modules = {mode: cls.enterClassContext(NativeModule(
            SRC, backend=mode, byte_exports=("f0",))) for mode in ("direct", "selfhost")}
        if len({mod.artifact_sha256 for mod in cls.modules.values()}) != 2:
            raise ValueError("expected different emitted direct/selfhost images")

    def check_rows(self, rows):
        for backend, module in self.modules.items():
            for start in range(0, len(rows), 12):
                cases = rows[start:start + 12]
                args = [(wire, MARK * capacity, scratch)
                        for wire, capacity, _, _, scratch in cases]
                observed = module.call_many([("f0", list(row)) for row in args])
                for index, (got, (wire, before, scratch), (_, _, code, report, _)) in enumerate(
                        zip(observed, args, cases, strict=True), start):
                    with self.subTest(backend=backend, case=index):
                        got.require_returned()
                        self.assertEqual(got.value, code)
                        self.assertEqual(got.arguments, [
                            wire, report + before[len(report):], scratch])

    def reference_results(self, matrices):
        stream = b"".join(parent + bytes([slot]) + SHAPE.pack(*coords)
                          for parent, slot, coords in matrices)
        data = run(self.reference, data=stream)
        result = []
        pos = 0
        for _, _, coords in matrices:
            extent, = struct.unpack_from("<I", data, pos)
            pos += 4
            a = data[pos:pos + extent]
            pos += extent
            report = json.loads(a)
            self.assertEqual(list(report), ["contract", "delta", "schema"])
            self.assertEqual(report["delta"], [coords[i:i + 257] for i in range(0, 771, 257)])
            self.assertEqual(report["schema"], "pon-normalized-linear-update-v1")
            result.append((framed(bytes.fromhex(report["contract"]), coords), a))
        self.assertEqual(pos, len(data))
        return result

    def test_exact_signed_decimal_row_order_and_opaque_lowercase_id(self):
        rng = random.Random(966241)
        edges = [0, 1, -1, 9, -9, 10, -10, 99, -99, 100, -100, 999, -999,
                 1000, -1000, 9999, -9999, 10000, -10000, 32767, -32767]
        matrices = [(bytes(32), 0, [0] * 771), (bytes([255] * 32), 1, [-32767] * 771),
                    (bytes(range(32)), 2, (edges * 37)[:771])]
        for i in range(24):
            values = [rng.randint(-32767, 32767) for _ in range(771)]
            values[256], values[257], values[513], values[514], values[-1] = edges[i % 21], 7, 0, -18, 1234
            matrices.append((rng.randbytes(32), i % 3, values))
        results = self.reference_results(matrices)
        self.assertEqual([len(r) for _, r in results[:2]], [MIN_OUT, MAX_OUT])
        self.check_rows([(wire, len(out) + i % 3 * 17, len(out), out,
                          SCRATCH if i % 2 else b"")
                         for i, (wire, out) in enumerate(results)])

    def test_all_zero_and_all_ff_id_are_opaque_report_fields(self):
        (wire, original), = self.reference_results([(bytes(32), 0, [0] * 771)])
        # The native report accepts an opaque field, not a valid/canonical
        # context witness. Keep the Rust report unchanged outside this field.
        self.check_rows([
            (wire[:8] + digest * 32 + wire[40:], len(original), len(original),
             original[:13] + ascii_hex * 64 + original[77:], SCRATCH)
            for digest, ascii_hex in ((b"\x00", b"0"), (b"\xff", b"f"))
        ])

    def test_late_invalid_and_short_output_never_modify_any_buffer(self):
        (wire, out), = self.reference_results([(bytes(32), 1, [-32767] * 771)])
        rows = [(wire[:size], MAX_OUT, 100, b"", SCRATCH) for size in
                (0, 1, 3, 4, 7, 8, 40, 1068, 2096, FRAME - 1)]
        rows += [(wire + b"\0", MAX_OUT, 100, b"", SCRATCH),
                 (b"ILN2" + wire[4:], MAX_OUT, 100, b"", SCRATCH)]
        for offset in range(4, 8):
            bad = bytearray(wire)
            bad[offset] = 1
            rows.append((bytes(bad), MAX_OUT, 100, b"", SCRATCH))
        for value in (-2**31, -32769, -32768, 32768, 2**31 - 1):
            for idx in (0, 256, 257, 513, 514, 770):
                offset = 40 + idx * 4
                bad = wire[:offset] + struct.pack("<i", value) + wire[offset + 4:]
                for capacity in (0, MAX_OUT + 10):
                    rows.append((bad, capacity, 101, b"", SCRATCH))
        rows += [(wire, size, 102, b"", SCRATCH) for size in
                 (0, 13, MIN_OUT - 1, MIN_OUT, MAX_OUT - 1)]
        rows += [(wire, MAX_OUT, MAX_OUT, out, b"")]
        self.check_rows(rows)

    def test_named_unmodified_original_example_reports_the_same_verified_matrix(self):
        def canonical(obj):
            return json.dumps(obj, separators=(",", ":")).encode()

        rows = []
        for slot, scale in enumerate((1, 19, -37)):
            contract = dict(columns=257, delta_bound=32767, factor_bound=32767, family=FAMILY,
                            numeric="exact-BA-no-rounding-fixed-router-add-to-delta-v1",
                            parent_artifact=(bytes([slot]) * 32).hex(), rank_max=8, rows=3, scale=1024,
                            schema="pon-exact-integer-linear-insertion-v1", slot=slot)
            a = [i % 27 - 13 for i in range(257)]
            b = [scale, -scale, 0]
            matrix = [i * j for i in b for j in a]
            ((wire, original_normal),) = self.reference_results(
                [(bytes([slot]) * 32, slot, matrix)])
            expected_id = json.loads(original_normal)["contract"]
            adapter = dict(A=[a], B=[[v] for v in b], contract=expected_id,
                           schema="pon-integer-linear-adapter-v1")
            cf, af = self.work / f"contract-{slot}.json", self.work / f"adapter-{slot}.json"
            cf.write_bytes(canonical(contract))
            af.write_bytes(canonical(adapter))
            published = run(self.example, cf, af, "--max-multiplications", "771")
            top = json.loads(published)
            self.assertIs(top["consensus_authority"], False)
            self.assertIs(top["reward_authority"], False)
            self.assertEqual(top["product_multiplications"], 771)
            self.assertEqual(top["rank"], 1)
            # Independently compare exact bytes at the example's genuine report
            # boundary, not reconstructed JSON and not its internal fingerprint path.
            extracted = published.split(b',"normal":', 1)[1].split(b',"product_multiplications":', 1)[0]
            self.assertEqual(extracted, original_normal)
            rows.append((wire, len(extracted) + 1, len(extracted), extracted, SCRATCH))
        self.check_rows(rows)
