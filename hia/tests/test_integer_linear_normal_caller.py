"""Whole original CLI process differential at its sole native report call."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.test_integer_linear_normal import (
    EXAMPLE, FAMILY, ORIGINAL, ROOT, SRC, build_original,
)
from hia.tools.toolchain import build_native

BRIDGE = Path(__file__).with_name("rust_integer_linear_normal_caller.rs")
ORIGINAL_SHA256 = "facb287627a3a9e9c07d55a2c563d7923fc21e93b20308c74398b2dcf95e1eda"
EXAMPLE_SHA256 = "4a40c710a247da020eb97787a3be6d1a4797f557d34094312655b65f10a08c89"
ORIGINAL_CALL = b"    let normal = String::from_utf8(checked.normal_bytes())?;\n"
NATIVE_CALL = b"    let normal = String::from_utf8(iln1_normal(&checked)?)?;\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def frame_source():
    original_example = EXAMPLE.read_bytes()
    if (digest(original_example) != EXAMPLE_SHA256 or digest(ORIGINAL.read_bytes()) != ORIGINAL_SHA256
            or original_example.count(ORIGINAL_CALL) != 1):
        raise ValueError("original oracle or exact post-verification seam changed")
    return original_example.replace(ORIGINAL_CALL, NATIVE_CALL) + b"\n" + BRIDGE.read_bytes()


def build_candidates(work):
    candidate = work / "candidate.rs"
    candidate.write_bytes(frame_source())
    crate = work / "libtrnm_verification_profiles.rlib"
    edition = tomllib.loads((ROOT / "trillionnium/Cargo.toml").read_text())[
        "workspace"]["package"]["edition"]
    rust = ["rustc", f"--edition={edition}", "-Dwarnings", "-Cstrip=symbols",
            "--crate-name=integer_linear_normal_form", "--extern",
            f"trnm_verification_profiles={crate}"]
    candidates, objects = {}, {}
    for backend in ("direct", "selfhost"):
        private = work / backend
        private.mkdir()
        artifact = private / "iln1.o"
        pins = {} if backend == "direct" else {
            "compiler": os.environ.get("HIA_NATIVE_COMPILER"),
            "compiler_sha256": os.environ.get("HIA_NATIVE_COMPILER_SHA256"),
        }
        receipt, _ = build_native(SRC, artifact, backend=backend, kind="object",
                                  byte_exports=("f0",), **pins)
        objects[backend] = digest(artifact.read_bytes())
        if receipt["artifact_sha256"] != objects[backend]:
            raise ValueError("native object differs from its build receipt")
        output = private / "integer_linear_normal_form"
        subprocess.run(rust + [f"-Clink-arg={artifact}", candidate, "-o", output],
                       check=True, timeout=30)
        candidates[backend] = output
    if len(set(objects.values())) != 2:
        raise ValueError("caller qualification needs independent native objects")
    fault = work / "short-capacity-control"
    subprocess.run(rust + [f"-Clink-arg={work / 'direct/iln1.o'}",
                           "--cfg=trnm_iln_short_capacity", candidate, "-o", fault],
                   check=True, timeout=30)
    return candidates, fault


def preserve_fixture(path, contents):
    with path.open("xb") as stream:
        stream.write(contents)
    path.chmod(0o400)
    return path


def contract_and_adapter(slot, a, b):
    contract = canonical(dict(columns=257, delta_bound=32767, factor_bound=32767, family=FAMILY,
                              numeric="exact-BA-no-rounding-fixed-router-add-to-delta-v1",
                              parent_artifact=(bytes([slot]) * 32).hex(), rank_max=8, rows=3, scale=1024,
                              schema="pon-exact-integer-linear-insertion-v1", slot=slot))
    domain = b"integer-linear-insertion-contract-v1"
    contract_id = digest(b"TRNM-PON1\0" + len(domain).to_bytes(2, "little") + domain
                         + len(contract).to_bytes(4, "little") + contract)
    return contract, canonical(dict(A=a, B=b, contract=contract_id,
                                    schema="pon-integer-linear-adapter-v1"))


class IntegerLinearNormalCaller(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-iln-caller-")))
        # Refuse revisions other than the exact original *before* doing any build.
        frame_source()
        _, cls.original = build_original(cls.work)
        cls.candidates, cls.fault = build_candidates(cls.work)
        cls.rank_models = [
            ([[-32767, *[x % 21 - 10 for x in range(255)], 32767]], [[1], [-1], [0]]),
            ([[32767] * 257, [32767] * 256 + [32766]],
             [[32767, -32767], [-32767, 32767], [0, 0]]),
            ([[int(i % 8 == r) for i in range(257)] for r in range(8)],
             [list(range(8)), list(range(0, -8, -1)), [0] * 8]),
            ([[32767] * 257], [[0], [0], [0]]),
            ([[32767] * 257], [[-1], [-1], [-1]]),
        ]
        cls.inputs = []
        for index, (a, b) in enumerate(cls.rank_models):
            raw = contract_and_adapter(index % 3, a, b)
            cls.inputs.append((
                preserve_fixture(cls.work / f"contract-{index}.json", raw[0]),
                preserve_fixture(cls.work / f"adapter-{index}.json", raw[1]),
            ))

    def invoke(self, executable, args):
        result = subprocess.run([executable, *args], cwd=self.work, env={},
                                capture_output=True, timeout=20)
        return result.returncode, result.stdout, result.stderr

    def verify_parity(self, args, code):
        expected = self.invoke(self.original, args)
        self.assertEqual(expected[0], code)
        for backend, executable in self.candidates.items():
            with self.subTest(backend=backend):
                self.assertEqual(self.invoke(executable, args), expected)
        return expected

    def test_rank_boundaries_canceling_factors_and_complete_actual_stdout(self):
        for index, ((contract, adapter), (a, b)) in enumerate(
                zip(self.inputs, self.rank_models, strict=True)):
            input_bytes = (contract.read_bytes(), adapter.read_bytes())
            rank = len(a)
            work = 771 * rank
            for args in ((contract, adapter), (contract, adapter, "--max-multiplications", str(work))):
                _, stdout, stderr = self.verify_parity(args, 0)
                self.assertEqual(stderr, b"")
                self.assertEqual(stdout.count(b"\n"), 1)
                result = json.loads(stdout)
                self.assertEqual(result["rank"], rank)
                self.assertEqual(result["product_multiplications"], work)
                self.assertEqual(result["factor_coefficients"], 260 * rank)
                self.assertEqual(result["normal"]["delta"], [
                    [sum(row[k] * a[k][j] for k in range(rank)) for j in range(257)]
                    for row in b
                ])
                self.assertEqual(result["normal"]["contract"], result["contract"])
                if index in (3, 4):
                    raw_normal = stdout.split(b',"normal":', 1)[1].split(
                        b',"product_multiplications":', 1)[0]
                    self.assertEqual(len(raw_normal), (1680, 5535)[index - 3])
                for flag in ("consensus_authority", "general_model_equivalence", "reward_authority"):
                    self.assertIs(result[flag], False)
            self.assertEqual((contract.read_bytes(), adapter.read_bytes()), input_bytes)
            self.assertEqual((contract.stat().st_mode & 0o777, adapter.stat().st_mode & 0o777), (0o400, 0o400))

    def test_original_rejections_stay_before_report_and_native_refusal_has_no_fallback(self):
        contract, adapter = self.inputs[0]
        _, bad_adapter = self.inputs[1]
        empty = preserve_fixture(self.work / "empty-adapter", b"")
        cases = [
            ((), b"usage: integer_linear_normal_form "),
            ((contract, adapter, "--other", "771"), b"INTEGER_LINEAR:WorkBudget\n"),
            ((contract, adapter, "--max-multiplications", "770"), b"INTEGER_LINEAR:WorkBudget\n"),
            ((contract, adapter, "--max-multiplications", "6169"), b"INTEGER_LINEAR:WorkBudget\n"),
            ((contract, bad_adapter), b"INTEGER_LINEAR:Context\n"),
            ((contract, empty), b"INTEGER_LINEAR:Length\n"),
        ]
        for args, diagnostic in cases:
            _, stdout, stderr = self.verify_parity(args, 2)
            self.assertEqual(stdout, b"")
            self.assertTrue(stderr.startswith(diagnostic), stderr)
            # Even in the actual native control, these upstream failures precede
            # report dispatch, so should not become NativeNormalReport refusal.
            self.assertEqual(self.invoke(self.fault, args), (2, stdout, stderr))
        self.assertEqual(self.invoke(self.original, (contract, adapter))[0], 0)
        self.assertEqual(self.invoke(self.fault, (contract, adapter)),
                         (2, b"", b"INTEGER_LINEAR:NativeNormalReport\n"))
