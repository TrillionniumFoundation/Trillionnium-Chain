"""Original V0 builder provenance order, hash, and composition in both emitters."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_artifact_set_digest import BASE as ARTIFACT_FIXTURE, frame as pack_artifacts
from hia.tests.test_release_sbom_digest import (
    ADAPTER as SBOM_ADAPTER,
    BASE as SBOM_FIXTURE,
    ROOT,
    byte_digest,
    exact_comparison_source,
    frame as pack_sbom,
    original_binding_rows,
    replace,
)

SOURCE = ROOT / "hia/src/release_bundle/builder_provenance.hepta"
ADAPTER = Path(__file__).with_name("rust_release_builder_provenance_reference.rs")
HEADER, ROW, SCRATCH, START = 259, 578, 5114, 2800
PROV_DOMAIN = b"trnm.release.builder-provenance.v0"
INPUT_DOMAIN = b"trnm.release.build-input.v0"
EMPTY_GOLDEN = bytes.fromhex("969393a1bce3b426bccc9ca307afdbc6a8021a9115ed52361e6875cd3d2f9090")
IDENTITIES = tuple(byte_digest(i) for i in (20, 14, 21, 16))
FIXED = IDENTITIES + tuple(byte_digest(i) for i in (50, 60, 70))
BUILD_INPUT = (b"Cargo.lock", byte_digest(17), byte_digest(4))
ZERO = bytes(32)


def pack(mode, fixed, rows, declaration, *, pad=0):
    packet = struct.pack("<BH", mode, len(rows)) + b"".join(fixed) + declaration
    for name, source, content in rows:
        packet += (struct.pack("<H", len(name)) + source + content
                   + name.ljust(512, bytes([pad])))
    return packet


def leaves(rows):
    return b"".join(hashlib.sha256(b"".join(len(part).to_bytes(8, "big") + part
                                           for part in (INPUT_DOMAIN, *row))).digest()
                    for row in sorted(rows))


def transcript(fixed, rows):
    return (PROV_DOMAIN + b"".join(fixed[:5]) + len(rows).to_bytes(8, "big")
            + leaves(rows) + b"".join(fixed[5:]))


def declared(fixed, rows):
    return hashlib.sha256(transcript(fixed, rows)).digest()


def original(cases):
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    common = exact_comparison_source()
    old_adapter = SBOM_ADAPTER.read_bytes()
    if not common.endswith(old_adapter):
        raise ValueError("Cannot isolate original ownership and digest seam")
    with tempfile.TemporaryDirectory(prefix="trnm-build-provenance-original-") as tmp:
        source = Path(tmp) / "reference.rs"
        program = source.with_suffix("")
        source.write_bytes(common.removesuffix(old_adapter) + ADAPTER.read_bytes())
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(program)],
                       check=True, capture_output=True, timeout=30)
        run = subprocess.run([str(program)], input=b"".join(pack(*c[:4]) for c in cases),
                             check=True, capture_output=True, timeout=60)
    raw, results = run.stdout, []
    for case in cases:
        extent = 33 + len(case[2]) * 32
        if len(raw) < extent:
            raise ValueError("Incomplete original provenance observation")
        results.append((raw[0], raw[1:33], raw[33:extent]))
        raw = raw[extent:]
    if raw or run.stderr:
        raise ValueError("Unexpected original output")
    return results


class ReleaseBuilderProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("Expected different machine artifacts")

    def native_cases(self, cases):
        for backend, module in self.native.items():
            for start in range(0, len(cases), 8):
                group = cases[start:start + 8]
                requests = [("f0", [raw, b"\xbb" * cap, b"\xf1" * work])
                            for raw, cap, work, *_ in group]
                outcomes = module.call_many(requests, timeout=45)
                self.assertEqual(len(outcomes), len(group))
                for i, (case, req, result) in enumerate(zip(group, requests, outcomes)):
                    raw, _, _, code, digest, hashed = case
                    with self.subTest(backend=backend, row=start + i):
                        result.require_returned()
                        self.assertEqual(result.value, code)
                        self.assertEqual(result.arguments[0], raw)
                        self.assertEqual(result.arguments[1], digest + req[1][1][len(digest):])
                        scratch = result.arguments[2]
                        if hashed:
                            self.assertEqual(scratch[START:START + len(hashed)], hashed)
                            self.assertEqual(scratch[SCRATCH:], req[1][2][SCRATCH:])
                        else:
                            self.assertEqual(scratch, req[1][2])

    def test_original_exact_digest_order_and_refusal_precedence(self):
        name_order = [replace(BUILD_INPUT, 0, value) for value in (
            b"", b"a", b"a\0", b"a\xff", b"aa", b"\xff", "é".encode(), "e\u0301".encode(),
            "中".encode(), "😀".encode(), "😀!".encode())]
        tie_order = [replace(BUILD_INPUT, field, bytes(31) + bytes([byte]))
                     for field in (1, 2) for byte in (0, 1, 127, 128, 255)]
        tie_order += [BUILD_INPUT, BUILD_INPUT]
        large = [replace(replace(BUILD_INPUT, 0, b"A" * 512), 1, bytes(31) + bytes([n + 1]))
                 for n in range(64)]
        random.Random(169).shuffle(large)
        pure = [([], (ZERO,) * 7), ([], FIXED), ([BUILD_INPUT], FIXED),
                ([BUILD_INPUT, BUILD_INPUT], FIXED), (name_order, FIXED),
                (name_order[::-1], FIXED), (tie_order, FIXED), (tie_order[::-1], FIXED),
                (large, FIXED), (large[::-1], FIXED)]
        pure += [([BUILD_INPUT], replace(FIXED, i, ZERO)) for i in range(7)]
        cases = [(0, fixed, rows, ZERO, 0, True) for rows, fixed in pure]

        changed_source = replace(BUILD_INPUT, 1, byte_digest(18))
        changed_content = replace(BUILD_INPUT, 2, byte_digest(19))
        changed_name = replace(BUILD_INPUT, 0, b"Cargo.lock2")
        invalid_conflict = replace(BUILD_INPUT, 2, ZERO)
        invalid_other = replace(changed_name, 1, ZERO)
        candidates = [
            (FIXED, [], 105, False), (FIXED, [BUILD_INPUT], 0, True),
            (FIXED, [BUILD_INPUT, changed_source], 0, True),
            (FIXED, [changed_name, BUILD_INPUT], 0, True),
            (FIXED, [BUILD_INPUT, BUILD_INPUT], 107, True),
            (FIXED, [BUILD_INPUT, changed_content], 107, True),
            (FIXED, [BUILD_INPUT, invalid_conflict], 106, True),
            (FIXED, [BUILD_INPUT, changed_content, invalid_other], 107, True),
            (FIXED, [BUILD_INPUT, invalid_other, changed_content], 106, True),
            (FIXED, large, 0, True),
            (FIXED, large[:-1] + [replace(large[0], 2, byte_digest(77))], 107, True),
        ]
        candidates += [(replace(FIXED, i, ZERO), [BUILD_INPUT], 105, False) for i in range(7)]
        candidates += [(FIXED, [replace(BUILD_INPUT, field, wrong)], 106, True)
                       for field, wrong in ((0, b""), (0, b"\x7f"), (0, "中".encode()),
                                            (1, ZERO), (2, ZERO))]
        for fixed, rows, code, work_touched in candidates:
            cases.append((1, fixed, rows, declared(fixed, rows), code, work_touched))
        for rows in ([BUILD_INPUT], [BUILD_INPUT, changed_content], [invalid_conflict]):
            stale = bytearray(declared(FIXED, rows))
            stale[-1] ^= 0x80
            cases.append((1, FIXED, rows, bytes(stale), 105, True))

        rust = original(cases)
        self.assertEqual(rust[0], (0, EMPTY_GOLDEN, b""))
        observed = []
        for i, ((mode, fixed, rows, declaration, code, touched), (status, digest, members)) in enumerate(
                zip(cases, rust)):
            preimage = transcript(fixed, rows)
            self.assertEqual(members, leaves(rows))
            self.assertEqual(digest, hashlib.sha256(preimage).digest())
            self.assertEqual(status, code)
            observed.append((pack(mode, fixed, rows, declaration, pad=0xad if i % 2 else 0),
                             39, SCRATCH + 9, status, digest if status == 0 else b"",
                             preimage if touched else b""))
        self.native_cases(observed)

    def test_framing_and_capacity_leave_caller_buffers_intact(self):
        valid = pack(1, FIXED, [BUILD_INPUT], declared(FIXED, [BUILD_INPUT]))
        bad = [valid[:n] for n in (0, 1, 2, 258, len(valid) - 1)]
        bad += [valid + bytes(1), b"\x02" + valid[1:],
                valid[:HEADER] + struct.pack("<H", 513) + valid[HEADER + 2:],
                pack(0, FIXED, [BUILD_INPUT] * 65, ZERO)]
        cases = [(frame, cap, work, 100, b"", b"") for frame in bad
                 for cap, work in ((0, 0), (39, SCRATCH + 9))]
        cases += [(valid, 31, SCRATCH, 102, b"", b""),
                  (valid, 32, SCRATCH - 1, 102, b"", b""),
                  (pack(1, FIXED, [], ZERO), 0, 0, 105, b"", b""),
                  (valid, 32, SCRATCH, 0, declared(FIXED, [BUILD_INPUT]),
                   transcript(FIXED, [BUILD_INPUT]))]
        self.native_cases(cases)

    def test_actual_native_inputs_supply_original_provenance_then_bundle_binding(self):
        original, code, stage, expected_bundle = original_binding_rows()[0]
        self.assertEqual((code, stage), (0, 0))
        for backend, provenance in self.native.items():
            with self.subTest(backend=backend), ExitStack() as stack:
                def enter(name):
                    return stack.enter_context(NativeModule(SOURCE.with_name(name), backend=backend,
                                                            byte_exports=("f0",)))

                def derive(module, packet, extent):
                    result = module.call("f0", [packet, bytes(32), bytes(extent)]).require_returned()
                    self.assertEqual(result.value, 0)
                    return result.arguments[1]

                exact = derive(enter("exact_source.hepta"), original[:193], 1493)
                art_kernel = enter("artifact_set_digest.hepta")
                artifact = derive(art_kernel, pack_artifacts(1, [ARTIFACT_FIXTURE]), 4876)
                sbom = derive(enter("sbom_digest.hepta"), pack_sbom([SBOM_FIXTURE]), 4868)
                fixed = (*IDENTITIES, exact, artifact, sbom)
                original_declared = original[289:321]
                actual_provenance = derive(
                    provenance, pack(1, fixed, [BUILD_INPUT], original_declared), SCRATCH)
                self.assertEqual(actual_provenance, original_declared)
                binding = enter("bundle_binding.hepta")
                combined = original[:225] + artifact + sbom + actual_provenance + original[321:]
                self.assertEqual(derive(binding, combined, 2302), expected_bundle)

                modified_artifact = derive(art_kernel, pack_artifacts(
                    1, [replace(ARTIFACT_FIXTURE, 2, 2048)]), 4876)
                modified_fixed = (*IDENTITIES, exact, modified_artifact, sbom)
                stale = pack(1, modified_fixed, [BUILD_INPUT], original_declared)
                marker = b"\xc1" * 39
                result = provenance.call("f0", [stale, marker, bytes(SCRATCH)]).require_returned()
                self.assertEqual((result.value, result.arguments[1]), (105, marker))


if __name__ == "__main__":
    unittest.main()
