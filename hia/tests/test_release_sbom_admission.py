"""Original V0 required key coverage and actual native SBOM digest issuance."""
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
from hia.tests.test_release_artifact_set_digest import BASE as ARTIFACT_BASE, frame as pack_artifacts
from hia.tests.test_release_builder_provenance import BUILD_INPUT, IDENTITIES, pack as pack_provenance
from hia.tests.test_release_sbom_digest import (
    ADAPTER as SBOM_ADAPTER,
    BASE,
    ROOT,
    ROW,
    SCRATCH,
    SET_DOMAIN,
    SET_START,
    byte_digest,
    exact_comparison_source,
    frame as pack_packages,
    original_binding_rows,
    replace,
    sorted_leaf_hashes,
)

SOURCE = ROOT / "hia/src/release_bundle/sbom_admission.hepta"
ADAPTER = Path(__file__).with_name("rust_release_sbom_admission_reference.rs")
KEY = BASE[:2]
KEY_SIZE = 772


def packet(rows, required, *, pad=0):
    parts = [pack_packages(rows, pad=pad), struct.pack("<H", len(required))]
    for name, version in required:
        parts.extend((struct.pack("<HH", len(name), len(version)),
                      name.ljust(512, bytes([pad])), version.ljust(256, bytes([pad]))))
    return b"".join(parts)


def original(cases):
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    common = exact_comparison_source()
    test_tail = SBOM_ADAPTER.read_bytes()
    if not common.endswith(test_tail):
        raise ValueError("Cannot locate the unchanged original source and digest seam")
    with tempfile.TemporaryDirectory(prefix="trnm-sbom-admission-reference-") as temp:
        source = Path(temp) / "original.rs"
        program = source.with_suffix("")
        source.write_bytes(common.removesuffix(test_tail) + ADAPTER.read_bytes())
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(program)],
                       check=True, capture_output=True, timeout=30)
        report = subprocess.run([str(program)], input=b"".join(packet(r, k) for r, k, _ in cases),
                                check=True, capture_output=True, timeout=60)
    raw, results = report.stdout, []
    for rows, _, _ in cases:
        status = raw[0]
        extent = 1 if status else 33 + len(rows) * 32
        if len(raw) < extent:
            raise ValueError("Original outcome truncated")
        results.append((status, raw[1:min(33, extent)], raw[33:extent]))
        raw = raw[extent:]
    if report.stderr or raw:
        raise ValueError("Unexpected original output")
    return results


class SbomAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("Expected independently emitted artifacts")

    def compare(self, cases):
        for backend, module in self.native.items():
            for offset in range(0, len(cases), 8):
                batch = cases[offset:offset + 8]
                req = [("f0", [raw, b"\xb5" * out, b"\xa7" * work])
                       for raw, out, work, *_ in batch]
                got = module.call_many(req, timeout=45)
                self.assertEqual(len(got), len(batch))
                for i, (observed, case, ask) in enumerate(zip(got, batch, req)):
                    with self.subTest(backend=backend, row=offset + i):
                        raw, _, _, status, digest, members = case
                        observed.require_returned()
                        self.assertEqual(observed.value, status)
                        self.assertEqual(observed.arguments[0], raw)
                        self.assertEqual(observed.arguments[1], digest + ask[1][1][len(digest):])
                        if status:
                            self.assertEqual(observed.arguments[2], ask[1][2])
                        else:
                            feed = SET_DOMAIN + members
                            self.assertEqual(observed.arguments[2][SET_START:SET_START + len(feed)],
                                             feed)
                            self.assertEqual(observed.arguments[2][SCRATCH:], ask[1][2][SCRATCH:])

    def test_original_package_validity_duplicates_then_exact_required_coverage(self):
        false = replace(BASE, 5, False)
        alternate = replace(BASE, 1, BASE[1] + b"1")
        other = replace(BASE, 0, b"another")
        duplicate = replace(false, 3, byte_digest(55))
        invalid = replace(duplicate, 4, b"")
        missing = (b"no coverage", b"1")
        cases = [
            ([], [KEY], 105), ([BASE], [], 0), ([false], [KEY], 0),
            ([false], [KEY, KEY], 0), ([BASE], [KEY, missing], 108),
            ([BASE], [missing, KEY], 108), ([BASE], [alternate[:2]], 108),
            ([BASE], [other[:2]], 108), ([BASE], [(KEY[0].upper(), KEY[1])], 108),
            ([BASE], [(KEY[0] + b"y", KEY[1])], 108), ([BASE], [(KEY[0], KEY[1][:-1])], 108),
            ([BASE], [(b"", b"")], 108), ([BASE], [(b"\xff", b"\0")], 108),
            ([alternate, BASE], [KEY, alternate[:2], KEY], 0),
            ([other, BASE, alternate], [KEY, other[:2], alternate[:2]], 0),
            ([BASE, duplicate], [missing], 107),
            ([BASE, invalid], [missing], 106),
            ([BASE, duplicate, invalid], [missing], 107),
            ([BASE, invalid, duplicate], [missing], 106),
        ]
        cases += [([replace(BASE, field, val)], [missing], 106) for field, val in (
            (0, b""), (0, b"\x7f"), (1, b""), (1, b"\x1f"), (4, b""), (4, "中".encode()),
            (2, bytes(32)), (3, bytes(32)))]
        maximized = [replace(BASE, 0, b"Z" * 510 + f"{i:02}".encode()) for i in range(64)]
        maximized = [replace(replace(row, 1, b"x" * 256), 4, b"L" * 512) for row in maximized]
        random.Random(161).shuffle(maximized)
        max_keys = [row[:2] for row in maximized[::-1]]
        cases += [(maximized, max_keys, 0), (maximized, [*max_keys[:-1], missing], 108),
                  (maximized[:-1] + [maximized[0]], max_keys, 107)]
        rust = original(cases)
        self.assertEqual([code for code, _, _ in rust], [case[-1] for case in cases])
        self.assertEqual(rust[2][1], rust[3][1])  # required roster is not a hash field
        self.assertNotEqual(rust[1][1], rust[2][1])  # direct flag is a digest field
        observations = []
        for i, ((rows, required, code), (_, digest, leaves)) in enumerate(zip(cases, rust)):
            if code == 0:
                self.assertEqual(leaves, sorted_leaf_hashes(rows))
                self.assertEqual(digest, hashlib.sha256(SET_DOMAIN + leaves).digest())
            observations.append((packet(rows, required, pad=0xc3 if i % 2 else 0),
                                 39, SCRATCH + 13, code, digest, leaves))
        self.compare(observations)

    def test_framing_capacity_and_refusal_are_atomic(self):
        valid = packet([BASE], [KEY])
        key_start = 4 + ROW
        malformed = [valid[:i] for i in (0, 1, 3, 2 + ROW, 3 + ROW, len(valid) - 1)]
        malformed += [valid + bytes(1), packet([BASE] * 65, []), packet([BASE], [KEY] * 65),
                      valid[:8] + b"\x02" + valid[9:],
                      valid[:key_start] + struct.pack("<H", 513) + valid[key_start + 2:],
                      valid[:key_start + 2] + struct.pack("<H", 257) + valid[key_start + 4:]]
        cases = [(raw, out, scratch, 100, b"", b"") for raw in malformed
                 for out, scratch in ((0, 0), (39, SCRATCH + 13))]
        cases += [
            (packet([], []), 0, 0, 105, b"", b""),
            (packet([replace(BASE, 2, bytes(32))], [KEY]), 0, 0, 106, b"", b""),
            (packet([BASE, BASE], [KEY]), 0, 0, 107, b"", b""),
            (packet([BASE], [(b"missing", b"1")]), 0, 0, 108, b"", b""),
            (valid, 31, SCRATCH, 102, b"", b""),
            (valid, 32, SCRATCH - 1, 102, b"", b""),
        ]
        members = sorted_leaf_hashes([BASE])
        cases.append((valid, 32, SCRATCH, 0, hashlib.sha256(SET_DOMAIN + members).digest(), members))
        self.compare(cases)

    def test_native_coverage_and_digest_feed_provenance_and_binding(self):
        release, c, s, bundle_digest = original_binding_rows()[0]
        self.assertEqual((c, s), (0, 0))
        for backend, admission in self.native.items():
            with self.subTest(backend=backend), ExitStack() as stack:
                def enter(name):
                    return stack.enter_context(NativeModule(SOURCE.with_name(name), backend=backend,
                                                            byte_exports=("f0",)))

                def digest(module, raw, scratch):
                    result = module.call("f0", [raw, bytes(32), bytes(scratch)]).require_returned()
                    self.assertEqual(result.value, 0)
                    return result.arguments[1]

                exact = digest(enter("exact_source.hepta"), release[:193], 1493)
                artifacts = digest(enter("artifact_set_digest.hepta"),
                                   pack_artifacts(1, [ARTIFACT_BASE]), 4876)
                bom = digest(admission, packet([BASE], [KEY, KEY]), SCRATCH)
                pure = digest(enter("sbom_digest.hepta"), pack_packages([BASE]), SCRATCH)
                self.assertEqual(bom, pure)
                actual_prov = digest(enter("builder_provenance.hepta"), pack_provenance(
                    1, (*IDENTITIES, exact, artifacts, bom), [BUILD_INPUT], release[289:321]), 5114)
                bound = release[:225] + artifacts + bom + actual_prov + release[321:]
                self.assertEqual(digest(enter("bundle_binding.hepta"), bound, 2302), bundle_digest)
                out = b"\xfe" * 32
                missing = admission.call("f0", [packet([BASE], [(b"not declared", KEY[1])]),
                                               out, bytes(SCRATCH)]).require_returned()
                self.assertEqual((missing.value, missing.arguments[1]), (108, out))


if __name__ == "__main__":
    unittest.main()
