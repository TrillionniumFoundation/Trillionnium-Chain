"""Original V0 artifact arithmetic, membership and native bundle composition."""
from __future__ import annotations

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

SOURCE = ROOT / "hia/src/release_bundle/artifact_set_digest.hepta"
ADAPTER = Path(__file__).with_name("rust_release_artifact_set_reference.rs")
ARG_MIN, ROW_BYTES, SCRATCH, SET_START = 3, 877, 4876, 2800
SET_DOMAIN = b"trnm.release.artifact-set.v0"
ENTRY_DOMAIN = b"trnm.release.artifact.v0"
EMPTY_DIGEST = bytes.fromhex("5fea0601e75c821feebfa310749a049391edb557b74f10b274bf90f0e3ee636a")
BASE = (b"trnm-portable-node", b"application/vnd.trnm.elf", 1024, byte_digest(7),
        True, byte_digest(8), byte_digest(9))


def frame(mode, rows, *, pad=0):
    parts = [struct.pack("<BH", mode, len(rows))]
    for n, m, size, content, executable, platform, path in rows:
        parts.append(struct.pack("<HHQB", len(n), len(m), size, executable))
        parts.extend([content, platform, path, n.ljust(512, bytes([pad])),
                      m.ljust(256, bytes([pad]))])
    return b"".join(parts)


def transcript(rows):
    fields = [SET_DOMAIN]
    for n, m, size, content, executable, platform, path in sorted(rows):
        parts = (ENTRY_DOMAIN, n, m, size.to_bytes(8, "big"), content,
                 bytes([executable]), platform, path)
        member = b"".join(len(part).to_bytes(8, "big") + part for part in parts)
        fields.append(hashlib.sha256(member).digest())
    return b"".join(fields)


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
        raise ValueError("SBOM comparison source no longer exposes the original source prefix")
    with tempfile.TemporaryDirectory(prefix="trnm-artifact-set-original-") as tmp:
        source = Path(tmp) / "original.rs"
        program = source.with_suffix("")
        source.write_bytes(common.removesuffix(old_adapter) + ADAPTER.read_bytes())
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(program)],
                       check=True, capture_output=True, timeout=30)
        run = subprocess.run([str(program)], input=b"".join(frame(m, r) for m, r in cases),
                             check=True, capture_output=True, timeout=60)
    results = []
    raw = run.stdout
    for _, rows in cases:
        status = raw[0]
        length = 1 if status else 33 + 32 * len(rows)
        if len(raw) < length:
            raise ValueError("Incomplete original artifact result")
        results.append((status, raw[1:min(33, length)], raw[33:length]))
        raw = raw[length:]
    if raw or run.stderr:
        raise ValueError("Extra original artifact oracle output")
    return results


class ReleaseArtifactSet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("Expected different machine artifacts")

    def compare(self, cases):
        for backend, module in self.native.items():
            for start in range(0, len(cases), 8):
                group = cases[start:start + 8]
                invocations = [("f0", [packet, b"\xc5" * width, b"\x8a" * work])
                               for packet, width, work, _, _, _ in group]
                outcomes = module.call_many(invocations, timeout=45)
                for i, (request, result, case) in enumerate(zip(invocations, outcomes, group)):
                    packet, _, _, code, digest, source_bytes = case
                    with self.subTest(backend=backend, row=start + i):
                        result.require_returned()
                        self.assertEqual(result.value, code)
                        self.assertEqual(result.arguments[0], packet)
                        self.assertEqual(result.arguments[1], digest + request[1][1][len(digest):])
                        scratch = result.arguments[2]
                        if code:
                            self.assertEqual(scratch, request[1][2])
                        else:
                            self.assertEqual(scratch[SET_START:SET_START + len(source_bytes)],
                                             source_bytes)
                            self.assertEqual(scratch[SCRATCH:], request[1][2][SCRATCH:])

    def test_original_complete_order_and_distinct_membership(self):
        rosters = [[], [BASE], [BASE, BASE]]
        for field in (0, 1):
            items = [replace(BASE, field, text) for text in (
                b"", b"x", b"x\0", b"x\xff", b"xx", b"\xff", "合".encode(), "😀".encode())]
            rosters += [items, items[::-1]]
        sizes = [0, 1, 255, 256, 257, 65535, 65536, 1 << 37, (1 << 37) + 1,
                 (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        items = [replace(BASE, 2, size) for size in sizes]
        items += [replace(BASE, i, bytes(31) + bytes([last])) for i in (3, 5, 6)
                  for last in (0, 1, 127, 128, 255)]
        items += [replace(BASE, 4, False), BASE, BASE]
        rosters += [items, items[::-1]]
        maximum = replace(replace(BASE, 0, b"Z" * 512), 1, b"x" * 256)
        roll = [replace(maximum, 6, bytes(31) + bytes([i])) for i in range(64)]
        random.Random(405).shuffle(roll)
        rosters += [[maximum], [maximum] * 64, roll, roll[::-1]]

        unique = replace(BASE, 0, BASE[0] + b"x")
        altered_duplicate = replace(BASE, 6, byte_digest(16))
        invalid_duplicate = replace(BASE, 2, 0)
        invalid_other = replace(unique, 2, 0)
        valid_maximum = replace(maximum, 2, 1 << 37)
        unique_maximum = [replace(valid_maximum, 0, b"Z" * 510 + f"{i:02}".encode())
                          for i in range(64)][::-1]
        membership = [([], 105), ([BASE], 0), ([valid_maximum], 0), ([unique, BASE], 0),
                      ([BASE, BASE], 107), ([BASE, altered_duplicate], 107),
                      ([BASE, invalid_duplicate], 106),
                      ([BASE, altered_duplicate, invalid_other], 107),
                      ([BASE, invalid_other, altered_duplicate], 106),
                      (unique_maximum, 0),
                      (unique_maximum[:-1] + [unique_maximum[0]], 107)]
        membership += [([replace(BASE, field, value)], 106) for field, value in (
            (0, b""), (0, b"x\x7f"), (1, b""), (1, b"x\x1f"), (1, "中".encode()),
            (2, (1 << 37) + 1), (3, bytes(32)), (5, bytes(32)), (6, bytes(32)))]
        instances = [(0, rows) for rows in rosters] + [(1, rows) for rows, _ in membership]
        results = original(instances)
        self.assertEqual(results[0], (0, EMPTY_DIGEST, b""))
        self.assertNotEqual(results[1][1], results[2][1])
        self.assertEqual([code for code, *_ in results[len(rosters):]],
                         [code for _, code in membership])
        cases = []
        for i, ((mode, rows), (code, digest, leaves)) in enumerate(zip(instances, results)):
            data = frame(mode, rows, pad=0xef if i % 2 else 0)
            canon = transcript(rows) if code == 0 else b""
            if code == 0:
                self.assertEqual(canon, SET_DOMAIN + leaves)
                self.assertEqual(digest, hashlib.sha256(canon).digest())
            cases.append((data, 39, SCRATCH + 11, code, digest, canon))
        self.compare(cases)

    def test_wire_bounds_and_refusals_precede_publication(self):
        valid = frame(1, [BASE])
        malformed = [b"", valid[:1], valid[:2], valid[:-1], valid + bytes(1),
                     frame(0, [BASE] * 65), b"\xff" + valid[1:],
                     valid[:15] + b"\x02" + valid[16:],
                     valid[:ARG_MIN] + struct.pack("<H", 513) + valid[ARG_MIN + 2:],
                     valid[:ARG_MIN + 2] + struct.pack("<H", 257) + valid[ARG_MIN + 4:]]
        duplicate_then_bad_wire = frame(1, [BASE, BASE, BASE])
        flag = ARG_MIN + 2 * ROW_BYTES + 12
        malformed.append(duplicate_then_bad_wire[:flag] + b"\x03" + duplicate_then_bad_wire[flag + 1:])
        cases = [(bad, out, work, 100, b"", b"") for bad in malformed
                 for out, work in ((0, 0), (39, SCRATCH + 11))]
        cases.extend([
            (frame(1, []), 0, 0, 105, b"", b""),
            (frame(1, [replace(BASE, 2, 0)]), 0, 0, 106, b"", b""),
            (frame(1, [BASE, BASE]), 0, 0, 107, b"", b""),
            (valid, 31, SCRATCH, 102, b"", b""),
            (valid, 32, SCRATCH - 1, 102, b"", b""),
        ])
        canon = transcript([BASE])
        cases.append((valid, 32, SCRATCH, 0, hashlib.sha256(canon).digest(), canon))
        self.compare(cases)

    def test_bundle_binding_consumes_actual_native_artifact_and_sbom_rosters(self):
        original_packet, code, stage, expected = original_binding_rows()[0]
        self.assertEqual((code, stage), (0, 0))
        for backend, artifacts in self.native.items():
            with NativeModule(SOURCE.with_name("sbom_digest.hepta"), backend=backend,
                              byte_exports=("f0",)) as sbom, NativeModule(
                                  SOURCE.with_name("bundle_binding.hepta"), backend=backend,
                                  byte_exports=("f0",)) as binding:
                for rows, packages, accepted in (
                    ([BASE], [SBOM_FIXTURE], True),
                    ([replace(BASE, 2, 256)], [SBOM_FIXTURE], False),
                    ([BASE], [SBOM_FIXTURE, SBOM_FIXTURE], False),
                ):
                    with self.subTest(backend=backend, accepted=accepted):
                        art = artifacts.call("f0", [frame(1, rows), bytes(32), bytes(SCRATCH)])
                        bom = sbom.call("f0", [pack_sbom(packages), bytes(32), bytes(4868)])
                        self.assertEqual((art.require_returned().value, bom.require_returned().value),
                                         (0, 0))
                        packet = (original_packet[:225] + art.arguments[1] + bom.arguments[1]
                                  + original_packet[289:])
                        marker = b"\xde" * 39
                        result = binding.call("f0", [packet, marker, bytes(2302)]).require_returned()
                        self.assertEqual(result.value, 0 if accepted else 104)
                        self.assertEqual(result.arguments[1], expected + marker[32:] if accepted else marker)


if __name__ == "__main__":
    unittest.main()
