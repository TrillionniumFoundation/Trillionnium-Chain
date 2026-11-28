"""One real emitted M15 prefix owner over nonzero-offset raw sections."""
from __future__ import annotations

from dataclasses import dataclass, replace as change
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_artifact_set_digest import (
    BASE as ARTIFACT,
    frame as pack_artifacts,
    transcript as artifact_transcript,
)
from hia.tests.test_release_exact_source import transcript as source_transcript
from hia.tests.test_release_sbom_admission import packet as pack_coverage
from hia.tests.test_release_sbom_digest import (
    ADAPTER as SBOM_ADAPTER,
    BASE as PACKAGE,
    ROOT,
    SET_DOMAIN,
    byte_digest,
    exact_comparison_source,
    frame as pack_packages,
    replace,
    sorted_leaf_hashes,
)

SOURCE = ROOT / "hia/src/release_bundle/unsigned_prefix.hepta"
ADAPTER = Path(__file__).with_name("rust_release_unsigned_prefix_reference.rs")
HEADER, WORK, OUT = 1067, 5296, 96
RETAINED = 5200
KEY = PACKAGE[:2]
MISSING = (b"not declared", b"1")
ZERO = bytes(32)
EXACT = b"".join(byte_digest(i) for i in range(1, 7)) + b"\0"


@dataclass(frozen=True)
class Header:
    name: bytes = b"trnm-native-portable"
    version: bytes = b"0.1.0-dev"
    protocol: bytes = byte_digest(12)
    signer: bytes = byte_digest(18)
    signature_label: bytes = byte_digest(19)
    source: bytes = EXACT


HEAD = Header()
BASE = (HEAD, [ARTIFACT], [PACKAGE], [KEY], 0)


def pack(header, artifacts, packages, required, *, pad=0):
    counts = struct.pack("<HHHHH", len(header.name), len(header.version),
                         len(artifacts), len(packages), len(required))
    fixed = counts + header.protocol + header.signer + header.signature_label + header.source
    names = header.name.ljust(512, bytes([pad])) + header.version.ljust(256, bytes([pad]))
    return (fixed + names + pack_artifacts(0, artifacts, pad=pad)[3:]
            + pack_packages(packages, pad=pad)[2:]
            + pack_coverage([], required, pad=pad)[4:])


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
        raise ValueError("Original V0 source/seam extraction changed")
    with tempfile.TemporaryDirectory(prefix="trnm-release-unsigned-prefix-") as folder:
        source = Path(folder) / "reference.rs"
        program = source.with_suffix("")
        source.write_bytes(common.removesuffix(old_adapter) + ADAPTER.read_bytes())
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(program)],
                       check=True, capture_output=True, timeout=30)
        report = subprocess.run([str(program)], input=b"".join(pack(*c[:4]) for c in cases),
                                check=True, capture_output=True, timeout=60)
    raw, results = report.stdout, []
    for _ in cases:
        status = raw[0]
        extent = 1 if status else 1 + OUT
        if len(raw) < extent:
            raise ValueError("Incomplete original V0 prefix result")
        results.append((status, raw[1:extent]))
        raw = raw[extent:]
    if raw or report.stderr:
        raise ValueError("Extra original observation")
    return results


def arithmetic(header, artifacts, packages):
    return b"".join(hashlib.sha256(physical).digest() for physical in (
        source_transcript(header.source), artifact_transcript(artifacts),
        SET_DOMAIN + sorted_leaf_hashes(packages),
    ))


class ReleaseUnsignedPrefix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.modules["direct"].artifact_sha256 == cls.modules["selfhost"].artifact_sha256:
            raise ValueError("Expected independently emitted native artifacts")

    def check(self, cases):
        for backend, module in self.modules.items():
            for start in range(0, len(cases), 4):
                batch = cases[start:start + 4]
                requests = [("f0", [frame, b"\xd7" * out, b"\x86" * work])
                            for frame, out, work, *_ in batch]
                got = module.call_many(requests, timeout=45)
                self.assertEqual(len(got), len(batch))
                for pos, (case, request, result) in enumerate(zip(batch, requests, got)):
                    packet, _, _, status, output = case
                    with self.subTest(backend=backend, index=start + pos, status=status):
                        result.require_returned()
                        self.assertEqual(result.value, status)
                        self.assertEqual(result.arguments[0], packet)
                        self.assertEqual(result.arguments[1], output + request[1][1][len(output):])
                        scratch = result.arguments[2]
                        if status:
                            self.assertEqual(scratch, request[1][2])
                        else:
                            self.assertEqual(scratch[RETAINED:WORK], output)
                            self.assertEqual(scratch[WORK:], request[1][2][WORK:])

    def test_original_unsigned_order_and_exact_digests_at_multiple_offsets(self):
        a2 = replace(ARTIFACT, 0, b"extra artifact")
        p2 = replace(PACKAGE, 1, b"2.0.0")
        bad_source = change(HEAD, source=EXACT[:-1] + b"\1")
        bad_artifact = replace(ARTIFACT, 2, 0)
        repeated_artifact = replace(ARTIFACT, 6, byte_digest(23))
        bad_package = replace(PACKAGE, 4, b"")
        repeated_package = replace(PACKAGE, 5, False)
        max_artifacts = [replace(ARTIFACT, 0, b"A" * 510 + f"{i:02}".encode())
                         for i in range(64)][::-1]
        max_packages = [replace(PACKAGE, 0, b"P" * 510 + f"{i:02}".encode())
                        for i in range(64)][::-1]
        max_packages = [replace(replace(x, 1, b"v" * 256), 4, b"k" * 512) for x in max_packages]
        max_required = [x[:2] for x in max_packages[::-1]]
        cases = [
            BASE, (HEAD, [a2, ARTIFACT], [p2, PACKAGE], [KEY, p2[:2], KEY], 0),
            (change(HEAD, name=b"N" * 512, version=b"v" * 256),
             max_artifacts, max_packages, max_required, 0),
            (change(HEAD, source=bytes(31) + b"\xff" + EXACT[32:]),
             [ARTIFACT], [repeated_package], [KEY], 0),
            (change(bad_source, name=b""), [bad_artifact], [bad_package], [MISSING], 110),
            (change(bad_source, version=b"\x1f"), [bad_artifact], [bad_package], [MISSING], 110),
            (change(bad_source, protocol=ZERO), [bad_artifact], [bad_package], [MISSING], 110),
            (change(bad_source, signer=ZERO), [bad_artifact], [bad_package], [MISSING], 110),
            (change(bad_source, signature_label=ZERO), [bad_artifact], [bad_package], [MISSING], 110),
            (bad_source, [], [bad_package], [MISSING], 110),
            (bad_source, [bad_artifact], [], [MISSING], 110),
            (bad_source, [bad_artifact], [bad_package], [MISSING], 101),
            (HEAD, [bad_artifact], [bad_package], [MISSING], 106),
            (HEAD, [ARTIFACT, repeated_artifact, bad_artifact], [bad_package], [MISSING], 107),
            (HEAD, [ARTIFACT, bad_artifact, repeated_artifact], [bad_package], [MISSING], 106),
            (HEAD, [ARTIFACT], [PACKAGE, repeated_package, bad_package], [MISSING], 117),
            (HEAD, [ARTIFACT], [PACKAGE, bad_package, repeated_package], [MISSING], 116),
            (HEAD, [ARTIFACT], [PACKAGE], [KEY, MISSING], 108),
        ]
        for i in range(6):
            source = EXACT[:i * 32] + ZERO + EXACT[(i + 1) * 32:]
            cases.append((change(HEAD, source=source), [bad_artifact], [bad_package],
                          [MISSING], 101))
        rust = original(cases)
        checks = []
        for i, ((header, artifacts, packages, required, want), (status, observed)) in enumerate(
                zip(cases, rust)):
            self.assertEqual(status, want)
            if not status:
                self.assertEqual(observed, arithmetic(header, artifacts, packages))
            checks.append((pack(header, artifacts, packages, required, pad=0xea if i % 2 else 0),
                           OUT + 13, WORK + 17, status, observed))
        self.check(checks)

    def test_frame_extent_and_atomic_publication(self):
        valid = pack(*BASE[:4])
        art_end = HEADER + 877
        pkg_end = art_end + 1351
        def changed(at, value):
            return valid[:at] + value + valid[at + len(value):]
        malformed = [valid[:i] for i in (0, 9, HEADER - 1, HEADER, art_end, pkg_end, len(valid) - 1)]
        malformed += [valid + b"\0", changed(0, struct.pack("<H", 513)),
                      changed(2, struct.pack("<H", 257)), changed(298, b"\2"),
                      changed(HEADER + 12, b"\3"), changed(art_end + 6, b"\3"),
                      changed(pkg_end, struct.pack("<H", 513))]
        malformed += [pack(HEAD, [ARTIFACT] * 65, [PACKAGE], [KEY]),
                      pack(HEAD, [ARTIFACT], [PACKAGE] * 65, [KEY]),
                      pack(HEAD, [ARTIFACT], [PACKAGE], [KEY] * 65)]
        checks = [(raw, out, scratch, 100, b"") for raw in malformed
                  for out, scratch in ((0, 0), (OUT + 13, WORK + 11))]
        checks += [(valid, OUT - 1, WORK, 102, b""), (valid, OUT, WORK - 1, 102, b""),
                   (pack(HEAD, [ARTIFACT], [PACKAGE], [MISSING]), 0, 0, 108, b""),
                   (valid, OUT, WORK, 0, arithmetic(*BASE[:3]))]
        self.check(checks)


if __name__ == "__main__":
    unittest.main()
