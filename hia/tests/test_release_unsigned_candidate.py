"""One emitted unsigned release entry, exact Rust precedence and result bytes."""
from __future__ import annotations

from dataclasses import replace as change
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_builder_provenance import (
    BUILD_INPUT,
    IDENTITIES,
    declared as provenance_digest,
    pack as pack_provenance,
)
from hia.tests.test_release_sbom_digest import (
    ADAPTER as SHA_FIXTURE,
    ROOT,
    byte_digest,
    exact_comparison_source,
    replace,
)
from hia.tests.test_release_unsigned_prefix import (
    ARTIFACT,
    HEAD,
    KEY,
    MISSING,
    PACKAGE,
    ZERO,
    arithmetic,
    pack as pack_prefix,
)

SOURCE = ROOT / "hia/src/release_bundle/unsigned_candidate.hepta"
ADAPTER = Path(__file__).with_name("rust_release_unsigned_candidate_reference.rs")
OUT, WORK, PROVENANCE_SLOT, BUNDLE_SLOT = 168, 5360, 5296, 5328
BUNDLE_DOMAIN = b"trnm.release.bundle.v0"
MAX_ROW = 64


def bundle_digest(header, computed, provenance, prior):
    fields = [BUNDLE_DOMAIN, header.name, header.version, header.protocol,
              *(computed[i:i + 32] for i in range(0, 96, 32)),
              provenance, prior, header.signer]
    return hashlib.sha256(b"".join(len(p).to_bytes(8, "big") + p for p in fields)).digest()


def case(header=HEAD, artifacts=(ARTIFACT,), packages=(PACKAGE,), required=(KEY,),
         inputs=(BUILD_INPUT,), prior=ZERO, *, override_fixed=None, prov_claim=None,
         bundle_claim=None, status=0, footprint="complete"):
    prefix = pack_prefix(header, artifacts, packages, required, pad=0xbe)
    computed = arithmetic(header, artifacts, packages)
    fixed = (*IDENTITIES, *(computed[i:i + 32] for i in range(0, 96, 32)))
    if override_fixed is not None:
        index, value = override_fixed
        fixed = replace(fixed, index, value)
    proof = provenance_digest(fixed, inputs)
    actual_bundle = bundle_digest(header, computed, proof, prior)
    if prov_claim is None:
        prov_claim = proof
    if bundle_claim is None:
        bundle_claim = actual_bundle
    # Retain the same declaration and actual records as the original test.
    # The older provenance entry's mode byte is not part of this ABI.
    prov = pack_provenance(1, fixed, inputs, prov_claim, pad=0xc1)
    tail = prov[1:259] + prior + bundle_claim + prov[259:]
    expected = (actual_bundle + computed + proof
                + struct.pack("<II", len(artifacts), len(packages))) if status == 0 else b""
    return (prefix + tail, status, expected, footprint, computed + proof)


def original(cases):
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version[:2] != ["rustc", pin]:
        raise ValueError(f"Expected rustc {pin}, got {version[:2]}")
    common = exact_comparison_source()
    old_adapter = SHA_FIXTURE.read_bytes()
    if not common.endswith(old_adapter):
        raise ValueError("Original ownership/seam extraction changed")
    with tempfile.TemporaryDirectory(prefix="trnm-unsigned-candidate-original-") as folder:
        source = Path(folder) / "reference.rs"
        program = source.with_suffix("")
        source.write_bytes(common.removesuffix(old_adapter) + ADAPTER.read_bytes())
        subprocess.run([rustc, "--edition=2021", "-Dwarnings", str(source), "-o", str(program)],
                       check=True, capture_output=True, timeout=30)
        report = subprocess.run([str(program)], input=b"".join(row[0] for row in cases),
                                check=True, capture_output=True, timeout=80)
    raw, result = report.stdout, []
    for _ in cases:
        status = raw[0]
        width = 1 if status else OUT + 1
        if len(raw) < width:
            raise ValueError("Incomplete observation from original pre-signature verifier")
        result.append((status, raw[1:width]))
        raw = raw[width:]
    if raw or report.stderr:
        raise ValueError("Unexpected original verifier observation tail")
    return result


class ReleaseUnsignedCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {
            backend: cls.enterClassContext(NativeModule(SOURCE, backend=backend,
                                                        byte_exports=("f0",)))
            for backend in ("direct", "selfhost")
        }
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("Expected two independent machine outputs")

    def check(self, rows):
        for backend, module in self.native.items():
            for start in range(0, len(rows), 4):
                batch = rows[start:start + 4]
                asks = [("f0", [row[0], b"\xe3" * out, b"\x9d" * work])
                        for row, out, work in batch]
                got = module.call_many(asks, timeout=45)
                self.assertEqual(len(got), len(batch))
                for i, ((row, _, _), ask, result) in enumerate(zip(batch, asks, got)):
                    packet, status, output, footprint, computed = row
                    with self.subTest(backend=backend, row=start + i, status=status):
                        result.require_returned()
                        self.assertEqual(result.value, status)
                        self.assertEqual(result.arguments[0], packet)
                        self.assertEqual(result.arguments[1], output + ask[1][1][len(output):])
                        scratch = result.arguments[2]
                        self.assertEqual(scratch[WORK:], ask[1][2][WORK:])
                        if footprint == "none":
                            self.assertEqual(scratch, ask[1][2])
                        elif footprint == "provenance":
                            self.assertNotEqual(scratch[:1208], ask[1][2][:1208])
                            self.assertEqual(scratch[5200:], ask[1][2][5200:])
                        elif footprint == "links":
                            self.assertEqual(scratch[5200:BUNDLE_SLOT], computed)
                            self.assertEqual(scratch[BUNDLE_SLOT:], ask[1][2][BUNDLE_SLOT:])
                        elif footprint == "complete":
                            self.assertEqual(scratch[5200:BUNDLE_SLOT], computed)
                            self.assertEqual(scratch[BUNDLE_SLOT:WORK], output[:32])
                        else:
                            self.fail(f"Unknown fixture footprint {footprint}")

    def test_real_original_pre_signature_statuses_and_complete_candidate_output(self):
        invalid_input = replace(BUILD_INPUT, 2, ZERO)
        duplicate_input = replace(BUILD_INPUT, 2, byte_digest(81))
        bad_source = change(HEAD, source=HEAD.source[:-1] + b"\1")
        bad_art = replace(ARTIFACT, 2, 0)
        bad_sbom = replace(PACKAGE, 4, b"")
        a2 = replace(ARTIFACT, 0, b"two")
        p2 = replace(PACKAGE, 1, b"v2")
        inp2 = replace(BUILD_INPUT, 1, byte_digest(82))
        max_arts = [replace(ARTIFACT, 0, b"a" * 510 + f"{i:02}".encode())
                    for i in range(MAX_ROW)][::-1]
        max_pkgs = [replace(PACKAGE, 0, b"p" * 510 + f"{i:02}".encode())
                    for i in range(MAX_ROW)][::-1]
        max_inputs = [replace(BUILD_INPUT, 0, b"i" * 510 + f"{i:02}".encode())
                      for i in range(MAX_ROW)][::-1]
        all_keys = [x[:2] for x in max_pkgs[::-1]]
        rows = [
            case(), case(header=change(HEAD, signature_label=byte_digest(91))),
            case(header=change(HEAD, name=b"X" * 512, version=b"V" * 256),
                 artifacts=max_arts, packages=max_pkgs, required=all_keys,
                 inputs=max_inputs, prior=byte_digest(101)),
            case(artifacts=[a2, ARTIFACT], packages=[p2, PACKAGE],
                 required=[p2[:2], KEY, KEY], inputs=[inp2, BUILD_INPUT], prior=byte_digest(20)),
            case(artifacts=[ARTIFACT, a2], packages=[PACKAGE, p2],
                 required=[KEY, p2[:2]], inputs=[BUILD_INPUT, inp2], prior=byte_digest(20)),
            case(header=change(bad_source, signature_label=ZERO), artifacts=[bad_art],
                 packages=[bad_sbom], required=[MISSING], inputs=[], prov_claim=ZERO,
                 bundle_claim=ZERO, status=110, footprint="none"),
            case(header=bad_source, artifacts=[bad_art], packages=[bad_sbom],
                 required=[MISSING], inputs=[], status=101, footprint="none"),
            case(artifacts=[bad_art], packages=[bad_sbom], required=[MISSING], inputs=[],
                 status=106, footprint="none"),
            case(artifacts=[ARTIFACT, ARTIFACT], packages=[bad_sbom], required=[MISSING],
                 inputs=[], status=107, footprint="none"),
            case(packages=[bad_sbom], required=[MISSING], inputs=[], status=116, footprint="none"),
            case(packages=[PACKAGE, PACKAGE], required=[MISSING], inputs=[], status=117,
                 footprint="none"),
            case(required=[MISSING], inputs=[], status=108, footprint="none"),
            case(inputs=[], bundle_claim=ZERO, status=105, footprint="none"),
            case(inputs=[invalid_input], prov_claim=ZERO, bundle_claim=ZERO, status=105,
                 footprint="provenance"),
            case(inputs=[invalid_input], override_fixed=(4, byte_digest(56)), bundle_claim=ZERO,
                 status=126, footprint="provenance"),
            case(inputs=[BUILD_INPUT, duplicate_input, invalid_input],
                 override_fixed=(5, byte_digest(57)), bundle_claim=ZERO, status=127,
                 footprint="provenance"),
            case(inputs=[BUILD_INPUT, invalid_input, duplicate_input],
                 override_fixed=(5, byte_digest(57)), bundle_claim=ZERO, status=126,
                 footprint="provenance"),
            case(bundle_claim=ZERO, status=104, footprint="links"),
        ]
        rows += [case(override_fixed=(i, ZERO), inputs=[invalid_input], status=105,
                      footprint="none") for i in range(7)]
        rows += [case(override_fixed=(i, byte_digest(99)), status=104,
                      footprint="links") for i in (4, 5, 6)]
        self.assertEqual(rows[0][2], rows[1][2])  # signature label not in canonical transcript
        self.assertEqual(rows[3][2], rows[4][2])  # no input-order leakage in the hashes
        rust = original(rows)
        self.assertEqual(rust, [(row[1], row[2]) for row in rows])
        self.check([(row, OUT + 13, WORK + 21) for row in rows])

    def test_exact_frame_and_capacities_never_publish_partial_output(self):
        valid = case()
        frame = valid[0]
        tail = len(pack_prefix(HEAD, [ARTIFACT], [PACKAGE], [KEY]))
        width = 322
        malformed = [frame[:n] for n in (0, 1066, tail, tail + 1, tail + width - 1, len(frame) - 1)]
        malformed += [frame + b"\0", frame[:tail] + struct.pack("<H", 65) + frame[tail + 2:],
                      frame[:tail + width] + struct.pack("<H", 513) + frame[tail + width + 2:],
                      case(inputs=[BUILD_INPUT] * 65)[0],
                      frame[:298] + b"\xff" + frame[299:]]
        attempts = [((x, 100, b"", "none", b""), out, work)
                    for x in malformed for out, work in ((0, 0), (OUT + 9, WORK + 9))]
        short = (frame, 102, b"", "none", b"")
        attempts.extend([(short, OUT - 1, WORK), (short, OUT, WORK - 1), (valid, OUT, WORK)])
        attempts.append((case(required=[MISSING], inputs=[], status=108, footprint="none"), 0, 0))
        self.check(attempts)


if __name__ == "__main__":
    unittest.main()
