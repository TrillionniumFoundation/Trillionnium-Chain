"""Pure post-callback NodeSoftware state ordering, never a release approval."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_pq_signing import DIR, RELEASE, ROOT, ZERO, payload

ADAPTER = Path(__file__).with_name("rust_release_pq_bundle_state_reference.rs")
EXACT_ORIGINAL = "733433bcda793c15f6aba5180da77de5ac8dd8a5811f55ff35de04fe4300ed1f"
NETWORK = bytes(range(32))
TIP = b"\x2a" * 32
CONTENT = b"\x7c" * 32
OLD = b"\x2b" * 32
U64_MAX = 2**64 - 1


def option(digest):
    return bytes([digest is not None]) + (ZERO if digest is None else digest)


def snapshot(*, offered_network=NETWORK, offered_generation=9, offered_version=4,
             offered_expiry=101, offered_tip=TIP, previous=None, content=CONTENT,
             rollback=0, trusted_tip=TIP, owner_tip=TIP, root_network=NETWORK,
             generation=9, root_expiry=110, current=None, version=3,
             floor=12, now=12, events=4, history=()):
    metadata = payload(role=1, network=offered_network,
                       values=(offered_generation, offered_version, offered_expiry),
                       checkpoint=offered_tip, previous=previous, content=content,
                       rollback=rollback)
    return (metadata + trusted_tip + root_network + struct.pack("<QQ", generation, root_expiry)
            + owner_tip + option(current) + struct.pack("<QQQQH", version, floor, now, events,
                                                        len(history))
            + b"".join(bytes([role]) + digest for role, digest in history))


def original(cases):
    rustc = os.environ.get("RUSTC", "rustc")
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    ver = subprocess.run([rustc, "--version"], capture_output=True, text=True, check=True, timeout=15)
    if ver.stdout.split()[:2] != ["rustc", pin]:
        raise ValueError("wrong original Rust toolchain")
    raw = RELEASE.read_bytes()
    excerpt = raw.split(b"    fn accept_with_quorum(", 1)[1]
    body = excerpt[excerpt.index(b"        if self.event_count"):excerpt.index(b"        let message =")]
    if hashlib.sha256(body).hexdigest() != EXACT_ORIGINAL:
        raise ValueError("original post-callback state logic changed; review the scope first")
    patterns = (
        (rb"(?m)^pub type ReleaseDigestV1 = \[u8; 32\];\n", 1),
        (rb"(?m)^pub const MAX_(?:RETAINED_RELEASES|RECOVERY_EVENTS)_V1:[^\n]+;\n", 2),
        (rb"(?ms)^#\[derive[^\n]+\n#\[repr\(u8\)\]\npub enum PqReleaseRoleV1 \{.*?^\}\n", 1),
        (rb"(?ms)^#\[derive[^\n]+\npub struct PqReleaseMetadataV1 \{.*?^\}\n", 1),
        (rb"(?ms)^#\[derive[^\n]+\]\nstruct CurrentPqReleaseV1 \{.*?^\}\n", 1),
        (rb"(?ms)^#\[derive[^\n]+\npub enum PqReleaseErrorV1 \{.*?^\}\n", 1),
    )
    pieces = []
    for pattern, count in patterns:
        found = re.findall(pattern, raw)
        if len(found) != count:
            raise ValueError(f"original type roster changed: {pattern!r}")
        pieces.extend(found)
    adapter = ADAPTER.read_bytes()
    marker = b"        // EXACT_ORIGINAL_GUARD\n"
    if adapter.count(marker) != 1:
        raise ValueError("ambiguous original Rust insertion")
    with tempfile.TemporaryDirectory(prefix="trnm-release-shadow-state-") as temp:
        path = Path(temp) / "original.rs"
        binary = path.with_suffix("")
        path.write_bytes(b"\n".join([*pieces, adapter.replace(marker, body)]))
        subprocess.run([rustc, "--edition=2024", "-Dwarnings", path, "-o", binary],
                       check=True, timeout=30)
        req = b"".join(struct.pack("<I", len(frame)) + frame for _, frame, _ in cases)
        proc = subprocess.run([binary], input=req, capture_output=True, check=True, timeout=60)
    if len(proc.stdout) != len(cases) or proc.stderr:
        raise ValueError("unexpected original state guard stream")
    return list(proc.stdout)


class ReleasePqBundleState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        validator = DIR / "pq_bundle_state.hepta"
        cls.native = {backend: cls.enterClassContext(NativeModule(validator, backend=backend,
                                                                  byte_exports=("f0",)))
                      for backend in ("direct", "selfhost")}
        if cls.native["direct"].artifact_sha256 == cls.native["selfhost"].artifact_sha256:
            raise ValueError("both independent HIA emitters are required")

    def check_native(self, cases):
        for backend, module in self.native.items():
            for name, frame, expected in cases:
                with self.subTest(backend=backend, name=name):
                    canaries = [frame, b"native-not-authority", b"\x5a" * 43]
                    result, = module.call_many([("f0", canaries)], timeout=40)
                    result.require_returned()
                    self.assertEqual(result.value, expected)
                    self.assertEqual(result.arguments, canaries)

    def test_exact_original_policy_with_full_role_history(self):
        registered = ((1, CONTENT),)
        full = tuple((2, i.to_bytes(32, "big")) for i in range(1, 4097))
        revisited_full = registered + full[:-1]
        cases = [
            ("state_prefix_only", snapshot(), 0),
            ("exclusive_event_limit", snapshot(events=8191), 0),
            ("event_limit_precedes_clock_and_all_later", snapshot(events=8192, now=2,
                                                                 offered_tip=OLD), 201),
            ("clock_precedes_expiry", snapshot(now=2, root_expiry=2), 202),
            ("root_expiry_equal_now", snapshot(root_expiry=12), 203),
            ("metadata_expiry_equal_now", snapshot(offered_expiry=12), 203),
            ("metadata_expiry_beyond_root", snapshot(offered_expiry=111,
                                                    offered_network=OLD), 203),
            ("offered_expiry_equal_root_valid", snapshot(offered_expiry=110), 0),
            ("wrong_network_precedes_checkpoint", snapshot(offered_network=OLD,
                                                           offered_tip=OLD), 204),
            ("wrong_generation", snapshot(offered_generation=8), 204),
            ("wrong_checkpoint_precedes_version", snapshot(offered_tip=OLD,
                                                          offered_version=3), 205),
            ("similarly_encoded_none_not_some_zero", snapshot(current=ZERO), 205),
            ("both_some_zero", snapshot(current=ZERO, previous=ZERO), 0),
            ("prior_content_mismatch", snapshot(current=OLD, previous=CONTENT), 205),
            ("version_must_advance_once", snapshot(offered_version=5), 206),
            ("overflow_cannot_wrap", snapshot(version=U64_MAX, offered_version=0,
                                              content=ZERO), 206),
            ("upper_version_boundary", snapshot(version=U64_MAX - 1, offered_version=U64_MAX), 0),
            ("content_before_approval", snapshot(content=ZERO, rollback=1), 207),
            ("wrong_rollback_approval", snapshot(rollback=1), 208),
            ("same_content_not_a_rollback", snapshot(current=CONTENT, previous=CONTENT,
                                                     history=registered), 0),
            ("same_content_wrong_approval", snapshot(current=CONTENT, previous=CONTENT,
                                                      history=registered, rollback=1), 208),
            ("revisit_requires_approval", snapshot(current=OLD, previous=OLD,
                                                   history=registered), 208),
            ("authorized_rollback_bit_only", snapshot(current=OLD, previous=OLD,
                                                      history=registered, rollback=1), 0),
            ("history_is_role_qualified", snapshot(history=((2, CONTENT),)), 0),
            ("4095_global_rows_still_have_room", snapshot(history=full[:-1]), 0),
            ("4096_global_rows_refuse_novel", snapshot(history=full), 201),
            ("rollback_mismatch_precedes_global_cap", snapshot(history=full, rollback=1), 208),
            ("existing_content_at_full_history", snapshot(history=revisited_full, current=CONTENT,
                                                         previous=CONTENT), 0),
        ]
        self.assertEqual(original(cases), [expected for _, _, expected in cases])
        self.check_native(cases)

    def test_independent_fresh_anchor_and_bounded_shape(self):
        good = snapshot()
        cases = [
            ("stale_snapshot_self_consistent", snapshot(owner_tip=OLD, offered_tip=OLD), 111),
            ("fresh_candidate_stale_shadow_owner", snapshot(owner_tip=OLD), 111),
            ("all_zero_is_not_a_fresh_anchor", snapshot(owner_tip=ZERO, offered_tip=ZERO,
                                                        trusted_tip=ZERO), 111),
            ("anchor_refusal_before_policy", snapshot(owner_tip=OLD, events=8192), 111),
            ("fresh_tip_but_stale_candidate", snapshot(offered_tip=OLD), 205),
            ("trailing_byte", good + b"\x00", 100),
            ("truncated_history_header", good[:-1], 100),
            ("wrong_metadata_role_for_bundle", b"\x02" + good[1:], 100),
            ("bad_metadata_option", good[:89] + b"\x02" + good[90:], 100),
            ("absent_metadata_with_bytes", good[:90] + b"\xff" + good[91:], 100),
            ("wrong_current_option", good[:267] + b"\x02" + good[268:], 100),
            ("absent_current_with_bytes", good[:268] + b"\xff" + good[269:], 100),
            ("unknown_history_role", snapshot(history=((5, CONTENT),)), 100),
            ("duplicate_history", snapshot(history=((1, CONTENT), (1, CONTENT))), 100),
            ("noncanonical_order", snapshot(history=((2, OLD), (1, CONTENT))), 100),
            ("4097_history_rows", snapshot(history=tuple((1, i.to_bytes(32, "big"))
                                                         for i in range(1, 4098))), 100),
        ]
        self.check_native(cases)


if __name__ == "__main__":
    unittest.main()
