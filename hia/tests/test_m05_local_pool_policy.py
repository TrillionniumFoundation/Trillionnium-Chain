"""Standalone M05 policy comparison; the persistent Node/SQLite owner is not exercised."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
POOL = ROOT / "trillionnium/crates/trnm-pon-node/src/store/mempool.rs"
NODE = ROOT / "trillionnium/crates/trnm-pon-node/src/lib.rs"
PROTOCOL = ROOT / "trillionnium/crates/trnm-protocol"
POLICY = ROOT / "hia/src/mempool/local_pool_policy.hepta"
ABI = POLICY.with_name("local_pool_policy_abi.json")
ADAPTER = Path(__file__).with_name("rust_m05_local_pool_policy_reference.rs")
LOCK = ADAPTER.parent / "oracles/m05-local-pool-policy-lock.json"
DOMAIN = b"native-local-queued-pnx1-v2"
IDENTITIES = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
DEFAULT = (64, 8192, 8, 3, 128)
FIELDS = ("max_records", "max_bytes", "max_group_members", "critical_reserve", "max_removals")
FIELD_ORDER = FIELDS + ("preview_miner",)


def original_spans(source, left, right):
    start = source.index(left)
    return source[start:source.index(right, start)]


def original_program():
    pool, node = POOL.read_bytes(), NODE.read_bytes()
    policy = original_spans(pool, b"pub const LOCAL_POOL_PROFILE:",
                            b"#[derive(Debug, Clone, PartialEq, Eq, Serialize)]\npub enum PoolState")
    binding = original_spans(pool, b"        limits.validate()?;\n        let raw = serde_json::to_vec(&limits)?;",
                             b"        let owner_permit =")
    result = original_spans(node, b"pub type Result<T>", b"/// (model bytes")
    ensure = original_spans(node, b"pub(crate) fn ensure(", b"pub fn digest(")
    return (
        b'''use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use trnm_protocol::pon_wire::{Hash, hash};
type Error = Box<dyn std::error::Error>;
'''
        + result + ensure
        + b'''
mod store {
use super::{Hash, Result, ensure, hash, Deserialize, Serialize};
mod mempool {
use super::{Hash, Result, ensure, hash, Deserialize, Serialize};
'''
        + policy
        + b'''
pub struct LightSettings(pub [Hash; 3]);
impl LightSettings {
    fn network(&self) -> Hash { self.0[0] }
    fn parameters(&self) -> Hash { self.0[1] }
    fn genesis(&self) -> Hash { self.0[2] }
}
pub struct IdentityOnly { pub settings: LightSettings }
impl IdentityOnly {
    pub fn bind(&self, limits: PoolLimits) -> Result<(Vec<u8>, Hash)> {
'''
        + binding
        + b'''
        Ok((raw, context))
    }
}
}
pub use mempool::{LightSettings, IdentityOnly, PoolLimits};
pub fn mempool_profile() -> &'static str { mempool::LOCAL_POOL_PROFILE }
}
'''
        + ADAPTER.read_bytes()
    )


def run_original(inputs):
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = os.environ.get("RUSTC", "rustc")
    version = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.split()
    if version[:2] != ["rustc", toolchain]:
        raise ValueError("Unexpected original Rust toolchain: " + repr(version[:2]))
    lock_document = json.loads(LOCK.read_bytes())
    if lock_document["schema"] != "trnm.hia.m05-local-pool-policy-rust-lock.v1":
        raise ValueError("Unexpected original excerpt dependency schema")
    lock = lock_document["lock_toml"]
    want = tomllib.loads((ROOT / "trillionnium/Cargo.lock").read_text())["package"]

    def identities(rows):
        return {(r["name"], r["version"], r["source"], r["checksum"]) for r in rows if "source" in r}

    selected = identities(tomllib.loads(lock)["package"])
    if not selected or not selected <= identities(want):
        raise ValueError("Original locked registry identity differs")
    manifest = '''[package]
name = "m05-local-pool-policy-verification"
version = "0.0.0"
edition = "2021"
[dependencies]
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.149"
trnm-protocol = { path = %s }
[profile.dev]
debug = 0
incremental = false
''' % json.dumps(str(PROTOCOL))
    with tempfile.TemporaryDirectory(prefix="trnm-hia-m05-local-policy-") as temporary:
        base = Path(temporary)
        (base / "src").mkdir()
        (base / "src/main.rs").write_bytes(original_program())
        (base / "Cargo.toml").write_text(manifest)
        (base / "Cargo.lock").write_text(lock)
        env = {**os.environ, "CARGO_TARGET_DIR": str(base / "target")}
        build = subprocess.run(["cargo", "build", "--locked", "--offline", "--jobs", "2",
                                "--manifest-path", str(base / "Cargo.toml"), "--message-format=json"],
                               cwd=ROOT, env=env, capture_output=True, timeout=120)
        if build.returncode:
            raise RuntimeError(build.stderr.decode("utf-8", "replace"))
        events = [json.loads(line) for line in build.stdout.splitlines() if line.startswith(b"{")]
        protocol = [row for row in events if row.get("reason") == "compiler-artifact"
                    and row["target"]["name"] == "trnm_protocol" and not row["fresh"]
                    and row["manifest_path"] == str(PROTOCOL / "Cargo.toml")]
        original = [row["executable"] for row in events if row.get("reason") == "compiler-artifact"
                    and row["target"]["name"] == "m05-local-pool-policy-verification"
                    and not row["fresh"] and row["executable"]]
        if len(protocol) != 1 or len(original) != 1:
            raise ValueError("Missing freshly compiled original protocol or excerpt owner")
        run = subprocess.run(original, input=b"".join(inputs), capture_output=True, check=True, timeout=20)
        if run.stderr:
            raise ValueError("Unexpected original excerpt stderr")
        return run.stdout


def frame(limits=DEFAULT, miner=bytes(range(32)), identities=IDENTITIES):
    return b"LPV1" + b"".join(identities) + miner + struct.pack("<5Q", *limits)


def expected(request):
    records, size, members, reserve, removals = limits = struct.unpack_from("<5Q", request, 132)
    miner = request[100:132]
    if not (1 <= records <= 256 and 1 <= size <= 524288 and 1 <= members <= min(16, records)
            and reserve < records and 1 <= removals <= 4096 and any(miner)):
        return 3, b""
    raw = json.dumps(dict(zip(FIELD_ORDER, (*limits, list(miner)))), separators=(",", ":")).encode()
    preimage = b"TRNM-PON1\0" + struct.pack("<H", len(DOMAIN)) + DOMAIN
    for part in (request[4:36], request[36:68], request[68:100], raw):
        preimage += struct.pack("<I", len(part)) + part
    return 32 + len(raw), hashlib.sha256(preimage).digest() + raw


def cases():
    result = [frame(), frame((1, 1, 1, 0, 1)),
              frame((256, 524288, 16, 255, 4096), b"\xff" * 32)]
    for i, values in enumerate((
            (0, 1, 99, 100, 255, 256, 257), (0, 1, 99999, 100000, 524287, 524288, 524289),
            (0, 1, 9, 10, 16, 17, 64, 65), (0, 1, 63, 64, 65),
            (0, 1, 9, 10, 4096, 4097, 1 << 63))):
        for value in (*values, (1 << 64) - 1):
            limits = list(DEFAULT)
            limits[i] = value
            result.append(frame(limits))
    for i in range(32):
        miner = bytearray(32)
        miner[i] = 1 << (i % 8)
        result.append(frame(miner=bytes(miner)))
    result.append(frame(miner=bytes(32)))
    for i in range(3):
        for value in (0, 255):
            identities = list(IDENTITIES)
            identities[i] = bytes([value]) * 32
            result.append(frame(identities=identities))
    result += [frame(v) for v in ((16, 2, 16, 15, 2), (15, 2, 16, 14, 2), (16, 2, 16, 16, 2))]
    rng = random.Random(0x9FED4430)
    for _ in range(80):
        records = rng.randrange(1, 257)
        result.append(frame((records, rng.randrange(1, 524289), rng.randrange(1, min(records, 16) + 1),
                             rng.randrange(records), rng.randrange(1, 4097)),
                            rng.randbytes(32), tuple(rng.randbytes(32) for _ in range(3))))
    return result


class M05LocalPoolPolicy(unittest.TestCase):
    def test_standalone_original_policy_and_native_rollback(self):
        abi = json.loads(ABI.read_bytes())
        self.assertEqual(abi["export"], "f0(readbuf,mutbuf,mutbuf)->u32")
        self.assertEqual(abi["magic"], "LPV1")
        self.assertEqual(abi["input_identities"], ["network", "parameters", "genesis", "preview_miner"])
        self.assertEqual(abi["input_identity_bytes"], 32)
        self.assertEqual(abi["input_u64le"], list(FIELDS))
        self.assertEqual(abi["input_bytes"], 172)
        self.assertEqual(abi["hash_domain"], DOMAIN.decode())
        self.assertEqual(abi["output"], ["context_sha256_32", "compact_rust_struct_json"])
        self.assertEqual(abi["refusals"], {"frame": 1, "capacity": 2, "policy": 3, "hash_internal": 4})
        self.assertIs(abi["node_integration_complete"], False)
        self.assertIs(abi["persistent_authority"], False)
        self.assertEqual(abi["minimum_output_bytes"], 282)
        self.assertEqual(abi["minimum_scratch_bytes"], 1664)
        self.assertEqual(abi["maximum_scratch_write_end"], 1609)

        inputs = cases()
        outcomes = [expected(request) for request in inputs]
        self.assertEqual((len(inputs), sum(bool(reply) for _, reply in outcomes)), (164, 142))
        want = b"".join(struct.pack("<H", status) + reply for status, reply in outcomes)
        self.assertEqual(run_original(inputs), want)
        batch = [(request, 301, 1711, *result) for request, result in zip(inputs, outcomes)]
        seed = inputs[0]
        batch += [(seed[:n], 282, 1664, 1, b"") for n in range(len(seed))]
        batch += [(seed + b"X" * n, 282, 1664, 1, b"") for n in (1, 2, 16, 128)]
        batch += [(b"LPV2" + seed[4:], 282, 1664, 1, b""), (bytes(len(seed)), 0, 0, 1, b"")]
        batch += [(seed, out, work, 2, b"") for out, work in
                  ((0, 1664), (281, 1664), (282, 0), (282, 1663), (281, 1663))]
        batch += [(request, 282, 1664, *expected(request)) for request in (inputs[2], inputs[1])]
        self.assertEqual(len(batch), 349)

        hashes = set()
        for backend in ("direct", "selfhost"):
            with NativeModule(POLICY, byte_exports=("f0",), backend=backend) as native:
                hashes.add(native.artifact_sha256)
                for start in range(0, len(batch), 32):
                    group = batch[start:start + 32]
                    requests = [("f0", [request, b"\x95" * out, b"\xa6" * work])
                                for request, out, work, _, _ in group]
                    got = native.call_many(requests, timeout=60)
                    for index, (observed, item) in enumerate(zip(got, group, strict=True)):
                        with self.subTest(backend=backend, row=start + index):
                            request, out, work, status, prefix = item
                            observed.require_returned()
                            self.assertEqual(observed.value, status)
                            self.assertEqual(observed.arguments[0], request)
                            self.assertEqual(observed.arguments[1], prefix + b"\x95" * (out - len(prefix)))
                            tail = abi["maximum_scratch_write_end"] - 250 + len(prefix) - 32 if prefix else 0
                            self.assertEqual(observed.arguments[2][tail:], b"\xa6" * (work - tail))
                previous, scratch = b"\x95" * 301, b"\xa6" * 1711
                for request in (inputs[2], frame((0, *DEFAULT[1:])), inputs[1], frame(miner=bytes(32)), seed):
                    status, prefix = expected(request)
                    observed = native.call("f0", [request, previous, scratch]).require_returned()
                    self.assertEqual(observed.value, status)
                    self.assertEqual(observed.arguments[0], request)
                    self.assertEqual(observed.arguments[1], prefix + previous[len(prefix):])
                    if not prefix:
                        self.assertEqual(observed.arguments[2], scratch)
                    previous, scratch = observed.arguments[1:]
        self.assertEqual(len(hashes), 2)
