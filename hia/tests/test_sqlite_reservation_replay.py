"""Native finite SQLite growth reservation vs the exact original Rust ledger."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.locked_cargo_target import locked_cargo_build
from hia.tests.test_settlement_schema_read import execute

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "trillionnium/crates/trnm-sqlite-io-boundary"
LEDGER = CRATE / "src/ledger.rs"
LIB = CRATE / "src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_sqlite_reservation_replay_reference.rs"
KERNEL = ROOT / "hia/src/sqlite_io_boundary/reservation_replay.hepta"
BOUND = 16 * 1024 * 1024
Q = 64 * 1024


def original_adapter(owned, adapter=ADAPTER):
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if execute([rustc, "--version"]).stdout.decode().split()[1] != pin:
        raise ValueError("Exact Rust pin required")
    exact = LEDGER.read_bytes()
    if hashlib.sha256(exact).hexdigest() != "ccfd0dd5fbc5f18067da5450d94cfca70bfef51be43632856668c4981761afe7":
        raise ValueError("Original reservation ledger source differs")
    lib = LIB.read_bytes()
    constants = []
    for name in (b"DOMAIN", b"RESERVATION_DOMAIN_V2", b"GROWTH_QUANTUM_BYTES_V2", b"OBJECTS_PER_ROOT", b"FILE_BYTES"):
        [declaration] = re.findall(rb"^pub const " + name + rb": [^\n]+;\n", lib, re.M)
        constants.append(declaration)
    reference = owned / "original-ledger-reference.rs"
    reference.write_bytes(b"#![allow(dead_code)]\n" + b"".join(constants) + adapter.read_bytes())
    target, events = locked_cargo_build(ROOT, rustc=rustc, cargo=cargo,
                                        package="trnm-sqlite-io-boundary", execute=execute)
    [crate] = [e for e in events if e.get("reason") == "compiler-artifact" and
               e["target"]["name"] == "trnm_sqlite_io_boundary"]
    if Path(crate["target"]["src_path"]) != LIB or Path(crate["manifest_path"]) != CRATE / "Cargo.toml":
        raise ValueError("Unexpected original crate binding")
    externs = []
    for package in ("rusqlite", "serde", "serde_json"):
        [event] = [e for e in events if e.get("reason") == "compiler-artifact" and
                   e["target"]["name"] == package and f"{package}@" in e["package_id"]]
        [rlib] = [p for p in event["filenames"] if p.endswith(".rlib")]
        externs += ["--extern", f"{package}={rlib}"]
    [origin_sqlite] = [e for e in events if e.get("reason") == "build-script-executed"
                       and e["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [path] = origin_sqlite["linked_paths"]
    if origin_sqlite["linked_libs"] != ["static=sqlite3"] or not path.startswith("native="):
        raise ValueError("Original reservation ledger requires the locked SQLite")
    binary = owned / "original-ledger"
    execute([rustc, "--edition=2024", "-O", *externs, "-L", f"dependency={target/'debug/deps'}",
             "-L", path, reference, "-o", binary], timeout=60,
            env={**os.environ, "TRNM_M15_LEDGER_ORIGINAL": str(LEDGER)})
    return binary


class SqliteReservationReplayTests(unittest.TestCase):
    def test_original_bound_slot_reservation_replay(self):
        maximum = (1 << 64) - 1
        scenarios = (
            (0, (0, 1, 1, 4096, 4095, Q-1, Q, Q+1, BOUND-1, BOUND, BOUND+1, maximum, 0)),
            (1, (0, 1, Q-1, Q, Q+1, 2*Q, 1, BOUND-1, BOUND, BOUND+1, maximum, 0)),
            (1, tuple(range(4096, BOUND+1, 4096)) + (BOUND+1, 0)),
            (2, (BOUND, BOUND+1, 0)),
            (2, (BOUND+1, 0)),
        )
        raw = b"".join(bytes([mode]) + struct.pack("<Q", len(endpoints)) +
                       b"".join(struct.pack("<Q", e) for e in endpoints) for mode, endpoints in scenarios)
        with tempfile.TemporaryDirectory(prefix="trnm-m15-reservation-") as directory:
            original = original_adapter(Path(directory))
            observed = execute([original], input=raw).stdout
        count = sum(len(extents) for _, extents in scenarios)
        self.assertEqual(len(observed), count*120)
        records = list(struct.iter_unpack("<15Q", observed))
        self.assertEqual([row[7] for row in records[-5:]], [0,13,10,13,10])
        self.assertEqual((records[-5][2], records[-5][9], records[-4][12], records[-2][12]), (1016,1017,1,2))
        self.assertEqual(sum(row[13] == 3 for row in records[25:25+4096]), 256)
        self.assertTrue(any(row[13] == 1 for row in records))
        self.assertTrue(all(row[8] <= BOUND for row in records))
        per_backend = {}
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(KERNEL, byte_exports=("f0",), backend=backend) as native:
                statuses = []
                # Batch kept deliberately below normal disposable worker limits.
                for start in range(0, len(records), 192):
                    group = records[start:start+192]
                    args = [[struct.pack("<7Q", *row[:7]), b"\xa5"*65, b"\x4c"*8] for row in group]
                    replies = native.call_many([("f0", a) for a in args], timeout=35)
                    for row, a, answer in zip(group, args, replies, strict=True):
                        self.assertEqual(answer.require_returned().value, row[7])
                        statuses.append(row[7])
                        self.assertEqual(answer.arguments, [a[0], struct.pack("<7Q", *row[8:])+a[1][56:], a[2]])
                per_backend[backend] = len(statuses)
                for defective, out_n, status in [
                    (bytes(55),56,100), (bytes(57),56,100), (bytes(56),55,102),
                    (struct.pack("<7Q", 2,0,0,0,0,0,0),56,100),
                    (struct.pack("<7Q", 1,1,0,0,0,0,0),56,100),
                    (struct.pack("<7Q", 0,BOUND+1,0,0,0,0,0),56,100),
                    (struct.pack("<7Q", 0,0,1025,0,0,0,0),56,100),
                    (struct.pack("<7Q", 0,0,0,0,0,3,0),56,100),
                ]:
                    args = [defective, b"\x33"*out_n, bytes(6)]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (status, args))
        self.assertEqual(per_backend, {"direct": count, "selfhost": count})
