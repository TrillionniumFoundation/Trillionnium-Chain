"""Native chronology from the unchanged locked Rust owner and real SQLite WAL."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "trillionnium/crates/trnm-sqlite-io-boundary"
ADAPTER = ROOT / "hia/tests/rust_sqlite_real_vfs_receipt_reference.rs"
SOURCE = ROOT / "hia/src/sqlite_io_boundary/real_vfs_receipt_fold.hepta"
PINNED = {
    "ledger": "ccfd0dd5fbc5f18067da5450d94cfca70bfef51be43632856668c4981761afe7",
    "owner": "5ad8201dc6f2caa621656f0836a517b7b3bc90fb269b0ea405ed739468e0f019",
    "sql": "be7f66cf8996f2e5504c1fe11f15bf5884cde66bcd8163cf3f9ad8710ad221f1",
    "vfs": "d891024786e4c37555fce6d5d107b04ddb830dd2452b528e70a000b75f2480b9",
    "unix_abi": "a89db6e79d895d56dba85710671ec07e5d227004a612581ac153dfcebabe0156",
}


def original_owner(owned):
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    pin = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if execute([rustc, "--version"]).stdout.decode().split()[1] != pin:
        raise ValueError("Exact Rust pin required")
    for name, digest in PINNED.items():
        if hashlib.sha256((CRATE/"src"/(name+".rs")).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Original owner source differs: {name}")
    sysroot = Path(execute([rustc, "--print", "sysroot"]).stdout.decode().strip()).resolve(strict=True)
    canonical = sysroot/"bin/rustc"
    cargo = sysroot/"bin/cargo"
    lib = sysroot/"lib"
    if (canonical.resolve(strict=True) != canonical or cargo.resolve(strict=True) != cargo
            or lib.resolve(strict=True) != lib or not lib.is_dir()
            or execute([canonical, "--version"]).stdout != execute([rustc, "--version"]).stdout):
        raise ValueError("Canonical original owner toolchain differs")
    # The original checked SQLite build policy documents this library seed.
    # It verifies Cargo's full loader-directory set and refuses foreign paths.
    inherited = os.environ.get("LD_LIBRARY_PATH")
    if inherited not in (None, "", str(lib)):
        raise ValueError("Unexpected inherited loader path for original owner witness")
    target = owned/"target"
    build = execute([cargo, "build", "--locked", "--offline",
                     "--manifest-path", ROOT/"trillionnium/Cargo.toml",
                     "--target-dir", target, "-p", "trnm-sqlite-io-boundary",
                     "--message-format=json"], timeout=160,
                    env={**os.environ, "RUSTC":str(canonical), "LD_LIBRARY_PATH":str(lib),
                         "CARGO_BUILD_JOBS":"2"})
    events = [json.loads(line) for line in build.stdout.splitlines()]
    names = ("trnm_sqlite_io_boundary", "rusqlite", "serde_json")
    externs = []
    for name in names:
        [entry] = [e for e in events if e.get("reason")=="compiler-artifact" and e["target"]["name"]==name]
        [rlib] = [f for f in entry["filenames"] if f.endswith(".rlib")]
        if name == "trnm_sqlite_io_boundary":
            if Path(entry["target"]["src_path"]) != CRATE/"src/lib.rs" or Path(entry["manifest_path"]) != CRATE/"Cargo.toml":
                raise ValueError("Original native owner crate binding differs")
        externs += ["--extern", f"{name}={rlib}"]
    [sqlite] = [e for e in events if e.get("reason")=="build-script-executed"
                and e["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [link] = sqlite["linked_paths"]
    if sqlite["linked_libs"] != ["static=sqlite3"] or not link.startswith("native="):
        raise ValueError("Exact bundled SQLite required")
    output = owned/"native-owner"
    execute([canonical,"--edition=2024","-O",*externs,"-L",f"dependency={target/'debug/deps'}",
             "-L",link,ADAPTER,"-o",output],timeout=60)
    return output


class SqliteRealVfsReceiptFoldTests(unittest.TestCase):
    def test_original_native_owner_wal_receipt_chronology(self):
        rows = []
        with tempfile.TemporaryDirectory(prefix="trnm-m15-actual-owner-receipts-") as here:
            owned = Path(here)
            actual = original_owner(owned)
            for policy in (1, 2):
                root = owned/f"owner-{policy}"
                root.mkdir(mode=0o700)
                data = execute([actual, root, str(policy)], timeout=30).stdout
                for stage in range(5):
                    kind, phase, extent, ordinary, cleanup, total = struct.unpack_from("<6Q", data)
                    self.assertEqual((kind, phase), (policy, stage))
                    body = data[48:48+extent]
                    used = 48+extent+8*(ordinary+cleanup)
                    self.assertEqual(len(body), extent)
                    widths = struct.unpack(f"<{ordinary+cleanup}Q", data[48+extent:used])
                    self.assertEqual(sum(w//2 for w in widths), total)
                    self.assertEqual(sum(w%2 for w in widths), cleanup)
                    stamp = 14695981039346656037
                    for tag in widths:
                        stamp = ((stamp ^ tag) * 1099511628211) & ((1 << 64)-1)
                    expected = struct.pack("<5Q", ordinary, cleanup, ordinary+cleanup, total, stamp)
                    rows.append((policy, stage, body, expected, widths))
                    data = data[used:]
                self.assertEqual(data, b"")
        for start in (0,5):
            group = rows[start:start+5]
            self.assertEqual(group[0][4], ())
            self.assertTrue(all(len(a[4]) <= len(b[4]) for a,b in zip(group,group[1:])))
            self.assertTrue(any(x%2 for x in group[-1][4]))
            ordered = [x%2 for x in group[-1][4]]
            self.assertIn([1,0], [ordered[i:i+2] for i in range(len(ordered)-1)])

        body = rows[4][2]
        ord_count, clean_count, split = struct.unpack_from("<3Q", body)
        self.assertGreater(ord_count, 3)
        self.assertGreater(clean_count, 2)
        def field(at, val):
            return body[:at] + struct.pack("<Q",val) + body[at+8:]
        first_width, = struct.unpack_from("<Q", body,24)
        second_position = 32+first_width
        malformed = [
            (body[:23],40,100), (body+b"x",40,100), (body[:-1],40,100),
            (field(0,1025),40,100), (field(8,257),40,100),
            (field(0,ord_count-1),40,100), (field(8,clean_count-1),40,100),
            (field(16,23),40,100), (field(16,len(body)+1),40,100),
            (field(16,split-1),40,100), (field(24,103),40,100),
            (field(24,617),40,100), (field(32,11),40,100),
            (field(split+8,1),40,100), (field(40,1),40,100),
            (field(second_position+16,0),40,100), (body,39,102),
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                args = [[raw,b"\x4e"*47,b"\x77"*9] for _,_,raw,_,_ in rows]
                for a, (_,_,_,expected,_), result in zip(args,rows,n.call_many([("f0",t) for t in args]),strict=True):
                    self.assertEqual((result.require_returned().value,result.arguments),
                                     (0,[a[0],expected+a[1][40:],a[2]]))
                args = [[raw,b"\xa6"*size,b"\x71"*11] for raw,size,_ in malformed]
                for a, (_,_,status), result in zip(args,malformed,n.call_many([("f0",t) for t in args]),strict=True):
                    self.assertEqual((result.require_returned().value,result.arguments),(status,a))
