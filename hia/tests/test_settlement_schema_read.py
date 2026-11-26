"""Original/native M12 schema gate on disposable SQLite rollback snapshots."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule, unlinked_path

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"
STORE = ROOT / "trillionnium/crates/trnm-service-settlement"


def execute(argv, *, timeout=30, **kwargs):
    answer = subprocess.run(argv, capture_output=True, timeout=timeout, **kwargs)
    if answer.returncode:
        raise ValueError(answer.stderr.decode(errors="replace"))
    return answer


def original_adapter(out, *, metadata=False, operation=False, marker=False):
    source = (STORE / "src/store.rs").read_bytes()
    pieces = []
    for name in (b"META_SQL", b"OP_SQL", b"COMMITTED_BLOCKS_SQL"):
        [piece] = re.findall(rb"^const " + name + rb': &str = ".*";\n', source, re.M)
        pieces.append(piece)
    for name in (b"open_read_snapshot", b"read_only_store_uri", b"reject_sidecars",
                 b"require_existing_regular_store", b"verify_schema"):
        [piece] = re.findall(rb"(?ms)^fn " + name + rb"\(.*?^\}\n", source)
        pieces.append(piece)
    raw = b"\n".join(pieces)
    if hashlib.sha256(raw).hexdigest() != "44c38e08d2865eeba458315a4ad462af475582a073ed04519a1759fb1fc6b388":
        raise ValueError("Original Settlement schema/open source differs")
    section = out / "original.rs"
    section.write_bytes(raw)
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if execute([rustc, "--version"]).stdout.decode().split()[1] != pin:
        raise ValueError("Original Settlement schema requires the pinned Rust toolchain")
    target = out / "target"
    build = execute([cargo, "build", "--locked", "--offline", "--manifest-path",
                     str(ROOT / "trillionnium/Cargo.toml"), "--target-dir", str(target),
                     "-p", "trnm-service-settlement", "--message-format=json"],
                    timeout=160, env={**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2"})
    events = [json.loads(row) for row in build.stdout.splitlines()]
    [settlement] = [e for e in events if e.get("reason") == "compiler-artifact"
                    and e["target"]["name"] == "trnm_service_settlement"]
    if Path(settlement["target"]["src_path"]) != STORE / "src/lib.rs" or settlement["features"] != ["default"]:
        raise ValueError("Expected exact original Settlement source and profile")
    [rusqlite] = [e for e in events if e.get("reason") == "compiler-artifact"
                  and e["target"]["name"] == "rusqlite" and e["package_id"].endswith("rusqlite@0.41.1")]
    [rust] = [unlinked_path(p) for p in rusqlite["filenames"] if p.endswith(".rlib")]
    [sqlite] = [e for e in events if e.get("reason") == "build-script-executed"
                and e["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [provider_source] = [e for e in events if e.get("reason") == "compiler-artifact"
                         and e["package_id"] == sqlite["package_id"]
                         and e["target"]["name"] == "libsqlite3_sys"]
    [native] = sqlite["linked_paths"]
    if not native.startswith("native=") or sqlite["linked_libs"] != ["static=sqlite3"]:
        raise ValueError("Original must link the locked bundled SQLite")
    binary = out / "original"
    extra = []
    adapter = "rust_settlement_schema_reference.rs"
    if metadata or operation or marker:
        [owner] = [unlinked_path(p) for p in settlement["filenames"] if p.endswith(".rlib")]
        [borsh_event] = [e for e in events if e.get("reason") == "compiler-artifact"
                         and e["target"]["name"] == "borsh"]
        [borsh] = [unlinked_path(p) for p in borsh_event["filenames"] if p.endswith(".rlib")]
        extra = ["--extern", f"trnm_service_settlement={owner}", "--extern", f"borsh={borsh}"]
        adapter = "rust_settlement_metadata_reference.rs"
    if operation or marker:
        for dependency in ("sha2", "trnm_task_kernel"):
            [event] = [e for e in events if e.get("reason") == "compiler-artifact"
                       and e["target"]["name"] == dependency
                       and (dependency != "sha2" or e["package_id"].endswith("sha2@0.10.9"))]
            [artifact] = [unlinked_path(p) for p in event["filenames"] if p.endswith(".rlib")]
            extra.extend(["--extern", f"{dependency}={artifact}"])
        parts = []
        for name in (b"load_operation", b"operation_checksum", b"from_sqlite"):
            [part] = re.findall(rb"(?ms)^fn " + name + rb"\(.*?^\}\n", source)
            parts.append(part)
        engine = (STORE / "src/engine.rs").read_bytes()
        [identity] = re.findall(rb"(?ms)^pub\(crate\) fn operation_id\(.*?^\}\n", engine)
        parts.append(identity)
        lookup = b"\n".join(parts)
        if hashlib.sha256(lookup).hexdigest() != "396a5426b2ca2ae6c52090eb4e5dcae8f89d85e845a5961054b6dd5f23d8635f":
            raise ValueError("Exact retained M12 operation lookup source differs")
        (out / "operation.rs").write_bytes(lookup)
        adapter = "rust_settlement_operation_reference.rs"
    if marker:
        parts = []
        for name in (b"JOURNAL_SCHEMA_VERSION_V1", b"MAX_OPERATION_ROWS_V1", b"MAX_COMMITTED_BLOCK_ROWS_V1",
                     b"MAX_OPERATION_FIELD_BYTES_V1", b"MAX_OPERATION_JOURNAL_BYTES_V1"):
            [part] = re.findall(rb"(?m)^const " + name + rb": [^\n]*;\n", source)
            parts.append(part)
        [record] = re.findall(rb"(?ms)^struct CommittedBlockMarkerV1 \{.*?^\}\n", source)
        parts.append(record)
        for name in (b"load_committed_block_markers", b"load_committed_block_markers_with_limit",
                     b"committed_block_marker_checksum", b"config_bytes", b"from_sqlite", b"array32",
                     b"metadata_checksum", b"operation_journal_root_through", b"checked_operation_field_len_v1",
                     b"account_operation_bytes_v1", b"to_sqlite", b"operation_checksum"):
            [part] = re.findall(rb"(?ms)^fn " + name + rb"\(.*?^\}\n", source)
            parts.append(part)
        marker_src = b"\n".join(parts)
        if hashlib.sha256(marker_src).hexdigest() != "a481ceb50fd0a575621dd3b11226c558ec65467b52b701432c35cbafcadaa780":
            raise ValueError("Exact retained M12 committed-block marker source differs")
        (out / "markers.rs").write_bytes(marker_src)
        adapter = "rust_settlement_marker_reference.rs"
    execute([rustc, "--edition=2024", "-Dwarnings", "--extern", f"rusqlite={rust}", *extra,
             "-L", f"dependency={rust.parent}", "-L", f"native={native[7:]}",
             Path(__file__).with_name(adapter), "-o", binary],
            timeout=60, env={**os.environ, "TRNM_SETTLEMENT_SCHEMA_SOURCE": str(section),
                             "TRNM_SETTLEMENT_SCHEMA_ERROR": str(STORE / "src/error.rs"),
                             "TRNM_SETTLEMENT_OPERATION_SELECTED": str(out / "operation.rs"),
                             "TRNM_SETTLEMENT_MARKERS_SELECTED": str(out / "markers.rs"),
                             "TRNM_SETTLEMENT_OPERATION_CODEC": str(STORE / "src/codec.rs")})
    return binary, unlinked_path(provider_source["manifest_path"]).parent


class SettlementSchemaReadTests(unittest.TestCase):
    def test_read_only_closed_schema_and_held_rollback_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-schema-") as tmp, NativeModule(
                OWNER / "schema_read.hepta", byte_exports=("f0",), backend="selfhost") as reader, NativeModule(
                ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                byte_exports=("f0",), backend="selfhost") as uri:
            directory = Path(tmp)
            original, dependency = original_adapter(directory)
            provider = ProviderBuild(dependency, directory / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            provider_sha = proof.checked[str(provider)]["sha256"]
            files = directory / "owned"
            files.mkdir(mode=0o700)

            def invoke(db, *, hold=False):
                request = {"uri": [str(uri.library), uri.artifact_sha256],
                           "reader": [str(reader.library), reader.artifact_sha256],
                           "provider": [str(provider), provider_sha], "directory": str(files),
                           "database": str(db), "writer": str(original) if hold else None}
                response = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                   timeout=45, input=json.dumps(request).encode())
                self.assertEqual(response.stderr, b"")
                return json.loads(response.stdout)

            def reference(db):
                result = execute([original, "verify", db])
                self.assertEqual(result.stderr, b"")
                return result.stdout.strip()

            def seed(name):
                db = files / name
                execute([original, "seed", db])
                return db

            db = seed("owned schema ?#+%.db")
            before = db.read_bytes()
            self.assertEqual(reference(db), b"VALID")
            answer = invoke(db, hold=True)
            self.assertEqual((answer["status"], answer["held"], answer["released"]), (0, True, 0), answer)
            self.assertEqual(answer["transcript"][-1], [15, 3, 24])
            self.assertEqual(db.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in files.iterdir()), [db.name])
            for i, sql in enumerate(("CREATE TABLE extra(x)", "DROP TABLE operations",
                                     "ALTER TABLE metadata ADD COLUMN changed INTEGER",
                                     "CREATE TRIGGER insertion AFTER INSERT ON metadata BEGIN SELECT 1; END;")):
                with self.subTest(sql=sql):
                    case = seed(f"drift-{i}.db")
                    edit = sqlite3.connect(case)
                    try:
                        edit.executescript(sql)
                    finally:
                        edit.close()
                    before = case.read_bytes()
                    self.assertEqual(reference(case), b"SchemaMismatch")
                    refused = invoke(case)
                    self.assertEqual((refused["status"], refused["held"]), (100, False), refused)
                    self.assertGreater(refused["released"], 0)
                    self.assertEqual(case.read_bytes(), before)
            wal = seed("wal.db")
            conn = sqlite3.connect(wal)
            try:
                self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            finally:
                conn.close()
            self.assertFalse(wal.with_name("wal.db-wal").exists())
            self.assertEqual(reference(wal), b"SchemaMismatch")
            self.assertEqual(invoke(wal), {"status": 100, "held": False, "released": 0, "transcript": []})
