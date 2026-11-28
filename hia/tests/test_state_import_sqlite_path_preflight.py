"""Original private existing-path policy vs actual HIA-owned lstat sequence."""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, _build_original, _run
from hia.tests.test_state_import_sqlite_cold_read import OWNER, ROOT

ADAPTER = ROOT / "hia/tests/rust_state_import_sqlite_path_reference.rs"


def unchanged_original(raw):
    start = raw.index(b"fn validate_existing_store_path_v0(")
    end = raw.index(b"fn read_rows_from_connection_v0(", start)
    return (b"use std::{fs, path::{Path, PathBuf}};\n"
            b"use trnm_state_import::DurableDeltaStoreErrorV0;\n" + raw[start:end])


class StateImportSqlitePathPreflight(unittest.TestCase):
    def test_original_lexical_policy_and_real_lstat_transcript(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-path-") as tmp, NativeModule(
            OWNER / "path_preflight.hepta", byte_exports=("f0",), backend="selfhost"
        ) as native:
            directory = Path(tmp).resolve()
            # The actual stock locked crate also seeds a genuine disposable DB.
            seed, dependency = _build_original(directory)
            cold = seed.rename(directory / "original-seed")
            original = directory / "original-path.rs"
            original.write_bytes(unchanged_original((CRATE / "src/lib.rs").read_bytes()) + ADAPTER.read_bytes())
            oracle, _ = _build_original(directory, original)
            provider = ProviderBuild(dependency, directory / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            digest = proof.checked[str(provider)]["sha256"]
            owned = directory / "owned"
            owned.mkdir(mode=0o700)
            deeper = owned / "inner" / "child"
            deeper.mkdir(parents=True)
            db = deeper / "seed.db"
            _run([cold, "seed", db, "1"])

            def verify(path, expected, inspected=None):
                before = subprocess.run([oracle, path], capture_output=True, timeout=10)
                self.assertEqual(before.returncode, expected, before.stderr)
                request = {
                    "path_preflight": True, "reader": [str(native.library), native.artifact_sha256],
                    "provider": [str(provider), digest], "directory": str(owned), "database": str(path),
                }
                actual = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(request), text=True, capture_output=True, timeout=20,
                )
                self.assertEqual((actual.returncode, actual.stderr), (0, ""))
                report = json.loads(actual.stdout)
                self.assertEqual((report["status"], report["released"]), (expected, 0))
                if inspected is not None:
                    self.assertEqual([bytes.fromhex(item[1]) for item in report["observations"]],
                                     [os.fsencode(p) for p in inspected])
                for phase, wire, errno, mode in report["observations"]:
                    item = os.fsdecode(bytes.fromhex(wire))
                    try:
                        expected_type = stat.S_IFMT(os.lstat(item).st_mode)
                    except OSError as error:
                        self.assertEqual(errno, error.errno)
                    else:
                        self.assertEqual((errno, stat.S_IFMT(mode)), (0, expected_type))
                return report

            suffixes = [Path(str(db) + suffix) for suffix in ("-wal", "-shm", "-journal")]
            full = [db, *db.parents, *suffixes]
            initial = db.read_bytes()
            verify(db, 0, full)
            verify(deeper / "missing", 100, [deeper / "missing"])
            verify(deeper, 100, [deeper])
            alias = owned / "alias.db"
            alias.symlink_to(db)
            verify(alias, 100, [alias])
            alias_parent = owned / "link-parent"
            alias_parent.symlink_to(deeper.parent, target_is_directory=True)
            linked = alias_parent / deeper.name / db.name
            verify(linked, 100, [linked, linked.parent, alias_parent])
            fifo = owned / "fifo"
            os.mkfifo(fifo, 0o600)
            verify(fifo, 100, [fifo])
            regular_non_utf8 = os.fsdecode(os.fsencode(deeper) + b"/bytes-" + bytes((255,)))
            Path(regular_non_utf8).write_bytes(b"owned non-UTF8 stat fixture")
            verify(Path(regular_non_utf8), 0)

            # Original filesystem preflight permits non-symlink sidecars
            # without pretending they are a coherent SQLite journal.
            suffixes[0].write_bytes(b"owned harmless sidecar fixture")
            suffixes[1].mkdir()
            verify(db, 0, full)
            suffixes[0].unlink()
            suffixes[1].rmdir()
            target = owned / "sidecar-target"
            target.write_bytes(b"owned symlink target")
            for i, link in enumerate(suffixes):
                with self.subTest(suffix=link.suffix, index=i):
                    link.symlink_to(target if i != 2 else owned / "missing-target")
                    verify(db, 100, [db, *db.parents, *suffixes[:i+1]])
                    self.assertTrue(link.is_symlink())
                    link.unlink()
            self.assertEqual(db.read_bytes(), initial)

            long_basename = deeper / ("x" * os.pathconf(deeper, "PC_NAME_MAX"))
            long_basename.write_bytes(b"owned maximum-basename fixture")
            observed = verify(long_basename, 0)
            self.assertEqual([e[2] for e in observed["observations"][-3:]], [errno.ENAMETOOLONG] * 3)

            # Raw lexical refusals have no syscall/response phase.
            for bad in (b"", b"/", b"a", b"/bad/../file", b"/a//b", b"/a/./b",
                        b"/a/b/", b"/a/" + bytes((0,)), b"/" + b"a" * 512):
                packet = [bad, bytes(8192), bytes(1)]
                got = native.call("f0", packet).require_returned()
                self.assertEqual((got.value, got.arguments), (100, packet))
