"""Original and native final-file/sidecar gate against owned disposable paths."""
from contextlib import ExitStack
import ctypes
import json
import os
import struct
from pathlib import Path
import sys
import tempfile
import unittest

if __name__ == "__main__":
    # The private child is deliberately launched with -I -S -B.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hia.platform.service_settlement.schema_fixture_host import native_post_open_path, native_store_header
from hia.platform.state_import_sqlite.qualification_host import bind, sealed_library
from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute, original_adapter

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementStorePathPreflightTests(unittest.TestCase):
    def test_actual_lstat_matches_original_before_sqlite(self):
        with ExitStack() as stack:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-native-lstat-")))
            original, source = original_adapter(tmp)
            provider = ProviderBuild(source, tmp / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            images = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                      for name, path in {
                          "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                          "reader": OWNER / "schema_read.hepta",
                          "path_gate": OWNER / "store_path_preflight.hepta",
                          "header_reader": OWNER / "store_header_read.hepta",
                          "post_open_path": OWNER / "store_post_open_path.hepta",
                          "open_lifecycle": OWNER / "store_open_lifecycle.hepta",
                      }.items()}
            owned = tmp / "owned"
            owned.mkdir(mode=0o700)
            db = owned / "actual native path #%?🧪.db"
            execute([original, "seed", db])
            prior = db.read_bytes()

            def observed(path, *, hold=False, header=False, post_open=False, lifecycle=False):
                selected = {"uri", "reader"}
                selected.add("open_lifecycle" if lifecycle else "path_gate")
                if header:
                    selected.add("header_reader")
                if post_open:
                    selected.add("post_open_path")
                request = {name: [str(images[name].library), images[name].artifact_sha256] for name in selected}
                request.update(database=str(path), directory=str(owned),
                               provider=[str(provider), proof.checked[str(provider)]["sha256"]],
                               writer=str(original) if hold else None)
                outcome = execute([sys.executable, "-I", "-S", "-B", OWNER/"schema_fixture_host.py"],
                                  input=json.dumps(request).encode(), timeout=45)
                self.assertEqual(outcome.stderr, b"")
                return json.loads(outcome.stdout)

            def original_result(path):
                result = execute([original, "verify", path])
                self.assertEqual(result.stderr, b"")
                return result.stdout.strip()

            def refusals(path, code, examined):
                actual = observed(path, header=True, post_open=True)
                self.assertNotIn("header_checks", actual)
                self.assertNotIn("post_open_checks", actual)
                self.assertEqual((actual["status"], actual["held"], actual["released"], actual["transcript"]),
                                 (code, False, 0, []), actual)
                self.assertEqual(actual["path_checks"], [[i, 15, 24] for i in range(1, examined+1)])
                composed = observed(path, lifecycle=True)
                self.assertEqual(composed, {"status": code, "transcript": [], "held": False, "released": 0,
                                            "open_lifecycle": [[1, 15, 24]] * examined})

            self.assertEqual(original_result(db), b"VALID")
            def observe_descriptors(mode, paths, cases=(), expected_header=b""):
                request = {
                    "mode": mode,
                    "database": str(db),
                    "provider": [str(provider), proof.checked[str(provider)]["sha256"]],
                    "images": [[str(image.library), image.artifact_sha256] for image in paths],
                    "cases": [str(case) for case in cases],
                    "expected_header": expected_header.hex(),
                }
                outcome = execute(
                    [sys.executable, "-I", "-S", "-B", __file__, "--descriptor-observer"],
                    input=json.dumps(request).encode(), timeout=45,
                )
                self.assertEqual(outcome.stderr, b"")
                self.assertEqual(outcome.stdout, b"")

            # Keep the direct checks out of the long-lived General test host.
            # The dynamic loader keys the sealed memfd by its procfs pathname;
            # retaining simultaneous descriptors does not isolate earlier tests.
            observe_descriptors("header", [images["header_reader"]], expected_header=prior[:20])
            native = observed(db, hold=True, header=True)
            self.assertEqual(native, {**observed(db, hold=True), "header_checks": [[17, 24], [29, 44], [18, 24]]})
            self.assertEqual((native["status"], native["held"], native["released"]),
                             (0, True, 0), native)
            self.assertEqual(native["path_checks"], [[i, 15, 24] for i in range(1, 5)])
            self.assertEqual(native["transcript"][0], [1, 2, 24])
            self.assertEqual(native["transcript"][-1], [15, 3, 24])
            post = observed(db, hold=True, header=True, post_open=True)
            self.assertEqual(native["transcript"][1][:2], [2, 4])  # original sqlite3_busy_timeout
            self.assertEqual(post, {**native, "post_open_checks": [[15, 24]],
                                    "transcript": [native["transcript"][0], [1, 15, 24], *native["transcript"][1:]]})

            for stage, suffix in enumerate(("-wal", "-shm", "-journal"), 2):
                with self.subTest(suffix=suffix):
                    entry = db.with_name(db.name+suffix)
                    entry.write_bytes(b"owned fixture sidecar, not SQLite data")
                    self.assertEqual(original_result(db), b"SidecarPresent")
                    refusals(db, 101, stage)
                    self.assertEqual(entry.read_bytes(), b"owned fixture sidecar, not SQLite data")
                    entry.unlink()
            missing = owned/"missing.db"
            not_file = owned/"ordinary directory.db"
            not_file.mkdir()
            for case in (missing, not_file):
                self.assertEqual(original_result(case), b"StoreFailure")
                refusals(case, 100, 1)
            direct_image = stack.enter_context(NativeModule(
                OWNER / "store_post_open_path.hepta", byte_exports=("f0",), backend="direct"))
            observe_descriptors("post-open", [images["post_open_path"], direct_image], (missing, not_file))
            for width in (0, 1, 19):
                with self.subTest(short=width):
                    short = owned / f"short-{width}.db"
                    short.write_bytes(prior[:width])
                    self.assertEqual(original_result(short), b"StoreFailure")
                    actual = observed(short, header=True)
                    self.assertEqual((actual["status"], actual["transcript"], actual["released"]), (100, [], 0))
                    reads = [[29, 24 + width]] if width else []
                    self.assertEqual(actual["header_checks"], [[17, 24], *reads, [29, 24], [18, 24]])
                    composed = observed(short, lifecycle=True)
                    self.assertEqual(composed, {"status": 100, "transcript": [], "held": False, "released": 0,
                                                "open_lifecycle": [[1, 15, 24]] * 4
                                                + [[3, op, amount] for op, amount in actual["header_checks"]]})
                    self.assertEqual(short.read_bytes(), prior[:width])
                    short.unlink()
            wal = owned / "actual closed WAL.db"
            execute([original, "seed-wal", wal])
            wal_bytes = wal.read_bytes()
            self.assertEqual(wal_bytes[18:20], b"\x02\x02")
            self.assertEqual(original_result(wal), b"SchemaMismatch")
            actual = observed(wal, header=True)
            self.assertEqual((actual["status"], actual["transcript"], actual["released"]), (100, [], 0))
            self.assertEqual(actual["header_checks"], [[17, 24], [29, 44], [18, 24]])
            composed = observed(wal, lifecycle=True)
            self.assertEqual(composed, {"status": 100, "transcript": [], "held": False, "released": 0,
                                        "open_lifecycle": [[1, 15, 24]] * 4
                                        + [[3, op, amount] for op, amount in actual["header_checks"]]})
            self.assertEqual(wal.read_bytes(), wal_bytes)
            wal.unlink()
            self.assertEqual(db.read_bytes(), prior)
            self.assertEqual(sorted(p.name for p in owned.iterdir()), [db.name, not_file.name])


def descriptor_observer(request):
    checks = unittest.TestCase()
    db = Path(request["database"])
    with ExitStack() as stack:
        images = [stack.enter_context(sealed_library(*image)) for image in request["images"]]
        lib = stack.enter_context(sealed_library(*request["provider"]))
        if request["mode"] == "header":
            [header_image] = images
            actual_header, header_trace = native_store_header(os.fsencode(db), header_image, lib)
            # Transfer all 20 bytes, not merely the format bytes the HIA reader uses.
            checks.assertEqual(actual_header, bytes.fromhex(request["expected_header"]))
            checks.assertEqual(header_trace, [[17, 24], [29, 44], [18, 24]])
            return
        if request["mode"] != "post-open":
            raise ValueError("Unknown private descriptor observation")
        post_gate, direct_gate = images
        cases = [Path(case) for case in request["cases"]]
        # Isolated refusal cleanup: use a separate real read-only SQLite handle
        # and observe two independent static paths. The end-to-end fixture
        # always passes its own original database path. No pathname changes.
        ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
        fetch = bind(lib, "trnm_task_provider", u64, ptr, u64, ptr, u64, ptr, u64)
        make = bind(lib, "trnm_task_provider_new", ptr)
        reset = bind(lib, "trnm_task_provider_reset", u64, ptr)
        free = bind(lib, "trnm_task_provider_free", None, ptr)
        uri = (db.as_uri() + "?mode=ro").encode("ascii")
        opening = ctypes.create_string_buffer(struct.pack("<QQ", 16810049, len(uri)) + uri)
        for backend, post_close_gate in (("selfhost", post_gate), ("direct", direct_gate)):
            for case in cases:
                with checks.subTest(close_after_refused_path=case.name, backend=backend):
                    owner = make()
                    checks.assertTrue(owner)
                    try:
                        response = ctypes.create_string_buffer(24)
                        checks.assertEqual(fetch(owner, 2, opening, len(opening) - 1, response, 24), 24)
                        checks.assertEqual(native_post_open_path(os.fsencode(case), post_close_gate, fetch, owner, response.raw),
                                         (100, [[15, 24], [3, 24]]))
                        checks.assertEqual(reset(owner), 0)
                    finally:
                        free(owner)


if __name__ == "__main__":
    if sys.argv[1:] != ["--descriptor-observer"]:
        raise SystemExit("Expected the private descriptor observer role")
    descriptor_observer(json.load(sys.stdin))
