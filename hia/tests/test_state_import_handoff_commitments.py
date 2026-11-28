"""Actual original checkpoint transfer fingerprints versus two native backends."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import CRATE, _build_original, _run
from hia.tests.test_state_import_sqlite_handoff_read import retained_fixture

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/src/state_import/handoff_commitments.hepta"
REFERENCE = ROOT / "hia/tests/rust_state_import_handoff_commitments_reference.rs"
SOURCE = (b"trnm.migration.finalized-source-binding.v0", (32,32,8,32,32,32,32,32,32,8))
PROJECTION = (b"trnm.migration.projection.v0", (32,32,32,8,32,32,32))


def independent(body, shape):
    domain, widths = shape
    parts, offset = [domain], 0
    for width in widths:
        parts.append(body[offset:offset + width])
        offset += width
    assert len(body) == offset
    return hashlib.sha256(b"".join(len(p).to_bytes(8, "big") + p for p in parts)).digest()


def flip(body, at):
    return body[:at] + bytes([body[at] ^ 1]) + body[at+1:]


class StateImportHandoffCommitments(unittest.TestCase):
    def test_original_source_and_projection_commitments(self):
        source = CRATE / "src/lib.rs"
        before = hashlib.sha256(source.read_bytes()).digest()
        with tempfile.TemporaryDirectory(prefix="trnm-m13-handoff-commitments-") as tmp:
            path = Path(tmp)
            adapter = path / "handoff-commitments.rs"
            adapter.write_bytes(retained_fixture(source.read_bytes()) + REFERENCE.read_bytes())
            original, _ = _build_original(path, adapter, ("sha2",))
            raw = _run([original]).stdout
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), before)
        self.assertEqual(len(raw), 536 * 4 + 16)
        records = [raw[i:i+536] for i in range(0, 536*4, 536)]
        binding, projection = [(r[:272], r[272:304]) for r in records], [(r[304:504], r[504:536]) for r in records]
        self.assertEqual([int.from_bytes(b[264:272],"big") for b, _ in binding], [1,2,3,17])
        self.assertEqual([int.from_bytes(b[96:104],"big") for b, _ in projection], [1,2,3,17])
        exact = []
        for (src, src_hash), (pro, pro_hash) in zip(binding, projection, strict=True):
            self.assertEqual(src_hash, independent(src,SOURCE))
            self.assertEqual(pro_hash, independent(pro,PROJECTION))
            exact.extend(((src, 0, src_hash), (pro, 0, pro_hash)))
        for i, (claimed, digest) in enumerate(binding):
            for j, (actual, _) in enumerate(binding):
                status = raw[536*4 + i*4 + j]
                self.assertEqual(status, 0 if i == j else 101)
                exact.append((claimed + digest + actual, status, digest))
        b, digest = binding[0]
        exact.extend(((b + bytes(32) + b, 101, digest), (b + flip(digest,31) + b, 101, digest)))
        for at in (0,32,64,72,104,136,168,200,232,264):
            changed = flip(b,at)
            exact.append((changed + independent(changed,SOURCE) + b, 101, digest))
        for n in (0,199,201,271,273,575,577):
            exact.append((bytes(n), 100, digest))

        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(OWNER, byte_exports=("f0",), backend=backend) as native:
                for at in range(0,len(exact),12):
                    rows = exact[at:at+12]
                    args = [[body, b"\xa5"*39, b"\x6d"*1623] for body, _, _ in rows]
                    calls = native.call_many([("f0", item) for item in args])
                    for (_, status, wanted), item, call in zip(rows,args,calls,strict=True):
                        self.assertEqual(call.require_returned().value,status)
                        self.assertEqual(call.arguments[0],item[0])
                        self.assertEqual(call.arguments[1],item[1] if status else wanted + item[1][32:])
                        self.assertEqual(call.arguments[2][1616:], item[2][1616:])
                for output, work, status in ((32,1616,0),(31,1616,102),(32,1615,102)):
                    reply = native.call("f0",[b, bytes(output), bytes(work)]).require_returned()
                    self.assertEqual((reply.value,reply.arguments[1]),(status,bytes(output) if status else digest))
