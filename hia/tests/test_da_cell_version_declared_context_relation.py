"""Real original TCV1 declared context comparison and pinned native dual."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LIMIT, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/cell_version_declared_context_relation.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_version_declared_context_relation_reference.rs"
WORK = 131232
DOMAIN = b"TRNM/Cell/CompleteVersion/v1\0"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (MANIFEST, LOCK, REFERENCE, *(CRATE / f"src/cell/{name}.rs"
                for name in ("version", "closure", "manifest", "model_root")))
    before = tuple(sha(p.read_bytes()) for p in paths)
    version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True,
                             text=True, timeout=10).stdout
    if not version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("expected original locked Rust 1.95.0")
    built = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                            str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                            "--lib", "--target-dir", str(target), "--message-format=json"],
                           env=env, check=True, capture_output=True, text=True, timeout=180)
    records = [v for v in map(json.loads, built.stdout.splitlines())
               if v.get("reason") == "compiler-artifact"
               and v["target"]["name"] == "trnm_data_availability" and v["target"]["kind"] == ["lib"]]
    if len(records) != 1 or records[0]["features"] != ["default"]:
        raise ValueError("expected one actual unchanged original default-feature DA library")
    library, = (Path(x) for x in records[0]["filenames"] if x.endswith(".rlib"))
    library_sha = sha(library.read_bytes())
    executable = directory / "original-version-declared-context"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(executable)],
                   env=env, check=True, capture_output=True, timeout=35)
    observed = subprocess.run([str(executable)], env=env, check=True, capture_output=True, timeout=45)
    if (not observed.stdout or observed.stderr or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original version context evidence")
    rows = []
    cursor = 0
    while cursor < len(observed.stdout):
        length = struct.unpack_from("<I", observed.stdout, cursor)[0]
        pos, end = cursor+4, cursor+4+length
        if not (600 <= length <= LIMIT and end < len(observed.stdout)):
            raise ValueError("invalid original version fixture extent")
        rows.append((observed.stdout[pos:end], observed.stdout[end]))
        cursor = end+1
    print(json.dumps({"original_inputs": dict(zip([p.name for p in paths], before, strict=True)),
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(executable.read_bytes()),
                      "oracle_stdout_sha256": sha(observed.stdout), "oracle_rows": len(rows)},
                     sort_keys=True), flush=True)
    return rows


def replace(raw, at, value):
    return raw[:at] + value + raw[at+len(value):]


class CellVersionDeclaredContextRelation(unittest.TestCase):
    def test_extent_adapter_does_not_change_canonical_validation_cfg(self):
        existing = SOURCE.with_name("cell_version_commitment.hepta").read_text()
        prior = "fn tcv_validate_for_commitment(" + existing.split("\nfn tcv_validate_for_commitment(", 1)[1]
        current = "fn tv_validate_prefix(" + SOURCE.read_text().split("\nfn tv_validate_prefix(", 1)[1]
        self.assertEqual(current.replace("tv_validate_prefix", "tcv_validate_for_commitment", 1)
                         .replace("b1_w:mutbuf,b1_n:u64)", "b1_w:mutbuf)", 2)
                         .replace('block entry(b1_i:readbuf,b1_w:mutbuf)\n',
                                  'block entry(b1_i:readbuf,b1_w:mutbuf)\n'
                                  '  b1_n_size:usize = buffer.len(b1_i)\n'
                                  '  b1_n:u64 = int.cast(b1_n_size) {"mode":"wrap"}\n', 1), prior)
        # The two synthetically framed TCD1 adapters must preserve old non-publishing
        # expected-role and payload checks byte-for-byte (unchanged published blocks).
        old_td = SOURCE.with_name("cell_closure_declared_context_relation.hepta").read_text()
        start = "block identity("
        end = "\nfn tv_validate_prefix"
        new_td = "block identity(" + SOURCE.read_text().split(start, 1)[1].split(end, 1)[0].rstrip() + "\n"
        self.assertEqual(new_td, start + old_td.split(start, 1)[1])

    def test_actual_locked_original_version_declared_context_both_stock(self):
        with tempfile.TemporaryDirectory(prefix="trnm-version-context-locked-") as tmp:
            rows = original_rows(Path(tmp))
        self.assertEqual(set(s for _,s in rows), set(range(60,67)) | {0})
        sample = rows[0][0]
        end = int.from_bytes(sample[-4:], "big")
        self.assertEqual(hashlib.sha512(DOMAIN + sample[:end]).digest(), sample[end:end+64])
        model = end + 68
        invalid = (
            (b"",100), (sample[:-1],100), (replace(sample,len(sample)-4,b"\xff"*4),100),
            (replace(sample,0,b"BAD!"),104),
            (replace(sample,end+64,b"\xff"*4),100),
            (replace(sample,model,b"BAD!"),100),
            (replace(sample,model+96,b"\xff"*2),100),
        )
        out,work=b"O"*13,b"W"*(WORK+7)
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),8):
                    sub = rows[at:at+8]
                    got = module.call_many([("f0",[raw,out,work]) for raw,_ in sub], timeout=45)
                    for (raw,status), result in zip(sub,got,strict=True):
                        self.assertEqual((result.status,result.value),("returned",status),(at,len(raw)))
                        self.assertTrue(result.arguments[0]==raw, "immutable input changed")
                        self.assertEqual(result.arguments[1],out)
                        self.assertEqual(result.arguments[2][WORK:],work[WORK:])
                for raw,status in invalid:
                    result = module.call("f0",[raw,out,work])
                    self.assertEqual((result.status,result.value),("returned",status))
                    self.assertEqual(result.arguments[:2],[raw,out])
                    self.assertEqual(result.arguments[2][WORK:],work[WORK:])
                short=module.call("f0",[sample,out,work[:WORK-1]])
                self.assertEqual((short.status,short.value),("returned",102))
                self.assertEqual(short.arguments,[sample,out,work[:WORK-1]])
                exact=module.call("f0",[sample,b"",work[:WORK]])
                self.assertEqual((exact.status,exact.value),("returned",0))
                print(json.dumps({"backend":backend,"native_elf_sha256":module.artifact_sha256,
                                  "original_rows":len(rows),"abi_controls":len(invalid)+2,
                                  "original_status_counts":dict(Counter(s for _,s in rows))},
                                 sort_keys=True),flush=True)
