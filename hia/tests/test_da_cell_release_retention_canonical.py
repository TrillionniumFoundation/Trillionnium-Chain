"""Real original TCA2 typed validation and canonical commitment and pinned native dual."""
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

SOURCE = ROOT / "hia/src/data_availability/cell_release_retention_canonical.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_release_retention_canonical_reference.rs"
WORK = 18080
DOMAIN = b"trnm.cell-release-retention-contract.v2\0"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (MANIFEST, LOCK, REFERENCE, *(CRATE / f"src/cell/{name}.rs"
                for name in ("archive", "closure", "manifest", "model_root", "tensor", "retention")))
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
    executable = directory / "original-release-retention-canonical"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(executable)],
                   env=env, check=True, capture_output=True, timeout=35)
    observed = subprocess.run([str(executable)], env=env, check=False, capture_output=True, timeout=90)
    if observed.returncode:
        raise ValueError(f"original public typed fixture failed: {observed.stderr.decode(errors='replace')}")
    if (not observed.stdout or observed.stderr or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original retention codec evidence")
    rows = []
    cursor = 0
    while cursor < len(observed.stdout):
        length = struct.unpack_from("<I", observed.stdout, cursor)[0]
        pos, end = cursor+4, cursor+4+length
        if not (64 <= length <= LIMIT and end + 36 <= len(observed.stdout)):
            raise ValueError("invalid original retention fixture extent")
        rows.append((observed.stdout[pos:end], struct.unpack_from("<I",observed.stdout,end)[0],
                     observed.stdout[end+4:end+36]))
        cursor = end+36
    print(json.dumps({"original_inputs": dict(zip([p.name for p in paths], before, strict=True)),
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(executable.read_bytes()),
                      "oracle_stdout_sha256": sha(observed.stdout), "oracle_rows": len(rows)},
                     sort_keys=True), flush=True)
    return rows



class CellReleaseRetentionCanonical(unittest.TestCase):
    def test_actual_locked_public_validate_and_commitment_both_stock(self):
        with tempfile.TemporaryDirectory(prefix="trnm-retention-codec-locked-") as tmp:
            rows=original_rows(Path(tmp))
        codes={s for _,s,_ in rows}
        self.assertEqual(codes, {0,80,81,311,320,321,322,323,324,326,421,422,423,424,425,427})
        base,_,dig=rows[0]
        self.assertEqual(hashlib.sha256(DOMAIN + base[8:40] + base[64:]).digest(),dig)
        self.assertEqual(len({d for _,s,d in rows[:65] if s==0}),65)
        out=b"O"*39
        work=b"W"*(WORK+7)
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend),NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as mod:
                for index in range(0,len(rows),8):
                    group=rows[index:index+8]
                    read=mod.call_many([("f0",[raw,out,work]) for raw,_,_ in group],timeout=45)
                    for j,((raw,status,digest),reported) in enumerate(zip(group,read,strict=True)):
                        self.assertEqual((reported.status,reported.value),("returned",status),
                                         (index+j,len(raw),reported.stderr))
                        self.assertTrue(reported.arguments[0]==raw)
                        self.assertEqual(reported.arguments[1],(digest+out[32:]) if status==0 else out)
                        self.assertEqual(reported.arguments[2][WORK:],work[WORK:])
                root_end=228+int.from_bytes(base[224:228],"big")
                malformed = [(base[:64]+b"BAD!"+base[68:],39,work,300),
                             (base[:root_end],39,work,301),
                             (base[:root_end]+bytes([2])+base[root_end+1:],39,work,309),
                             (base+b"\x00",39,work,313),
                             (base[:56]+bytes([1])+base[57:],39,work,397)]
                controls = [(b"",39,work,397),(b"ADAPTER!"+base[8:],39,work,397),
                            (base,31,work,398),(base,39,work[:WORK-1],398),(base,32,work[:WORK],0)]
                for raw,size,w,expect in malformed+controls:
                    result=mod.call("f0",[raw,out[:size],w])
                    self.assertEqual((result.status,result.value),("returned",expect))
                    self.assertEqual(result.arguments[0],raw)
                    self.assertEqual(result.arguments[1],dig if expect==0 else out[:size])
                    self.assertEqual(result.arguments[2][WORK:],w[WORK:])
                print(json.dumps({"native_backend":backend,"native_elf_sha256":mod.artifact_sha256,
                      "oracle_rows":len(rows),"abi_controls":len(malformed)+len(controls),
                      "original_status_counts":dict(Counter(s for _,s,_ in rows))},
                      sort_keys=True),flush=True)
