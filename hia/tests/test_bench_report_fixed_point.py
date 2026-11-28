"""Stateless original Rust fixed-point arithmetic versus both native report backends.

The report bodies are captured initial observations, not recomputed schedules.
BRPT0001 uses unchanged Rust; BRPT0002 is explicitly marked and uses the
separately patched high-water witness only. All paths and errors supplied
below are already displayed text. No Bench process, file writer, clock,
filesystem owner or runtime path resolution participates.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_bench_report import ORIGINAL, ROOT


FIXTURE = Path(__file__).with_name("fixtures") / "bench_report_fixed_point_v1.json"
BODY_MARK = b"schedule_semantics=reader-high-water-v1\n"
PATH = b"profile.report.path="
BASENAME = b"profile.report.artifact_basename="
ERROR = b"profile.report.persist_error="


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rust_fixed_point(source):
    """Copy literally the exact checked arithmetic; do not include either I/O call."""
    begin = source.index(b'    let line_count_prefix = "profile.report.output_line_count=";')
    end = source.index(b'    fs::write(&out_path, persisted_content)?;', begin)
    return source[begin:end]


def seed(case):
    frame = bytes.fromhex(case["frame_prefix_hex"])
    assert len(frame) == 848 and frame[:8] == case["version"].encode()
    assert frame[816:] == bytes(32)
    body = case["unmarked_body_utf8"].encode()
    assert body.endswith(b"\n") and BODY_MARK not in body
    fields = dict(line.split(b"=", 1) for line in body.splitlines()[1:])
    assert fields[b"determinism.input_sha256"] == frame[752:784].hex().encode()
    assert fields[b"determinism.groups_sha256"] == frame[784:816].hex().encode()
    return frame, body + (b"" if case["original_rust_cli"] else BODY_MARK)


def state_frame(prefix, state, path=b"", basename=b"", error=b""):
    return (prefix[:816] + struct.pack("<4Q", state, len(path), len(basename), len(error))
            + path + basename + error)


def call_request(frame, output_delta=0, scratch_delta=0):
    b = 32768 + len(frame) - 848
    return "f0", [frame, b"\xa5" * (40 + 2*b + output_delta),
                        b"\xd3" * (8192 + len(frame) + 2*b + scratch_delta)]


class BenchReportFixedPoint(unittest.TestCase):
    def test_both_report_versions_and_all_persistence_states_are_stateless(self):
        witness = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(witness["schema"], "bench.stateless-persist-fixed-point-witness.v1")
        rust_source = ORIGINAL.read_bytes()
        self.assertEqual(sha(rust_source), witness["original_bench_source_sha256"])
        self.assertEqual(sha((ROOT/"trillionnium/Cargo.lock").read_bytes()), witness["cargo_lock_sha256"])
        arithmetic = rust_fixed_point(rust_source)
        self.assertEqual(sha(arithmetic), witness["rust_arithmetic_block_sha256"])
        self.assertEqual([case["version"] for case in witness["witnesses"]], ["BRPT0001","BRPT0002"])
        legacy, corrected = witness["witnesses"]
        self.assertTrue(legacy["original_rust_cli"])
        self.assertIsNone(legacy["semantic_marker"])
        self.assertFalse(corrected["original_rust_cli"])
        self.assertEqual(corrected["semantic_marker"].encode()+b"\n", BODY_MARK)
        provenance = corrected["corrected_oracle_identity"]
        self.assertTrue(provenance["test_only"] and provenance["tracked_original_untouched"])
        self.assertEqual((provenance["semantics"], provenance["reader_map_updates"]), ("reader-high-water-v1",4))
        self.assertEqual(provenance["original_sources"]["crates/trnm-bench/src/main.rs"], sha(rust_source))
        executor = (ROOT/"trillionnium/crates/trnm-executor/src/lib.rs").read_bytes()
        self.assertEqual(provenance["original_sources"]["crates/trnm-executor/src/lib.rs"], sha(executor))
        self.assertNotEqual(provenance["corrected_executor_sha256"], sha(executor))

        oracle = b"""
use std::io::{self, BufRead};
fn fixed(lines: Vec<String>) -> String {
""" + arithmetic + br"""
    persisted_content
}
fn decode(line: &str) -> String {
    let bytes: Vec<u8> = (0..line.len()).step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i+2], 16).unwrap()).collect();
    String::from_utf8(bytes).unwrap()
}
fn main() {
    for row in io::stdin().lock().lines() {
        let plain = decode(&row.unwrap());
        let lines = plain.strip_suffix('\n').unwrap().split('\n').map(str::to_owned).collect();
        for byte in fixed(lines).as_bytes() { print!("{byte:02x}"); }
        println!();
    }
}
"""
        rust_pin = subprocess.check_output(("rustc","--version"), text=True).split()[1]
        self.assertEqual(rust_pin, provenance["rustc_and_cargo_pin"])
        modules = {}
        for backend in ("direct", "selfhost"):
            module = NativeModule(ROOT/"hia/src/bench/report.hepta", byte_exports=("f0",), backend=backend)
            modules[backend] = module
            self.addCleanup(module.close)

        rows, candidates = [], []
        display = "輪郭 é/候補\r\nline\n終".encode()
        basename = "要約-🥸.txt".encode()
        failure = "synthetic: 許可\r\nmissing\n終".encode()

        def add(version, prefix, body, state, path=b"", name=b"", error=b""):
            prewrite = body + (PATH+path+b"\n"+BASENAME+name+b"\n" if state in (2,3) else b"")
            candidate_index = None
            if state in (2,3):
                candidate_index = len(candidates)
                candidates.append(prewrite)
            stdout = prewrite + (ERROR+error+b"\n" if state in (1,3) else b"")
            rows.append((version,state,state_frame(prefix,state,path,name,error),stdout,candidate_index))

        for case in witness["witnesses"]:
            prefix, body = seed(case)
            version = case["version"]
            add(version,prefix,body,0)
            add(version,prefix,body,1,error=failure)
            add(version,prefix,body,2,display,basename)
            add(version,prefix,body,3,display,basename,failure)
            # Carry the self-describing byte count across two decimal widths.
            # The input lengths include the maximum possible +/- digit carry;
            # checking the Rust results below requires actual coverage.
            fixed_overhead = len(body+PATH+b"\n"+BASENAME+basename+b"\n")
            for boundary in (10_000,100_000):
                target = boundary-fixed_overhead-80
                for offset in (-12,-4,4,12):
                    add(version,prefix,body,2,display+b"z"*(target+offset-len(display)),basename)
            # Embedded CRLF and LF exercise Rust str::lines and 3->4 digit
            # line counts independently of UTF-8 byte counts.
            line_base = (body+PATH+display+b"\n"+BASENAME+basename+b"\n").count(b"\n")+2
            for target in (998,999,1000,1001):
                n=target-line_base
                add(version,prefix,body,2,display+b"\r\n"*(n//2)+b"\n"*(n-n//2),basename)

        with tempfile.TemporaryDirectory(prefix="trnm-report-fixedpoint-") as td:
            scratch = Path(td)
            rust = scratch/"fixed.rs"
            rust.write_bytes(oracle)
            binary = scratch/"fixed"
            compiled = subprocess.run(("rustc","--edition=2021","--deny=warnings",str(rust),"-o",str(binary)),
                                      capture_output=True,timeout=30)
            self.assertEqual((compiled.returncode,compiled.stdout,compiled.stderr),(0,b"",b""))
            before = set(scratch.iterdir())
            actual = subprocess.run((str(binary),), input=b"".join(x.hex().encode()+b"\n" for x in candidates),
                                    cwd=scratch,env={},check=True,capture_output=True,timeout=20)
            self.assertFalse(actual.stderr)
            self.assertEqual(set(scratch.iterdir()), before, "The stateless oracle created an artifact")
        rust_results = [bytes.fromhex(row.decode()) for row in actual.stdout.splitlines()]
        self.assertEqual(len(rust_results),len(candidates))

        records = []
        for version,state,frame,expected,index in rows:
            oracle_file = b"" if index is None else rust_results[index]
            used = 40+len(expected)+len(oracle_file)
            raw = struct.pack("<8s4Q",b"BRPTOUT1",0,len(expected),0,len(oracle_file))+expected+oracle_file
            for backend,module in modules.items():
                request = call_request(frame)
                got = module.call_many([request],timeout=30)[0]
                got.require_returned()
                self.assertEqual(got.value, 0, (version, state, backend))
                self.assertEqual(got.arguments[0],frame)
                self.assertEqual(got.arguments[1][:used],raw,(version,state,backend))
                self.assertEqual(got.arguments[1][used:],request[1][1][used:])
            records.append((version,state,len(oracle_file),oracle_file.count(b"\n"),sha(raw)))

        for version in ("BRPT0001","BRPT0002"):
            counts = {(size,lines) for v,state,size,lines,_ in records if v==version and state==2}
            for boundary in (10_000,100_000):
                self.assertTrue(any(0<boundary-size<50 for size,_ in counts),(version,boundary,counts))
                self.assertTrue(any(0<=size-boundary<50 for size,_ in counts),(version,boundary,counts))
            self.assertTrue({998,999,1000,1001}<={lines for _,lines in counts})
        for version,module in modules.items():
            for case in witness["witnesses"]:
                prefix,_ = seed(case)
                frame=state_frame(prefix,2,display,basename)
                for one_short in ((-1,0),(0,-1)):
                    request=call_request(frame,*one_short)
                    result=module.call_many([request],timeout=30)[0]
                    result.require_returned()
                    self.assertEqual((result.value,result.arguments),(100,request[1]),version)

        sink = os.environ.get("HIA_BENCH_FIXED_POINT_REPORT")
        if sink:
            report = {"fixture_sha256":sha(FIXTURE.read_bytes()),"rust_source_sha256":sha(rust_source),
                      "arithmetic_sha256":sha(arithmetic),"oracle_sha256":sha(oracle),
                      "oracle_candidate_files":len(rust_results),"stateless_cases":len(records),
                      "backend_reads":{k:v.artifact_sha256 for k,v in modules.items()},
                      "no_filesystem_authority":True,"production_qualified":False,"records":records}
            Path(sink).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")


if __name__ == "__main__":
    unittest.main()
