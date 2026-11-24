"""Native WER2 query-file geometry tested with actual original Rust stdout."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query.build import build as build_old_named
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_row_decode import (
    NATIVE as WER1, RAW_MAX, STAGE_MAX, WID1, WTQ2, compact, export_row,
    fixture_cases, require_headroom, sha, transfer,
)
from hia.tests.test_worker_audit_export_transaction import observe
from hia.tests.test_worker_audit_sealed_query import original_case
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_audit_task_query import MAX_TASK, SCRATCH, query_original
from hia.tools.toolchain import checked_source

WER2 = WER1.with_name("audit_export_row_lines_v2.hepta")
BLANK = "\t \r\x0b\x0c\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000".encode()
OLD_NAMED = "86fe45bdb66593c4a1587e2accd66e53a35d8bfeb4658d0ed70dd841d8ed3989"


def guard(path):
    require_headroom(path)
    tmp = os.statvfs("/tmp")
    if tmp.f_bavail * tmp.f_frsize < 25 * 1024 * 1024:
        raise RuntimeError("Qualification stopped before the 25 MiB /tmp floor")


def functions(path):
    p, wire, _, _, sources = checked_source(path)
    return {f["name"]: f for f in p.as_dict()["functions"]}, wire, sources


def graph():
    old, _, _ = functions(WER1)
    new, wire, sources = functions(WER2)
    replaced = {"f0", "wer_batch", "wer_row"}
    added = {"f0", "wer2_batch", "wer2_row", "wer2_line", "or_character",
             "or_char_size", "or_space", "or_trim_start"}
    shared = set(old) - replaced
    if set(new) != shared | added or any(new[k] != old[k] for k in shared):
        raise AssertionError("WER2 altered an existing scalar or typed field helper")
    for old_name, new_name, changes in (
        ("f0", "f0", {"entry", "utf8", "parse"}),
        ("wer_batch", "wer2_batch", {"rows", "line", "bounds", "header"}),
        ("wer_row", "wer2_row", {"close"}),
    ):
        lhs = {b["id"]: b for b in old[old_name]["blocks"] if b["id"] not in changes}
        rhs = {b["id"]: b for b in new[new_name]["blocks"] if b["id"] not in changes}
        if lhs != rhs:
            raise AssertionError("WER2 changed a block outside bounded line geometry")
    return new, wire, sources


def mixed(data):
    # Transform LF transport only. Never parse JSON or change a record value.
    rows = data.split(b"\n")
    assert rows[-1] == b""
    return BLANK + b"\r\n\n" + (b"\r\n" + BLANK + b"\n").join(rows[:-1])


def check_controls(new, old):
    row = compact(export_row(task=2, request_id="opaque é"))
    pair = row + row
    n, expected = observe(old, pair, 2048)
    expected = expected[:n]
    for sample in (pair, pair[:-1], pair.replace(b"\n", b"\r\n"), mixed(pair)):
        assert observe(new, sample, n+3, SCRATCH+7) == (n, expected+FILL*3)
    assert observe(new, mixed(pair), n-1) == (INSUFFICIENT, FILL*(n-1))
    assert observe(new, mixed(pair), n, SCRATCH-1) == (INSUFFICIENT, FILL*n)
    assert observe(new, BLANK + b"\r\n" + BLANK, 8) == (8, b"WAT1\0\0\0\0")
    maximum = b" " * (RAW_MAX - len(pair)) + b"\n" + pair[:-1]
    assert len(maximum) == RAW_MAX and observe(new, maximum, n) == (n, expected)
    wrong = (
        maximum+b"\n", row*65, row+BLANK+b"\xff", row+b"{}",
        row+row[:-2], row+b"\r"+row, row+row[:-1]+b"\r\r\n",
        row+b"\xc2\xa0"+row, row+row[:-1]+b" ",
    )
    for sample in wrong:
        assert observe(new, sample, 2176) == (INVALID, FILL*2176)
    for sample in (mixed(pair), pair[:-1], pair.replace(b"\n", b"\r\n")):
        assert observe(old, sample, 2176) == (INVALID, FILL*2176)
    return len(wrong)


class WorkerAuditExportRowLinesV2(unittest.TestCase):
    def test_changed_geometry_preserves_field_core_and_refusing_output(self):
        graph()
        for backend in BACKENDS:
            with (NativeModule(WER1, backend=backend, byte_exports=("f0",)) as old,
                  NativeModule(WER2, backend=backend, byte_exports=("f0",)) as new):
                self.assertEqual(check_controls(new, old), 9)


def qualify(binary, original, output):
    def bound():
        return (original["repository_inputs"] == original_inputs()
                and original["executable_sha256"] == sha(binary.read_bytes()))
    if not bound():
        raise AssertionError("Wrong actual original locked Worker inputs")
    fs, wire, sources = graph()
    guard(output)
    old_elf, old_report = build_old_named(output/"strict-old-wqs1")
    assert sha(old_elf) == old_report["elf"]["sha256"] == OLD_NAMED
    cases = {}
    test_cases = (
        ("empty", "blank-only", lambda x: BLANK+b"\r\n"+BLANK, (0,)),
        ("maximum-ordered", "mixed-max-rows", mixed, (MAX_TASK, 0)),
        ("escaped-display-no-schema", "crlf", lambda x: x.replace(b"\n", b"\r\n"), (10,2,0)),
        ("original-control-escapes", "unterminated", lambda x: x[:-1], (2,0)),
        ("original-control-escapes", "exact-65536", lambda x: b" "*(RAW_MAX-len(x))+b"\n"+x[:-1], (2,)),
    )
    roles = {"old":WER1, "new":WER2, "sidecar":WID1, "query":WTQ2}
    receipts = {}
    with ExitStack() as stack:
        modules = {}
        for backend in BACKENDS:
            guard(output)
            bundle = {key:stack.enter_context(NativeModule(path,backend=backend,byte_exports=("f0",)))
                      for key,path in roles.items()}
            modules[backend] = bundle
            receipts[backend] = {key:{"sha256":m.artifact_sha256,"receipt":m.receipt}
                                 for key,m in bundle.items()}
            receipts[backend]["refusals"] = check_controls(bundle["new"], bundle["old"])
        for origin, name, convert, tasks in test_cases:
            guard(output)
            directory = fresh_directory(output/name)
            sidecar, canonical = original_case(binary,directory,fixture_cases()[origin][0])
            raw = convert(canonical)
            if raw == canonical or len(raw) > RAW_MAX or (name == "exact-65536" and len(raw) != RAW_MAX):
                raise AssertionError("Fixture did not exercise bounded new geometry")
            physical = directory/"transformed.jsonl"
            physical.write_bytes(raw)
            physical.chmod(0o600)
            side = directory/"transformed.jsonl.index.json"
            side.write_bytes(sidecar)
            side.chmod(0o600)
            native = {}
            for backend, four in modules.items():
                n, want = observe(four["old"],canonical,RAW_MAX+3)
                got, staged = observe(four["new"],raw,RAW_MAX+3,SCRATCH+7)
                if got != n or not 8 <= got <= RAW_MAX or staged != want:
                    raise AssertionError("WER2 changed canonical typed values or output tail")
                si, typed_index = observe(four["sidecar"],sidecar,STAGE_MAX+7)
                if not 40 <= si <= STAGE_MAX or typed_index[si:] != FILL*(STAGE_MAX+7-si):
                    raise AssertionError("Untouched original sidecar did not fit pinned WID")
                native[backend] = typed_index[:si],staged[:got]
            if len(set(native.values())) != 1:
                raise AssertionError("Native backends disagree about held typed bytes")
            queries = {}
            for task in tasks:
                oracle, digest = query_original(binary,physical,task,directory)
                stdout = (directory/f"query-{task}.stdout.raw").read_bytes()
                for backend, four in modules.items():
                    length, answer = observe(four["query"],transfer(*native[backend],task),len(stdout)+7)
                    if length != len(stdout) or answer != stdout+FILL*7:
                        raise AssertionError("Actual original query stdout differed")
                    (directory/f"{task}.{backend}.stdout.raw").write_bytes(answer[:length])
                if sha(stdout) != digest or not stdout.endswith(b"\n"):
                    raise AssertionError("Unexpected original full stdout")
                if name == "mixed-max-rows" and task == MAX_TASK and oracle["hit_indexes"] != list(range(64)):
                    raise AssertionError("Missing original 64th compact ordinal")
                queries[str(task)] = {"hits":oracle["hit_indexes"],"bytes":len(stdout),"sha256":digest}
            if physical.read_bytes() != raw or side.read_bytes() != sidecar:
                raise AssertionError("Immutable synthetic fixtures changed")
            cases[name] = {"bytes":len(raw),"jsonl_sha256":sha(raw),"sidecar_sha256":sha(sidecar),"queries":queries}
        # Independent actual Serde evidence for our deliberately narrower
        # grammar: NBSP beside a real row is not blank; ordinary edge space
        # is original-valid but remains outside this compact-row candidate.
        directory = output/"crlf"
        canonical = (directory/"original.jsonl").read_bytes()
        sidecar = (directory/"original.jsonl.index.json").read_bytes()
        before, split, last = canonical[:-1].rpartition(b"\n")
        if not split or not before or not last:
            raise AssertionError("Late control needs genuine good preceding rows")
        boundary = {}
        for label, line_edge, accepted_by_rust in (
            ("late-nbsp", b"\xc2\xa0"+last, False),
            ("late-ascii-edge", b" "+last, True),
        ):
            data = before+split+line_edge
            path = directory/(label+".jsonl")
            path.write_bytes(data)
            path.chmod(0o600)
            index = directory/(label+".jsonl.index.json")
            index.write_bytes(sidecar)
            index.chmod(0o600)
            measured = subprocess.run(
                [str(binary), "query-audit", "--output-file", str(path), "--task-id", "10"],
                cwd=directory, capture_output=True, timeout=25,
            )
            (directory/(label+".original-stdout.raw")).write_bytes(measured.stdout)
            (directory/(label+".original-stderr.raw")).write_bytes(measured.stderr)
            rust_ok = (measured.returncode==0 and not measured.stderr
                       and measured.stdout==(directory/"query-10.stdout.raw").read_bytes())
            if rust_ok!=accepted_by_rust or (not accepted_by_rust and (measured.returncode==0 or measured.stdout)):
                raise AssertionError("Changed original query boundaries")
            for backend, four in modules.items():
                if observe(four["new"],data,4096)!=(INVALID,FILL*4096):
                    raise AssertionError(f"Changed atomic compact framing refusal: {backend}/{label}")
            boundary[label] = {"original_status":measured.returncode,"original_stdout_sha256":sha(measured.stdout),
                               "native_status":INVALID,"native_atomic":True}
    if not bound() or any(p.read_bytes()!=data for p,data in sources):
        raise AssertionError("Source changed during actual replay")
    report = {"status":"PASS","cases":cases,"scope_controls":boundary,"native":receipts,"old_named":old_report["elf"],
              "compiled_core_sha256":sha(wire),"functions":len(fs),
              "operations":sum(len(block["ops"]) for fn in fs.values() for block in fn["blocks"]),
              "original_executable_sha256":original["executable_sha256"],"original_inputs":original_inputs(),
              "host_row_or_map_parser":False,"candidate_opens_files":False,"production_dispatch":False,
              "checkout_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=WER1.parents[3],
                                                        env={**os.environ,"GIT_NO_LAZY_FETCH":"1"}).decode().strip()}
    (output/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("output","original-binary","original-build-receipt"):
        p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args()
    guard(a.output.parent)
    receipt=qualify(a.original_binary.resolve(strict=True),
                    json.loads(a.original_build_receipt.read_bytes()),fresh_directory(a.output))
    print(json.dumps({"status":receipt["status"],"cases":receipt["cases"]},sort_keys=True))


if __name__ == "__main__":
    main()
