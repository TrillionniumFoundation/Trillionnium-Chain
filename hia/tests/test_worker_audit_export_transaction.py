"""One native typed Worker batch emits three genuine original artifact payloads."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_index_group import MAPS, SCRATCH_BYTES, scenarios
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame, invalid_frames
from hia.tests.test_worker_audit_markdown_batch import ACTIVE_HEADER
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INSUFFICIENT, INVALID, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/audit_export_transaction.hepta"
INPUT_HEADER = struct.Struct("<4sI")
RESULT_HEADER = struct.Struct("<4sIII")
NAMES = ("jsonl", "md", "md.index.json")
MAX_INPUT = 65536
SCRATCH_BYTE = b"\x59"


def wire(rows):
    return INPUT_HEADER.pack(b"WAT1", len(rows)) + b"".join(
        struct.pack("<I", len(row)) + row for row in rows)


def artifacts(payload):
    magic, jl, md, ix = RESULT_HEADER.unpack_from(payload)
    if magic != b"WAO1" or len(payload) != RESULT_HEADER.size+jl+md+ix:
        raise AssertionError("Transaction envelope is not the exact three-artifact result")
    start = RESULT_HEADER.size
    return (payload[start:start+jl], payload[start+jl:start+jl+md], payload[start+jl+md:])


def observe(module, raw, capacity, scratch_bytes=SCRATCH_BYTES, *, scratch_fill=SCRATCH_BYTE):
    scratch = scratch_fill*scratch_bytes
    result = module.call("f0", [raw, FILL*capacity, scratch]).require_returned()
    replied_input, output, workspace = result.arguments
    if replied_input != raw or workspace[SCRATCH_BYTES:] != scratch[SCRATCH_BYTES:]:
        raise AssertionError("The input or scratch tail changed")
    return result.value, output


def typed_row(task=0, status="rejected", **fields):
    record = dict.fromkeys(FIELDS)
    record.update(request_id="local", task_id=task, status=status, **fields)
    return frame(tuple(record[name] for name in FIELDS))


class WorkerAuditExportTransaction(unittest.TestCase):
    def test_one_batch_order_artifact_offsets_and_atomic_capacity(self):
        a = typed_row(2, "failed_adapter", provider='Acme|"West"', model="Case")
        b = typed_row(10, "rejected", provider_request_id="", reputation_delta=-2147483648)
        raw = wire([a, b, a])
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as module:
                n, out = observe(module, raw, 8192, SCRATCH_BYTES+13)
                self.assertGreater(n, 698)
                self.assertEqual(out[n:], FILL*(8192-n))
                jl, md, ix = artifacts(out[:n])
                self.assertEqual([json.loads(x)["task_id"] for x in jl.splitlines()], [2,10,2])
                self.assertTrue(md.startswith(ACTIVE_HEADER))
                self.assertEqual(md.count(b'Acme\\|"West"'), 2)
                self.assertTrue(md.endswith(b" | - | - | - |\n"))
                lookup = json.loads(ix)
                self.assertEqual(tuple(lookup), ("version", "total_records", *MAPS))
                self.assertEqual(list(lookup["by_task_id"].items()), [("10",[1]),("2",[0,2])])
                self.assertEqual(lookup["by_status_phase"], {"active":[0,2],"terminal":[1]})
                self.assertEqual(lookup["by_provider"], {'Acme|"West"':[0,2]})
                self.assertEqual(observe(module, raw, n, scratch_fill=b"\xd1"), (n,out[:n]))
                self.assertEqual(observe(module, raw, n-1), (INSUFFICIENT,FILL*(n-1)))
                self.assertEqual(observe(module, raw, n, SCRATCH_BYTES-1),
                                 (INSUFFICIENT,FILL*n))
                self.assertEqual(observe(module, wire([]), 697), (INSUFFICIENT,FILL*697))
                n0, empty = observe(module, wire([]), 698)
                ej, em, ei = artifacts(empty)
                self.assertEqual((n0, ej, em, json.loads(ei)["total_records"]),
                                 (698,b"",ACTIVE_HEADER,0))

    def test_late_indexed_and_nonindexed_row_errors_change_no_output_byte(self):
        good = typed_row(10, "reveal_submitted", agent_protocol="mcp")
        output_capacity = 3120
        valid = wire([good, good])
        broken = [*invalid_frames(good), typed_row(1, "Rejected"), typed_row(1, "pending"),
                  typed_row(1, provider="a"*65), typed_row(1, model="🧾"),
                  typed_row(1, agent_protocol="mcp2")]
        late = [wire([good,bad]) for bad in broken]
        bad_requests = [b"", valid[:7], valid[:-1], valid+b"x", b"WAT2"+valid[4:],
                        wire([good]*65), *late]
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as module:
                for bad in bad_requests:
                    self.assertEqual(observe(module,bad,output_capacity),
                                     (INVALID,FILL*output_capacity))
                max_frame = list((None,)*18)
                max_frame[0], max_frame[1], max_frame[2] = "", 0, "rejected"
                max_frame[0] = "p"*(MAX_INPUT-len(wire([frame(max_frame)])))
                limit = wire([frame(max_frame)])
                self.assertEqual(len(limit), MAX_INPUT)
                total, out = observe(module, limit, 140000)
                parts = artifacts(out[:total])
                self.assertEqual(json.loads(parts[0])["request_id"],max_frame[0])
                self.assertEqual(out[total:],FILL*(len(out)-total))
                max_frame[0] += "p"
                self.assertEqual(observe(module,wire([frame(max_frame)]),512),(INVALID,FILL*512))


def fixtures():
    cases = scenarios()
    for i, row in enumerate(cases["maximum"]):
        row["request_id"] = f"synthetic|{i}\r\n\\🧾"
        row["reputation_delta"] = (None,3,-1,-2,-3,0)[i % 6]
    rows = cases["maximum"]
    # Preserve count; neither transaction nor envelope deduplicates.
    rows[12] = dict(rows[11])
    return cases


def observe_original(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Exact locked Worker executable/source binding differs")
    proof = {}
    with ExitStack() as stack:
        modules = {b:stack.enter_context(NativeModule(
            NATIVE,backend=b,byte_exports=("f0",))) for b in BACKENDS}
        for name, rows in fixtures().items():
            d = directory / name
            d.mkdir(mode=0o700)
            journal = d / "synthetic-ingress.jsonl"
            journal.write_bytes(b"".join((json.dumps(rec,ensure_ascii=False)+"\n").encode()
                                         for rec in rows))
            journal.chmod(0o600)
            source_hash = sha256(journal.read_bytes()).hexdigest()
            # The first execution supplies typed input only. The next two
            # independent executions produce all three full byte oracles.
            for destination in ("typed.jsonl","oracle.jsonl","oracle.md"):
                result = subprocess.run([str(binary),"export-audit","--ingress-file",str(journal),
                                          "--output-file",str(d/destination)],cwd=d,
                                         capture_output=True,timeout=25)
                (d/(destination+".stdout.raw")).write_bytes(result.stdout)
                (d/(destination+".stderr.raw")).write_bytes(result.stderr)
                if result.returncode or result.stderr or sha256(journal.read_bytes()).hexdigest() != source_hash:
                    raise AssertionError("Original locked export/source observation failed")
            rows_typed = [json.loads(line) for line in (d/"typed.jsonl").read_bytes().splitlines()]
            if any(tuple(row) != FIELDS for row in rows_typed):
                raise AssertionError("Original typed export row field roster changed")
            expected = 64 if name=="maximum" else 0
            if len(rows_typed)!=expected:
                raise AssertionError("Original selected fixture size changed")
            raw = wire([frame(tuple(row[k] for k in FIELDS)) for row in rows_typed])
            (d/"typed-wire.raw").write_bytes(raw)
            want = tuple((d/("oracle."+ext)).read_bytes() for ext in NAMES)
            if (d/"oracle.jsonl.index.json").read_bytes() != want[2]:
                raise AssertionError("Independent original format choices emitted different index bytes")
            native_envelope_len = RESULT_HEADER.size+sum(map(len,want))
            admitted_index = json.loads(want[2])
            if admitted_index["total_records"]!=expected:
                raise AssertionError("Original index count disagrees with rows")
            if name=="maximum":
                keys=list(admitted_index["by_task_id"])
                if (not all(admitted_index[k] for k in MAPS) or keys.index("10")>=keys.index("2")
                        or rows_typed[10] != rows_typed[11]
                        or not any(len(row["model"] or "")==128 for row in rows_typed)
                        or b"\\|" not in want[1]):
                    raise AssertionError("Original fixture lost required three-artifact shape")
            for b,m in modules.items():
                n,out=observe(m,raw,native_envelope_len+11,SCRATCH_BYTES+11)
                actual=artifacts(out[:n])
                if n!=native_envelope_len or actual!=want or out[n:]!=FILL*11:
                    raise AssertionError(f"{b}: original and native artifact bytes differ for {name}")
                (d/(b+".envelope.raw")).write_bytes(out[:n])
                for ext,payload in zip(NAMES,actual,strict=True):
                    (d/(b+"."+ext)).write_bytes(payload)
            proof[name] = {"ingress_rows":len(rows),"selected_rows":len(rows_typed),
                           "typed_input_sha256":sha256(raw).hexdigest(),
                           "artifact_sizes":dict(zip(NAMES,map(len,want),strict=True)),
                           "artifact_sha256":dict(zip(NAMES,(sha256(x).hexdigest() for x in want),strict=True)),
                           "native_envelope_size":native_envelope_len}
    if not bound():
        raise AssertionError("Original locked Worker binding changed")
    report = {"source_lock_bindings":original_inputs(),
              "original_worker_executable_sha256":build["executable_sha256"],
              "one_native_call_all_three_artifacts":True,"one_typed_input_not_host_derived_artifacts":True,
              "independent_original_jsonl_markdown_index_byte_oracles":True,
              "journal_parser_production_file_authority_changed":False,
              "native_builds":{b:{"artifact_sha256":m.artifact_sha256,"receipt":m.receipt} for b,m in modules.items()},
              "scenarios":proof}
    (directory/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--original-binary",type=Path,required=True)
    parser.add_argument("--original-build-receipt",type=Path,required=True)
    args=parser.parse_args()
    directory=args.output.resolve()
    if directory.is_relative_to(ROOT):
        parser.error("Store private proof outside checkout")
    directory.mkdir(mode=0o700)
    print(json.dumps(observe_original(args.original_binary.resolve(strict=True),
                                       json.loads(args.original_build_receipt.read_bytes()),
                                       directory)["scenarios"],sort_keys=True))


if __name__=="__main__":
    main()
