"""One native call takes a whole bounded raw ordinary journal snapshot."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import NAMES, RESULT_HEADER, artifacts, observe
from hia.tests.test_worker_audit_index_group import SCRATCH_BYTES
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_journal_audit_dto import (
    MAX_RAW, ROOT, cases, declared_input, make, raw,
)
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/journal_audit_export.hepta"


def snapshot(*lines):
    return b"".join(line+b"\n" for line in lines)


class WorkerJournalAuditExport(unittest.TestCase):
    def test_shared_selector_one_callsite_and_never_during_publication(self):
        program,*_=checked_source(NATIVE)
        values=[(fn["name"],bl["id"],op["attrs"]["function"])
                for fn in program.as_dict()["functions"] for bl in fn["blocks"] for op in bl["ops"]
                if op["op"]=="call"]
        self.assertEqual([(f,b) for f,b,target in values if target=="wt_selected"],
                         [("wq_select_and_measure","entry")])
        self.assertEqual([(f,b) for f,b,target in values if target=="ws_selected"],
                         [("wt_selected","entry")])
        self.assertTrue(any(f=="wq_publish" and target=="wx_index" for f,b,target in values))

    def test_scratch_phases_freshness_exact_output_tail_and_authoritative_bits(self):
        # First projected WJL is deliberately much larger than the active
        # map cells; the later table phase must clear all previous row bytes.
        big="x"*36000+"| 🧾"
        rows=[raw(make("failed_adapter",2,big)),raw(make("pending",777)),
              raw(make("rejected",10,"selected")),raw(make("failed_adapter",2,"duplicate id"))]
        raw_snapshot=snapshot(*rows)
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE,backend=backend,byte_exports=("f0",)) as module:
                n,buf=observe(module,raw_snapshot,100000,SCRATCH_BYTES+19)
                self.assertLess(n,len(buf))
                jl,md,idx=artifacts(buf[:n])
                records=[json.loads(line) for line in jl.splitlines()]
                self.assertEqual([v["task_id"] for v in records],[2,10,2])
                self.assertEqual(records[0]["request_id"],big)
                self.assertIn(b"\\|",md)
                maps=json.loads(idx)
                self.assertEqual(list(maps["by_task_id"].items()),[("10",[1]),("2",[0,2])])
                self.assertEqual(maps["by_status_phase"],{"active":[0,2],"terminal":[1]})
                self.assertTrue(all(maps[k]=={} for k in ("by_provider","by_model","by_agent_protocol",
                                 "by_compliance_profile","by_provenance_fingerprint")))
                self.assertEqual(buf[n:],FILL*(len(buf)-n))
                self.assertEqual(observe(module,raw_snapshot,n,scratch_fill=b"\xe7"),(n,buf[:n]))
                self.assertEqual(observe(module,raw_snapshot,n-1),(INSUFFICIENT,FILL*(n-1)))
                self.assertEqual(observe(module,raw_snapshot,2048,SCRATCH_BYTES-1),
                                 (INSUFFICIENT,FILL*2048))

    def test_whole_validation_and_exact_private_input_bounds(self):
        first=raw(make("rejected",2))
        good_excluded=raw(make("Pending",1))
        max_record=make("rejected",7,request="")
        max_record["request_id"]="x"*(MAX_RAW-len(snapshot(raw(max_record))))
        maximum=snapshot(raw(max_record))
        self.assertEqual(len(maximum),MAX_RAW)
        invalid=[snapshot(first)[:-1],snapshot(first,b"",b"\xc3"),
                 snapshot(first,raw({**make("pending",4),"local_test_note":"outside"})),
                 snapshot(first,b"{}"),snapshot(first,b"\xc2\xa0"+first)]
        for backend in BACKENDS:
            with self.subTest(backend=backend),NativeModule(NATIVE,backend=backend,byte_exports=("f0",)) as module:
                for data in invalid:
                    self.assertEqual(observe(module,data,2048),(INVALID,FILL*2048))
                for data in (snapshot(*([good_excluded]*65)),maximum+b"\n"):
                    self.assertEqual(observe(module,data,2048),(INSUFFICIENT,FILL*2048))
                size,found=observe(module,maximum,140000)
                parts=artifacts(found[:size])
                self.assertEqual(json.loads(parts[0])["request_id"],max_record["request_id"])
                self.assertEqual(found[size:],FILL*(len(found)-size))
                n,out=observe(module,snapshot(*([good_excluded]*64)),698)
                self.assertEqual((n,json.loads(artifacts(out)[2])["total_records"]),(698,0))


def scenarios():
    result=cases()
    complete=[]
    for i in range(64):
        status=("pending" if i%5==0 else ("rejected" if i%2==0 else "reveal_submitted"))
        request=("a"*32000+"| 🧾" if i==1 else f"source-{i}|🧾")
        line=raw(make(status,(10,2,2,0)[i%4],request,stamp=(1<<128)-1,
                      null_suffix=i%7==0),escape=i%2==0)
        complete.append(line)
    whole=snapshot(*complete)
    if len(whole)>MAX_RAW:
        raise AssertionError("The known 64-candidate fixture lost its bounded raw size")
    result["maximum_records"]=(whole,64,51)
    return result


def qualify(binary,build,directory):
    def bound():
        return (build["repository_inputs"]==original_inputs()
                and sha256(binary.read_bytes()).hexdigest()==build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual locked Worker sources/executable differ")
    declaration=declared_input()
    proof={}
    with ExitStack() as stack:
        modules={b:stack.enter_context(NativeModule(NATIVE,backend=b,byte_exports=("f0",))) for b in BACKENDS}
        for label,(whole,count,selected) in scenarios().items():
            d=directory/label
            d.mkdir(mode=0o700)
            original=d/"unchanged-source.jsonl"
            original.write_bytes(whole)
            original.chmod(0o600)
            want=cli_artifacts(binary,original,"original",True,None)
            if (d/"original.jsonl.index.json").read_bytes()!=want[2]:
                raise AssertionError("Independent original index mode disagrees")
            index=json.loads(want[2])
            if index["total_records"]!=selected:
                raise AssertionError("Known genuine original selected cardinality changed")
            if label=="maximum_records" and (max(i for hits in index["by_task_id"].values() for i in hits)!=50
                     or not b"source-63" in want[0] or b"source-60" in want[0]):
                raise AssertionError("Last selected raw row or original compact ordinals changed")
            want_len=RESULT_HEADER.size+sum(map(len,want))
            for backend,mod in modules.items():
                # This is the only candidate call. No host split, JSON,
                # DTO/WJL framing, canonization, selection, or file writes by HIA.
                size,out=observe(mod,whole,want_len+13,SCRATCH_BYTES+13)
                if size!=want_len or artifacts(out[:size])!=want or out[size:]!=FILL*13:
                    raise AssertionError(f"{backend} whole native journal output differs: {label}")
                (d/(backend+".wao")).write_bytes(out[:size])
                for ext,payload in zip(NAMES,artifacts(out[:size]),strict=True):
                    (d/(backend+"."+ext)).write_bytes(payload)
            proof[label]={"raw_candidates":count,"original_selected":selected,
                          "raw_sha256":sha256(whole).hexdigest(),"envelope_bytes":want_len,
                          "lengths":dict(zip(NAMES,map(len,want),strict=True)),
                          "sha256":dict(zip(NAMES,(sha256(x).hexdigest() for x in want),strict=True))}
        control=directory/"late-out-of-profile"
        control.mkdir(mode=0o700)
        ordinary=raw(make("rejected",1))
        # The unselected later row remains original-valid but has a non-null
        # optional value; WJD's narrow contract refuses the entire snapshot.
        unsupported=raw({**make("pending",2),"reputation_delta":-1})
        source=control/"unchanged-source.jsonl"
        whole=snapshot(ordinary,unsupported)
        source.write_bytes(whole)
        source.chmod(0o600)
        original_bytes=cli_artifacts(binary,source,"original",True,None)
        if json.loads(original_bytes[2])["total_records"]!=1:
            raise AssertionError("Expected original valid late-compatible case")
        for backend,mod in modules.items():
            status,out=observe(mod,whole,2048,SCRATCH_BYTES+13)
            if (status,out)!=(INVALID,FILL*2048):
                raise AssertionError("Late WJD refusal was not atomic")
            (control/(backend+".status")).write_text(f"{status:#010x}\n")
        proof["late_out_of_profile"]={"original_accepts":True,"native_refuses_output_unchanged":True}
    if not bound() or declaration!=declared_input():
        raise AssertionError("Original executable/source changed")
    report={"pins":original_inputs(),"original_cli_sha256":build["executable_sha256"],
            "original_struct_sha256":declaration,"direct_native_input_whole_raw_journal":True,
            "one_call_no_host_parse_or_intermediate_framing":True,
            "new_parser_policy_or_io_authority":False,
            "backends":{b:{"artifact_sha256":m.artifact_sha256,"receipt":m.receipt} for b,m in modules.items()},
            "scenarios":proof}
    (directory/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--original-binary",type=Path,required=True)
    p.add_argument("--original-build-receipt",type=Path,required=True)
    opts=p.parse_args()
    output=opts.output.resolve()
    if output.is_relative_to(ROOT):
        p.error("Store private proof outside checkout")
    output.mkdir(mode=0o700)
    print(json.dumps(qualify(opts.original_binary.resolve(strict=True),
        json.loads(opts.original_build_receipt.read_bytes()),output)["scenarios"],sort_keys=True))


if __name__=="__main__":
    main()
