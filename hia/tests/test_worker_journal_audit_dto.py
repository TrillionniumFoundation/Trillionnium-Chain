"""A bounded native ordinary Worker audit DTO against its actual original CLI."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_preselection import NATIVE as WAT2, wat2
from hia.tests.test_worker_audit_export_transaction import artifacts, observe
from hia.tests.test_worker_audit_jsonl_row import ROOT, frame
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, observed_call, original_inputs
from hia.tests.test_worker_journal_line_frame import NATIVE as WJF1, cli_artifacts, unpack_bytes

NATIVE = ROOT / "hia/src/worker_agent/journal_audit_dto.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-worker-agent/src/main.rs"
MAX_RAW = 65536
FIELDS = ("request_id:u", "task_id:u64", "channel:u", "user_id:u", "session_id:u",
          "text:u", "idempotency_key:u", "status:u", "created_at_unix_ms:u128")
OPTIONS = ("assigned_worker", "assigned_at_unix_ms", "model_output", "provider_request_id",
           "provenance_schema_version", "llm_provenance", "result_hash", "verifier_status",
           "resolution_code", "commit_tx_hash", "reveal_tx_hash", "adapter_error", "reputation_delta")


def make(status="rejected", task=17, request="private-synthetic|🧾", *, stamp=0, null_suffix=False):
    row={"request_id":request,"task_id":task,"channel":"fixture","user_id":"local",
         "session_id":"fixture","text":"sample text: \u0085 \u2028 \t \" \\",
         "idempotency_key":"synthetic","status":status,"created_at_unix_ms":stamp}
    if null_suffix:
        row.update(dict.fromkeys(OPTIONS))
    return row


def raw(row, *, escape=False, compact=True):
    args={"separators":(",",":")} if compact else {}
    return json.dumps(row,ensure_ascii=escape,**args).encode()


def declared_input():
    original=ORIGINAL.read_text()
    declaration=original.split("pub(crate) struct MessageIngressRecord {",1)[1].split("\n}",1)[0]
    types=tuple(tuple(line.strip().removeprefix("pub(crate) ").removesuffix(",").split(": ",1))
                for line in declaration.splitlines() if line.strip().startswith("pub(crate) "))
    expected=tuple(tuple(v.replace(":u",":String").split(":")) if v.endswith(":u") else tuple(v.split(":"))
                   for v in FIELDS)
    if types[:9]!=expected or tuple(k for k,_ in types[9:])!=OPTIONS or not all(
            v.startswith("Option<") for _,v in types[9:]):
        raise AssertionError("Active original struct changed outside the declared DTO grammar")
    return sha256(declaration.encode()).hexdigest()


def ordinary_wjl_values(request_id,task_id,status):
    return frame((request_id,task_id,status,*([None]*15)))


class WorkerJournalAuditDto(unittest.TestCase):
    def test_range_and_unicode_with_both_admitted_suffix_modes(self):
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE,backend=backend,byte_exports=("f0",)) as module:
                request="\u0000\r\n café \U0001f9ea \\ / \""
                status="rejected\u00a0"
                want=ordinary_wjl_values(request,(1<<64)-1,status)
                for suffix in (False,True):
                    for escape in (False,True):
                        item=make(status,(1<<64)-1,request,stamp=(1<<128)-1,null_suffix=suffix)
                        source=b"\t "+raw(item,escape=escape,compact=not suffix)+b"\r\t "
                        self.assertEqual(observed_call(module,source,len(want)+9),(len(want),want+FILL*9))
                        self.assertEqual(observed_call(module,source,len(want)),(len(want),want))
                        self.assertEqual(observed_call(module,source,len(want)-1),
                                         (INSUFFICIENT,FILL*(len(want)-1)))
                minimum=raw(make("",0,""))
                self.assertEqual(observed_call(module,minimum,108),(108,ordinary_wjl_values("",0,"")))

    def test_refuses_wrong_structure_numbers_incomplete_suffix_and_literal_lf(self):
        good=raw(make("rejected",1,"safe"))
        valid_null=make(null_suffix=True)
        partial=make()
        partial["assigned_worker"]=None
        nonstring=make()
        nonstring["text"]=17
        wrong_order=make()
        wrong_order={"status":wrong_order.pop("status"),**wrong_order}
        complete=make()
        complete["text"]="x"*(MAX_RAW-len(raw({**complete,"text":""})))
        max_case=raw(complete)
        self.assertEqual(len(max_case),MAX_RAW)
        truncated_null=dict(valid_null)
        truncated_null.pop("reputation_delta")
        invalid=[b"",b"{}",good[:-1],good+b"{}",good+b"\n",
                 raw(make(task=1<<64)),raw(make(stamp=1<<128)),raw(make(task=-1)),
                 raw(make(stamp=10**39)),raw(nonstring),raw(partial),raw(wrong_order),raw(truncated_null),
                 good.replace(b'"task_id":1',b'"task_id":01'),good.replace(b'"task_id":1',b'"task_id":1e0'),
                 good.replace(b'"text":',b'"status":"rejected","text":'),
                 good.replace(b'"safe"',b'"\x01"'),good.replace(b'"safe"',b'"\\ud800"'),
                 good.replace(b'"safe"',b'"\xff"')]
        for backend in BACKENDS:
            with self.subTest(backend=backend),NativeModule(NATIVE,backend=backend,byte_exports=("f0",)) as module:
                for bad in invalid:
                    self.assertEqual(observed_call(module,bad,192),(INVALID,FILL*192))
                self.assertEqual(observed_call(module,max_case+b" ",192),(INSUFFICIENT,FILL*192))
                needed, found=observed_call(module,max_case,192)
                want=ordinary_wjl_values(complete["request_id"],complete["task_id"],complete["status"])
                self.assertEqual((needed,found),(len(want),want+FILL*(192-len(want))))


def cases():
    statuses=("rejected","pending","failed_adapter","reveal_submitted","Rejected","failed_submission","rejected ")
    rows=[make(status,(1<<64)-1 if i in (0,2) else i,
               request=f"fixture|{i} \u2028 🧾\r\n\\\"",
               stamp=((1<<128)-1,0,99999999999999999999999999999999999999)[i%3])
          for i,status in enumerate(statuses)]
    normal_lines=[(b"\t "+raw(row,escape=i%2==0,compact=i%2!=0)+b"\r" if i==2
                   else raw(row,escape=i%2==0,compact=i%2!=0)) for i,row in enumerate(rows)]
    required=(b"\n"+b"\r\n".join(normal_lines)+b"\r\n"+"\u0085\u2029\n".encode())
    allnull=b"\n".join(raw({**row,**dict.fromkeys(OPTIONS)},escape=True) for row in rows)+b"\n"
    return {"required":(required,len(rows),4),"all_null":(allnull,len(rows),4),
            "blank":("\u2003\r\n".encode(),0,0),"empty":(b"",0,0)}


def unsupported_cases():
    base=make()
    reorder={"status":base["status"],**{k:v for k,v in base.items() if k!="status"}}
    option={**base,"reputation_delta":-1}
    unknown={**base,"local_test_note":"ignored by Rust"}
    escaped_key=raw(base).replace(b'"status"',b'"st\\u0061tus"')
    return {"reordered":raw(reorder),"present_optional":raw(option),"unknown":raw(unknown),
            "escaped_key":escaped_key,"one_explicit_null":raw({**base,"assigned_worker":None})}


def qualify(binary,build,directory):
    def bound():
        return (original_inputs()==build["repository_inputs"]
                and sha256(binary.read_bytes()).hexdigest()==build["executable_sha256"])
    if not bound():
        raise AssertionError("Original locked Worker executable/source identity differs")
    declarations=declared_input()
    results={}
    with ExitStack() as stack:
        images={b:{k:stack.enter_context(NativeModule(src,backend=b,byte_exports=("f0",)))
                   for k,src in (("framer",WJF1),("dto",NATIVE),("transaction",WAT2))}
                for b in BACKENDS}
        for label,(snapshot,spans_count,selected) in cases().items():
            d=directory/label
            d.mkdir(mode=0o700)
            journal=d/"unchanged-ingress.jsonl"
            journal.write_bytes(snapshot)
            journal.chmod(0o600)
            original=cli_artifacts(binary,journal,"original",True,None)
            if json.loads(original[2])["total_records"]!=selected:
                raise AssertionError("Genuine original CLI selected a different known count")
            if (d/"original.jsonl.index.json").read_bytes()!=original[2]:
                raise AssertionError("Both original output modes must agree on the index")
            for backend,m in images.items():
                n,spans=observed_call(m["framer"],snapshot,783)
                if n<8 or spans[n:]!=FILL*(783-n):
                    raise AssertionError("HIA WJF1 did not frame the original raw journal")
                spans_parsed=unpack_bytes(spans[:n])
                if len(spans_parsed)!=spans_count:
                    raise AssertionError("WJF1 raw span attendance differs")
                ordered=[]
                for ordinal,start,size in spans_parsed:
                    view=snapshot[start:start+size]
                    required,build_raw=observed_call(m["dto"],view,108+size)
                    if not 108 <= required <= 108+size or build_raw[required:]!=FILL*(108+size-required):
                        raise AssertionError(f"{backend}: WJD1 did not project candidate {ordinal}")
                    ordered.append(build_raw[:required])
                # The host concatenates unchanged WJL1 byte frames only.
                # No parse, selected field query or row classifier participates.
                packed=wat2(ordered)
                wanted=16+sum(map(len,original))
                result,out=observe(m["transaction"],packed,wanted+7)
                if result!=wanted or artifacts(out[:result])!=original or out[result:]!=FILL*7:
                    raise AssertionError(f"{backend}: raw → WJF → WJD → WAT2 differs from the original CLI")
                (d/(backend+".wjf")).write_bytes(spans[:n])
                (d/(backend+".wat2")).write_bytes(packed)
                (d/(backend+".wao")).write_bytes(out[:result])
                for key,data in zip(("jsonl","md","md.index.json"),artifacts(out[:result]),strict=True):
                    (d/(backend+"."+key)).write_bytes(data)
            results[label]={"raw_sha256":sha256(snapshot).hexdigest(),"logical_spans":spans_count,
                            "original_selected":selected,"artifacts":[sha256(x).hexdigest() for x in original],
                            "artifact_lengths":[len(x) for x in original]}
        outcomes={}
        for label,line in unsupported_cases().items():
            d=directory/("unsupported-"+label)
            d.mkdir(mode=0o700)
            journal=d/"unchanged-ingress.jsonl"
            journal.write_bytes(line+b"\n")
            journal.chmod(0o600)
            original=cli_artifacts(binary,journal,"original",True,None)
            if json.loads(original[2])["total_records"]!=1:
                raise AssertionError("Original accepts these deliberately unimplemented DTO layouts")
            for backend,m in images.items():
                if observed_call(m["dto"],line,192)!=(INVALID,FILL*192):
                    raise AssertionError(f"{backend}: outside declared grammar did not refuse")
            outcomes[label]="original_accepted_candidate_refused"
    if not bound() or declarations!=declared_input():
        raise AssertionError("Original source/binary binding changed")
    proof={"source_locks":original_inputs(),"declaration_sha256":declarations,
           "original_executable_sha256":build["executable_sha256"],
           "native_only_framing_decoding_and_selection":True,
           "scope":"narrow ordinary DTO, not generic Serde, filesystem or dispatch",
           "images":{b:{k:{"artifact_sha256":m.artifact_sha256,"receipt":m.receipt}
                        for k,m in roster.items()} for b,roster in images.items()},
           "scenarios":results,"unsupported_original_valid":outcomes}
    (directory/"report.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    return proof


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--original-binary",type=Path,required=True)
    p.add_argument("--original-build-receipt",type=Path,required=True)
    args=p.parse_args()
    d=args.output.resolve()
    if d.is_relative_to(ROOT):
        p.error("Store private proof outside checkout")
    d.mkdir(mode=0o700)
    print(json.dumps(qualify(args.original_binary.resolve(strict=True),
                             json.loads(args.original_build_receipt.read_bytes()),d)["scenarios"],sort_keys=True))


if __name__=="__main__":
    main()
