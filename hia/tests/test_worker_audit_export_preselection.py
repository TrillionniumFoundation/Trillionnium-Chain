"""Exact Worker export from a single ordered preselection typed batch."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import (
    MAX_INPUT, NAMES, RESULT_HEADER, artifacts, fixtures, observe, typed_row, wire,
)
from hia.tests.test_worker_audit_index_group import MAPS, SCRATCH_BYTES
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame
from hia.tests.test_worker_audit_markdown_batch import ACTIVE_HEADER
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, ingress_rows, original_inputs,
)
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/audit_export_preselection.hepta"
ORIGINAL_AUDIT = ROOT / "trillionnium/crates/trnm-worker-agent/src/audit.rs"
SHADOW_STATUSES = ("rejected", "failed_adapter")


def wat2(rows):
    return b"WAT2"+wire(rows)[4:]


class WorkerAuditExportPreselection(unittest.TestCase):
    def test_one_shared_literal_decision_only_dry_before_cached_emit(self):
        checked,*_ = checked_source(NATIVE)
        functions = checked.as_dict()["functions"]
        calls = []
        for function in functions:
            for block in function["blocks"]:
                for op in block["ops"]:
                    if op.get("op") == "call":
                        calls.append((function["name"],block["id"],op["attrs"]["function"]))
        self.assertEqual([c for c in calls if c[2]=="ws_selected"],
                         [("wt_selected","entry","ws_selected")])
        self.assertEqual([c for c in calls if c[2]=="wt_selected"],
                         [("wt_measure","decide","wt_selected")])
        self.assertTrue(any(c[0]=="wt_emit_rows" and c[2]=="wj_row" for c in calls))

    def test_sparse_attendance_including_row_63_and_compact_index_offsets(self):
        # The long/unknown label on excluded rows is structurally valid WJL1.
        # No export or WIG affinity policy needs to run for that row.
        excluded = typed_row(777,"Rejected",model="안녕",agent_protocol="example-synthetic")
        active = typed_row(2,"failed_adapter",provider="display")
        terminal = typed_row(10,"rejected",provider="display")
        rows = [excluded,active,*([excluded]*28),terminal,*([excluded]*32),active]
        raw = wat2(rows)
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE,backend=backend,byte_exports=("f0",)) as module:
                n, out = observe(module,raw,8192,SCRATCH_BYTES+9)
                jl, md, idx = artifacts(out[:n])
                self.assertEqual([json.loads(r)["task_id"] for r in jl.splitlines()],[2,10,2])
                self.assertTrue(md.startswith(ACTIVE_HEADER))
                self.assertEqual(len(md.splitlines()),5)
                self.assertNotIn(b"777",out[:n])
                index=json.loads(idx)
                self.assertEqual(index["total_records"],3)
                self.assertEqual(list(index["by_task_id"].items()),[("10",[1]),("2",[0,2])])
                self.assertEqual(index["by_provider"],{"display":[0,1,2]})
                self.assertEqual(index["by_status_phase"],{"active":[0,2],"terminal":[1]})
                self.assertEqual(out[n:],FILL*(len(out)-n))
                self.assertEqual(observe(module,raw,n),(n,out[:n]))
                self.assertEqual(observe(module,raw,n-1),(INSUFFICIENT,FILL*(n-1)))
                self.assertEqual(observe(module,raw,n,SCRATCH_BYTES-1),
                                 (INSUFFICIENT,FILL*n))

    def test_late_unselected_malformed_and_both_wire_version_boundaries(self):
        selected=typed_row(2,"reveal_submitted")
        excluded=typed_row(9,"rejected ")
        # Nonindexed request ID's first byte violates its own UTF-8 field.
        bad_excluded=excluded[:108]+b"\xff"+excluded[109:]
        bad_selected=typed_row(10,"failed_submission",agent_protocol="1234")
        valid=wat2([excluded,selected,excluded])
        malformed=[b"",valid[:7],valid[:-1],valid+b"t",wire([selected]),
                   wat2([selected]*65),b"WAT2"+b"x"*(MAX_INPUT-3),
                   wat2([selected,excluded,bad_excluded]),wat2([excluded,selected,bad_selected])]
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE,backend=backend,byte_exports=("f0",)) as module:
                for invalid in malformed:
                    self.assertEqual(observe(module,invalid,4096),(INVALID,FILL*4096))
                n,out=observe(module,wat2([excluded]*64),698)
                self.assertEqual(n,698)
                jl,md,idx=artifacts(out)
                self.assertEqual((jl,md,json.loads(idx)["total_records"]),(b"",ACTIVE_HEADER,0))


def scenarios():
    base=fixtures()["maximum"][:64]
    selected=sorted(INCLUDED)
    mixed=[dict(rec,status=selected[i%4]) for i,rec in enumerate(base)]
    # Fixed positional fixture attendance, not a host classifier.
    not_present={0:"pending",2:"Rejected",5:"rejected ",7:" rejected",13:"",
                 23:"reveal_submitted\r",32:"未完成",44:"REJECTED",54:"failed_adapter "}
    for at,status in not_present.items():
        mixed[at]["status"]=status
    mixed[12]=dict(mixed[11])
    all_selected=[dict(row,status=selected[i%4]) for i,row in enumerate(base)]
    excluded=ingress_rows(["pending","Rejected","rejected\u00a0","reveal_submitted "])
    return {"mixed":(mixed,55),"all_selected":(all_selected,64),
            "excluded":(excluded,0),"empty":([],0)}


def read_jsonl(path):
    result=[json.loads(line) for line in path.read_bytes().splitlines()]
    if any(tuple(row)!=FIELDS for row in result):
        raise AssertionError("Actual exact Rust audit record layout changed")
    return result


def write_journal(path, rows):
    path.write_bytes(b"".join((json.dumps(r,ensure_ascii=False)+"\n").encode() for r in rows))
    path.chmod(0o600)
    return sha256(path.read_bytes()).hexdigest()


def invoke(binary, journal, identity, destination):
    r=subprocess.run([str(binary),"export-audit","--ingress-file",str(journal),
                      "--output-file",str(destination)],cwd=journal.parent,
                     capture_output=True,timeout=25)
    destination.with_name(destination.name+".stdout.raw").write_bytes(r.stdout)
    destination.with_name(destination.name+".stderr.raw").write_bytes(r.stderr)
    if r.returncode or r.stderr or sha256(journal.read_bytes()).hexdigest()!=identity:
        raise AssertionError("Original locked CLI/source observation failed")


def observe_original(binary, build, directory):
    def bound():
        return (build["repository_inputs"]==original_inputs()
                and sha256(binary.read_bytes()).hexdigest()==build["executable_sha256"])
    if not bound():
        raise AssertionError("Exact Worker binary/source identity differs")
    audit=ORIGINAL_AUDIT.read_bytes()
    converter=audit.split(b"fn to_enterprise_audit_export(",1)[1].split(b"\n}",1)[0]
    if converter.count(b"rec.status")!=1 or b"status: rec.status.clone()," not in converter:
        raise AssertionError("Original converter has a new dependency on status")
    base_report={}
    with ExitStack() as stack:
        modules={b:stack.enter_context(NativeModule(
            NATIVE,backend=b,byte_exports=("f0",))) for b in BACKENDS}
        for name,(rows,attendance) in scenarios().items():
            d=directory/name
            d.mkdir(mode=0o700)
            journal=d/"real-ingress.jsonl"
            original_identity=write_journal(journal,rows)
            for ext in ("jsonl","md"):
                invoke(binary,journal,original_identity,d/("oracle."+ext))
            wanted=tuple((d/("oracle."+n)).read_bytes() for n in NAMES)
            if (d/"oracle.jsonl.index.json").read_bytes()!=wanted[2]:
                raise AssertionError("Original index format oracles disagree")
            shadows=[]
            for i,status in enumerate(SHADOW_STATUSES):
                source=d/f"shadow-input-{i}.jsonl"
                changed=[{**row,"status":status} for row in rows]
                if any({k:v for k,v in x.items() if k!="status"} !=
                       {k:v for k,v in y.items() if k!="status"} for x,y in zip(rows,changed,strict=True)):
                    raise AssertionError("Shadow changed more than status")
                sid=write_journal(source,changed)
                destination=d/f"shadow-output-{i}.jsonl"
                invoke(binary,source,sid,destination)
                typed=read_jsonl(destination)
                if len(typed)!=len(rows) or any(t["status"]!=status for t in typed):
                    raise AssertionError("Shadow did not obtain all original typed records")
                shadows.append(typed)
            # Status is copied by the active converter. Restore from every
            # untouched positional source row, without a predicate or reorder.
            packed=[]
            for original, first, second in zip(rows,*shadows,strict=True):
                if any(first[k]!=second[k] for k in FIELDS if k!="status"):
                    raise AssertionError("Original shadow conversion depends on status")
                if first["task_id"]!=original["task_id"] or first["request_id"]!=original["request_id"]:
                    raise AssertionError("Original shadow row order differs from input")
                first["status"]=original["status"]
                packed.append(frame(tuple(first[k] for k in FIELDS)))
            raw=wat2(packed)
            (d/"unfiltered-typed.wat2").write_bytes(raw)
            selected=read_jsonl(d/"oracle.jsonl")
            original_index=json.loads(wanted[2])
            if len(selected)!=attendance or original_index["total_records"]!=attendance:
                raise AssertionError("Actual original exported attendance differs from fixture")
            if name=="mixed":
                if (not all(original_index[k] for k in MAPS)
                        or selected[7]!=selected[8] # ordinal 7 duplicates source row 11
                        or max(x for v in original_index["by_task_id"].values() for x in v)!=54
                        or selected[-1]["request_id"]!=rows[-1]["request_id"]):
                    raise AssertionError("Original mixed compact ordering evidence changed")
            total=RESULT_HEADER.size+sum(map(len,wanted))
            for backend,module in modules.items():
                n,out=observe(module,raw,total+11,SCRATCH_BYTES+11)
                if n!=total or artifacts(out[:n])!=wanted or out[n:]!=FILL*11:
                    raise AssertionError(f"{name} {backend}: native three-artifact bytes differ from Rust")
                (d/(backend+".envelope.raw")).write_bytes(out[:n])
                for key,data in zip(NAMES,artifacts(out[:n]),strict=True):
                    (d/(backend+"."+key)).write_bytes(data)
            if sha256(journal.read_bytes()).hexdigest()!=original_identity:
                raise AssertionError("Untouched original source snapshot changed")
            base_report[name]={"input_rows":len(packed),"original_selected_rows":attendance,
                               "typed_input_sha256":sha256(raw).hexdigest(),
                               "sizes":dict(zip(NAMES,map(len,wanted),strict=True)),
                               "sha256":dict(zip(NAMES,(sha256(v).hexdigest() for v in wanted),strict=True)),
                               "packet_bytes":total}
    if not bound():
        raise AssertionError("Actual original binary/source identity changed during observation")
    report={"original_inputs":original_inputs(),
            "original_executable_sha256":build["executable_sha256"],
            "original_converter_sha256":sha256(converter).hexdigest(),
            "shadow_source_is_test_only_status_replacement":True,
            "output_oracles_are_original_unmodified_journal":True,
            "host_preselection_or_index_construction":False,
            "native_single_call_three_artifacts":True,
            "no_raw_parser_filesystem_authority_or_production_change":True,
            "backends":{k:{"artifact_sha256":m.artifact_sha256,"receipt":m.receipt} for k,m in modules.items()},
            "scenarios":base_report}
    (directory/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    return report


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
    print(json.dumps(observe_original(args.original_binary.resolve(strict=True),
          json.loads(args.original_build_receipt.read_bytes()),d)["scenarios"],sort_keys=True))


if __name__=="__main__":
    main()
