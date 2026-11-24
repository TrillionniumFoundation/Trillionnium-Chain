"""Physical WQS2 compatibility with the exact WQS1 wire and original Rust stdout."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query import build as prior
from hia.platform.worker_audit_sealed_query_lines.build import (
    ELF_NAME, ELF_SLOTS, CALLS, EMITTER, RAW_MAX, bounded, build, projection,
)
from hia.tests.test_worker_audit_export_row_lines_v2 import BLANK, fixture_cases, mixed
from hia.tests.test_worker_audit_sealed_query import (
    ALL_SEALS, EMPTY_INDEX, EMPTY_STDOUT, HEADER, checked_layout, digest, original_case,
    physical_fixture, refusals, transport,
)
from hia.tests.test_worker_audit_select import original_inputs
from hia.tests.test_worker_audit_task_query import MAX_TASK, query_original
from hia.tools.toolchain import checked_source


def checked_projection():
    def functions(path):
        checked, _, _, _, inputs=checked_source(path)
        return {f["name"]:f for f in checked.as_dict()["functions"]},inputs

    if EMITTER.read_bytes()!=projection():
        raise AssertionError("Unreviewed WQS2 HIA projection")
    old,_=functions(prior.EMITTER)
    new,inputs=functions(EMITTER)
    allowed={"f0","elf_header","query_thunk_1","query_thunk_3"}
    if old.keys()!=new.keys() or {k for k in old if old[k]!=new[k]}!=allowed:
        raise AssertionError("Changed HIA functions outside exact geometry projection")
    return inputs


def compare_prefix(root, receipt):
    old=(root/"old-wqs1"/"sealed-worker-task-query.elf").read_bytes()
    new=(root/ELF_NAME).read_bytes()
    left=old[:prior.THUNK_END]
    right=new[:prior.THUNK_END]
    changes={i for i,(a,b) in enumerate(zip(left,right,strict=True)) if a!=b}
    permitted={i for pos in ELF_SLOTS for i in range(pos,pos+8)}
    permitted.update(i for _,_,pos,_ in CALLS for i in range(pos+1,pos+5))
    if (not changes <= permitted or not all(pos in changes for pos in ELF_SLOTS)
            or not all(pos+1 in changes for _,_,pos,_ in CALLS)
            or left[176:prior.ADAPTER_END]!=right[176:prior.ADAPTER_END]):
        raise AssertionError("Wrong artifact-local delta")
    relocs=subprocess.check_output(["/usr/bin/readelf","-rW",str(root/"wer2.o")])
    if b"There are no relocations in this file." not in relocs:
        raise AssertionError("Strict WER2 object contains relocations")
    (root/"wer2-readelf.txt").write_bytes(relocs)
    native=checked_layout(root/ELF_NAME,root,receipt)
    return {"differing_prefix_byte_offsets":sorted(changes),**native}


class WorkerAuditSealedQueryLines(unittest.TestCase):
    def test_static_projection_and_old_wire_physical_controls(self):
        checked_projection()
        with tempfile.TemporaryDirectory(prefix="trnm-private-query-lines-") as tmp:
            root=Path(tmp)
            image,receipt=build(root/"build")
            compare_prefix(root/"build",receipt)
            head=transport(EMPTY_INDEX,BLANK+b"\r\n"+BLANK,MAX_TASK)
            got,outcome=physical_fixture(image,head)
            self.assertEqual((got.returncode,got.stdout,outcome["offset_after"]),
                             (0,EMPTY_STDOUT,len(head)))
            self.assertEqual(len(refusals(image,EMPTY_INDEX)),14)


def qualify(binary, original, output):
    def bound():
        return (original["repository_inputs"]==original_inputs()
                and original["executable_sha256"]==digest(binary.read_bytes()))
    if not bound():
        raise AssertionError("Wrong genuine locked Worker source/executable")
    pins=checked_projection()
    build_root=output/"target"
    image,receipt=build(build_root)
    static=compare_prefix(build_root,receipt)
    results={}
    pure={}
    witnessed_cap=None
    plan=(
        ("empty","blank-only",(0,)),
        ("maximum-ordered","mixed-max-rows",(MAX_TASK,0)),
        ("escaped-display-no-schema","crlf",(10,2,0)),
        ("original-control-escapes","unterminated",(2,0)),
        ("original-control-escapes","combined-65536",(2,)),
    )
    for origin,name,tasks in plan:
        bounded(output)
        directory=fresh_directory(output/name)
        sidecar,canonical=original_case(binary,directory,fixture_cases()[origin][0])
        if name=="blank-only":
            raw=BLANK+b"\r\n"+BLANK
        elif name=="mixed-max-rows":
            raw=mixed(canonical)
        elif name=="crlf":
            raw=canonical.replace(b"\n",b"\r\n")
        elif name=="unterminated":
            raw=canonical[:-1]
        else:
            pad=RAW_MAX-HEADER.size-len(sidecar)-len(canonical)
            if pad<=0 or not canonical.endswith(b"\n"):
                raise AssertionError("Cannot stage actual bounded sidecar/rows")
            raw=b" "*pad+b"\n"+canonical[:-1]
        raw_path=directory/"transformed.jsonl"
        index=directory/"transformed.jsonl.index.json"
        for p,body in ((raw_path,raw),(index,sidecar)):
            p.write_bytes(body)
            p.chmod(0o600)
        if canonical==raw:
            raise AssertionError("No physical row geometry change")
        queries={}
        for task in tasks:
            wire=transport(sidecar,raw,task)
            if len(wire)>RAW_MAX or (name=="combined-65536" and len(wire)!=RAW_MAX):
                raise AssertionError("New positive geometry left the old physical cap")
            oracle,expected=query_original(binary,raw_path,task,directory)
            want=(directory/f"query-{task}.stdout.raw").read_bytes()
            actual,trace=physical_fixture(image,wire)
            if (actual.returncode or actual.stderr or actual.stdout!=want or digest(want)!=expected
                    or trace["offset_before"]!=0 or trace["offset_after"]!=len(wire)
                    or trace["seals"]!=ALL_SEALS or not trace["input_bytes_unchanged"]):
                raise AssertionError("Named HIA output differs from genuine original stdout")
            if name=="mixed-max-rows" and task==MAX_TASK and oracle["hit_indexes"]!=list(range(64)):
                raise AssertionError("The original and candidate must include the 64th compact ordinal")
            (directory/f"{task}.sealed-frame.raw").write_bytes(wire)
            (directory/f"{task}.native-stdout.raw").write_bytes(actual.stdout)
            queries[str(task)]={**trace,"actual_rust_hits":oracle["hit_indexes"],"actual_rust_sha256":expected}
            if name=="combined-65536":
                witnessed_cap=wire
        if raw_path.read_bytes()!=raw or index.read_bytes()!=sidecar:
            raise AssertionError("Changed immutable original query copies")
        pure[name]=(sidecar,canonical)
        results[name]={"queries":queries,"sidecar_bytes":len(sidecar),"raw_rows_bytes":len(raw)}

    side,rows=pure["crlf"]
    other_side,other_rows=pure["unterminated"]
    before,sep,last=rows[:-1].rpartition(b"\n")
    if not (before and sep and last):
        raise AssertionError("Late rejection must follow multiple valid original rows")
    negatives=refusals(image,pure["blank-only"][0],(
        ("late-nbsp-next-to-ordinary-object",transport(side,before+sep+b"\xc2\xa0"+last,10)),
        ("late-unsupported-ascii-edge-space",transport(side,before+sep+b" "+last,10)),
        ("late-extra-cr-before-lf",transport(side,before+sep+last+b"\r\r\n",10)),
        ("valid-reframed-rows-mismatched-index",transport(other_side,mixed(rows),10)),
    ),fresh_directory(output/"controls"))
    if not witnessed_cap:
        raise AssertionError("Original valid combined physical cap was not observed")
    received,trace=physical_fixture(image,witnessed_cap+b"\n")
    if (received.returncode,received.stdout,trace["offset_after"])!=(71,b"",0):
        raise AssertionError("Oversize version of genuine combined witness consumed bytes")
    (output/"one-byte-over-genuine-combined.sealed-frame.raw").write_bytes(witnessed_cap+b"\n")
    negatives["one-byte-over-genuine-combined"]=trace
    # Same old wire + original compact records still runs identically on each
    # executable, and the old fixture still refuses the new raw CRLF geometry.
    previous=(build_root/"old-wqs1"/"sealed-worker-task-query.elf").read_bytes()
    for old_input,old_should_accept in ((transport(side,rows,10),True),
                                        (transport(other_side,other_rows[:-1],2),False)):
        past,_=physical_fixture(previous,old_input)
        now,_=physical_fixture(image,old_input)
        if old_should_accept:
            matches = now.returncode==0 and (past.returncode,past.stdout)==(now.returncode,now.stdout)
        else:
            matches = past.returncode==74 and not past.stdout and now.returncode==0
        if not matches:
            raise AssertionError("The new name changed compact parity or the old name widened")
    if not bound() or any(p.read_bytes()!=data for p,data in pins):
        raise AssertionError("Changed qualification source during actual execution")
    proof={"status":"PASS","build":receipt,"static_layout":static,"cases":results,"refusals":negatives,
           "original_inputs":original_inputs(),"original_executable_sha256":original["executable_sha256"],
           "host_row_or_map_parser":False,"candidate_opens_named_paths":False,"production_dispatch":False,
           "runtime_eintr_observed":False,"independent_syscall_trace":False,
           "checkout_commit":subprocess.check_output(["git","rev-parse","HEAD"],
                      cwd=EMITTER.parents[3],env={**os.environ,"GIT_NO_LAZY_FETCH":"1"}).decode().strip()}
    (output/"report.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    return proof


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for label in ("output","original-binary","original-build-receipt"):
        p.add_argument("--"+label,required=True,type=Path)
    a=p.parse_args()
    bounded(a.output.parent)
    d=qualify(a.original_binary.resolve(strict=True),
              json.loads(a.original_build_receipt.read_bytes()),fresh_directory(a.output))
    print(json.dumps({k:d[k] for k in ("status","cases","refusals")},sort_keys=True))


if __name__=="__main__":
    main()
