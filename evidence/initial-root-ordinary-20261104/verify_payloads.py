#!/usr/bin/env python3
"""Verify an evidence data archive; never execute or extract embedded content."""
from pathlib import Path, PurePosixPath
import base64, hashlib, json, re, zlib
ROOT=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def read(name):
    p=PurePosixPath(name)
    assert not p.is_absolute() and ".." not in p.parts and "\\" not in name
    return (ROOT/name).read_bytes()
delivery=json.loads(read("DELIVERY_MANIFEST.json"))
for f in delivery["files"]:
    b=read(f["path"])
    assert len(b)==f["size"] and sha(b)==f["sha256"] and blob(b)==f["git_blob_sha"], f["path"]
index=json.loads(read("index.json"))
pieces=[];offset=0
for c in index["chunks"]:
    raw=read(c["path"])
    assert len(raw)==c["size"] and sha(raw)==c["sha256"]
    q=json.loads(raw);b=base64.b64decode(q["data_base64"],validate=True)
    assert q["offset"]==c["raw_offset"]==offset
    assert len(b)==q["size"]==c["raw_size"]
    assert sha(b)==q["sha256"]==c["raw_sha256"]
    pieces.append(b);offset+=len(b)
packed=b"".join(pieces)
assert len(packed)==index["gzip_size"] and sha(packed)==index["gzip_sha256"]
assert blob(packed)==delivery["gzip_git_blob_sha"]
dec=zlib.decompressobj(16+zlib.MAX_WBITS)
payload=dec.decompress(packed,index["payload_size"]+1)
assert dec.eof and not dec.unused_data and not dec.unconsumed_tail
assert len(payload)==index["payload_size"] and sha(payload)==index["payload_sha256"]
package=json.loads(payload);items={}
for f in package["files"]:
    name=f["path"];p=PurePosixPath(name)
    assert not p.is_absolute() and ".." not in p.parts and "\\" not in name
    assert name not in items and f["mode"]=="100644"
    b=base64.b64decode(f["data_base64"],validate=True)
    assert len(b)==f["size"] and sha(b)==f["sha256"] and blob(b)==f["git_blob_sha"]
    items[name]=b
assert len(items)==index["file_count"]==479
assert sum(len(b) for b in items.values())==index["raw_file_bytes"]==2659050
def obj(name):return json.loads(items[name])
sources=[
 ("failed-0878","0878ee2b630c64ac67e742165c3f20df718c537a","d92a896ce181ff473dc64b9ea49f7d9906594011",101,None),
 ("failed-ecb","ecb54d9c7b1e3fe98b7889f5c89a8b06c27c0b71","105715b984a76b5e389298d35fac5ff2c6554e5b",0,[52,1,1,0]),
 ("passed-a09","a09d2e3d70a89c69422583d020a732b9fd5a4011","a32c5e3b169370b1c923bb9a6ef7094a3d3ef041",0,[53,0,1,0]),
]
verified=[]
for prefix,head,tree,build_exit,expected in sources:
    source=obj(prefix+"/source-commit.json")
    assert (source["head"],source["tree"])==(head,tree)
    build=obj(prefix+"/initial-root-node-build.json")
    assert build["exit_code"]==build_exit and build["before"]==build["after"]
    assert (build["before"]["tested_commit"],build["before"]["tested_tree"])==(head,tree)
    assert sha(items[prefix+"/"+build["log_file"]])==build["log_sha256"]
    if expected is None:
        assert sha(items[prefix+"/initial-root-node-build.log"])=="723e3f53f7c8916a46f16f6d93ef94866983f96e1ef30eed2342995d4bb5502a"
        assert prefix+"/initial-root-node-semantics-binding.json" not in items
        verified.append({"source":head,"build_exit":101,"native_commands":0})
        continue
    binding=obj(prefix+"/initial-root-node-semantics-binding.json")
    assert binding["head"]==head and binding["all_native_commands_terminal"] and len(binding["native_commands"])==27
    assert binding["binary_sha256_before"]==binding["binary_sha256_after_latest"]
    total=[0,0,0,0];members=set()
    for c in binding["native_commands"]:
        receipt=obj(prefix+"/"+c["label"]+".json")
        assert receipt["before"]==receipt["after"] and receipt["exit_code"]==c["recorded_exit"]
        assert (receipt["before"]["tested_commit"],receipt["before"]["tested_tree"])==(head,tree)
        raw=items[prefix+"/"+receipt["log_file"]]
        assert len(raw)==receipt["log_bytes"] and sha(raw)==receipt["log_sha256"]
        matches=re.findall(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;",raw.decode(),re.M)
        assert len(matches)==1
        numbers=list(map(int,matches[0]));assert sum(numbers[:3])==len(c["registered_controls"])
        total=[a+b for a,b in zip(total,numbers)]
        for name in c["registered_controls"]:
            assert name not in members and "test "+name+" ..." in raw.decode();members.add(name)
        if c["reader_exit"]==0:
            r=obj(prefix+"/"+c["label"]+".execution.json")
            assert r["result"]=="PASS" and r["executed_tests"]==1 and r["test"]==c["registered_controls"][0]
    assert total==expected and len(members)==54
    verified.append({"source":head,"build_exit":0,"normal_native_commands":27,"passed":total[0],"failed":total[1],"ignored":total[2]})
head=sources[-1][1];tree=sources[-1][2];prefix="passed-a09"
for label in ["initial-root-clippy","initial-root-host-cargo-graph"]:
    r=obj(prefix+"/"+label+".json");assert r["exit_code"]==0 and r["before"]==r["after"]
    assert (r["before"]["tested_commit"],r["before"]["tested_tree"])==(head,tree)
    assert sha(items[prefix+"/"+r["log_file"]])==r["log_sha256"]
cpu=obj(prefix+"/initial-root-node-cpu-binding.json")
assert cpu["head"]==head and cpu["aggregate_exit"]==0 and cpu["all_native_commands_terminal"] and len(cpu["native_commands"])==2
assert cpu["binary_sha256_before"]==cpu["binary_sha256_after_latest"]=="107cf5c8589f5ce516d7d19ac9f786641ef9b17c1d57a70476b8615b13d2ddab"
assert cpu["artifact"]["features"]==["default"] and cpu["artifact"]["target"]["kind"]==["lib"]
assert cpu["artifact"]["profile"]["opt_level"]=="3" and cpu["artifact"]["profile"]["debug_assertions"] and cpu["artifact"]["profile"]["overflow_checks"]
expected_cpu={
 "initial-root-large-genesis":"store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner",
 "initial-root-auth-parent":"store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator",
}
assert [c["label"] for c in cpu["native_commands"]]==list(expected_cpu)
preflight=obj(prefix+"/cpu-preflight.json")
assert preflight["free_bytes"]==43098816512>40*1024**3
admission=obj(prefix+"/cpu-admission.json")
assert admission["head"]==head and admission["tree"]==tree and admission["approved"] is True
assert admission["selectors"]==2 and admission["executions_per_selector"]==1 and admission["retry_allowed"] is False
terminal=obj("operator-terminal/cpu-job-status.json")
assert terminal["job_id"]=="1a1a3f215de-96a-7797" and terminal["state"]=="succeeded" and terminal["exit_code"]==0 and terminal["output_complete"] and not terminal["timed_out"]
outcome=obj(prefix+"/cpu-once-result.json")
assert outcome["driver_exit"]==0 and outcome["postconditions_passed"] and not outcome["source_or_binary_retry_performed"]
assert outcome["postconditions"]["head"]==head and outcome["postconditions"]["tree"]==tree and outcome["postconditions"]["clean"]
assert outcome["postconditions"]["original_elf_sha256"]==outcome["postconditions"]["preserved_elf_sha256"]==cpu["binary_sha256_before"]
observations=[]
for c in cpu["native_commands"]:
    assert c["registered_controls"]==[expected_cpu[c["label"]]]
    assert c["recorded_exit"]==c["reader_exit"]==0
    r=obj(prefix+"/"+c["label"]+".json");assert r["exit_code"]==0 and r["before"]==r["after"]
    assert (r["before"]["tested_commit"],r["before"]["tested_tree"])==(head,tree)
    assert r["argv"][-4:]==[expected_cpu[c["label"]],"--exact","--nocapture","--test-threads=1"]
    assert r["argv"][1]=="--chdir=/home/qian-qi/worktrees/trnm-pq-history-initial-root-20261103/trillionnium/crates/trnm-pon-node"
    assert all(r["environment"][key] is None for key in ("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER"))
    raw=items[prefix+"/"+r["log_file"]]
    assert len(raw)==r["log_bytes"] and sha(raw)==r["log_sha256"]
    assert len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;",raw.decode(),re.M))==1
    rr=obj(prefix+"/"+c["label"]+".execution.json")
    assert rr["result"]=="PASS" and rr["executed_tests"]==1 and rr["test"]==c["registered_controls"][0]
    records=[json.loads(line[line.index("{"):]) for line in raw.decode().splitlines() if "{" in line]
    for d in [q for q in records if q["schema"]=="native-large-parent-original-dispatch-diagnostic-v1"]:
        f=d["actual_cpu_flow_after"];b=d["cpu_budget_after"]
        assert d["original_dispatch_result"]=={"Ok":"ok"} and f["initial_credit_ns"]==2000000000
        assert f["initial_credit_ns"]+f["credited_refill_ns"]-f["paid_cpu_debit_ns"]==f["remaining_paid_credit_ns"]>0
        assert (b["burst_ns"],b["refill_ns_per_second"],b["start_reserve_ns"],b["worker_limit"])==(2000000000,250000000,100000000,2)
        parity=[q for q in records if q["schema"]=="native-large-parent-schedule-parity-v1" and q["authenticated_backend"]==d["authenticated_backend"]]
        assert len(parity)==1 and parity[0]["native_result"]=={"Ok":"ok"}
        assert parity[0]["original_cpu_receipt"]["total_cpu_ns"]==f["paid_cpu_debit_ns"]
        observations.append({"label":c["label"],"authenticated_backend":d["authenticated_backend"],"paid_cpu_ns":f["paid_cpu_debit_ns"],"remaining_credit_ns":f["remaining_paid_credit_ns"]})
assert len(observations)==3
git_h=obj("git-objects/4c46eca89a006616e9240d983c66919071f79b41.json")
git_m=obj("git-objects/e0f831d0af21cc9eea69b5ec84788ef66e0b025c.json")
assert git_h["tree"]["sha"]==git_m["tree"]["sha"]==tree
assert [p["sha"] for p in git_m["parents"]]==["2e72a989d001cf51bd0aed0e1401526e45db31f1","4c46eca89a006616e9240d983c66919071f79b41"]
assert sha(items["cloud-harness-reviewed/chain_initial_root_normal_20261103.final.yml"])=="af6f66151bba9dc3d7d58218b2dbf84b570e75cd2acc2eec86b165200f8d5983"
print(json.dumps({"result":"PASS","scope":"lossless data and original source-bound result verification; no native execution","files":len(items),"raw_bytes":index["raw_file_bytes"],"sources":verified,"cpu_tests_passed":2,"cpu_tests_failed":0,"cpu_observations":observations,"cloud_results_claimed":False,"whole_chain_qualification_claimed":False},indent=2))
