#!/usr/bin/env python3
"""Acquire only fixed selected member records of R1 required protocol artifact; never execute members."""
import ast,concurrent.futures,datetime,hashlib,json,os,re,stat,struct,sys,time,zlib
from pathlib import Path,PurePosixPath
BASE=Path("/private/tmp/chain-R1-required-head-protocol-artifact-review-20261114-v1")
OUT=BASE/"selected-members-v1"
TAILDIR=BASE/"tail-acquisition-v1"
HELPER=BASE/"acquire-tail-v1.py"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
TEST_SHA="c20a1d34bcb4ad9d0f37a9b65815aac3c9e50b267edb9a65e856b3acd954064f"
ARTIFACT=14120622057; SIZE=7001798; TAILSTART=6936241
DIGEST="a8c9b352fdb5bcd27785b13d753d59949e6330bbd29222104bf284b7c9822961"
SELECTORS=(
"caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct",
"from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection",
"four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged",
"from_zero_service_shares_cpu_with_honest_work_and_reopened_owner",
"from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline")
GROUPS=(("caller-records",9041,10106),("confirmation-report",155189,681123),("remaining-selectors-and-manifest",747567,765048))
INPUTS=((HELPER,19563,"34f629cbbfabfd76f733a013d1349b631c75cc14bda59d64b69401d902d3d9f1"),
(TAILDIR/"summary.json",5929,"c38a2d565cc1138d9aa543108223e3d1495b6b13412fa9f9ec8bce09da7c3431"),
(TAILDIR/"central-directory.json",46153,"6b9b809e2c65ad5540603dc16246f67c9eac158d988dedbb1966ba8a4c1c762a"),
(TAILDIR/"tail-range.body",65557,"476359df8fcc3c38b09623fa66807cce0c6f1c17c008a7738fda798e0b104b4a"),
(TAILDIR/"artifact-metadata.json",821,"44b83b461a6f5a346d2e45eba77fc0b6e65f46b91891cd5ad900b1f89239379f"),
(TAILDIR/"outer-source-and-host.json",10979,"dab4d22d6f0d80f0c6ed4469eebfc8c6fc4152f8d7aa164d626207a8e405bac1"))
VERSIONS={}
def need(ok,s):
    if not ok:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def fp(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def stable(p,n,h):
    a=p.lstat();need(p.is_absolute() and p.resolve(strict=True)==p and stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==n,"INPUT_PATH_SIZE")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as f:
        need(fp(os.fstat(f.fileno()))==fp(a),"INPUT_OPEN")
        b=f.read(n+1);need(fp(os.fstat(f.fileno()))==fp(a),"INPUT_FD_CHANGED")
    need(fp(p.lstat())==fp(a) and len(b)==n and sha(b)==h,"INPUT_SHA_OR_CHANGED")
    if str(p) in VERSIONS:need(VERSIONS[str(p)]==fp(a),"INPUT_FINAL_CHANGED")
    VERSIONS[str(p)]=fp(a)
    return b
def pairs(rows):
    o={}
    for k,v in rows:need(k not in o,"DUPLICATE_JSON_KEY");o[k]=v
    return o
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda s:(_ for _ in()).throw(ValueError("NONFINITE_JSON")))
def save(rel,b):
    p=OUT/rel;need(p.is_relative_to(OUT),"OUTPUT_BOUND")
    p.parent.mkdir(parents=True,exist_ok=True)
    need(p.parent.resolve(strict=True)==p.parent,"OUTPUT_PARENT")
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,"wb") as f:f.write(b)
    st=p.lstat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and p.read_bytes()==b,"OUTPUT_READBACK")
    return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def savej(rel,v):return save(rel,(json.dumps(v,indent=2,sort_keys=True,ensure_ascii=True)+"\n").encode())
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def get_namespace(source):
    source=source.replace('f"Range: bytes={START}-{SIZE - 1}"','f"Range: bytes={START}-{END}"').replace('f"bytes {START}-{SIZE - 1}/{SIZE}"','f"bytes {START}-{END}/{SIZE}"')
    parsed=ast.parse(source)
    wanted={"need","now","fingerprint","stable_bytes","save","save_json","pairs","parse_json","parsed_headers","capture"}
    nodes=[n for n in parsed.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign)) or isinstance(n,ast.FunctionDef) and n.name in wanted]
    need({n.name for n in nodes if isinstance(n,ast.FunctionDef)}==wanted,"EXACT_IMPORTED_HELPERS")
    ns={"__name__":"range_helpers_not_main","__file__":str(HELPER)}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(HELPER),"exec",optimize=0),ns)
    return ns,source
def acquire(source,g):
    label,start,end=g
    dest=OUT/"ranges"/label;dest.mkdir(parents=True)
    ns,_=get_namespace(source);ns.update(OUT=dest,START=start,END=end,TAIL=end-start+1,SIZE=SIZE)
    step,body=ns["capture"](label,"repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+str(ARTIFACT)+"/zip",time.monotonic()+180,range_probe=True)
    pin=None
    if step["http_status"]==206 and body:pin=ns["save"]("body" if step["complete_transport"] else "body.partial",body)
    out={"label":label,"start":start,"end":end,"bytes":end-start+1,"step":step,"body":pin}
    print(json.dumps({"range_closed":label,"exit":step["exit"],"complete":step["complete_transport"],"retained_bytes":len(body),"error":step["error"]}),flush=True)
    return out,body
def unpack(row,record):
    need(len(record)>=30,"LOCAL_HEADER_SIZE")
    sig,version,flags,method,mt,md,crc,csize,usize,nlen,xlen=struct.unpack_from("<4s5H3I2H",record,0)
    need(sig==b"PK\x03\x04" and version==row["version_needed"] and flags==row["flags"] and method==row["compression_method"],"LOCAL_CENTRAL_HEADER")
    need(not flags&0x41 and method in (0,8) and 0<nlen<=1024 and xlen<=65535,"LOCAL_FLAGS_METHOD_LENGTH")
    name=record[30:30+nlen]
    need(name.decode("utf-8" if flags&0x800 else "cp437")==row["path"],"LOCAL_CENTRAL_NAME")
    dataoff=30+nlen+xlen;end=dataoff+row["compressed_bytes"]
    need(end<=len(record) and row["uncompressed_bytes"]<=32*1024*1024,"LOCAL_COMPRESSED_BOUND")
    extra=record[30+nlen:dataoff];cur=0
    while cur<len(extra):
        need(cur+4<=len(extra),"EXTRA_FRAMING")
        tag,n=struct.unpack_from("<HH",extra,cur);cur+=4
        need(tag!=1 and cur+n<=len(extra),"ZIP64_OR_EXTRA_BOUND");cur+=n
    expected=(int(row["crc32_declared_hex"],16),row["compressed_bytes"],row["uncompressed_bytes"])
    if flags&8:
        need(all(v==0 or v==e for v,e in zip((crc,csize,usize),expected)),"LOCAL_PLACEHOLDERS")
        trailer=record[end:]
        if trailer.startswith(b"PK\x07\x08"):trailer=trailer[4:]
        need(len(trailer)==12 and struct.unpack("<3I",trailer)==expected,"DATA_DESCRIPTOR")
    else:need((crc,csize,usize)==expected and end==len(record),"LOCAL_EXACT_LENGTH")
    compressed=record[dataoff:end]
    if method==0:raw=compressed
    else:
        d=zlib.decompressobj(-15);raw=d.decompress(compressed,row["uncompressed_bytes"]+1)
        need(d.eof and not d.unused_data and not d.unconsumed_tail,"DEFLATE_EOF")
        need(not d.flush(),"DEFLATE_EXTRA_OUTPUT")
    need(len(raw)==row["uncompressed_bytes"] and zlib.crc32(raw)&0xffffffff==expected[0],"SELECTED_CRC_SIZE")
    return raw
def main():
    need(sys.flags.optimize==0,"OPTIMIZATION_FORBIDDEN");os.umask(0o077);OUT.mkdir()
    result={"schema":"trnm-r1-required-protocol-selected-member-inspection-v1","status":"HOLD","started_at":now(),"errors":[],"artifact_id":ARTIFACT,"job_id":132481412290,"run_id":43604217412,"run_attempt":1,"head":HEAD,"tree":TREE,"declared_artifact_bytes":SIZE,"declared_artifact_sha256":DIGEST,"whole_artifact_sha256_verified":False,"all_artifact_member_crc_verified":False,"selected_member_crc_sha_verified":False,"source_refs_config_CI_stage_modified":False,"no_inner_code_or_test_executed":True,"automatic_retry":False,"per_GET_timeout_seconds":180,"maximum_concurrent_GETs":3,"new_GETs":3}
    try:
        data={str(p):stable(p,n,h) for p,n,h in INPUTS}
        t=parse(data[str(TAILDIR/"summary.json")]);cd=parse(data[str(TAILDIR/"central-directory.json")])
        meta=parse(data[str(TAILDIR/"artifact-metadata.json")])
        need(t["status"]=="TAIL_AND_CENTRAL_DIRECTORY_OBSERVED" and t["metadata_identity_verified"] is True and t["artifact_id"]==ARTIFACT and t["expected_archive_bytes"]==SIZE and t["expected_whole_archive_sha256"]==DIGEST,"PINNED_TAIL_RESULT")
        need(meta["id"]==ARTIFACT and meta["digest"]=="sha256:"+DIGEST and meta["size_in_bytes"]==SIZE and meta["workflow_run"]["id"]==43604217412 and meta["workflow_run"]["head_sha"]==HEAD,"PINNED_METADATA")
        members=cd["members"];need(len(members)==109 and cd["central_directory_offset"]==6991166,"EXACT_CD")
        ordered=sorted(members,key=lambda r:r["local_header_offset"])
        need(len({r["local_header_offset"] for r in ordered})==109,"UNIQUE_LOCAL_OFFSETS")
        nextoff={r["path"]:(ordered[i+1]["local_header_offset"] if i+1<len(ordered) else cd["central_directory_offset"]) for i,r in enumerate(ordered)}
        selected={"from-zero-native/"+s+"/"+leaf for s in SELECTORS for leaf in ("stdout","stderr","process.json")}
        selected|={"from-zero-native/manifest.json","from-zero-native/confirmation/report.json","source.json"}
        chosen=[r for r in ordered if r["path"] in selected];need(len(chosen)==18,"EXACT_18_SELECTED_MEMBERS")
        for label,a,b in GROUPS:
            rows=[r for r in ordered if a<=r["local_header_offset"]<=b]
            need(rows and rows[0]["local_header_offset"]==a and nextoff[rows[-1]["path"]]==b+1 and all(r["path"] in selected for r in rows),"RANGE_ONLY_SELECTED_RECORDS")
        need(sum(b-a+1 for _,a,b in GROUPS)==544483,"EXACT_SELECTED_NETWORK_BYTES")
        source=data[str(HELPER)].decode()
        _,derived=get_namespace(source);result["capture_source"]=save("derived-capture-definitions-source.py",derived.encode())
        result["request_plan"]=savej("request-plan.json",{"groups":[{"label":l,"start":a,"end":b,"bytes":b-a+1} for l,a,b in GROUPS],"selected_paths":sorted(selected),"metadata_and_tail":t["metadata"],"new_bytes":544483,"existing_tail_reused":True,"whole_zip_unverified":True})
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futures=[ex.submit(acquire,source,g) for g in GROUPS]
            acquired=[f.result() for f in futures]
        result["ranges"]=[r for r,_ in acquired]
        savej("range-receipts.json",result["ranges"])
        need(all(r["step"]["complete_transport"] and r["step"]["exit"]==0 for r,_ in acquired),"ONE_OR_MORE_SELECTED_RANGES_FAILED")
        payloads={};records=[]
        for row in chosen:
            lo=row["local_header_offset"];hi=nextoff[row["path"]]
            need(hi>lo and hi-lo<=row["compressed_bytes"]+30+1024+65535+24,"LOCAL_RECORD_BOUND")
            if lo>=TAILSTART:
                record=data[str(TAILDIR/"tail-range.body")][lo-TAILSTART:hi-TAILSTART];origin="existing-validated-tail"
            else:
                fits=[(r,b) for r,b in acquired if r["start"]<=lo and hi<=r["end"]+1];need(len(fits)==1,"SELECTED_RECORD_COVERAGE")
                r,b=fits[0];record=b[lo-r["start"]:hi-r["start"]];origin=r["label"]
            need(len(record)==hi-lo,"EXACT_RECORD_BYTES")
            raw=unpack(row,record);payloads[row["path"]]=raw
            pin=None
            if row["path"]!="from-zero-native/confirmation/report.json":pin=save("members/"+row["path"],raw)
            records.append({"path":row["path"],"bytes":len(raw),"sha256":sha(raw),"crc32":row["crc32_declared_hex"],"crc32_verified":True,"compressed_bytes":row["compressed_bytes"],"range_source":origin,"expanded_original":pin,"expanded_in_memory_only":pin is None})
        result["selected_member_index"]=savej("selected-member-index.json",{"schema":"trnm-selected-zip-members-verified-v1","artifact_id":ARTIFACT,"whole_artifact_sha256_verified":False,"all_artifact_member_crc_verified":False,"selected_count":len(records),"files":records})
        prefix="from-zero-native/";m=parse(payloads[prefix+"manifest.json"]);fm=m.get("files")
        need(m.get("schema")=="trnm-from-zero-native-execution-v3" and isinstance(fm,dict),"MANIFEST_SCHEMA")
        actual={r["path"] for r in members if r["path"].startswith(prefix)}-{prefix+"manifest.json"}
        expected=set()
        for rel,h in fm.items():
            q=PurePosixPath(rel)
            need(q.as_posix()==rel and not q.is_absolute() and all(s not in ("",".","..") for s in q.parts) and isinstance(h,str) and re.fullmatch("[0-9a-f]{64}",h),"MANIFEST_MAP_FORMAT")
            expected.add(prefix+rel)
        need(expected==actual,"MANIFEST_CD_NAMES_EXACT")
        checked=[]
        for name,raw in payloads.items():
            if name.startswith(prefix) and name!=prefix+"manifest.json":
                need(fm[name[len(prefix):]]==sha(raw),"SELECTED_DECLARED_SHA");checked.append(name)
        need(len(checked)==16,"SELECTED_DECLARED_COUNT")
        result["filemap"]=savej("selected-filemap-verification.json",{"manifest_declared_count":len(fm),"central_directory_native_count":len(actual),"exact_declared_names_match_CD":True,"selected_declared_count":len(checked),"selected_declared_names":checked,"selected_declared_sha_matches":True,"unread_members_not_hash_verified":sorted(actual-set(checked)),"all_declared_hashes_verified":False})
        before,after=m.get("source_before"),m.get("source_after")
        need(isinstance(before,dict) and before==after and before.get("commit")==HEAD and before.get("tree")==TREE and before.get("test_sha256")==TEST_SHA,"NATIVE_SOURCE")
        tracked=before.get("tracked_source_identity")
        need(isinstance(tracked,dict) and tracked.get("schema")=="trnm-ci-source-v1" and tracked.get("candidate")==HEAD and tracked.get("tested_commit")==HEAD and tracked.get("tested_tree")==TREE and tracked.get("kind")=="head" and tracked.get("tracked_worktree_verified") is True,"TRACKED_SOURCE")
        top_source=parse(payloads["source.json"]);need(top_source==tracked,"TOP_LEVEL_NATIVE_SOURCE")
        bb,ba=m.get("binary_sha256_before"),m.get("binary_sha256_after")
        need(isinstance(bb,str) and re.fullmatch("[0-9a-f]{64}",bb) and bb==ba,"BINARY_BEFORE_AFTER")
        result["source_identity"]=savej("source-before-after-extracted.json",{"source_before":before,"source_after":after,"top_level_source":top_source,"binary_sha256_before":bb,"binary_sha256_after":ba,"binary_blob_not_downloaded":True})
        runs=m.get("runs");need(isinstance(runs,list) and [r.get("name") for r in runs]==list(SELECTORS),"FIVE_ROSTER")
        facts=[]
        for r in runs:
            name=r["name"];raws={leaf:payloads[prefix+name+"/"+leaf] for leaf in ("stdout","stderr","process.json")}
            proc=parse(raws["process.json"])
            need(proc==r.get("process") and proc.get("stdout_sha256")==sha(raws["stdout"]) and proc.get("stderr_sha256")==sha(raws["stderr"]),"PROCESS_STREAM_BINDING")
            facts.append({k:r.get(k) for k in ("name","process","passed","named_execution","failure","failure_diagnostic")})
        result["original_native_runs"]=facts
        result["manifest_outcome"]={k:m.get(k) for k in ("source_recompiled","all_named_tests_passed","format_passed","failures","passed","execution_finished","service_report","sustained_report","confirmation_report","independent_wan_accepted","work_hardness_accepted","production_activation")}
        report=parse(payloads[prefix+"confirmation/report.json"])
        need(report.get("schema")=="public-v3-signed-confirmation-pressure-v1" and isinstance(report.get("phases"),list) and len(report["phases"])==2,"REPORT_SCHEMA")
        compact=[]
        for i,phase in enumerate(report["phases"]):
            replays=phase.get("independent_history_page_replay");need(isinstance(replays,list) and len(replays)<=64,"REPLAY_BOUND")
            rows=[]
            for j,replay in enumerate(replays):
                native=replay.get("native_import_observation")
                rows.append({"json_pointer":f"/phases/{i}/independent_history_page_replay/{j}","replay":{k:v for k,v in replay.items() if k!="native_import_observation"},"host_checks":native.get("host_checks") if isinstance(native,dict) else None,"measurement_failures":native.get("measurement_failures") if isinstance(native,dict) else None})
            compact.append({"json_pointer":f"/phases/{i}","phase_scalars":{k:v for k,v in phase.items() if v is None or isinstance(v,(bool,int,float,str))},"honest_submissions_count":len(phase.get("honest_submissions",[])),"honest_history_count":len(phase.get("honest_history",[])),"verification_errors":phase.get("verification_errors"),"replays":rows})
        result["confirmation_facts"]=savej("bounded-confirmation-report-facts.json",{"report_member":next(r for r in records if r["path"]==prefix+"confirmation/report.json"),"top_scalar_values":{k:v for k,v in report.items() if v is None or isinstance(v,(bool,int,float,str))},"phases":compact,"raw_report_reconstructable_from_retained_exact_range":True,"whole_zip_not_downloaded_or_verified":True,"nested_intervals_not_additive":True,"no_wall_minus_CPU_causal_inference":True})
        result["selected_member_crc_sha_verified"]=True
        result["status"]="SELECTED_ORIGINAL_MEMBERS_VERIFIED"
    except Exception as e:
        result["errors"].append(str(e) if isinstance(e,ValueError) else type(e).__name__)
    finally:
        result["inputs_before_after_valid"]=False
        try:
            for p,n,h in INPUTS:stable(p,n,h)
            result["inputs_before_after_valid"]=True
        except Exception as e:result["errors"].append(str(e));result["status"]="HOLD"
        result["finished_at"]=now();pin=savej("summary.json",result)
        print(json.dumps({"status":result["status"],"summary":pin,"errors":result["errors"],"manifest_failures":result.get("manifest_outcome",{}).get("failures"),"whole_artifact_sha256_verified":False}),flush=True)
    return 0 if result["status"]=="SELECTED_ORIGINAL_MEMBERS_VERIFIED" else 1
if __name__=="__main__":raise SystemExit(main())
