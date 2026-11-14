import os,stat,hashlib,json,sys,datetime
from pathlib import Path
BASE=Path("/private/tmp/chain-R1-required-head-protocol-artifact-review-20261114-v1")
OUT=BASE/"final-review-v1"
def need(ok,s):
    if not ok:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,expected=None,cap=4*1024*1024):
    p=Path(p);a=p.lstat()
    need(p.resolve(strict=True)==p and stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"REGULAR_BOUND")
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),"rb") as f:
        need(fp(os.fstat(f.fileno()))==fp(a),"OPEN_IDENTITY");b=f.read(cap+1);need(fp(os.fstat(f.fileno()))==fp(a),"FD_IDENTITY")
    need(fp(p.lstat())==fp(a) and len(b)==a.st_size,"PATH_IDENTITY")
    if expected:need((len(b),sha(b))==expected,"FIXED_PIN")
    return b,fp(a)
def pin(p,b):return{"path":str(p),"bytes":len(b),"sha256":sha(b)}
def put(name,b):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
    need(p.parent.resolve(strict=True)==p.parent,"OUTPUT_PARENT")
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600),"wb") as f:f.write(b)
    rb,_=read(p);need(rb==b,"READBACK");return pin(p,b)
def jput(name,o):return put(name,(json.dumps(o,indent=2,sort_keys=True,ensure_ascii=True)+"\n").encode())
def scan(root):
    d={};dirs={}
    for current,subdirs,files in os.walk(root,followlinks=False):
        p=Path(current);st=p.lstat()
        need(stat.S_ISDIR(st.st_mode) and p.resolve(strict=True)==p,"DIRECTORY")
        dirs[str(p)]=(st.st_dev,st.st_ino,st.st_mode)
        for name in subdirs:
            q=p/name;s=q.lstat();need(stat.S_ISDIR(s.st_mode) and q.resolve(strict=True)==q,"SUBDIRECTORY")
        for name in files:
            q=p/name;b,v=read(q);d[str(q)]={"pin":pin(q,b),"identity":v}
    need(len(d)<=200 and sum(v["pin"]["bytes"] for v in d.values())<=16*1024*1024,"EVIDENCE_SCOPE_BOUND")
    return d,dirs
original,dirs=scan(BASE)
os.umask(0o077);OUT.mkdir()
put("seal-evidence-v1.py",sys.argv[1].encode())
jput("prelaunch-orchestration-error.json",{"scope":"ChatGPT JavaScript orchestration parsing before any target invocation","actual_error":"SyntaxError: Unexpected identifier 'IO'","target_started":False,"network_or_evidence_mutation":False,"correction":"Removed Markdown backtick delimiters from Python README string in orchestration literal; acquisition and inspection unchanged."})
terminals=json.loads(sys.argv[2]);tpins=[]
for g in terminals:
    pages=g["pages"];last=pages[-1];status=last["status"]
    need(status["state"]=="exited" and status["exit_code"]==0 and last["output_complete"] is True and status["capture_error"] is None,"ACTUAL_TERMINAL")
    session=last["session_id"];end=last["available_end"];ap=Path(last["archive_path"])
    need(all(p["session_id"]==session and p["truncated_before_offset"] is False for p in pages),"TERMINAL_SOURCE")
    raw,v=read(ap,cap=1024*1024);need(len(raw)==end,"COMPLETE_ARCHIVE_LENGTH")
    for page in pages:
        b=bytes.fromhex(page["bytes_hex"]);start=page["offset"]
        need(raw[start:start+len(b)]==b and sha(b)==page["chunk_sha256"] and page["next_offset"]==start+len(b),"ACTUAL_PAGE_CONTENT")
    rp=put("terminals/"+g["name"]+".stdout",raw)
    record={"schema":"trnm-actual-terminal-archive-readback-v1","session_id":session,"status":status,"actual_tool_readbacks":pages,"whole_archive":{"origin":{"host":"mac","path":str(ap)},"version":v,"preserved":rp},"raw_archive_complete":True}
    tpins.append(jput("terminals/"+g["name"]+".json",record))
def get(rel,n,h):
    p=BASE/rel;b,_=read(p,(n,h));return json.loads(b),pin(p,b)
summary,sp=get("selected-members-v1/summary.json",18874,"866b1ef149a2299538ae14449f912df1a73746af689508a08ba7aab43f28282a")
facts,fpin=get("selected-members-v1/bounded-confirmation-report-facts.json",30406,"6fff7c709de8039572ec0c210994ac4ae8059c0d6dea3a3ac73a3a6d3df2c3ac")
source,srcpin=get("selected-members-v1/source-before-after-extracted.json",2155,"fd2e27413602802d0ec163fb4af655b327a8ad9b73a1c957f8f817cf04cb5e23")
business,bpin=get("confirmation-boundary-v1/compact-business-boundaries.json",51030,"4c43e80ec62a42ed56a9d224ee256b5d78a0040523413b70385dbec72633be6d")
tail,tpin=get("tail-acquisition-v1/summary.json",5929,"c38a2d565cc1138d9aa543108223e3d1495b6b13412fa9f9ec8bce09da7c3431")
need(summary["status"]=="SELECTED_ORIGINAL_MEMBERS_VERIFIED" and not summary["errors"] and summary["inputs_before_after_valid"] is True,"SELECTED_RESULT")
need(summary["manifest_outcome"]["failures"]==["CONFIRMATION_TARGET"] and summary["manifest_outcome"]["all_named_tests_passed"] is True,"ACTUAL_OUTCOME")
need(len(summary["original_native_runs"])==5 and all(r["process"]["exit_code"]==0 and r["process"]["timed_out"] is False and r["passed"] is True and r["named_execution"]["executed_tests"]==1 for r in summary["original_native_runs"]),"FIVE_ACTUAL_RUNS")
need(source["source_before"]==source["source_after"] and source["binary_sha256_before"]==source["binary_sha256_after"],"SOURCES")
phases=[]
for p in facts["phases"]:
    scal=p["phase_scalars"]
    phases.append({"original_report_pointer":p["json_pointer"],"mode":scal["mode"],"workers":scal["workers"],"requested_window_ns":scal["requested_window_ns"],"confirmed":scal["client_confirmed_transactions"],"confirmation_latency_ns":scal["client_confirmation_latency_ns"],"honest_submissions_count":p["honest_submissions_count"],"honest_history_count":p["honest_history_count"],"replays":[{"original_report_pointer":r["json_pointer"],**r["replay"],"host_checks":r["host_checks"]} for r in p["replays"]],"verification_errors":p["verification_errors"],"finite_business_target_met":scal["finite_business_target_met"],"invariant_target_met":scal["invariant_target_met"]})
pressure=business["phases"][1];history=pressure["history"]
need(len(history)==2 and history[1]["error"]=="IO: Resource temporarily unavailable (os error 11)" and history[1]["metrics"]["failed_stage"]=="challenge" and history[1]["returned_after_window"] is True,"ACTUAL_SECOND_HISTORY")
review={"schema":"trnm-r1-required-head-protocol-selected-artifact-review-v1","closed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"status":"CLOSED_ACTUAL_REQUIRED_PROTOCOL_FAILURE","run_id":43604217412,"run_attempt":1,"job_id":132481412290,"job_url":"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43604217412/job/132481412290","head":"2a86462a1ab20c68151719ba4635e3c294391e64","tree":"5c26776f96f15fd131e85a5c2d7c5e895ad7fab4","artifact":{"id":14120622057,"name":tail["expected_artifact_name"],"bytes":7001798,"declared_sha256":tail["expected_whole_archive_sha256"],"metadata":tail["metadata"],"whole_zip_downloaded":False,"whole_zip_sha256_verified":False,"all_zip_member_CRC_verified":False,"central_directory_entries":109,"selected_members_CRC_SHA256_verified":18,"selected_native_declared_hashes_verified":16,"native_filemap_names_match_54_CD_members":True},"acquisition":{"new_GETs":5,"maximum_concurrent_GETs":3,"timeout_seconds_per_GET":180,"all_actual_exit_zero":True,"all_four_range_responses_exact_206":True,"range_body_bytes":610040,"metadata_body_bytes":821,"automatic_retry":False,"raw_headers_or_signed_URLs_retained":False,"stderr_bytes_each":0,"complete_actual_terminals":tpins},"evidence":{"tail":tpin,"selected_inspection":sp,"source":srcpin,"replay_facts":fpin,"business_boundaries":bpin,"native_filemap":summary["filemap"],"selected_member_index":summary["selected_member_index"]},"source_and_binary":source,"original_runs":summary["original_native_runs"],"manifest_outcome":summary["manifest_outcome"],"phases":phases,"specific_last_boundary":{"original_report_pointer":"/phases/1/honest_history/1","record":history[1],"independent_client_confirmation":pressure["independent_client_confirmation"],"independent_final_confirmation_stage":pressure["independent_final_confirmation_stage"],"confirmation_ended_ns":pressure["confirmation_ended_ns"],"no_second_replay_record":len(phases[1]["replays"])==1,"no_PUBLIC_REQUEST_DEADLINE_replay_error_in_this_sample":phases[1]["verification_errors"]==[] and all(r["replay_error"] is None for r in phases[1]["replays"])},"findings":["All five original Rust selector processes exited zero with one named test PASS; this does not assert the retained finite business target.","The separately validated signed confirmation report failed CONFIRMATION_TARGET on this exact required job.","Baseline confirmed one transaction within 3.196635249 seconds; the 16-worker pressure phase confirmed zero within the unchanged four-second window.","The single pressure replay was accepted at 3.999257347 seconds. A second History request began at 3.999364226 seconds and ended at 4.092303244 seconds with challenge-stage IO error 11.","This sample has no second replay and no replay PUBLIC_REQUEST_DEADLINE error; cross-cost errors are not substituted.","The record's returned_after_deadline=false and returned_after_window=true are both preserved; no reinterpretation of that measurement is asserted."],"limitations":["This is selected-member CRC/SHA and manifest binding, not whole ZIP verification. The declared provider whole ZIP digest was matched to original upload and fresh metadata, not recomputed.","The binary hash before/after is a retained manifest observation; the ELF was not downloaded.","No member code, tests, diagnostic workload, Git command, source mutation, stage mutation, resource or CI change was executed.","Host checkpoint CPU and replay CPU are nested observations; wall minus CPU does not prove scheduler or CFS cause."]}
reviewpin=jput("review.json",review)
readme="""# R1 required head protocol: retained actual failure

The exact required job 132481412290 in run 43604217412 attempt 1 tested R1 2a86462a1ab20c68151719ba4635e3c294391e64, tree 5c26776f96f15fd131e85a5c2d7c5e895ad7fab4. Its original source checks and native manifest agree before/after. All five original named Rust selectors passed with exit 0. The native runner separately rejected the finite signed-confirmation outcome with CONFIRMATION_TARGET.

Baseline confirmed one transaction in 3.196635249 s. Pressure retained exactly 16 workers and the original 4 s window: seven submissions, two History attempts, one accepted independent replay, zero completed confirmations. The accepted replay ran from 1.993352783 s to 3.999257347 s. The next History started at 3.999364226 s and ended at 4.092303244 s, failing during challenge with IO: Resource temporarily unavailable (os error 11). There is no second replay; verification_errors is empty. This is not the cross-cost sample's replay PUBLIC_REQUEST_DEADLINE.

Acquisition used one fresh metadata GET, one explicit positive 65,557-byte tail GET, and exactly three bounded selected-record GETs. All ended naturally with exit 0. All four byte ranges returned exact 206 Content-Range and body sizes. No retries or whole-ZIP download occurred. The full central directory contains 109 entries. Eighteen selected members passed CRC, size and SHA checks; sixteen native members also match the manifest's declared digests. All 54 native filenames match the directory, but unselected member contents were not checked.

The 11,707,964-byte original confirmation report is reconstructable from its retained exact compressed record. Only its necessary decoded fields are saved separately; the original packet strings in the first boundary extraction remain preserved. Compact boundary pointers address that extracted boundary document, while review.json identifies the original report pointers.

Original raw GET bodies, typed response headers, process receipts, source checks, selector streams and exact terminal archive copies are retained. Raw redirect/auth headers are not retained. No inner code, tests, source/Git/stage mutations or CI changes were performed.
"""
put("README.md",readme.encode())
for path,old in original.items():
    b,v=read(path,expected=(old["pin"]["bytes"],old["pin"]["sha256"]));need(v==old["identity"],"OLD_FILE_CHANGED")
for path,v in dirs.items():
    st=Path(path).lstat();need((st.st_dev,st.st_ino,st.st_mode)==v,"OLD_DIR_CHANGED")
jput("preexisting-identity-preservation.json",{"schema":"trnm-evidence-originals-preservation-v1","files_before":len(original),"all_original_files_bytes_sha_identity_unchanged":True,"all_original_directory_device_inode_mode_unchanged":True,"files":[{"path":p,**v} for p,v in sorted(original.items())]})
allfiles,_=scan(BASE)
entries=[{"relative_path":str(Path(p).relative_to(BASE)),"path":p,"bytes":r["pin"]["bytes"],"sha256":r["pin"]["sha256"],"origin":{"host":"mac","path":p}} for p,r in sorted(allfiles.items())]
idx=jput("EVIDENCE_INDEX.json",{"schema":"trnm-closed-evidence-index-v1","root":str(BASE),"file_count":len(entries),"total_bytes":sum(e["bytes"] for e in entries),"index_and_seal_excluded":True,"files":entries})
seal=jput("seal.json",{"schema":"trnm-closed-evidence-seal-v1","review":reviewpin,"index":idx,"original_files_preserved":len(original),"stage_modified":False,"network_or_tests_by_sealer":False,"actual_failure_preserved":"CONFIRMATION_TARGET","whole_artifact_sha256_verified":False})
for e in entries:read(e["path"],(e["bytes"],e["sha256"]))
total=sum(e["bytes"] for e in entries)+idx["bytes"]+seal["bytes"]
print(json.dumps({"review":reviewpin,"index":idx,"seal":seal,"total_files":len(entries)+2,"total_bytes":total,"selected_member_count":18,"manifest_failures":["CONFIRMATION_TARGET"]},sort_keys=True))
