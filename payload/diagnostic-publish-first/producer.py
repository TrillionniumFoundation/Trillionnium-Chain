"""Prepared task-specific R1 diagnostic tag publication and one dispatch.
Only main may create objects, one annotated tag, perform one ordinary push and one
workflow_dispatch. This never changes a source branch or grants qualification.
"""
import argparse, datetime, hashlib, json, math, os, pathlib, re, stat, sys
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
PREP=ROOT/"R1-diagnostic-tag-publication-preparation-v2"
SELF=PREP/"publish_r1_diagnostic_stage1_v2.py"
HOOK=PREP/"diagnostic_tag_pre_push_v1.py"
HOOK_BYTES=8344
HOOK_SHA="64a1d587d3a82a8232adb338da736ae0ab000f81a77b98d2f682ea8a895060e8"
PREPARER=ROOT/"prepare_pr847_audit_update_v10.py"
PREPARER_BYTES=53056
PREPARER_SHA="af773495a3e27a008377c08c87141af91f741c23a132c3615d57d51413411989"
RESUME_PRODUCER={"path":str(ROOT/"postpublication-diagnostics-resume-preparation-v1/resume_archive_only_v1.py"),"bytes":49176,"sha256":"7987be6707c8eadd6d2b14d260522b2ea95752c0358781ee69ae02739997b127"}
RESUME_SPEC={"path":str(ROOT/"postpublication-diagnostics-resume-preparation-v1/resume-spec-r1-002.json"),"bytes":2112,"sha256":"b871c073e00e8e0c74e3f593b9f5437f671ca04ba40aa6cf30290be1cb5413c6"}
RESUME_RECEIPT={"path":str(ROOT/"postpublication-diagnostics-publish-v1-r1-resume-002/summary.json"),"bytes":440684,"sha256":"70520e50f0259eb283252919ca4aa9f6da92bf15b8d5fff5d8c57dd2e0332ded"}
RESUME_TERMINAL={"path":str(ROOT/"postpublication-diagnostics-resume-002-actual-terminal-v1.json"),"bytes":4322,"sha256":"c3a04e0495394b1d6eb7b18f1eda3ed2f4a520d21252e0348e9be90bd149b738"}
RESUME_SESSION="dpty-73016034e579f3e38dff3152e1e4068a0a070dc6a81d8dd313d3f1be7d831a9c"
STAGE1=ROOT/"R1-diagnostic-tag-stage1-preparation-v3"
WORKFLOW_PIN={"path":str(STAGE1/"trnm-required-baseline.yml"),"bytes":37706,"sha256":"85e9ef1d83490fb98d57c653952fe3fff67c496c8074cbf89ee6adacb266041a"}
HELPER_PIN={"path":str(STAGE1/"r1_stage1_observation_prebuild.py"),"bytes":30436,"sha256":"98f37d9d034256acb46cc3e99282b34047033b2334021ff8b3db07c076fc6f51"}
WORKFLOW=".github/workflows/trnm-required-baseline.yml"
OLD_WORKFLOW_OID="7837ff18f48b3cb9b0d38f161fc8f27a9fdbf919"
REPO="TrillionniumFoundation/Trillionnium-Chain"
URL="https://github.com/"+REPO+".git"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
BASE="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
CANDIDATE="fix/chain-hepta-closure-candidate-20261109-481716"
TAG="diagnostic/r1-native-stage1-20261114-r1-v3"
TAGREF="refs/tags/"+TAG
ZERO="0"*40
OLD_HISTORY="5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b"
EXECUTION_ARCHIVE="0f4b8b70bde65f84139b4cc7ed9e176ed55cf1d9"
DIAG_ARCHIVE_REF="refs/tags/archive/post-publication-diagnostics-20261114-2a86462a1ab2-v1"
DIAG_ARCHIVE={"tag":DIAG_ARCHIVE_REF[10:],"tag_oid":"894875e2161bea8f0d4a135879e687de78c1f18a","commit":"ffc6e0ca4bfa7794ab6031a6e398dcd08b7a1982","tree":"49d60a411334ca5bae53c5ad6296787c3ffc496a","direct_parents":[EXECUTION_ARCHIVE],"source_commit":HEAD,"source_tree":TREE,"payload_manifest_sha256":"f39f2a27975982ec6806ff319fd15a3e902e29d92af4653d770acc1b470e9777","archive_files":1898,"archive_bytes":157679667,"file_index_sha256":"ce246d5bb36f7e18791e3041024f3ae5df81f60e470472dbb12781d9b0ddde68"}
OLD_TAGS={
 "refs/tags/archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2":"9dafd9192e4040fab530958ef71598aaec9265b9",
 "refs/tags/archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2^{}":OLD_HISTORY,
 "refs/tags/archive/execution-receipts-20261114-2a86462a1ab2-v1":"454761ef276433740453b5b80ce886c1d251c6d3",
 "refs/tags/archive/execution-receipts-20261114-2a86462a1ab2-v1^{}":EXECUTION_ARCHIVE,
 DIAG_ARCHIVE_REF:DIAG_ARCHIVE["tag_oid"],DIAG_ARCHIVE_REF+"^{}":DIAG_ARCHIVE["commit"]}
ACTOR={"login":"ProfHepta","id":102159240}
API_VERSION="2026-03-10"
DISPATCH_ENDPOINT="repos/"+REPO+"/actions/workflows/trnm-required-baseline.yml/dispatches"
TRANSPORT_SECONDS=3600
DISPATCH_SECONDS=180
MAX_META=16*1024*1024
MAX_FILE=64*1024*1024
READS={}

def need(ok, why):
    if not ok:
        raise ValueError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def encode(v):
    return (json.dumps(v,indent=2,sort_keys=True,ensure_ascii=False,allow_nan=False)+"\n").encode()

def parse(raw):
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,"duplicate JSON key"); out[k]=v
        return out
    def invalid(value):
        raise ValueError("nonfinite JSON")
    def finite(value):
        n=float(value); need(math.isfinite(n),"nonfinite JSON"); return n
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid,parse_float=finite)

def fp(s):
    return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns

def relative(value):
    need(type(value) is str and 0<len(value.encode())<=4096,"relative path type/size")
    p=pathlib.PurePosixPath(value)
    need(not p.is_absolute() and str(p)==value and len(p.parts)<=32
         and all(x not in (".","..","") and x.casefold()!=".git" for x in p.parts)
         and "\\" not in value and all(32<=ord(c)!=127 for c in value),"relative path")
    return p

def absolute(value):
    need(type(value) is str and "\\" not in value and all(32<=ord(c)!=127 for c in value),"absolute path")
    p=pathlib.Path(value)
    need(p.is_absolute() and str(p)==value and ".." not in p.parts
         and p.resolve(strict=True)==p and p.is_relative_to(ROOT),"canonical authorized path")
    return p

def stable(path, maximum=MAX_META):
    p=absolute(str(path)); before=p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,
         "regular single-link bounded file")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(fp(os.fstat(fd))==fp(before),"file replaced")
        chunks=[]; count=0
        while True:
            b=os.read(fd,1024*1024)
            if not b:
                break
            count+=len(b); need(count<=maximum,"file cap"); chunks.append(b)
        need(fp(os.fstat(fd))==fp(before),"file changed")
    finally:
        os.close(fd)
    need(fp(p.lstat())==fp(before) and count==before.st_size,"path changed")
    raw=b"".join(chunks)
    old=READS.setdefault(str(p),(fp(before),len(raw),sha(raw)))
    need(old==(fp(before),len(raw),sha(raw)),"input changed between reads")
    return raw

def pin(value, maximum=MAX_META):
    need(type(value) is dict and set(value)=={"path","bytes","sha256"},"pin fields")
    need(type(value["bytes"]) is int and 0<=value["bytes"]<=maximum
         and type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",value["sha256"]),
         "pin types")
    raw=stable(value["path"],maximum)
    need(len(raw)==value["bytes"] and sha(raw)==value["sha256"],"pin mismatch")
    return raw

def fence():
    for path,(identity,size,digest) in list(READS.items()):
        raw=stable(path,MAX_FILE)
        need(fp(pathlib.Path(path).lstat())==identity and len(raw)==size and sha(raw)==digest,
             "final input fence")

def source_identity(raw):
    v=parse(raw)
    wanted={"schema":"trnm-ci-source-v1","kind":"head","candidate":HEAD,
            "base":None,"prospective_merge":None,"tested_commit":HEAD,"tested_tree":TREE,
            "tracked_worktree_verified":True,"tests_executed_by_identity_check":False,
            "tracked_entries":41677,"tracked_bytes":3994964901}
    need(type(v) is dict and set(v)==set(wanted),"exact source fields")
    need(all(type(v[k]) is type(x) and v[k]==x for k,x in wanted.items()),"exact typed R1 source")
    return v


def saved_step(receipt,directory,label,argv,timeout):
    rows=[r for r in receipt["steps"] if r.get("label")==label]
    need(len(rows)==1,"single saved command:"+label)
    row=rows[0]
    need(row["argv"]==argv and row["cwd"]==str(SOURCE)
         and type(row["exit"]) is int and row["exit"]==0
         and type(row["timeout_seconds"]) is int and row["timeout_seconds"]==timeout,
         "saved command identity:"+label)
    streams={}
    for ch in ("stdout","stderr"):
        need(row[ch+"_path"]==str(directory/(label+"."+ch)),"saved output path")
        streams[ch]=pin({k:row[ch+"_"+k] for k in ("path","bytes","sha256")})
    return streams

def hook_proof(F,hroot,expected,oldtags,tagref,tagoid,template,schema):
    expected_hook={"origin":URL,"remote_heads":expected,"old_archive_tags":oldtags,
                   "new_tag_ref":tagref,"updates":{tagref:{"local_ref":tagref,"new":tagoid,"old":ZERO}}}
    expected_raw=encode(expected_hook)
    need(template.count(b"__EXPECTED_SHA256__")==1
         and template.count(b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__")==1,"fixed hook markers")
    effective=template.replace(b"__EXPECTED_SHA256__",sha(expected_raw).encode()).replace(
        b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__",("EXPECTED_BYTES = "+str(len(expected_raw))).encode())
    raw=stable(hroot/"receipt.json"); r=parse(raw)
    need(r["schema"]==schema and r["status"]=="passed" and r["errors"]==[]
         and r["argv"]==[str(hroot/"pre-push"),"origin",URL]
         and r["hook_sha256"]==sha(effective) and r["expected_sha256"]==sha(expected_raw)
         and r["updates"]==expected_hook["updates"],"actual EOF/tuple hook proof")
    commands=[
        ("push-url",["git","remote","get-url","--push","--all","origin"]),
        ("fetch-url",["git","remote","get-url","--all","origin"]),
        ("heads",["git","ls-remote","--heads","origin"]),
        ("tags",["git","ls-remote","origin",*sorted(oldtags),tagref,tagref+"^{}"])]
    need(type(r["commands"]) is list and len(r["commands"])==4,"four original hook commands")
    outputs={}
    for row,(label,argv) in zip(r["commands"],commands):
        need(row["label"]==label and row["argv"]==argv and type(row["exit"]) is int
             and row["exit"]==0 and type(row["timeout_seconds"]) is int
             and row["timeout_seconds"]==90,"hook command identity")
        for ch in ("stdout","stderr"):
            need(row[ch+"_path"]==str(hroot/(label+"."+ch)),"hook raw origin")
            outputs[label,ch]=pin({k:row[ch+"_"+k] for k in ("path","bytes","sha256")})
    need(outputs["push-url","stdout"].decode().splitlines()==[URL]
         and outputs["fetch-url","stdout"].decode().splitlines()==[URL]
         and F["parse_refs"](outputs["heads","stdout"],heads=True)==expected
         and F["parse_refs"](outputs["tags","stdout"],allowed=set(oldtags)|{tagref,tagref+"^{}"})==oldtags,
         "actual complete hook URL/heads/tags")
    need(stable(hroot/"expected.json")==expected_raw and stable(hroot/"pre-push")==effective,
         "original effective hook bytes")
    return {"path":str(hroot/"receipt.json"),"bytes":len(raw),"sha256":sha(raw)}

def closed_archive(spec):
    wanted={"producer":RESUME_PRODUCER,"spec":RESUME_SPEC,"receipt":RESUME_RECEIPT,"terminal":RESUME_TERMINAL}
    need(encode(spec)==encode(wanted),"fixed naturally closed resume002 inputs")
    rraw=pin(RESUME_PRODUCER)
    R={"__name__":"_reviewed_archive_resume_constants_only","__file__":RESUME_PRODUCER["path"]}
    exec(compile(rraw,RESUME_PRODUCER["path"],"exec",optimize=0),R)
    need(R["HEAD"]==HEAD and R["TREE"]==TREE and R["SOURCE"]==SOURCE,"reviewed archive producer scope")
    rs=parse(pin(RESUME_SPEC)); receipt=parse(pin(RESUME_RECEIPT)); terminal=parse(pin(RESUME_TERMINAL))
    need(rs["schema"]=="trnm-postpublication-diagnostic-archive-resume-spec-v1"
         and rs["producer_sha256"]==RESUME_PRODUCER["sha256"]
         and encode(rs["archive"])==encode(DIAG_ARCHIVE)
         and rs["original_producer"]==R["ORIGINAL_PRODUCER"]
         and rs["original_spec"]==R["ORIGINAL_SPEC"]
         and rs["original_receipt"]==R["ORIGINAL_RECEIPT"]
         and rs["original_terminal"]==R["ORIGINAL_TERMINAL"]
         and type(rs["transport_timeout_seconds"]) is int and rs["transport_timeout_seconds"]==3600,
         "fixed original archive provenance")
    directory=pathlib.Path(rs["evidence_dir"])
    need(directory==pathlib.Path(RESUME_RECEIPT["path"]).parent,"closed receipt directory")
    prior_spec=parse(pin(R["ORIGINAL_SPEC"]))
    pr=pin({"path":str(PREPARER),"bytes":PREPARER_BYTES,"sha256":PREPARER_SHA})
    P={"__name__":"_reviewed_r1_publication_proof_only","__file__":str(PREPARER)}
    exec(compile(pr,str(PREPARER),"exec",optimize=0),P)
    need(P["SOURCE"]==SOURCE and P["ROOT"]==ROOT and P["REPO"]==REPO,"reviewed R1 validator scope")
    ir=pin(prior_spec["publication_inputs"])
    ctx=P["validate_inputs"](prior_spec["publication_inputs"]["path"],sha(ir))
    F,H=ctx["F"],ctx["H"]
    expected=ctx["publication_completion"]["observation"]["heads"]
    older={k:v for k,v in OLD_TAGS.items() if k not in (DIAG_ARCHIVE_REF,DIAG_ARCHIVE_REF+"^{}")}
    need(ctx["head"]==HEAD and ctx["tree"]==TREE and ctx["facts"]["base"]==BASE
         and ctx["publication_actor"]==ACTOR and type(ctx["publication_actor"]["id"]) is int
         and ctx["publication_completion"]["status"]=="confirmed"
         and ctx["publication_completion"]["observation"]["tags"]==older
         and type(expected) is dict and len(expected)==908 and expected["main"]==BASE
         and expected[CANDIDATE]==HEAD,"actual published R1 and original 908 heads")
    original=parse(pin(R["ORIGINAL_RECEIPT"])); original_terminal=parse(pin(R["ORIGINAL_TERMINAL"]))
    original_source=R["validate_first_failure"](original,original_terminal,DIAG_ARCHIVE,expected,ctx)
    need(receipt["schema"]=="trnm-postpublication-diagnostic-archive-resume-receipt-v1"
         and receipt["status"]=="confirmed" and receipt["driver"]==RESUME_PRODUCER
         and receipt["spec"]==RESUME_SPEC and receipt["head"]==HEAD and receipt["tree"]==TREE
         and receipt["main"]==BASE and receipt["errors"]==[]
         and encode(receipt["archive"])==encode(DIAG_ARCHIVE)
         and receipt["push_started"] is True and type(receipt["push_exit"]) is int and receipt["push_exit"]==0,
         "actual successful closed archive resume")
    for key in ("source_after_valid","exact_hook_verified","local_ref_fence_valid","local_archive_verified","original_hook_verified"):
        need(receipt[key] is True,"closed archive required flag:"+key)
    for key in ("archive_objects_started","local_tag_created","qualification_granted","hosted_ci_qualification","main_merged",
                "branches_deleted","protection_changed","source_files_changed","candidate_branch_updated","automatic_retry_authorized"):
        need(receipt[key] is False,"archive cannot imply extra mutation:"+key)
    need(encode(receipt["original_attempt"])==encode({"receipt":R["ORIGINAL_RECEIPT"],"terminal":R["ORIGINAL_TERMINAL"],
         "status":original["status"],"push_exit":original["push_exit"]}) and original["status"]=="UNKNOWN"
         and original["push_exit"]==1,"original failed publication remains failed")
    need(receipt["publication_facts"]==ctx["facts"] and receipt["publication_completion"]==ctx["publication_completion"],
         "original R1 publication chain unchanged")
    need(terminal.get("host")=="mac" and terminal.get("session_id")==RESUME_SESSION
         and terminal.get("output_complete") is True and terminal.get("truncated_before_offset") is False
         and terminal.get("text_is_lossy") is False and terminal.get("utf8_pending") is False
         and terminal["status"].get("state")=="exited" and type(terminal["status"].get("exit_code")) is int
         and terminal["status"]["exit_code"]==0 and terminal["status"].get("output_complete") is True
         and terminal["status"].get("capture_error") is None,"actual natural complete resume002 terminal")
    need(type(terminal.get("bytes_hex")) is str and re.fullmatch(r"(?:[0-9a-f]{2})*",terminal["bytes_hex"]),"terminal bytes")
    tb=bytes.fromhex(terminal["bytes_hex"])
    need(sha(tb)==terminal["chunk_sha256"] and type(terminal["offset"]) is int and terminal["offset"]==0
         and all(type(n) is int and n==len(tb) for n in (terminal["next_offset"],terminal["available_end"],
             terminal["status"]["bytes_seen"],terminal["status"]["bytes_stored"])),"complete terminal byte coverage")
    printed={"schema":receipt["schema"],"status":"confirmed","head":HEAD,"tree":TREE,"archive":DIAG_ARCHIVE,
             "push_started":True,"push_exit":0,"source_after_valid":True,"exact_hook_verified":True,"receipt":RESUME_RECEIPT["path"]}
    need(len(tb.splitlines())==1 and encode(parse(tb.splitlines()[0]))==encode(printed),"terminal actual outcome binding")
    for suffix in ("before","after"):
        streams=saved_step(receipt,directory,"verify-source-"+suffix,
            [H["PYTHON"],"-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",HEAD,
             "--output",str(directory/("source-"+suffix+".json"))],180)
        sidecar=stable(directory/("source-"+suffix+".json"))
        need(streams["stdout"]==sidecar==original_source and source_identity(sidecar)==ctx["gate_source"],
             "closed archive exact source sidecar/stdout")
    saved_step(receipt,directory,"atomic-archive-resume",
        ["git","-c","core.hooksPath="+str(directory/"hooks"),"push","--verify","--atomic",
         "--porcelain","--verbose","--progress","origin",DIAG_ARCHIVE_REF+":"+DIAG_ARCHIVE_REF],3600)
    a=saved_step(receipt,directory,"remote-after-heads",["git","ls-remote","--heads","origin"],180)
    b=saved_step(receipt,directory,"remote-after-tags",["git","ls-remote","origin",*sorted(older),
         DIAG_ARCHIVE_REF,DIAG_ARCHIVE_REF+"^{}"],180)
    need(F["parse_refs"](a["stdout"],heads=True)==expected
         and F["parse_refs"](b["stdout"],allowed=set(OLD_TAGS))==OLD_TAGS
         and receipt["remote_after"]["matches"] is True and receipt["remote_after"]["errors"]==[]
         and receipt["remote_after"]["heads"]==expected and receipt["remote_after"]["tags"]==OLD_TAGS,
         "actual closed 908 heads and three archives")
    old_hook=R["pin"]({"path":str(R["HOOK"]),"bytes":R["HOOK_BYTES"],"sha256":R["HOOK_SHA"]})
    proof=hook_proof(F,directory/"hooks",expected,older,DIAG_ARCHIVE_REF,DIAG_ARCHIVE["tag_oid"],
                     old_hook,"trnm-postpublication-one-tag-prepush-v1")
    need(proof==receipt["hook_receipt"],"actual saved resume hook pin")
    fence(); R["fence"](); F["check_versions"](ctx["snapshots"])
    return P,R,F,H,ctx,expected,original_source

def index_snapshot(path):
    need(path.is_absolute() and path.resolve(strict=True)==path,"source index canonical")
    s=path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=MAX_FILE,"source index bounded regular")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    digest=hashlib.sha256(); count=0
    try:
        need(fp(os.fstat(fd))==fp(s),"source index replaced")
        while True:
            b=os.read(fd,1024*1024)
            if not b: break
            count+=len(b); need(count<=MAX_FILE,"source index bound"); digest.update(b)
        need(fp(os.fstat(fd))==fp(s),"source index changed")
    finally:
        os.close(fd)
    need(fp(path.lstat())==fp(s) and count==s.st_size,"source index path changed")
    return {"path":str(path),"version":list(fp(s)),"bytes":count,"sha256":digest.hexdigest()}

def dispatch_response(raw):
    need(len(raw)<=1024*1024,"dispatch response bound")
    normalized=raw.replace(b"\r\n",b"\n")
    header,sep,body=normalized.partition(b"\n\n")
    lines=header.splitlines()
    need(sep and lines and re.fullmatch(rb"HTTP/[0-9.]+ 200(?: [^\n]*)?",lines[0]),"actual dispatch HTTP 200")
    need(sum(line.startswith(b"HTTP/") for line in lines)==1,"single dispatch response")
    v=parse(body)
    need(type(v) is dict and set(v)=={"workflow_run_id","run_url","html_url"}
         and type(v["workflow_run_id"]) is int and v["workflow_run_id"]>0,
         "current API run response fields")
    rid=str(v["workflow_run_id"])
    need(v["run_url"]=="https://api.github.com/repos/"+REPO+"/actions/runs/"+rid
         and v["html_url"]=="https://github.com/"+REPO+"/actions/runs/"+rid,
         "exact repository dispatch URLs")
    return v

def main():
    need(not sys.flags.optimize and pathlib.Path(__file__).resolve(strict=True)==SELF,"fixed nonoptimized producer")
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--spec",required=True); ap.add_argument("--spec-bytes",required=True,type=int)
    ap.add_argument("--spec-sha256",required=True); args=ap.parse_args()
    spec_pin={"path":args.spec,"bytes":args.spec_bytes,"sha256":args.spec_sha256}
    raw=pin(spec_pin); spec=parse(raw)
    need(type(spec) is dict and set(spec)=={"schema","producer_sha256","evidence_dir","diagnostic_tag",
         "workflow","stage1_helper","confirmed_archive_resume","transport_timeout_seconds","dispatch_timeout_seconds"},
         "task-specific diagnostic publication spec")
    need(spec["schema"]=="trnm-r1-diagnostic-stage1-publication-spec-v1" and spec["diagnostic_tag"]==TAG
         and spec["workflow"]==WORKFLOW_PIN and spec["stage1_helper"]==HELPER_PIN
         and type(spec["transport_timeout_seconds"]) is int and spec["transport_timeout_seconds"]==TRANSPORT_SECONDS
         and type(spec["dispatch_timeout_seconds"]) is int and spec["dispatch_timeout_seconds"]==DISPATCH_SECONDS,
         "fixed reviewed workflow/helper/tag/budgets")
    own=stable(SELF,128*1024); need(sha(own)==spec["producer_sha256"],"producer pin")
    workflow=pin(WORKFLOW_PIN); helper=pin(HELPER_PIN)
    begin=b'          cat > "$RUNNER_TEMP/r1-stage1-helper.py" <<'+b"'R1_STAGE1_PY'\n"
    end=b"          R1_STAGE1_PY\n"
    need(workflow.count(begin)==workflow.count(end)==1,"one embedded reviewed helper")
    lines=workflow.split(begin,1)[1].split(end,1)[0].splitlines(keepends=True)
    need(all(x.startswith(b"          ") for x in lines) and b"".join(x[10:] for x in lines)==helper,
         "reviewed workflow/helper exact byte coupling")
    template=pin({"path":str(HOOK),"bytes":HOOK_BYTES,"sha256":HOOK_SHA})
    # This is a fixed already-closed actual success, not a Boolean supplied by a future caller.
    # No Git object/ref creation or remote call can precede this complete proof.
    P,R,F,H,ctx,expected,closed_source=closed_archive(spec["confirmed_archive_resume"])
    ev=pathlib.Path(spec["evidence_dir"])
    need(ev.parent==ROOT and re.fullmatch(r"r1-diagnostic-stage1-publish-v1-[a-z0-9-]+",ev.name)
         and ROOT.resolve(strict=True)==ROOT,"new create-only evidence directory")
    ev.mkdir(mode=0o700,exist_ok=False); os.umask(0o077)
    env=P["safe_environment"](H)
    env.pop("GH_DEBUG",None); env["GH_HOST"]="github.com"; env["GIT_TERMINAL_PROMPT"]="0"
    need("GIT_INDEX_FILE" not in env,"source index override forbidden")
    state={"schema":"trnm-r1-diagnostic-stage1-publication-receipt-v1","status":"HOLD","started_at":now(),
           "driver":{"path":str(SELF),"bytes":len(own),"sha256":sha(own)},"spec":spec_pin,
           "subject_commit":HEAD,"subject_tree":TREE,"main":BASE,"candidate_branch":CANDIDATE,
           "workflow":WORKFLOW_PIN,"stage1_helper":HELPER_PIN,"diagnostic_tag":TAG,
           "archive_resume_proof":spec["confirmed_archive_resume"],"preserved_archive_tags":OLD_TAGS,
           "control":None,"objects_started":False,"local_tag_created":False,
           "push_started":False,"push_exit":None,"publication_confirmed":False,
           "dispatch_started":False,"dispatch_exit":None,"dispatch_status":"NOT_STARTED","dispatch_response":None,
           "remote_before":None,"remote_after":None,"remote_final":None,
           "source_after_valid":False,"local_ref_fence_valid":False,"source_index_unchanged":False,
           "exact_hook_verified":False,"steps":[],"errors":[],
           "source_or_branch_changed":False,"main_or_pr_changed":False,"protection_changed":False,
           "required_ci_replaced":False,"qualification_granted":False,"diagnostic_result_observed":False,
           "repository_template_push_executed":False,"automatic_retry_authorized":False,
           "untouched_refs_atomically_locked":False}
    def emit(name,b):
        p=ev/name
        with p.open("xb") as f:
            f.write(b); f.flush(); os.fsync(f.fileno())
        return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
    def save():
        p=ev/"summary.next"
        with p.open("xb") as f:
            f.write(encode(state)); f.flush(); os.fsync(f.fileno())
        os.replace(p,ev/"summary.json")
    def run(label,argv,data=None,timeout=180,must=True):
        need(re.fullmatch(r"[a-z0-9-]+",label) and not any(x["label"]==label for x in state["steps"]),
             "unique command label")
        row={"label":label,"argv":argv,"cwd":str(SOURCE),"timeout_seconds":timeout,"started_at":now()}
        q=H["capture"](argv,env,data=data,timeout=timeout)
        row.update(exit=q.returncode,finished_at=now())
        if data is not None:
            row.update(stdin_bytes=len(data),stdin_sha256=sha(data))
        for channel in ("stdout","stderr"):
            b=getattr(q,channel)
            need(len(b)<=MAX_META,"bounded command output")
            rec=emit(label+"."+channel,b)
            for k,v in rec.items():
                row[channel+"_"+k]=v
        state["steps"].append(row)
        with (ev/"steps.jsonl").open("ab") as f:
            f.write(encode(row).replace(b"\n",b"")+b"\n"); f.flush(); os.fsync(f.fileno())
        if must and q.returncode!=0:
            save(); raise ValueError(label+" failed; original output retained")
        return q
    def git(label,*argv,data=None,must=True):
        return run(label,["git","--no-replace-objects",*argv],data=data,timeout=60,must=must)
    def value(label,*argv):
        return git(label,*argv).stdout.decode("ascii").strip()

    initial_identity=None
    def identity(label):
        v={"head":value(label+"-head","rev-parse","HEAD"),
           "tree":value(label+"-tree","rev-parse","HEAD^{tree}"),
           "status":git(label+"-status","status","--porcelain=v1","--untracked-files=all").stdout.decode(),
           "symbolic_ref":value(label+"-symbolic","symbolic-ref","HEAD")}
        need(v["head"]==HEAD and v["tree"]==TREE and v["status"]==""
             and v["symbolic_ref"].startswith("refs/heads/"),"fixed clean original source checkout")
        need(initial_identity is None or v==initial_identity,"original checkout identity changed")
        return v
    def refs(label):
        raw=git(label,"for-each-ref","--format=%(refname) %(objectname)").stdout
        out={}
        for line in raw.decode("ascii").splitlines():
            a=line.split(); need(len(a)==2 and a[0] not in out and re.fullmatch(r"[0-9a-f]{40}",a[1]),"local refs")
            out[a[0]]=a[1]
        return out
    def hook_guard(label):
        q=git(label+"-config","config","--get-all","core.hooksPath",must=False)
        need(q.returncode==1 and q.stdout==b"" and q.stderr==b"","an effective required hook must not be replaced")
        p=pathlib.Path(value(label+"-default","rev-parse","--path-format=absolute","--git-path","hooks/pre-push"))
        need(not p.exists() and not p.is_symlink(),"an existing default hook must not be replaced")
        for suffix,argv in (("push",["remote","get-url","--push","--all","origin"]),
                            ("fetch",["remote","get-url","--all","origin"])):
            need(git(label+"-"+suffix,*argv).stdout.decode().splitlines()==[URL],"single canonical origin")
        return {"config_exit":q.returncode,"default_hook_path":str(p),"origin":URL}

    def actor(label):
        v=parse(run(label,["gh","api","user","--jq","{login,id}"]).stdout)
        need(encode(v)==encode(ACTOR) and type(v["id"]) is int,"actual ProfHepta actor")
        return v
    def observe(label,control=None):
        a=run(label+"-heads",["git","ls-remote","--heads","origin"],must=False)
        b=run(label+"-tags",["git","ls-remote","origin",*sorted(OLD_TAGS),TAGREF,TAGREF+"^{}"],must=False)
        out={"observed_at":now(),"heads":None,"tags":None,"errors":[],"matches":False}
        try:
            need(a.returncode==b.returncode==0,"fresh complete readbacks")
            out["heads"]=F["parse_refs"](a.stdout,heads=True)
            out["tags"]=F["parse_refs"](b.stdout,allowed=set(OLD_TAGS)|{TAGREF,TAGREF+"^{}"})
            wanted=dict(OLD_TAGS)
            if control is not None: wanted.update({TAGREF:control["tag_oid"],TAGREF+"^{}":control["commit"]})
            out["matches"]=out["heads"]==expected and out["tags"]==wanted
        except Exception as e:
            out["errors"].append({"type":type(e).__name__,"message":str(e)})
        return out
    def object_raw(label,kind,oid,limit):
        need(re.fullmatch(r"[0-9a-f]{40}",oid),"object id")
        size=value(label+"-size","cat-file","-s",oid)
        need(re.fullmatch(r"[1-9][0-9]*",size) and int(size)<=limit,"object bound")
        b=git(label,"cat-file",kind,oid).stdout
        need(len(b)==int(size) and F["git_object_oid"](kind,b)==oid,"object content address")
        return b
    def verify_source(label,filename):
        q=run(label,[H["PYTHON"],"-B","scripts/ci/verify_ci_source.py","--kind","head",
              "--expected-head",HEAD,"--output",str(ev/filename)])
        sidecar=stable(ev/filename)
        need(q.stdout==sidecar==closed_source and source_identity(sidecar)==ctx["gate_source"],
             "actual R1 complete tracked source stdout/sidecar")
        return sidecar
    def input_fence():
        fence(); R["fence"](); F["check_versions"](ctx["snapshots"])
    emit("spec.json",raw); emit("producer.py",own); emit("reviewed-workflow.yml",workflow)
    emit("reviewed-stage1-helper.py",helper); emit("confirmed-archive-resume-proof.json",encode(spec["confirmed_archive_resume"]))
    save()
    before_refs=None; guard=None; index_path=None; before_index=None
    expected_raw=None; effective=None; control=None
    try:
        # Literal default preflight, never a substitution with --audit.
        run("project-preflight-before-objects",["bash","scripts/project-preflight.sh"])
        initial_identity=identity("source-initial")
        before_refs=refs("local-refs-before")
        need(TAGREF not in before_refs,"new diagnostic tag must not already exist locally")
        index_path=pathlib.Path(value("source-index-path","rev-parse","--path-format=absolute","--git-path","index"))
        before_index=index_snapshot(index_path); state["source_index_before"]=before_index
        guard=hook_guard("hook-initial"); who=actor("actor-before")
        state["remote_before"]=observe("remote-before")
        need(state["remote_before"]["matches"],"all heads/three archives differ or diagnostic tag already exists")
        verify_source("verify-source-before","source-before.json")
        for n,(ref,oid) in enumerate((x for x in OLD_TAGS.items() if not x[0].endswith("^{}")),1):
            need(value("old-tag-"+str(n),"rev-parse",ref)==oid
                 and value("old-peel-"+str(n),"rev-parse",ref+"^{}")==OLD_TAGS[ref+"^{}"],"old archive local identity")
            F["check_tag_object"](object_raw("old-tag-object-"+str(n),"tag",oid,64*1024),oid,ref[10:],OLD_TAGS[ref+"^{}"])
        F["check_commit_object"](object_raw("closed-diagnostic-archive","commit",DIAG_ARCHIVE["commit"],128*1024),
                                 DIAG_ARCHIVE["commit"],DIAG_ARCHIVE["tree"],DIAG_ARCHIVE["direct_parents"])
        old_line=git("original-workflow-entry","ls-tree",HEAD,"--",WORKFLOW).stdout.decode()
        need(old_line=="100644 blob "+OLD_WORKFLOW_OID+"\t"+WORKFLOW+"\n","original workflow entry")
        input_fence()
        state["objects_started"]=True; save()
        oid=git("diagnostic-workflow-blob","hash-object","-w","--stdin",data=workflow).stdout.decode().strip()
        need(oid==F["git_object_oid"]("blob",workflow),"written workflow identity")
        temporary_index=ev/"temporary-index"
        need(not temporary_index.exists() and not temporary_index.is_symlink(),"fresh independent temporary index")
        env["GIT_INDEX_FILE"]=str(temporary_index)
        try:
            git("temporary-index-read-tree","read-tree",TREE)
            git("temporary-index-one-workflow","update-index","--add","--cacheinfo","100644,"+oid+","+WORKFLOW)
            control_tree=value("temporary-index-write-tree","write-tree")
        finally:
            env.pop("GIT_INDEX_FILE",None)
        need(re.fullmatch(r"[0-9a-f]{40}",control_tree) is not None,"control tree")
        need(index_snapshot(index_path)==before_index,"real source index was not changed")
        changed=git("control-tree-changed-paths","diff-tree","--no-commit-id","--name-only","-r",TREE,control_tree).stdout.decode().splitlines()
        need(changed==[WORKFLOW],"diagnostic tree changes only existing workflow")
        need(git("control-tree-workflow-entry","ls-tree",control_tree,"--",WORKFLOW).stdout.decode()
             =="100644 blob "+oid+"\t"+WORKFLOW+"\n","exact control workflow mode/object")
        commit=git("diagnostic-control-commit","commit-tree",control_tree,"-p",HEAD,
            data=b"Prepare R1 stage-one observation capability and ELF material; no acceptance or qualification\n").stdout.decode().strip()
        F["check_commit_object"](object_raw("diagnostic-control-object","commit",commit,128*1024),commit,control_tree,[HEAD])
        need(refs("local-refs-before-tag")==before_refs and index_snapshot(index_path)==before_index,
             "only objects created; source refs/index unchanged")
        input_fence()
        git("diagnostic-annotated-tag","tag","-a",TAG,commit,"-m",
            "R1 stage-one diagnostic only. Subject stays R1. No native controls, formal tracing, main merge or qualification.")
        state["local_tag_created"]=True
        tagoid=value("diagnostic-tag-oid","rev-parse",TAGREF)
        need(value("diagnostic-tag-peel","rev-parse",TAGREF+"^{}")==commit,"diagnostic tag peel")
        F["check_tag_object"](object_raw("diagnostic-tag-object","tag",tagoid,64*1024),tagoid,TAG,commit)
        control={"tag":TAG,"tag_oid":tagoid,"commit":commit,"tree":control_tree,"parents":[HEAD],
                 "workflow_path":WORKFLOW,"workflow_blob":oid,"workflow_sha256":sha(workflow),
                 "subject_commit":HEAD,"subject_tree":TREE}
        state["control"]=control; emit("control.json",encode(control))
        hdir=ev/"hooks"; hdir.mkdir(mode=0o700)
        hook_expected={"origin":URL,"remote_heads":expected,"old_archive_tags":OLD_TAGS,"new_tag_ref":TAGREF,
                       "updates":{TAGREF:{"local_ref":TAGREF,"new":tagoid,"old":ZERO}}}
        expected_raw=encode(hook_expected)
        need(template.count(b"__EXPECTED_SHA256__")==1
             and template.count(b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__")==1,"exact owned hook substitutions")
        effective=template.replace(b"__EXPECTED_SHA256__",sha(expected_raw).encode()).replace(
            b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__",("EXPECTED_BYTES = "+str(len(expected_raw))).encode())
        for name,data in (("expected.json",expected_raw),("pre-push",effective)):
            with (hdir/name).open("xb") as f:
                f.write(data); f.flush(); os.fsync(f.fileno())
        (hdir/"pre-push").chmod(0o700)
        run("project-preflight-prepush",["bash","scripts/project-preflight.sh"])
        identity("source-prepush")
        need(actor("actor-prepush")==who,"actor drift")
        state["remote_prepush"]=observe("remote-prepush")
        need(state["remote_prepush"]["matches"],"fresh remote drift before single push")
        need(hook_guard("hook-final")==guard,"installed hook/URL drift")
        need(refs("local-refs-prepush")==dict(before_refs,**{TAGREF:tagoid})
             and index_snapshot(index_path)==before_index,"source refs/index drift")
        input_fence()
        need(stable(hdir/"expected.json")==expected_raw and stable(hdir/"pre-push")==effective,"owned hook bytes")
        state["push_started"]=True; state["status"]="UNKNOWN"; save()
        q=run("atomic-diagnostic-tag-publish",["git","-c","core.hooksPath="+str(hdir),"push","--verify","--atomic",
              "--porcelain","--verbose","--progress","origin",TAGREF+":"+TAGREF],timeout=TRANSPORT_SECONDS,must=False)
        state["push_exit"]=q.returncode; save()
    except Exception as e:
        state["errors"].append({"phase":"prepare-or-single-push","type":type(e).__name__,"message":str(e)})
    finally:
        if state["push_started"]:
            try:
                state["remote_after"]=observe("remote-after",control)
                need(state["remote_after"]["matches"],"remote after is not exact new tag plus unchanged old refs")
                state["hook_receipt"]=hook_proof(F,ev/"hooks",expected,OLD_TAGS,TAGREF,control["tag_oid"],
                                                 template,"trnm-r1-diagnostic-tag-prepush-v1")
                state["exact_hook_verified"]=True
            except Exception as e:
                state["errors"].append({"phase":"post-push-readback","type":type(e).__name__,"message":str(e)})
        try:
            run("project-preflight-after-publication",["bash","scripts/project-preflight.sh"])
            verify_source("verify-source-after-publication","source-after-publication.json")
            identity("source-after-publication"); state["source_after_valid"]=True
            need(guard is not None and hook_guard("hook-after-publication")==guard,"original hook/URL after publication")
            wanted=dict(before_refs or {})
            if state["local_tag_created"]:
                need(control is not None,"created local tag identity not fully known")
                wanted[TAGREF]=control["tag_oid"]
            need(before_refs is not None and refs("local-refs-after-publication")==wanted,"all local refs after publication")
            state["local_ref_fence_valid"]=True
            need(index_path is not None and before_index is not None and index_snapshot(index_path)==before_index,"original source index unchanged")
            state["source_index_unchanged"]=True
            input_fence()
        except Exception as e:
            state["errors"].append({"phase":"publication-source-ref-index-fence","type":type(e).__name__,"message":str(e)})
        state["publication_confirmed"]=(state["push_started"] and type(state["push_exit"]) is int and state["push_exit"]==0
            and not state["errors"] and state["source_after_valid"] and state["source_index_unchanged"]
            and state["local_ref_fence_valid"] and state["exact_hook_verified"]
            and state["remote_after"] is not None and state["remote_after"]["matches"] is True)
        state["status"]="PUBLISHED_NOT_DISPATCHED" if state["publication_confirmed"] else ("UNKNOWN" if state["push_started"] else "HOLD")
        save()
    if state["publication_confirmed"]:
        try:
            need(actor("actor-predispatch")==ACTOR,"dispatch actor")
            state["remote_predispatch"]=observe("remote-predispatch",control)
            need(state["remote_predispatch"]["matches"],"remote drift before dispatch")
            identity("source-predispatch")
            need(hook_guard("hook-predispatch")==guard and refs("local-refs-predispatch")==dict(before_refs,**{TAGREF:control["tag_oid"]})
                 and index_snapshot(index_path)==before_index,"original source/hooks/refs/index before dispatch")
            input_fence()
            body=encode({"ref":TAG}); state["dispatch_request"]=emit("dispatch-request.json",body)
            state["dispatch_started"]=True; state["dispatch_status"]="UNKNOWN"; state["status"]="UNKNOWN"; save()
            q=run("dispatch-stage1-once",["gh","api","--method","POST","--include",
                  "-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: "+API_VERSION,
                  DISPATCH_ENDPOINT,"--input","-"],data=body,timeout=DISPATCH_SECONDS,must=False)
            state["dispatch_exit"]=q.returncode
            need(q.returncode==0,"dispatch nonzero/timeout is UNKNOWN; no automatic resend")
            state["dispatch_response"]=dispatch_response(q.stdout)
            state["dispatch_status"]="ACCEPTED_NOT_OBSERVED"
        except Exception as e:
            state["errors"].append({"phase":"single-dispatch","type":type(e).__name__,"message":str(e)})
        finally:
            try:
                state["remote_final"]=observe("remote-final",control)
                need(state["remote_final"]["matches"],"final remote refs changed")
                verify_source("verify-source-final","source-final.json")
                identity("source-final")
                need(hook_guard("hook-final-after-dispatch")==guard
                     and refs("local-refs-final")==dict(before_refs,**{TAGREF:control["tag_oid"]})
                     and index_snapshot(index_path)==before_index,"final installed hook/source refs/index")
                input_fence()
            except Exception as e:
                state["source_after_valid"]=False
                state["errors"].append({"phase":"final-dispatch-source-ref-fence","type":type(e).__name__,"message":str(e)})
            state["status"]="DISPATCH_ACCEPTED_NOT_OBSERVED" if not state["errors"] and state["dispatch_status"]=="ACCEPTED_NOT_OBSERVED" else "UNKNOWN"
    state["finished_at"]=now(); save()
    print(json.dumps({"schema":state["schema"],"status":state["status"],"subject_commit":HEAD,"control":state["control"],
          "publication_confirmed":state["publication_confirmed"],"push_exit":state["push_exit"],
          "dispatch_started":state["dispatch_started"],"dispatch_exit":state["dispatch_exit"],
          "dispatch_status":state["dispatch_status"],"dispatch_response":state["dispatch_response"],
          "qualification_granted":False,"receipt":str(ev/"summary.json")}),flush=True)
    return 0 if state["status"]=="DISPATCH_ACCEPTED_NOT_OBSERVED" else 1

if __name__=="__main__":
    sys.exit(main())
