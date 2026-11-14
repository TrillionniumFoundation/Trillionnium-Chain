"""Prepare-only single-tag diagnostic archive publisher.
The reviewed spec must be complete. No main/branch/source/qualification mutation.
Only main performs Git object/tag creation and one ordinary verified atomic push.
"""
import argparse, datetime, hashlib, json, math, os, pathlib, re, stat, sys
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
PREP=pathlib.Path("/private/tmp/chain-R1-postpublication-diagnostic-archive-preparation-20261114-v1/driver-v2")
SELF=PREP/"publish_postpublication_diagnostics_v2.py"
HOOK=PREP/"archive_only_pre_push_v2.py"
HOOK_BYTES=8372
HOOK_SHA="364b612c0e048477828e72a27a8bfe271c14f5f05d0646647044ca644a3020af"
PREPARER=ROOT/"prepare_pr847_audit_update_v10.py"
PREPARER_BYTES=53056
PREPARER_SHA="af773495a3e27a008377c08c87141af91f741c23a132c3615d57d51413411989"
SCANNER=pathlib.Path("/private/tmp/chain-execution-payload-credential-scanner-20261114-v1/scan_frozen_execution_payload_v2.py")
SCANNER_BYTES=14664
SCANNER_SHA="14305dfe4b3edaecb601dffed336a13c916fe6a9182a9547770f0637031b50b6"
PATTERN_SHA="5c292f6554bbf1345d6e58a3c64cf9099230223fc9c70f217a575f6f20ee7368"
REPO="TrillionniumFoundation/Trillionnium-Chain"
URL="https://github.com/"+REPO+".git"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
BASE="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
CANDIDATE="fix/chain-hepta-closure-candidate-20261109-481716"
TAG="archive/post-publication-diagnostics-20261114-2a86462a1ab2-v1"
TAGREF="refs/tags/"+TAG
ZERO="0"*40
PARENT="0f4b8b70bde65f84139b4cc7ed9e176ed55cf1d9"
PARENT_TREE="e7c0cdcc71af648f430acd323d33dedfaf1ed63b"
OLD_HISTORY="5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b"
OLD_TAGS={
 "refs/tags/archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2":"9dafd9192e4040fab530958ef71598aaec9265b9",
 "refs/tags/archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2^{}":OLD_HISTORY,
 "refs/tags/archive/execution-receipts-20261114-2a86462a1ab2-v1":"454761ef276433740453b5b80ce886c1d251c6d3",
 "refs/tags/archive/execution-receipts-20261114-2a86462a1ab2-v1^{}":PARENT}
PAYLOAD_ROOT=ROOT/"execution-receipts-postpublication-r1-v1"
MAX_META=16*1024*1024
MAX_FILE=256*1024*1024
MAX_TOTAL=512*1024*1024
TRANSPORT_SECONDS=3600
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
         and p.resolve(strict=True)==p and (p.is_relative_to(ROOT) or p.is_relative_to(PREP)
         or p.is_relative_to(SCANNER.parent)),"canonical authorized path")
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

def load_payload(value):
    raw=pin(value); m=parse(raw)
    need(type(m) is dict and set(m)=={"schema","payload_root","file_count","total_bytes","files"}
         and m["schema"]=="trnm-frozen-execution-payload-manifest-v1","frozen payload schema")
    need(m["payload_root"]==str(PAYLOAD_ROOT) and absolute(m["payload_root"])==PAYLOAD_ROOT,
         "separate postpublication payload root; old F is never written")
    need(type(m["file_count"]) is int and 0<m["file_count"]<=10000
         and type(m["total_bytes"]) is int and 0<=m["total_bytes"]<=MAX_TOTAL
         and type(m["files"]) is list and len(m["files"])==m["file_count"],"payload counts")
    payload={}; total=0; wantdirs={""}; origins=set()
    for e in m["files"]:
        need(type(e) is dict and set(e)=={"path","bytes","sha256","origin"},"strict payload entry")
        rel=relative(e["path"]); need(e["path"] not in payload,"duplicate payload")
        o=e["origin"]
        need(type(o) is dict and set(o)=={"host","path"} and o["host"] in ("mac","rog")
             and type(o["path"]) is str and o["path"].startswith("/") and "\\" not in o["path"]
             and ".." not in pathlib.PurePosixPath(o["path"]).parts
             and all(32<=ord(c)!=127 for c in o["path"]),"original host/path")
        b=pin({"path":str(PAYLOAD_ROOT/rel),"bytes":e["bytes"],"sha256":e["sha256"]},MAX_FILE)
        payload[e["path"]]=b; total+=len(b)
        need(total<=MAX_TOTAL,"payload byte bound")
        for p in rel.parents:
            wantdirs.add("" if str(p)=="." else str(p))
        origins.add((o["host"],o["path"]))
    need(total==m["total_bytes"],"payload exact total")
    actual=set(); dirs=set()
    for dp,dns,fns in os.walk(PAYLOAD_ROOT,followlinks=False):
        d=pathlib.Path(dp); s=d.lstat()
        need(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and d.resolve(strict=True)==d,
             "payload directory")
        dirs.add("" if d==PAYLOAD_ROOT else d.relative_to(PAYLOAD_ROOT).as_posix())
        for n in dns:
            s=(d/n).lstat(); need(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode),"special directory")
        for n in fns:
            actual.add((d/n).relative_to(PAYLOAD_ROOT).as_posix())
    need(actual==set(payload) and dirs==wantdirs,"exact physical payload roster including directories")
    return raw,m,payload,origins

def scan_proof(spec,manifest_pin,manifest):
    need(type(spec) is dict and set(spec)=={"producer","summary","coverage","hits","terminal"},"scan proof pins")
    need(spec["producer"]=={"path":str(SCANNER),"bytes":SCANNER_BYTES,"sha256":SCANNER_SHA},"reviewed scanner")
    pin(spec["producer"])
    sr=pin(spec["summary"]); s=parse(sr); cr=pin(spec["coverage"]); hr=pin(spec["hits"])
    tr=pin(spec["terminal"]); t=parse(tr)
    counts={"aws_access_key_id":0,"github_classic_token":0,"github_fine_grained_token":0,
            "private_key_header":0,"slack_token":0}
    need(s.get("status")=="NO_PATTERN_HITS_IN_DECLARED_SCOPE" and s.get("coverage_complete") is True
         and s.get("review_required") is False and s.get("automatic_hit_classification") is False
         and s.get("all_secrets_absence_proved") is False and s.get("pattern_source_sha256")==PATTERN_SHA
         and s.get("regex_flags")==[] and type(s.get("counts")) is dict and set(s["counts"])==set(counts)
         and all(type(s["counts"][k]) is int and s["counts"][k]==0 for k in counts),"scan outcome/scope")
    need(type(s.get("files_scanned")) is int and s["files_scanned"]==manifest["file_count"]
         and type(s.get("bytes_scanned")) is int and s["bytes_scanned"]==manifest["total_bytes"]
         and s.get("payload_root")==str(PAYLOAD_ROOT)
         and s.get("manifest")=={"path":manifest_pin["path"],"size":manifest_pin["bytes"],
                                "sha256":manifest_pin["sha256"]} and hr==b"","scan manifest binding")
    rows=[parse(x) for x in cr.splitlines()]
    expected=[{"path":e["path"],"size":e["bytes"],"sha256":e["sha256"]} for e in manifest["files"]]
    need(len(rows)==len(expected) and all(type(a) is dict and set(a)==set(b)
         and all(type(a[k]) is type(v) and a[k]==v for k,v in b.items()) for a,b in zip(rows,expected)),
         "complete exact scanner coverage")
    need(t.get("host")=="mac" and type(t.get("status")) is dict and t["status"].get("state")=="exited"
         and type(t["status"].get("exit_code")) is int and t["status"]["exit_code"]==0
         and t["status"].get("output_complete") is True and t.get("output_complete") is True
         and t["status"].get("capture_error") is None and t.get("truncated_before_offset") is False
         and t.get("text_is_lossy") is False and t.get("utf8_pending") is False,"actual complete scanner terminal")
    need(type(t.get("bytes_hex")) is str and re.fullmatch(r"(?:[0-9a-f]{2})*",t["bytes_hex"]),"terminal bytes")
    tb=bytes.fromhex(t["bytes_hex"])
    need(sha(tb)==t.get("chunk_sha256") and type(t.get("offset")) is int and t["offset"]==0
         and all(type(n) is int and n==len(tb) for n in
                 (t.get("next_offset"),t.get("available_end"),t["status"].get("bytes_seen"),t["status"].get("bytes_stored"))),
         "complete terminal coverage")
    need(tb.splitlines() and parse(tb.splitlines()[-1])==
         {"status":s["status"],"summary":{"path":spec["summary"]["path"],"size":len(sr),"sha256":sha(sr)}},
         "actual scanner output identifies summary")
    return {"summary":sr,"coverage":cr,"hits":hr,"terminal":tr}

def main():
    need(not sys.flags.optimize and pathlib.Path(__file__).resolve(strict=True)==SELF,"fixed nonoptimized producer")
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--spec",required=True); ap.add_argument("--spec-bytes",required=True,type=int)
    ap.add_argument("--spec-sha256",required=True); args=ap.parse_args()
    spec_pin={"path":args.spec,"bytes":args.spec_bytes,"sha256":args.spec_sha256}
    raw=pin(spec_pin); spec=parse(raw)
    need(type(spec) is dict and set(spec)=={"schema","producer_sha256","evidence_dir","archive_tag",
         "publication_inputs","reviewed_remote_snapshot","payload_manifest","scan","report",
         "workflow_trigger_review","transport_timeout_seconds"},"archive-only spec fields")
    need(spec["schema"]=="trnm-postpublication-diagnostic-archive-spec-v1" and spec["archive_tag"]==TAG
         and type(spec["transport_timeout_seconds"]) is int
         and spec["transport_timeout_seconds"]==TRANSPORT_SECONDS,"fixed archive scope")
    own=stable(SELF,128*1024)
    need(type(spec["producer_sha256"]) is str and sha(own)==spec["producer_sha256"],"producer pin")
    hook_template=pin({"path":str(HOOK),"bytes":HOOK_BYTES,"sha256":HOOK_SHA})
    preparer_raw=pin({"path":str(PREPARER),"bytes":PREPARER_BYTES,"sha256":PREPARER_SHA})
    P={"__name__":"_pinned_publication_inputs_only","__file__":str(PREPARER)}
    exec(compile(preparer_raw,str(PREPARER),"exec",optimize=0),P)
    need(P["SELF"]==PREPARER and P["SOURCE"]==SOURCE and P["ROOT"]==ROOT and P["REPO"]==REPO,
         "pure publication-validator scope")
    inp=pin(spec["publication_inputs"])
    ctx=P["validate_inputs"](spec["publication_inputs"]["path"],sha(inp))
    F,H=ctx["F"],ctx["H"]
    need(ctx["head"]==HEAD and ctx["tree"]==TREE and ctx["facts"]["base"]==BASE
         and ctx["facts"]["archive"]["commit"]==PARENT and ctx["facts"]["archive"]["tree"]==PARENT_TREE
         and ctx["facts"]["archive"]["tag_oid"]==OLD_TAGS["refs/tags/archive/execution-receipts-20261114-2a86462a1ab2-v1"]
         and ctx["facts"]["archive"]["direct_parents"]==[OLD_HISTORY,HEAD],"exact published R1/archive lineage")
    completion=ctx["publication_completion"]
    need(completion["kind"]=="resume-executor" and completion["status"]=="confirmed"
         and type(completion["transport_exit"]) is int and completion["transport_exit"]==0,
         "actual closed successful R1 publication required")
    expected=completion["observation"]["heads"]
    need(type(expected) is dict and len(expected)==908 and expected.get("main")==BASE
         and expected.get(CANDIDATE)==HEAD and completion["observation"]["tags"]==OLD_TAGS
         and completion["observation"]["errors"]==[],"prior complete published refs")
    snap_raw=pin(spec["reviewed_remote_snapshot"]); snap=parse(snap_raw)
    need(snap.get("status")=="OBSERVED_UNCHANGED" and snap.get("heads_and_two_archives_match_publication") is True
         and snap.get("main")==BASE and snap.get("candidate")==HEAD
         and type(snap.get("head_count")) is int and snap["head_count"]==908
         and snap["observed"]["heads"]==expected and snap["observed"]["tags"]==OLD_TAGS,
         "root reviewed fresh complete snapshot")
    mr,m,payload,origins=load_payload(spec["payload_manifest"])
    scans=scan_proof(spec["scan"],spec["payload_manifest"],m)
    report=pin(spec["report"],64*1024)
    trigger=pin(spec["workflow_trigger_review"],128*1024)
    ev=pathlib.Path(spec["evidence_dir"])
    need(ev.parent==ROOT and re.fullmatch(r"postpublication-diagnostics-publish-v1-[a-z0-9-]+",ev.name)
         and ROOT.resolve(strict=True)==ROOT,"new owned evidence directory")
    ev.mkdir(mode=0o700,exist_ok=False); os.umask(0o077)
    env=P["safe_environment"](H)
    env.pop("GH_DEBUG",None); env["GH_HOST"]="github.com"; env["GIT_TERMINAL_PROMPT"]="0"
    state={"schema":"trnm-postpublication-diagnostic-archive-receipt-v1","status":"HOLD",
           "started_at":now(),"driver":{"path":str(SELF),"bytes":len(own),"sha256":sha(own)},
           "spec":spec_pin,"head":HEAD,"tree":TREE,"main":BASE,"previous_archive":ctx["facts"]["archive"],
           "publication_facts":ctx["facts"],"publication_completion":completion,
           "archive":None,"archive_objects_started":False,"local_tag_created":False,
           "push_started":False,"push_exit":None,"remote_before":None,"remote_after":None,
           "source_after_valid":False,"exact_hook_verified":False,"local_ref_fence_valid":False,
           "steps":[],"errors":[],"qualification_granted":False,"hosted_ci_qualification":False,
           "main_merged":False,"branches_deleted":False,"protection_changed":False,
           "source_files_changed":False,"candidate_branch_updated":False,
           "repository_template_push_executed":False,"owned_archive_hook_used":False,
           "untouched_refs_atomically_locked":False,"automatic_retry_authorized":False}
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
    def identity(label):
        v={"head":value(label+"-head","rev-parse","HEAD"),
           "tree":value(label+"-tree","rev-parse","HEAD^{tree}"),
           "status":git(label+"-status","status","--porcelain=v1","--untracked-files=all").stdout.decode()}
        need(v=={"head":HEAD,"tree":TREE,"status":""},"fixed clean source")
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
        need(type(v) is dict and set(v)=={"login","id"} and v["login"]=="ProfHepta"
             and type(v["id"]) is int and v["id"]>0 and v==ctx["publication_actor"],"actual actor")
        return v
    def observe(label,new=None):
        a=run(label+"-heads",["git","ls-remote","--heads","origin"],must=False)
        b=run(label+"-tags",["git","ls-remote","origin",*sorted(OLD_TAGS),TAGREF,TAGREF+"^{}"],must=False)
        out={"observed_at":now(),"heads":None,"tags":None,"errors":[],"matches":False}
        try:
            need(a.returncode==b.returncode==0,"fresh reads did not both complete")
            out["heads"]=F["parse_refs"](a.stdout,heads=True)
            out["tags"]=F["parse_refs"](b.stdout,allowed=set(OLD_TAGS)|{TAGREF,TAGREF+"^{}"})
            wanted=dict(OLD_TAGS)
            if new is not None:
                wanted.update({TAGREF:new["tag_oid"],TAGREF+"^{}":new["commit"]})
            out["matches"]=out["heads"]==expected and out["tags"]==wanted
        except Exception as e:
            out["errors"].append({"type":type(e).__name__,"message":str(e)})
        return out
    def object_raw(label,kind,oid,limit):
        need(re.fullmatch(r"[0-9a-f]{40}",oid),"object id")
        size=value(label+"-size","cat-file","-s",oid)
        need(re.fullmatch(r"[1-9][0-9]*",size) and int(size)<=limit,"object bound")
        b=git(label,"cat-file",kind,oid).stdout
        need(len(b)==int(size) and F["git_object_oid"](kind,b)==oid,"object address")
        return b
    def verify_hook(expected_raw,effective,expected_hook):
        receipt_raw=stable(ev/"hooks/receipt.json"); r=parse(receipt_raw)
        need(r["schema"]=="trnm-postpublication-one-tag-prepush-v1" and r["status"]=="passed"
             and r["errors"]==[] and r["argv"]==[str(ev/"hooks/pre-push"),"origin",URL]
             and r["hook_sha256"]==sha(effective) and r["expected_sha256"]==sha(expected_raw)
             and r["updates"]==expected_hook["updates"],"actual owned hook receipt")
        commands=[
            ("push-url",["git","remote","get-url","--push","--all","origin"]),
            ("fetch-url",["git","remote","get-url","--all","origin"]),
            ("heads",["git","ls-remote","--heads","origin"]),
            ("tags",["git","ls-remote","origin",*sorted(OLD_TAGS),TAGREF,TAGREF+"^{}"])]
        need(type(r["commands"]) is list and len(r["commands"])==4,"hook complete command roster")
        outputs={}
        for row,(label,argv) in zip(r["commands"],commands):
            need(row["label"]==label and row["argv"]==argv and type(row["exit"]) is int
                 and row["exit"]==0 and type(row["timeout_seconds"]) is int
                 and row["timeout_seconds"]==90,"hook command identity")
            for ch in ("stdout","stderr"):
                need(row[ch+"_path"]==str(ev/"hooks"/(label+"."+ch)),"hook output origin")
                outputs[label,ch]=pin({k:row[ch+"_"+k] for k in ("path","bytes","sha256")})
        need(outputs["push-url","stdout"].decode().splitlines()==[URL]
             and outputs["fetch-url","stdout"].decode().splitlines()==[URL]
             and F["parse_refs"](outputs["heads","stdout"],heads=True)==expected
             and F["parse_refs"](outputs["tags","stdout"],allowed=set(OLD_TAGS)|{TAGREF,TAGREF+"^{}"})==OLD_TAGS,
             "actual hook full URL/heads/tags observations")
        need(stable(ev/"hooks/expected.json")==expected_raw and stable(ev/"hooks/pre-push")==effective,
             "hook bytes after operation")
        return {"path":str(ev/"hooks/receipt.json"),"bytes":len(receipt_raw),"sha256":sha(receipt_raw)}
    emit("spec.json",raw); emit("producer.py",own); emit("payload-manifest.json",mr)
    emit("previous-publication-facts.json",encode(ctx["facts"])); emit("previous-publication-completion.json",encode(completion))
    emit("reviewed-remote-snapshot.json",snap_raw); save()
    before_source=None; before_refs=None; guard=None; expected_hook=None; effective=None; hook_expected_raw=None
    try:
        identity("source-initial"); before_refs=refs("local-refs-before")
        need(TAGREF not in before_refs,"new local tag must be absent")
        guard=hook_guard("hook-initial"); who=actor("actor-before")
        state["remote_before"]=observe("remote-before")
        need(state["remote_before"]["matches"],"fresh complete heads/old archives differ or new tag exists")
        run("project-preflight-before-objects",["bash","scripts/project-preflight.sh","--audit"])
        b=run("verify-source-before",[H["PYTHON"],"-B","scripts/ci/verify_ci_source.py",
              "--kind","head","--expected-head",HEAD,"--output",str(ev/"source-before.json")])
        before_source=stable(ev/"source-before.json")
        need(b.stdout==before_source and source_identity(before_source)==ctx["gate_source"],"source stdout/sidecar/known source")
        parentraw=object_raw("parent-archive-commit","commit",PARENT,128*1024)
        F["check_commit_object"](parentraw,PARENT,PARENT_TREE,[OLD_HISTORY,HEAD])
        for n,(ref,oid) in enumerate((x for x in OLD_TAGS.items() if not x[0].endswith("^{}")),1):
            need(value("old-tag-"+str(n),"rev-parse",ref)==oid
                 and value("old-peel-"+str(n),"rev-parse",ref+"^{}")==OLD_TAGS[ref+"^{}"],"old local tags")
            tagraw=object_raw("old-tag-object-"+str(n),"tag",oid,64*1024)
            F["check_tag_object"](tagraw,oid,ref[10:],OLD_TAGS[ref+"^{}"])
        scope={"schema":"trnm-postpublication-diagnostic-archive-scope-v1","source_commit":HEAD,"source_tree":TREE,
               "main_snapshot":BASE,"exact_ordered_parents":[PARENT],"payload_manifest":spec["payload_manifest"],
               "payload_files":m["file_count"],"payload_bytes":m["total_bytes"],
               "retains_prior_execution_and_history_by_parent":True,"incremental_tree_only":True,
               "original_failures_and_unknowns_preserved":True,"hosted_ci_qualification":False,
               "qualification_granted":False,"main_merged":False,"branches_deleted":False,
               "source_runtime_changed":False,"new_full_history_fsck_claimed":False,
               "current_publication_result_included":False,
               "credential_scan_scope":"Only payload manifest files; metadata, scanner receipts and this publication outcome are not claimed self-scanned.",
               "all_secrets_absence_proved":False}
        files={"payload/"+n:b for n,b in payload.items()}
        files.update({"README.md":report,"metadata/scope.json":encode(scope),"metadata/spec.json":raw,
             "metadata/payload-manifest.json":mr,"metadata/previous-publication-facts.json":encode(ctx["facts"]),
             "metadata/previous-publication-completion.json":encode(completion),
             "metadata/reviewed-remote-snapshot.json":snap_raw,"metadata/source-before.json":before_source,
             "metadata/parent-archive-commit.raw":parentraw,"metadata/workflow-trigger-review":trigger,
             "producers/archive-publisher.py":own,"producers/archive-hook-template.py":hook_template,
             "producers/publication-input-validator.py":preparer_raw})
        for n,b in scans.items():
            files["metadata/credential-scan/"+n+(".jsonl" if n in ("hits","coverage") else ".json")]=b
        need(len(files)<=10050 and sum(map(len,files.values()))<=MAX_TOTAL+MAX_META,"complete archive bound")
        index={"schema":"trnm-execution-archive-file-index-v1","self_excluded":"metadata/archive-file-index.json",
               "files":[{"path":n,"bytes":len(b),"sha256":sha(b),"git_blob":F["git_object_oid"]("blob",b),"mode":"100644"}
                        for n,b in sorted(files.items())]}
        files["metadata/archive-file-index.json"]=encode(index)
        for n in files:
            relative(n)
        fence(); F["check_versions"](ctx["snapshots"])
        state["archive_objects_started"]=True; save()
        nodes={}; blobmap={}
        for i,(n,b) in enumerate(sorted(files.items()),1):
            oid=git("archive-blob-"+str(i),"hash-object","-w","--stdin",data=b).stdout.decode().strip()
            need(oid==F["git_object_oid"]("blob",b),"written blob differs")
            parts=relative(n).parts; node=nodes
            for part in parts[:-1]:
                need(part not in node or type(node[part]) is dict,"path prefix collision")
                node=node.setdefault(part,{})
            need(parts[-1] not in node,"duplicate file"); node[parts[-1]]=oid; blobmap[n]=oid
        counter=[0]
        def write_tree(node):
            entries=[]
            for n,v in sorted(node.items()):
                oid,mode,kind=(write_tree(v),"040000","tree") if type(v) is dict else (v,"100644","blob")
                entries.append((mode+" "+kind+" "+oid+"\t"+n).encode()+b"\0")
            counter[0]+=1
            oid=git("archive-tree-"+str(counter[0]),"mktree","-z",data=b"".join(entries)).stdout.decode().strip()
            need(re.fullmatch(r"[0-9a-f]{40}",oid),"tree oid"); return oid
        tree=write_tree(nodes)
        listed=git("archive-tree-list","ls-tree","-r","-z",tree).stdout; actual={}
        for line in listed.split(b"\0"):
            if not line: continue
            meta,n=line.split(b"\t",1); mode,kind,oid=meta.decode().split(); n=n.decode()
            need(mode=="100644" and kind=="blob" and n not in actual,"archive tree entry"); actual[n]=oid
        need(actual==blobmap,"complete archive path/blob verification")
        commit=git("archive-commit","commit-tree",tree,"-p",PARENT,
                   data=("Preserve R1 post-publication diagnostic originals; no merge or qualification\n").encode()).stdout.decode().strip()
        F["check_commit_object"](object_raw("new-commit-object","commit",commit,128*1024),commit,tree,[PARENT])
        need(refs("local-refs-before-tag")==before_refs,"unowned local ref changed before tag creation")
        git("archive-annotated-tag","tag","-a",TAG,commit,"-m",
            "Closed post-publication diagnostics for R1. Existing failures retained. No source change, main merge, branch deletion, hosted qualification or activation.")
        state["local_tag_created"]=True
        tagoid=value("new-tag-oid","rev-parse",TAGREF)
        need(value("new-tag-peel","rev-parse",TAGREF+"^{}")==commit,"tag peel")
        F["check_tag_object"](object_raw("new-tag-object","tag",tagoid,64*1024),tagoid,TAG,commit)
        archive={"tag":TAG,"tag_oid":tagoid,"commit":commit,"tree":tree,"direct_parents":[PARENT],
                 "source_commit":HEAD,"source_tree":TREE,"payload_manifest_sha256":sha(mr),
                 "archive_files":len(files),"archive_bytes":sum(map(len,files.values())),
                 "file_index_sha256":sha(files["metadata/archive-file-index.json"])}
        state["archive"]=archive; emit("archive-local.json",encode(archive)); emit("archive-file-index.json",files["metadata/archive-file-index.json"])
        hdir=ev/"hooks"; hdir.mkdir(mode=0o700)
        expected_hook={"origin":URL,"remote_heads":expected,"old_archive_tags":OLD_TAGS,"new_tag_ref":TAGREF,
                       "updates":{TAGREF:{"local_ref":TAGREF,"new":tagoid,"old":ZERO}}}
        hook_expected_raw=encode(expected_hook)
        need(hook_template.count(b"__EXPECTED_SHA256__")==1
             and hook_template.count(b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__")==1,"hook fixed template substitutions")
        effective=hook_template.replace(b"__EXPECTED_SHA256__",sha(hook_expected_raw).encode()).replace(
             b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__",("EXPECTED_BYTES = "+str(len(hook_expected_raw))).encode())
        for n,b in (("expected.json",hook_expected_raw),("pre-push",effective)):
            with (hdir/n).open("xb") as f:
                f.write(b); f.flush(); os.fsync(f.fileno())
        (hdir/"pre-push").chmod(0o700)
        need(stat.S_ISREG((hdir/"pre-push").lstat().st_mode)
             and (hdir/"pre-push").lstat().st_nlink==1 and (hdir/"pre-push").lstat().st_mode & 0o111,
             "owned executable hook")
        run("project-preflight-prepush",["bash","scripts/project-preflight.sh","--audit"])
        identity("source-prepush")
        need(actor("actor-prepush")==who,"actor changed")
        latest=observe("remote-prepush")
        need(latest["matches"],"fresh prepush drift"); state["remote_prepush"]=latest
        need(hook_guard("hook-final")==guard,"effective hook/URL guard changed")
        need(refs("local-refs-prepush")==dict(before_refs,**{TAGREF:tagoid}),"unexpected local ref change")
        fence(); F["check_versions"](ctx["snapshots"])
        need(stable(hdir/"expected.json")==hook_expected_raw and stable(hdir/"pre-push")==effective,"hook bytes")
        state["push_started"]=True; state["owned_archive_hook_used"]=True; state["status"]="UNKNOWN"
        state["push_started_at"]=now(); save()
        q=run("atomic-archive-publish",["git","-c","core.hooksPath="+str(hdir),"push","--verify","--atomic",
              "--porcelain","--verbose","--progress","origin",TAGREF+":"+TAGREF],timeout=TRANSPORT_SECONDS,must=False)
        state["push_exit"]=q.returncode; save()
    except Exception as e:
        state["errors"].append({"phase":"prepare-or-single-push","type":type(e).__name__,"message":str(e)})
    finally:
        if state["push_started"]:
            try:
                state["remote_after"]=observe("remote-after",state["archive"])
                need(state["remote_after"]["matches"],"remote after not exactly one new tag with unchanged heads/old tags")
                state["hook_receipt"]=verify_hook(hook_expected_raw,effective,expected_hook)
                state["exact_hook_verified"]=True
            except Exception as e:
                state["errors"].append({"phase":"post-push-readback","type":type(e).__name__,"message":str(e)})
        try:
            q=run("verify-source-after",[H["PYTHON"],"-B","scripts/ci/verify_ci_source.py",
                  "--kind","head","--expected-head",HEAD,"--output",str(ev/"source-after.json")],must=False)
            after=stable(ev/"source-after.json")
            need(q.returncode==0 and before_source is not None and q.stdout==after==before_source
                 and source_identity(after)==ctx["gate_source"],"final exact typed source stdout/sidecar")
            identity("source-final"); state["source_after_valid"]=True
            need(guard is not None and hook_guard("hook-after")==guard,"final original hook/URL configuration")
            want=dict(before_refs or {})
            if state["local_tag_created"]:
                want[TAGREF]=state["archive"]["tag_oid"]
            need(before_refs is not None and refs("local-refs-after")==want,"final exact local refs")
            state["local_ref_fence_valid"]=True
            fence(); F["check_versions"](ctx["snapshots"])
        except Exception as e:
            state["errors"].append({"phase":"final-source-input-ref-fence","type":type(e).__name__,"message":str(e)})
        if (state["push_started"] and type(state["push_exit"]) is int and state["push_exit"]==0
                and not state["errors"] and state["source_after_valid"] and state["local_ref_fence_valid"]
                and state["exact_hook_verified"] and state["remote_after"] and state["remote_after"]["matches"]):
            state["status"]="confirmed"
        else:
            state["status"]="UNKNOWN" if state["push_started"] else "HOLD"
        state["finished_at"]=now(); save()
    print(json.dumps({"schema":state["schema"],"status":state["status"],"head":HEAD,"tree":TREE,
          "archive":state["archive"],"push_started":state["push_started"],"push_exit":state["push_exit"],
          "source_after_valid":state["source_after_valid"],"exact_hook_verified":state["exact_hook_verified"],
          "receipt":str(ev/"summary.json")}),flush=True)
    return 0 if state["status"]=="confirmed" else 1

if __name__=="__main__":
    sys.exit(main())
