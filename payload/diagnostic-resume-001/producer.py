"""Explicit once-only recovery of the existing R1 diagnostic tag, then one dispatch.
Importing this file is inert. main reuses the reviewed publisher helpers; it never
creates a Git object or local ref, and never rewrites any prior attempt.
"""
import argparse, ast, hashlib, json, os, pathlib, re, stat, sys
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
PREP=ROOT/"R1-diagnostic-tag-resume-preparation-v2"
SELF=PREP/"resume_diagnostic_stage1_v2.py"
ORIGINAL={"path":str(ROOT/"R1-diagnostic-tag-publication-preparation-v2/publish_r1_diagnostic_stage1_v2.py"),"bytes":42070,"sha256":"b9a3a967243f76c411ce799d30337c8652875aedc1ae4db3341d08c23b0454e9"}
ORIGINAL_SPEC={"path":str(ROOT/"R1-diagnostic-tag-publication-preparation-v2/spec.for-review.json"),"bytes":1997,"sha256":"6eb666c7aa003649764263a006932a7dc8405bb24c8c69fc29fa2d411568c246"}
ORIGINAL_RECEIPT={"path":str(ROOT/"r1-diagnostic-stage1-publish-v1-r1-001/summary.json"),"bytes":342603,"sha256":"cabdb51529518374495ffefd5da7d776b65e5836c28c390b03a2837d9a82256b"}
ORIGINAL_TERMINAL={"path":str(ROOT/"r1-diagnostic-stage1-publication-first-actual-terminal-v1.json"),"bytes":4281,"sha256":"28b9d6f3bd2b9c55c7092f15f23122de14804121587406430207bd23d685bc12"}
ORIGINAL_SESSION="dpty-0b9ef75073621c6dfec9b458a6dd79749e244aac6f743e4293e51f0af1dc4738"
CONTROL={"tag":"diagnostic/r1-native-stage1-20261114-r1-v3",
 "tag_oid":"bec22f093723cae0bb4625bd1fcbe9858d61f68b",
 "commit":"78985d9a36761cf3ab370796f72f9b587776880c",
 "tree":"b9999aa69ef7e148ea0760942f9b2bca6a8e6d6e",
 "parents":["2a86462a1ab20c68151719ba4635e3c294391e64"],
 "workflow_path":".github/workflows/trnm-required-baseline.yml",
 "workflow_blob":"2f242e4c1dc16fbf912a93d87454ee0ff4474b91",
 "workflow_sha256":"85e9ef1d83490fb98d57c653952fe3fff67c496c8074cbf89ee6adacb266041a",
 "subject_commit":"2a86462a1ab20c68151719ba4635e3c294391e64",
 "subject_tree":"5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"}
REMOTE_HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
DRIFT_DIR=ROOT/"candidate-drift-github-refs-20261114-v2"
DRIFT_SESSION="dpty-3482d23c5f5a55da85d36bb95ee81b4b21e5f88683085e5f3a0bf6e5e3196ff1"
DRIFT_INPUTS={
  "summary": {
    "path": "/private/tmp/chain-consolidation-20261114-root/candidate-drift-github-refs-20261114-v2/summary.json",
    "bytes": 149335,
    "sha256": "05fbce0a63427adc24ddc2e605ccee01734eb697ad9af1e35849cdc14665bc78"
  },
  "heads": {
    "path": "/private/tmp/chain-consolidation-20261114-root/candidate-drift-github-refs-20261114-v2/remote-heads.stdout",
    "bytes": 466336,
    "sha256": "321f442db08954c924707a0bdf321f5bdf6b9352ed00f0fdddfdd244425526b5"
  },
  "tags": {
    "path": "/private/tmp/chain-consolidation-20261114-root/candidate-drift-github-refs-20261114-v2/remote-tags.stdout",
    "bytes": 2712,
    "sha256": "6d6914509667f91c458e4dc952572a77d0ef842e06189b89a2eb9464297165e0"
  },
  "terminal": {
    "path": "/private/tmp/chain-consolidation-20261114-root/candidate-drift-github-refs-v2-actual-terminal.json",
    "bytes": 5863,
    "sha256": "410db2a3e3daabaf49396b09f9f995d9686dbed303bd6278043a1230a2a7bf24"
  },
  "comparison": {
    "path": "/private/tmp/chain-consolidation-20261114-root/candidate-drift-independent-comparison-20261114-v1/summary.json",
    "bytes": 2126,
    "sha256": "7c138916112981f8486d88b65590149875df137b5ff5892fdea65f9aaaf6bf5f"
  }
}
REMOTE_HOOK={'path': '/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-tag-resume-preparation-v2/diagnostic_tag_pre_push_v2.py', 'bytes': 8344, 'sha256': 'dbdc28bdd0e214b794b618fa588fc21a4747b7b088c8a472c7867d0f62e91097'}
HELPERS=("emit","save","run","git","value","identity","refs","hook_guard","actor",
         "observe","object_raw","verify_source","input_fence")

def need(ok,why):
    if not ok: raise ValueError(why)

def fixed_read(pin):
    need(type(pin) is dict and set(pin)=={"path","bytes","sha256"},"fixed pin fields")
    p=pathlib.Path(pin["path"])
    need(type(pin["bytes"]) is int and 0<=pin["bytes"]<=128*1024
         and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",pin["sha256"]),
         "bootstrap pin bounds")
    need(p.is_absolute() and str(p)==pin["path"] and p.is_relative_to(ROOT)
         and p.resolve(strict=True)==p,"bootstrap canonical scope")
    def identity(s): return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns
    s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==pin["bytes"],"bootstrap ordinary file")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(identity(os.fstat(fd))==identity(s),"bootstrap open identity")
        with os.fdopen(fd,"rb",closefd=False) as f: raw=f.read(pin["bytes"]+1)
        need(identity(os.fstat(fd))==identity(s),"bootstrap read identity")
    finally: os.close(fd)
    need(identity(p.lstat())==identity(s) and len(raw)==pin["bytes"]
         and hashlib.sha256(raw).hexdigest()==pin["sha256"],"bootstrap content/identity")
    return raw

def bind_reviewed_helpers(M,original_raw,bindings):
    # Exact fixed-source direct nested definitions only; no original main is called.
    tree=ast.parse(original_raw,ORIGINAL["path"])
    mains=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main"]
    need(len(mains)==1,"one reviewed main")
    found={n.name:n for n in mains[0].body if isinstance(n,ast.FunctionDef)}
    need(tuple(found)==HELPERS,"closed reviewed helper roster/order")
    ns=dict(M); ns.update(bindings)
    module=ast.Module(body=[found[n] for n in HELPERS],type_ignores=[])
    exec(compile(module,ORIGINAL["path"],"exec",optimize=0),ns)
    return ns

def validate_original_failure(M,F,H,ctx,expected,closed_source,old_spec,receipt,terminal):
    parse,pin,encode=M["parse"],M["pin"],M["encode"]
    directory=pathlib.Path(ORIGINAL_RECEIPT["path"]).parent
    need(receipt["schema"]=="trnm-r1-diagnostic-stage1-publication-receipt-v1"
         and receipt["driver"]==ORIGINAL and receipt["spec"]==ORIGINAL_SPEC
         and receipt["subject_commit"]==M["HEAD"] and receipt["subject_tree"]==M["TREE"]
         and receipt["main"]==M["BASE"] and receipt["candidate_branch"]==M["CANDIDATE"]
         and encode(receipt["control"])==encode(CONTROL)
         and receipt["workflow"]==M["WORKFLOW_PIN"] and receipt["stage1_helper"]==M["HELPER_PIN"]
         and receipt["archive_resume_proof"]==old_spec["confirmed_archive_resume"]
         and receipt["preserved_archive_tags"]==M["OLD_TAGS"],"original diagnostic identity")
    need(receipt["status"]=="UNKNOWN" and receipt["push_started"] is True
         and type(receipt["push_exit"]) is int and receipt["push_exit"]==128
         and receipt["publication_confirmed"] is False and receipt["exact_hook_verified"] is False
         and receipt["objects_started"] is True and receipt["local_tag_created"] is True
         and receipt["source_after_valid"] is True and receipt["source_index_unchanged"] is True
         and receipt["local_ref_fence_valid"] is True
         and receipt["dispatch_started"] is False and receipt["dispatch_exit"] is None
         and receipt["dispatch_status"]=="NOT_STARTED" and receipt["dispatch_response"] is None,
         "natural failed first attempt, no dispatch")
    for key in ("source_or_branch_changed","main_or_pr_changed","protection_changed","required_ci_replaced",
                "qualification_granted","diagnostic_result_observed","repository_template_push_executed",
                "automatic_retry_authorized","untouched_refs_atomically_locked"):
        need(receipt[key] is False,"original scope:"+key)
    need(receipt["errors"]==[{"message":"remote after is not exact new tag plus unchanged old refs",
         "phase":"post-push-readback","type":"ValueError"}],"original failure preserved")
    rows={}
    for row in receipt["steps"]:
        label=row["label"]
        need(type(label) is str and re.fullmatch(r"[a-z0-9-]+",label) and label not in rows
             and row["cwd"]==str(M["SOURCE"]),"original step identity")
        rows[label]=row
        for ch in ("stdout","stderr"):
            need(row[ch+"_path"]==str(directory/(label+"."+ch)),"original bounded stream path")
            pin({k:row[ch+"_"+k] for k in ("path","bytes","sha256")})
    need(len(rows)==72 and "dispatch-stage1-once" not in rows,"original closed command roster")
    push=rows["atomic-diagnostic-tag-publish"]
    need(push["argv"]==["git","-c","core.hooksPath="+str(directory/"hooks"),"push","--verify","--atomic",
              "--porcelain","--verbose","--progress","origin",M["TAGREF"]+":"+M["TAGREF"]]
         and type(push["exit"]) is int and push["exit"]==128
         and type(push["timeout_seconds"]) is int and push["timeout_seconds"]==3600,
         "original actual transport outcome")
    need(push["stdout_bytes"]==0 and push["stdout_sha256"]==hashlib.sha256(b"").hexdigest()
         and push["stderr_bytes"]==253
         and push["stderr_sha256"]=="e87dfa9246507fc202fc863d3aebb6502a7b394b9e3e91d2d086d423235d5b0d",
         "original complete connect-failure bytes")
    saved=lambda label,argv,timeout=180: M["saved_step"](receipt,directory,label,argv,timeout)
    for label in ("project-preflight-before-objects","project-preflight-prepush","project-preflight-after-publication"):
        saved(label,["bash","scripts/project-preflight.sh"])
    for label,name in (("verify-source-before","source-before.json"),
                       ("verify-source-after-publication","source-after-publication.json")):
        streams=saved(label,[H["PYTHON"],"-B","scripts/ci/verify_ci_source.py","--kind","head",
             "--expected-head",M["HEAD"],"--output",str(directory/name)])
        need(streams["stdout"]==M["stable"](directory/name)==closed_source
             and M["source_identity"](streams["stdout"])==ctx["gate_source"],"original full source")
    for phase,match in (("remote_before",True),("remote_prepush",True),("remote_after",False)):
        observation=receipt[phase]
        need(observation["heads"]==expected and observation["tags"]==M["OLD_TAGS"]
             and observation["errors"]==[] and observation["matches"] is match,
             "original exact absent diagnostic tag")
        prefix=phase.replace("_","-")
        a=saved(prefix+"-heads",["git","ls-remote","--heads","origin"])
        b=saved(prefix+"-tags",["git","ls-remote","origin",*sorted(M["OLD_TAGS"]),M["TAGREF"],M["TAGREF"]+"^{}"])
        need(F["parse_refs"](a["stdout"],heads=True)==expected
             and F["parse_refs"](b["stdout"],allowed=set(M["OLD_TAGS"])|{M["TAGREF"],M["TAGREF"]+"^{}"})==M["OLD_TAGS"],
             "original raw remote observations")
    need(receipt.get("remote_final") is None,"original dispatch was not entered")
    def local_refs(raw):
        out={}
        for line in raw.decode("ascii").splitlines():
            parts=line.split()
            need(len(parts)==2 and parts[0].startswith("refs/") and parts[0] not in out
                 and re.fullmatch(r"[0-9a-f]{40}",parts[1]),"original local refs")
            out[parts[0]]=parts[1]
        return out
    argv=["git","--no-replace-objects","for-each-ref","--format=%(refname) %(objectname)"]
    before=local_refs(saved("local-refs-before",argv,60)["stdout"])
    after=local_refs(saved("local-refs-after-publication",argv,60)["stdout"])
    need(M["TAGREF"] not in before and after==dict(before,**{M["TAGREF"]:CONTROL["tag_oid"]}),
         "original sole local tag creation")
    identity={}
    for field,tail in (("head",["rev-parse","HEAD"]),("tree",["rev-parse","HEAD^{tree}"]),
                       ("status",["status","--porcelain=v1","--untracked-files=all"]),
                       ("symbolic_ref",["symbolic-ref","HEAD"])):
        suffix="symbolic" if field=="symbolic_ref" else field
        a=saved("source-initial-"+suffix,["git","--no-replace-objects",*tail],60)["stdout"]
        b=saved("source-after-publication-"+suffix,["git","--no-replace-objects",*tail],60)["stdout"]
        need(a==b,"original source checkout identity")
        identity[field]=a.decode() if field=="status" else a.decode("ascii").strip()
    need(identity["head"]==M["HEAD"] and identity["tree"]==M["TREE"] and identity["status"]==""
         and identity["symbolic_ref"].startswith("refs/heads/"),"original unchanged development checkout")
    for label,kind,key,limit in (("diagnostic-control-object","commit","commit",128*1024),
                                ("diagnostic-tag-object","tag","tag_oid",64*1024)):
        raw=saved(label,["git","--no-replace-objects","cat-file",kind,CONTROL[key]],60)["stdout"]
        need(0<len(raw)<=limit and F["git_object_oid"](kind,raw)==CONTROL[key],"original object identity")
        if kind=="commit": F["check_commit_object"](raw,CONTROL[key],CONTROL["tree"],CONTROL["parents"])
        else: F["check_tag_object"](raw,CONTROL[key],CONTROL["tag"],CONTROL["commit"])
    t=terminal
    need(t["host"]=="mac" and t["session_id"]==ORIGINAL_SESSION
         and t["output_complete"] is True and t["truncated_before_offset"] is False
         and t["text_is_lossy"] is False and t["utf8_pending"] is False
         and t["status"]["state"]=="exited" and type(t["status"]["exit_code"]) is int
         and t["status"]["exit_code"]==1 and t["status"]["output_complete"] is True
         and t["status"]["capture_error"] is None,"actual natural original terminal")
    need(type(t["bytes_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2})*",t["bytes_hex"]),"original terminal bytes")
    raw=bytes.fromhex(t["bytes_hex"])
    need(len(raw)==1072 and hashlib.sha256(raw).hexdigest()==t["chunk_sha256"]
         =="50738df8c15db81515a783ddb06b786b4790c0dc3b0209b02aa973714c608e16"
         and type(t["offset"]) is int and t["offset"]==0
         and all(type(n) is int and n==1072 for n in (t["next_offset"],t["available_end"],
                t["status"]["bytes_seen"],t["status"]["bytes_stored"])),"complete original terminal")
    fields=("schema","status","subject_commit","control","publication_confirmed","push_exit",
            "dispatch_started","dispatch_exit","dispatch_status","dispatch_response","qualification_granted")
    printed={k:receipt[k] for k in fields};printed["receipt"]=ORIGINAL_RECEIPT["path"]
    need(len(raw.splitlines())==1 and encode(parse(raw.splitlines()[0]))==encode(printed),
         "original terminal and receipt exact equality")
    return {"local_refs":after,"identity":identity,"source_index":receipt["source_index_before"]}

def validate_reviewed_remote_drift(M,historical_expected,inputs):
    # Read only fixed closed evidence. This is not a fresh Git/peeled observation.
    need(M["encode"](inputs)==M["encode"](DRIFT_INPUTS),"fixed root-reviewed remote drift inputs")
    parse,pin,encode=M["parse"],M["pin"],M["encode"]
    retained={name:(item,pin(item)) for name,item in inputs.items()}
    observation=parse(retained["summary"][1])
    need(observation["schema"]=="trnm-complete-remote-refs-API-observation-v1"
         and observation["complete"] is True and observation["errors"]==[]
         and observation["network_readonly"] is True and observation["qualification"] is False
         and observation["automatic_retry"] is False
         and observation["HEAD_and_TAG_reads_not_atomic"] is True
         and observation["all_refs_from_nonpaginated_documented_matching_prefix_endpoint"] is True,
         "actual complete read-only non-atomic API observation")
    rows=observation["steps"]
    need(type(rows) is list and len(rows)==2,"exact two API reads")
    mapped={}
    for row,kind,count in zip(rows,("heads","tags"),(908,5)):
        label="remote-"+kind
        endpoint="repos/TrillionniumFoundation/Trillionnium-Chain/git/matching-refs/"+kind+"/"
        need(row["label"]==label and row["endpoint"]==endpoint and row["method"]=="GET"
             and row["argv"]==["/opt/homebrew/bin/gh","api","--hostname","github.com","--method","GET",endpoint]
             and row["cwd"]=="/private/tmp" and row["origin"]=="https://api.github.com/"+endpoint
             and type(row["exit"]) is int and row["exit"]==0 and row["complete_transport"] is True
             and row["automatic_retry"] is False and row["termination_reason"] is None
             and row["GH_DEBUG_removed"] is True and row["GH_HOST"]=="github.com"
             and row["HTTP_status_unparsed"] is True
             and all(type(row[k]) is int and row[k]==300 for k in ("timeout_seconds","overall_deadline_seconds"))
             and type(row["stdout_cap_bytes"]) is int and row["stdout_cap_bytes"]==4194304
             and type(row["stderr_cap_bytes"]) is int and row["stderr_cap_bytes"]==2097152
             and row["stdout"]==inputs[kind],"closed API command and raw output binding")
        step_pin=row["step_receipt"]
        need(step_pin["path"]==str(DRIFT_DIR/(label+".step.json"))
             and row["stderr"]=={"path":str(DRIFT_DIR/(label+".stderr")),"bytes":0,
                 "sha256":hashlib.sha256(b"").hexdigest()},"fixed original API step/stream paths")
        sr=pin(step_pin); er=pin(row["stderr"])
        need(encode(parse(sr))==encode({k:v for k,v in row.items() if k!="step_receipt"}) and er==b"",
             "original step receipt and empty stderr bytes")
        retained[kind+"_step"]=(step_pin,sr);retained[kind+"_stderr"]=(row["stderr"],er)
        items=parse(retained[kind][1])
        need(type(items) is list and len(items)==count,"complete matching-prefix reference count")
        refs={}
        for item in items:
            need(type(item) is dict and set(item)=={"ref","node_id","url","object"},"raw API reference shape")
            ref=item["ref"]; obj=item["object"]
            need(type(ref) is str and ref.startswith("refs/"+kind+"/") and len(ref)>len("refs/"+kind+"/")
                 and ref not in refs and type(item["node_id"]) is str and bool(item["node_id"])
                 and item["url"]=="https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/git/"+ref
                 and type(obj) is dict and set(obj)=={"sha","type","url"}
                 and type(obj["sha"]) is str and re.fullmatch(r"[0-9a-f]{40}",obj["sha"])
                 and obj["type"] in (("commit",) if kind=="heads" else ("commit","tag"))
                 and obj["url"]=="https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/git/"
                     +("commits/" if obj["type"]=="commit" else "tags/")+obj["sha"],
                 "raw immutable reference name/type/address")
            refs[ref]={"oid":obj["sha"],"type":obj["type"]}
        need(refs==observation["refs"][label],"raw API references equal saved summary")
        mapped[kind]=refs
    current={ref[len("refs/heads/"):]:item["oid"] for ref,item in mapped["heads"].items()}
    need(type(historical_expected) is dict and len(historical_expected)==908
         and historical_expected[M["CANDIDATE"]]==M["HEAD"]
         and set(current)==set(historical_expected) and current["main"]==M["BASE"]
         and current[M["CANDIDATE"]]==REMOTE_HEAD
         and {k for k in current if current[k]!=historical_expected[k]}=={M["CANDIDATE"]},
         "only explicit R1-to-5df candidate drift, other 907 heads unchanged")
    archive_objects={ref:oid for ref,oid in M["OLD_TAGS"].items() if not ref.endswith("^{}")}
    need(len(archive_objects)==3 and len(M["OLD_TAGS"])==6
         and all(mapped["tags"].get(ref)=={"oid":oid,"type":"tag"} for ref,oid in archive_objects.items())
         and M["TAGREF"] not in mapped["tags"] and M["TAGREF"]+"^{}" not in mapped["tags"],
         "same three archive tag objects and absent diagnostic tag; API does not assert peels")
    t=parse(retained["terminal"][1])
    need(t["host"]=="mac" and t["session_id"]==DRIFT_SESSION
         and t["output_complete"] is True and t["truncated_before_offset"] is False
         and t["text_is_lossy"] is False and t["utf8_pending"] is False
         and t["status"]["state"]=="exited" and type(t["status"]["exit_code"]) is int
         and t["status"]["exit_code"]==0 and t["status"]["output_complete"] is True
         and t["status"]["capture_error"] is None
         and type(t["bytes_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2})*",t["bytes_hex"]),
         "actual naturally completed remote-observation terminal")
    tb=bytes.fromhex(t["bytes_hex"])
    need(len(tb)==1582 and M["sha"](tb)==t["chunk_sha256"]
         =="3cdd7b580ea68cc91387a58ab439c41cf3812a8b056a696bb09052ec8a5dd1d2"
         and type(t["offset"]) is int and t["offset"]==0
         and all(type(n) is int and n==1582 for n in (t["next_offset"],t["available_end"],
                 t["status"]["bytes_seen"],t["status"]["bytes_stored"])),"complete actual terminal coverage")
    lines=tb.splitlines();need(len(lines)==3,"two actual command results and terminal summary")
    for line,row in zip(lines[:2],rows):
        need(encode(parse(line))==encode({"label":row["label"],"exit":0,"complete_transport":True,
             "stdout_bytes":row["stdout"]["bytes"],"stdout_sha256":row["stdout"]["sha256"]}),
             "actual terminal command result")
    index_pin={"path":str(DRIFT_DIR/"EVIDENCE_INDEX.json"),"bytes":1957,
               "sha256":"ba7947510273260216c8e7a54958c8dc2aec03a44b0f28b8d1e1bd01e2450bd8"}
    last={"complete":True,"summary":inputs["summary"],"index":index_pin,"heads":908,"tags":5,
          "main":mapped["heads"]["refs/heads/main"],
          "candidate":mapped["heads"]["refs/heads/"+M["CANDIDATE"]],
          "owned_tags":{ref:item for ref,item in mapped["tags"].items() if ref.startswith("refs/tags/archive/")},
          "errors":[]}
    need(encode(parse(lines[2]))==encode(last),"actual terminal refers to exact closed API summary")
    ir=pin(index_pin); index=parse(ir)
    reader_pin={"path":str(DRIFT_DIR/"reader.py"),"bytes":3417,
                "sha256":"90905300a25b4fa8f2e49a3f90dcdc57438709123f9e3b40646e48e347d8c286"}
    wanted=[reader_pin,inputs["summary"]]+[row[k] for row in rows for k in ("stdout","stderr","step_receipt")]
    need(set(index)=={"files","self_excluded"} and index["self_excluded"] is True
         and type(index["files"]) is list and len(index["files"])==8
         and encode(sorted(index["files"],key=lambda x:x["path"]))==encode(sorted(wanted,key=lambda x:x["path"])),
         "closed original index roster")
    retained["index"]=(index_pin,ir);retained["reader"]=(reader_pin,pin(reader_pin))
    comparison=parse(retained["comparison"][1])
    change={M["CANDIDATE"]:{"old":M["HEAD"],"new":REMOTE_HEAD}}
    need(comparison["schema"]=="trnm-explicit-R1-to-5df-remote-drift-comparison-v1"
         and comparison["inputs"]==[ORIGINAL_RECEIPT,inputs["summary"],inputs["heads"],inputs["tags"]]
         and comparison["changed"]==change and comparison["added"]==comparison["removed"]==[]
         and type(comparison["head_count"]) is int and comparison["head_count"]==908
         and type(comparison["unchanged_heads"]) is int and comparison["unchanged_heads"]==907
         and comparison["archive_tag_objects_unchanged"]==archive_objects
         and comparison["diagnostic_tag_absent"] is True and comparison["fresh_peeled_tag_observation"] is False
         and comparison["read_only"] is True and comparison["new_source_acceptance"] is False
         and comparison["qualification"] is False and type(comparison["new_network_calls"]) is int
         and comparison["new_network_calls"]==0
         and comparison["new_observed_from"]==observation["started_at"]
         and comparison["new_observed_to"]==observation["finished_at"],"root-reviewed exact drift boundary")
    proof={"inputs":inputs,"raw_files":{name:item for name,(item,_) in retained.items()},
           "actual_session":DRIFT_SESSION,"actual_terminal_exit":0,
           "observed_from":observation["started_at"],"observed_to":observation["finished_at"],
           "changed":change,"unchanged_heads":907,"added":[],"removed":[],
           "archive_tag_objects":archive_objects,"diagnostic_tag_absent":True,
           "fresh_peeled_tag_observation":False,"fresh_Git_six_archive_refs_still_required":True,
           "subject_commit":M["HEAD"],"subject_tree":M["TREE"],
           "new_source_acceptance":False,"qualification":False}
    return current,proof,retained

def main():
    need(not sys.flags.optimize and pathlib.Path(__file__).resolve(strict=True)==SELF,
         "fixed nonoptimized recovery producer")
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--spec",required=True);ap.add_argument("--spec-bytes",required=True,type=int)
    ap.add_argument("--spec-sha256",required=True);args=ap.parse_args()
    original_raw=fixed_read(ORIGINAL)
    M={"__name__":"_reviewed_diagnostic_publisher_definitions_only","__file__":ORIGINAL["path"]}
    exec(compile(original_raw,ORIGINAL["path"],"exec",optimize=0),M)
    need(M["ROOT"]==ROOT and str(M["SELF"])==ORIGINAL["path"]
         and M["TAG"]==CONTROL["tag"] and M["HEAD"]==CONTROL["subject_commit"]
         and M["TREE"]==CONTROL["subject_tree"],"reviewed original publisher scope")
    need(M["pin"](ORIGINAL)==original_raw,"loaded original source stable")
    spec_pin={"path":args.spec,"bytes":args.spec_bytes,"sha256":args.spec_sha256}
    raw=M["pin"](spec_pin);spec=M["parse"](raw)
    wanted={"schema","producer_sha256","evidence_dir","original_producer","original_spec",
            "original_receipt","original_terminal","control","transport_timeout_seconds","dispatch_timeout_seconds",
            "reviewed_remote_drift","remote_hook"}
    need(type(spec) is dict and set(spec)==wanted
         and spec["schema"]=="trnm-r1-diagnostic-stage1-resume-spec-v2"
         and spec["original_producer"]==ORIGINAL and spec["original_spec"]==ORIGINAL_SPEC
         and spec["original_receipt"]==ORIGINAL_RECEIPT and spec["original_terminal"]==ORIGINAL_TERMINAL
         and M["encode"](spec["reviewed_remote_drift"])==M["encode"](DRIFT_INPUTS)
         and spec["remote_hook"]==REMOTE_HOOK
         and M["encode"](spec["control"])==M["encode"](CONTROL)
         and type(spec["transport_timeout_seconds"]) is int and spec["transport_timeout_seconds"]==3600
         and type(spec["dispatch_timeout_seconds"]) is int and spec["dispatch_timeout_seconds"]==180,
         "fixed recovery inputs and original budgets")
    own=M["stable"](SELF,128*1024)
    need(M["sha"](own)==spec["producer_sha256"],"recovery producer pin")
    old_spec_raw=M["pin"](ORIGINAL_SPEC);old_spec=M["parse"](old_spec_raw)
    original_receipt_raw=M["pin"](ORIGINAL_RECEIPT);original_receipt=M["parse"](original_receipt_raw)
    original_terminal_raw=M["pin"](ORIGINAL_TERMINAL);original_terminal=M["parse"](original_terminal_raw)
    need(old_spec["producer_sha256"]==ORIGINAL["sha256"] and old_spec["diagnostic_tag"]==M["TAG"]
         and old_spec["workflow"]==M["WORKFLOW_PIN"] and old_spec["stage1_helper"]==M["HELPER_PIN"],
         "original reviewed diagnostic material")
    # This is the same complete pure proof that passed before the first attempt.
    P,R,F,H,ctx,historical_expected,closed_source=M["closed_archive"](old_spec["confirmed_archive_resume"])
    previous=validate_original_failure(M,F,H,ctx,historical_expected,closed_source,old_spec,
                                       original_receipt,original_terminal)
    expected,drift_proof,drift_retained=validate_reviewed_remote_drift(M,historical_expected,
                                                                  spec["reviewed_remote_drift"])
    workflow=M["pin"](M["WORKFLOW_PIN"]);helper=M["pin"](M["HELPER_PIN"])
    original_template_pin={"path":str(M["HOOK"]),"bytes":M["HOOK_BYTES"],"sha256":M["HOOK_SHA"]}
    original_template=M["pin"](original_template_pin)
    template=M["pin"](REMOTE_HOOK)
    old_literal=('HEAD = "'+M["HEAD"]+'"').encode()
    new_literal=('HEAD = "'+REMOTE_HEAD+'"').encode()
    need(original_template.count(old_literal)==1
         and template==original_template.replace(old_literal,new_literal),
         "effective hook changes only its explicit remote candidate head; R1 subject is unchanged")
    begin=b'          cat > "$RUNNER_TEMP/r1-stage1-helper.py" <<'+b"'R1_STAGE1_PY'\n"
    end=b"          R1_STAGE1_PY\n"
    need(workflow.count(begin)==workflow.count(end)==1,"one reviewed embedded helper")
    lines=workflow.split(begin,1)[1].split(end,1)[0].splitlines(keepends=True)
    need(all(x.startswith(b"          ") for x in lines) and b"".join(x[10:] for x in lines)==helper,
         "exact workflow/helper coupling")
    ev=pathlib.Path(spec["evidence_dir"])
    need(ev.parent==ROOT and re.fullmatch(r"r1-diagnostic-stage1-publish-v1-[a-z0-9-]+",ev.name)
         and ROOT.resolve(strict=True)==ROOT and ev!=pathlib.Path(ORIGINAL_RECEIPT["path"]).parent,
         "new create-only evidence, original hook namespace")
    ev.mkdir(mode=0o700,exist_ok=False);os.umask(0o077)
    env=P["safe_environment"](H)
    env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com";env["GIT_TERMINAL_PROMPT"]="0"
    need("GIT_INDEX_FILE" not in env and env.get("GIT_OPTIONAL_LOCKS")=="0","original source index protections")
    HEAD,TREE,BASE,SOURCE,TAG,TAGREF,OLD_TAGS,URL,ZERO,ACTOR,WORKFLOW,API_VERSION,DISPATCH_ENDPOINT=(
        M[k] for k in ("HEAD","TREE","BASE","SOURCE","TAG","TAGREF","OLD_TAGS","URL","ZERO","ACTOR",
                        "WORKFLOW","API_VERSION","DISPATCH_ENDPOINT"))
    sha,encode,stable,index_snapshot,hook_proof,dispatch_response=(
        M[k] for k in ("sha","encode","stable","index_snapshot","hook_proof","dispatch_response"))
    DISPATCH_SECONDS=M["DISPATCH_SECONDS"]
    control=dict(CONTROL)
    state={"schema":"trnm-r1-diagnostic-stage1-resume-receipt-v2","status":"HOLD","started_at":M["now"](),
       "driver":{"path":str(SELF),"bytes":len(own),"sha256":sha(own)},"spec":spec_pin,
       "original_attempt":{"producer":ORIGINAL,"spec":ORIGINAL_SPEC,"receipt":ORIGINAL_RECEIPT,
           "terminal":ORIGINAL_TERMINAL,"status":"UNKNOWN","push_exit":128,
           "exact_hook_verified":False,"dispatch_started":False,"dispatch_status":"NOT_STARTED"},
       "subject_commit":HEAD,"subject_tree":TREE,"main":BASE,"candidate_branch":M["CANDIDATE"],
       "remote_candidate_head":REMOTE_HEAD,"reviewed_remote_drift":drift_proof,
       "hook_template_plan":{"original":original_template_pin,"effective":REMOTE_HOOK,
           "only_change":{"remote_candidate_head":{"old":HEAD,"new":REMOTE_HEAD}},
           "subject_commit_unchanged":True},
       "workflow":M["WORKFLOW_PIN"],"stage1_helper":M["HELPER_PIN"],"diagnostic_tag":TAG,
       "archive_resume_proof":old_spec["confirmed_archive_resume"],"preserved_archive_tags":OLD_TAGS,
       "control":control,"objects_started":False,"local_tag_created":False,"existing_control_verified":False,
       "push_started":False,"push_exit":None,"publication_confirmed":False,
       "dispatch_started":False,"dispatch_exit":None,"dispatch_status":"NOT_STARTED","dispatch_response":None,
       "remote_before":None,"remote_prepush":None,"remote_after":None,"remote_final":None,
       "source_after_valid":False,"local_ref_fence_valid":False,"source_index_unchanged":False,
       "exact_hook_verified":False,"steps":[],"errors":[],"source_or_branch_changed":False,
       "main_or_pr_changed":False,"protection_changed":False,"required_ci_replaced":False,
       "qualification_granted":False,"diagnostic_result_observed":False,
       "repository_template_push_executed":False,"automatic_retry_authorized":False,
       "untouched_refs_atomically_locked":False}
    ns=bind_reviewed_helpers(M,original_raw,{"ev":ev,"env":env,"state":state,"H":H,"R":R,"F":F,
        "ctx":ctx,"expected":expected,"closed_source":closed_source,"initial_identity":previous["identity"]})
    emit,save,run,git,value,identity,refs,hook_guard,actor,observe,object_raw,verify_source,input_fence=(
        ns[name] for name in HELPERS)
    emit("spec.json",raw);emit("producer.py",own)
    emit("original-publication-spec.json",old_spec_raw)
    emit("original-failed-publication-receipt.json",original_receipt_raw)
    emit("original-failed-publication-terminal.json",original_terminal_raw)
    emit("reviewed-workflow.yml",workflow);emit("reviewed-stage1-helper.py",helper)
    emit("original-validated-boundary.json",encode(previous))
    emit("reviewed-remote-drift.json",encode(drift_proof))
    for name,(_,data) in drift_retained.items():
        emit("remote-drift-"+name+".original",data)
    emit("original-hook-template.py",original_template);emit("current-hook-template.py",template)
    emit("control.json",encode(control));save()
    before_refs=previous["local_refs"]
    before_index=previous["source_index"]
    index_path=pathlib.Path(before_index["path"])
    state["source_index_before"]=before_index
    guard=None
    try:
        run("project-preflight-before-resume",["bash","scripts/project-preflight.sh"])
        identity("source-initial")
        need(refs("local-refs-before")==before_refs,"complete local refs differ from closed original")
        need(pathlib.Path(value("source-index-path","rev-parse","--path-format=absolute","--git-path","index"))==index_path
             and index_snapshot(index_path)==before_index,"same original source index bytes and identity")
        guard=hook_guard("hook-initial");who=actor("actor-before")
        state["remote_before"]=observe("remote-before")
        # This executor deliberately has no already-published/dispatch-only branch.
        need(state["remote_before"]["matches"],"require exact reviewed current 908 heads/three archives and diagnostic tag absent")
        verify_source("verify-source-before","source-before.json")
        for number,(ref,oid) in enumerate((x for x in OLD_TAGS.items() if not x[0].endswith("^{}")),1):
            need(value("old-tag-"+str(number),"rev-parse",ref)==oid
                 and value("old-peel-"+str(number),"rev-parse",ref+"^{}")==OLD_TAGS[ref+"^{}"],
                 "original archive local identity")
            F["check_tag_object"](object_raw("old-tag-object-"+str(number),"tag",oid,64*1024),
                                   oid,ref[10:],OLD_TAGS[ref+"^{}"])
        F["check_commit_object"](object_raw("closed-diagnostic-archive","commit",M["DIAG_ARCHIVE"]["commit"],128*1024),
             M["DIAG_ARCHIVE"]["commit"],M["DIAG_ARCHIVE"]["tree"],M["DIAG_ARCHIVE"]["direct_parents"])
        need(value("existing-diagnostic-tag","rev-parse",TAGREF)==control["tag_oid"]
             and value("existing-diagnostic-peel","rev-parse",TAGREF+"^{}")==control["commit"],"same existing local tag")
        F["check_tag_object"](object_raw("existing-diagnostic-tag-object","tag",control["tag_oid"],64*1024),
                              control["tag_oid"],TAG,control["commit"])
        F["check_commit_object"](object_raw("existing-diagnostic-control","commit",control["commit"],128*1024),
                                 control["commit"],control["tree"],[HEAD])
        need(object_raw("existing-workflow-blob","blob",control["workflow_blob"],64*1024)==workflow,
             "same existing exact reviewed workflow blob")
        need(git("original-workflow-entry","ls-tree",HEAD,"--",WORKFLOW).stdout.decode()
             =="100644 blob "+M["OLD_WORKFLOW_OID"]+"\t"+WORKFLOW+"\n","original R1 workflow entry")
        need(git("control-tree-changed-paths","diff-tree","--no-commit-id","--name-only","-r",TREE,control["tree"]).stdout.decode().splitlines()
             ==[WORKFLOW],"existing control changes only reviewed workflow")
        need(git("control-tree-workflow-entry","ls-tree",control["tree"],"--",WORKFLOW).stdout.decode()
             =="100644 blob "+control["workflow_blob"]+"\t"+WORKFLOW+"\n","existing workflow mode/object")
        state["existing_control_verified"]=True
        hdir=ev/"hooks";hdir.mkdir(mode=0o700)
        expected_raw=encode({"origin":URL,"remote_heads":expected,"old_archive_tags":OLD_TAGS,"new_tag_ref":TAGREF,
            "updates":{TAGREF:{"local_ref":TAGREF,"new":control["tag_oid"],"old":ZERO}}})
        need(template.count(b"__EXPECTED_SHA256__")==1
             and template.count(b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__")==1,"exact original hook substitutions")
        effective=template.replace(b"__EXPECTED_SHA256__",sha(expected_raw).encode()).replace(
            b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__",("EXPECTED_BYTES = "+str(len(expected_raw))).encode())
        original_hooks=pathlib.Path(ORIGINAL_RECEIPT["path"]).parent/"hooks"
        historical_raw=encode({"origin":URL,"remote_heads":historical_expected,"old_archive_tags":OLD_TAGS,
            "new_tag_ref":TAGREF,"updates":{TAGREF:{"local_ref":TAGREF,"new":control["tag_oid"],"old":ZERO}}})
        historical_effective=original_template.replace(b"__EXPECTED_SHA256__",sha(historical_raw).encode()).replace(
            b"EXPECTED_BYTES = 0  # __EXPECTED_BYTES__",("EXPECTED_BYTES = "+str(len(historical_raw))).encode())
        need(stable(original_hooks/"expected.json")==historical_raw
             and stable(original_hooks/"pre-push")==historical_effective,
             "same original historical R1 hook inputs; no claim it ran")
        for name,data in (("expected.json",expected_raw),("pre-push",effective)):
            with (hdir/name).open("xb") as f:
                f.write(data);f.flush();os.fsync(f.fileno())
        (hdir/"pre-push").chmod(0o700)
        run("project-preflight-prepush",["bash","scripts/project-preflight.sh"])
        identity("source-prepush");need(actor("actor-prepush")==who,"actor drift")
        state["remote_prepush"]=observe("remote-prepush")
        need(state["remote_prepush"]["matches"],"fresh remote maps/tag drift")
        need(hook_guard("hook-final")==guard,"installed hook/URL drift")
        need(refs("local-refs-prepush")==before_refs and index_snapshot(index_path)==before_index,
             "source refs/index drift")
        input_fence()
        need(stable(hdir/"expected.json")==expected_raw and stable(hdir/"pre-push")==effective,"new owned hook bytes")
        state["push_started"]=True;state["status"]="UNKNOWN";save()
        q=run("atomic-diagnostic-tag-resume",["git","-c","core.hooksPath="+str(hdir),"push","--verify","--atomic",
              "--porcelain","--verbose","--progress","origin",TAGREF+":"+TAGREF],
              timeout=M["TRANSPORT_SECONDS"],must=False)
        state["push_exit"]=q.returncode;save()
    except Exception as e:
        state["errors"].append({"phase":"verify-existing-or-single-push","type":type(e).__name__,"message":str(e)})
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
            identity("source-after-publication");state["source_after_valid"]=True
            need(guard is not None and hook_guard("hook-after-publication")==guard,"original hook/URL after publication")
            need(refs("local-refs-after-publication")==before_refs,"all original local refs unchanged")
            state["local_ref_fence_valid"]=True
            need(index_snapshot(index_path)==before_index,"original source index unchanged")
            state["source_index_unchanged"]=True;input_fence()
        except Exception as e:
            state["errors"].append({"phase":"publication-source-ref-index-fence","type":type(e).__name__,"message":str(e)})
        state["publication_confirmed"]=(state["push_started"] and type(state["push_exit"]) is int and state["push_exit"]==0
            and state["existing_control_verified"] and not state["errors"] and state["source_after_valid"]
            and state["source_index_unchanged"] and state["local_ref_fence_valid"] and state["exact_hook_verified"]
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
    state["finished_at"]=M["now"]();save()
    print(json.dumps({"schema":state["schema"],"status":state["status"],"subject_commit":HEAD,"control":control,
        "publication_confirmed":state["publication_confirmed"],"push_exit":state["push_exit"],
        "dispatch_started":state["dispatch_started"],"dispatch_exit":state["dispatch_exit"],
        "dispatch_status":state["dispatch_status"],"dispatch_response":state["dispatch_response"],
        "qualification_granted":False,"receipt":str(ev/"summary.json")}),flush=True)
    return 0 if state["status"]=="DISPATCH_ACCEPTED_NOT_OBSERVED" else 1

if __name__=="__main__":
    sys.exit(main())
