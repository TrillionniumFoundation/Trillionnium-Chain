"""Dispatch-only continuation for the already published R1 stage-one diagnostic tag.
Definitions are inert. main contains no Git write, push, tag creation or retry.
The original UNKNOWN receipt and its failed final observations remain unchanged.
"""
import argparse, ast, hashlib, json, os, pathlib, re, stat, sys
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
PREP=ROOT/"R1-diagnostic-tag-dispatch-only-preparation-v1"
SELF=PREP/"dispatch_published_r1_stage1_v1.py"
RESUME={"path":str(ROOT/"R1-diagnostic-tag-resume-preparation-v3/resume_diagnostic_stage1_v3.py"),"bytes":54443,"sha256":"6f6a2dd66b0baa46eb9bcf4ed9d51cb4b502316a643abb1a184ae844a874bd50"}
RESUME_SPEC={"path":str(ROOT/"R1-diagnostic-tag-resume-preparation-v3/spec.for-review.json"),"bytes":5156,"sha256":"e6afd04a65a3e8e305f2fe1a74239b751816b7c8e17e16d30ab9568ab0222543"}
PUBLISHED={"path":str(ROOT/"r1-diagnostic-stage1-publish-v1-r1-after-5df-resume-002/summary.json"),"bytes":361082,"sha256":"0d3791feb688b349c3208dcc87b2a1acd5213ea0dd5b8077f879307be04b1992"}
TERMINAL={"path":str(ROOT/"r1-diagnostic-stage1-resume-v3-actual-terminal-v1.json"),"bytes":4308,"sha256":"ee22af5d330ea19f55c40c539434311cdd986ea7c9265a14245fac69e76c45df"}
CLOSED_INDEX={"path":str(PREP/"original-closure-v1/original-stream-index.json"),"bytes":64177,"sha256":"cf0e96cf73b41245692a3d5c5b8d1aaf11733bff944e462a67782a58e3ae5081"}
SESSION="dpty-9cd3095cc45ab87bad401c660609e77a7998de240b3befd09e8a184fe0123593"
REUSED=("emit","save","run","git","value","identity","refs","hook_guard","actor","object_raw","verify_source","input_fence")

def need(ok,why):
    if not ok: raise ValueError(why)

def bootstrap():
    p=pathlib.Path(RESUME["path"])
    need(p.resolve(strict=True)==p and p.is_relative_to(ROOT),"fixed bootstrap path")
    def fp(s):return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns
    s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==RESUME["bytes"],"bootstrap file")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(fp(os.fstat(fd))==fp(s),"bootstrap opened identity")
        with os.fdopen(fd,"rb",closefd=False) as f:raw=f.read(RESUME["bytes"]+1)
        need(fp(os.fstat(fd))==fp(s),"bootstrap read identity")
    finally:os.close(fd)
    need(fp(p.lstat())==fp(s) and len(raw)==RESUME["bytes"]
         and hashlib.sha256(raw).hexdigest()==RESUME["sha256"],"bootstrap pin")
    Q={"__name__":"_fixed_resume_definitions_only","__file__":str(p)}
    exec(compile(raw,str(p),"exec",optimize=0),Q)
    original=Q["fixed_read"](Q["ORIGINAL"])
    M={"__name__":"_fixed_publisher_definitions_only","__file__":Q["ORIGINAL"]["path"]}
    exec(compile(original,Q["ORIGINAL"]["path"],"exec",optimize=0),M)
    need(M["pin"](RESUME)==raw and M["pin"](Q["ORIGINAL"])==original
         and Q["ROOT"]==M["ROOT"]==ROOT,"loaded fixed definitions")
    return Q,M,original

def parse_local(raw):
    out={}
    for line in raw.decode("ascii").splitlines():
        bits=line.split()
        need(len(bits)==2 and bits[0].startswith("refs/") and bits[0] not in out
             and re.fullmatch(r"[0-9a-f]{40}",bits[1]),"closed local ref row")
        out[bits[0]]=bits[1]
    return out

def validate_published(Q,M,F,H,ctx,expected,previous,local_refs,closed_source,r,t):
    directory=pathlib.Path(PUBLISHED["path"]).parent
    need(r["schema"]=="trnm-r1-diagnostic-stage1-resume-receipt-v3"
         and r["driver"]==RESUME and r["spec"]==RESUME_SPEC and r["status"]=="UNKNOWN"
         and M["encode"](r["control"])==M["encode"](Q["CONTROL"])
         and r["subject_commit"]==M["HEAD"] and r["subject_tree"]==M["TREE"]
         and r["remote_candidate_head"]==Q["REMOTE_HEAD"]
         and r["preserved_archive_tags"]==M["OLD_TAGS"],"actual published V3 identity")
    for key in ("push_started","publication_confirmed","exact_hook_verified","existing_control_verified",
                "source_index_unchanged","local_ref_fence_valid"):
        need(r[key] is True,"closed publication flag:"+key)
    need(type(r["push_exit"]) is int and r["push_exit"]==0 and r["source_after_valid"] is False,
         "preserve successful push and actual false final source flag")
    for key in ("objects_started","local_tag_created","dispatch_started","qualification_granted",
                "diagnostic_result_observed","source_or_branch_changed","main_or_pr_changed",
                "protection_changed","required_ci_replaced","automatic_retry_authorized",
                "repository_template_push_executed"):
        need(r[key] is False,"closed no-extra-action flag:"+key)
    need(r["dispatch_status"]=="NOT_STARTED" and r["dispatch_exit"] is None
         and r["dispatch_response"] is None and "dispatch_request" not in r,"no dispatch attempted")
    need(r["errors"]==[
        {"message":"remote drift before dispatch","phase":"single-dispatch","type":"ValueError"},
        {"message":"final remote refs changed","phase":"final-dispatch-source-ref-fence","type":"ValueError"}],
        "original post-publication failure boundaries")
    index=M["parse"](M["pin"](CLOSED_INDEX))
    need(index["receipt"]==PUBLISHED and index["terminal"]==TERMINAL
         and index["all_step_streams_verified"] is True and index["step_count"]==72,"closed stream index")
    indexed={}
    for item in index["files"]:
        pin={k:item[k] for k in ("path","bytes","sha256")}
        need(pin["path"] not in indexed,"unique closed input")
        raw=M["pin"](pin)
        need(list(M["fp"](pathlib.Path(pin["path"]).lstat()))==item["version"],"closed evidence identity")
        indexed[pin["path"]]=(pin,raw)
    rows={}
    for row in r["steps"]:
        label=row["label"]
        need(re.fullmatch(r"[a-z0-9-]+",label) and label not in rows and row["cwd"]==str(M["SOURCE"])
             and type(row["exit"]) is int and type(row["timeout_seconds"]) is int,"closed command record")
        need("POST" not in row["argv"],"no previous POST")
        streams={}
        for ch in ("stdout","stderr"):
            pin={k:row[ch+"_"+k] for k in ("path","bytes","sha256")}
            need(pin["path"]==str(directory/(label+"."+ch)) and indexed[pin["path"]][0]==pin,
                 "closed complete original stream")
            streams[ch]=indexed[pin["path"]][1]
        rows[label]=(row,streams)
    need(len(rows)==72 and "dispatch-stage1-once" not in rows,"complete known command roster")
    failures={"hook-initial-config":1,"hook-final-config":1,"hook-after-publication-config":1,
              "remote-predispatch-heads":128,"remote-predispatch-tags":128,"remote-final-heads":128}
    need({label:row["exit"] for label,(row,_) in rows.items() if row["exit"]!=0}==failures,
         "exact original nonzero outcomes")
    def saved(label,argv,timeout=180):
        return M["saved_step"](r,directory,label,argv,timeout)
    for label in ("project-preflight-before-resume","project-preflight-prepush","project-preflight-after-publication"):
        saved(label,["bash","scripts/project-preflight.sh"])
    saved("atomic-diagnostic-tag-resume",["git","-c","core.hooksPath="+str(directory/"hooks"),"push",
        "--verify","--atomic","--porcelain","--verbose","--progress","origin",M["TAGREF"]+":"+M["TAGREF"]],3600)
    wanted=dict(M["OLD_TAGS"])
    wanted.update({M["TAGREF"]:Q["CONTROL"]["tag_oid"],M["TAGREF"]+"^{}":Q["CONTROL"]["commit"]})
    for phase in ("before","prepush","after"):
        a=saved("remote-"+phase+"-heads",["git","ls-remote","--heads","origin"])
        b=saved("remote-"+phase+"-tags",["git","ls-remote","origin",*sorted(M["OLD_TAGS"]),M["TAGREF"],M["TAGREF"]+"^{}"])
        tags=wanted if phase=="after" else M["OLD_TAGS"]
        obs=r["remote_"+phase]
        need(F["parse_refs"](a["stdout"],heads=True)==expected
             and F["parse_refs"](b["stdout"],allowed=set(wanted))==tags
             and obs["heads"]==expected and obs["tags"]==tags and obs["matches"] is True and obs["errors"]==[],
             "actual complete historical Git observation")
    for label in ("remote-predispatch-heads","remote-predispatch-tags","remote-final-heads"):
        row,streams=rows[label]
        need(streams["stdout"]==b"" and b"Failed to connect to github.com port 443" in streams["stderr"],
             "actual retained connection failure")
    need(r["remote_predispatch"]["matches"] is False and r["remote_final"]["matches"] is False,
         "failed final observations retained")
    need(F["parse_refs"](rows["remote-final-tags"][1]["stdout"],allowed=set(wanted))==wanted,
         "independent successful final tag read retained")
    for label,filename in (("verify-source-before","source-before.json"),
                           ("verify-source-after-publication","source-after-publication.json")):
        stream=saved(label,[H["PYTHON"],"-B","scripts/ci/verify_ci_source.py","--kind","head",
            "--expected-head",M["HEAD"],"--output",str(directory/filename)])
        need(stream["stdout"]==M["stable"](directory/filename)==closed_source
             and M["source_identity"](stream["stdout"])==ctx["gate_source"],"actual publication-phase source")
    for label in ("local-refs-before","local-refs-prepush","local-refs-after-publication"):
        stream=saved(label,["git","--no-replace-objects","for-each-ref","--format=%(refname) %(objectname)"],60)
        need(parse_local(stream["stdout"])==local_refs and len(local_refs)==1028,"actual exact local baseline")
    need(r["source_index_before"]==previous["source_index"],"same original source index")
    guards=[]
    for label in ("hook-initial","hook-final","hook-after-publication"):
        row,stream=rows[label+"-config"]
        need(row["argv"]==["git","--no-replace-objects","config","--get-all","core.hooksPath"]
             and row["timeout_seconds"]==60 and stream=={"stdout":b"","stderr":b""},"original default hook configuration")
        path=saved(label+"-default",["git","--no-replace-objects","rev-parse","--path-format=absolute",
                   "--git-path","hooks/pre-push"],60)["stdout"].decode().strip()
        for suffix,args in (("push",["remote","get-url","--push","--all","origin"]),
                            ("fetch",["remote","get-url","--all","origin"])):
            need(saved(label+"-"+suffix,["git","--no-replace-objects",*args],60)["stdout"].decode().splitlines()==[M["URL"]],
                 "original single origin")
        guards.append({"config_exit":1,"default_hook_path":path,"origin":M["URL"]})
    need(guards[0]==guards[1]==guards[2],"original installed-hook/URL identity")
    for label in ("actor-before","actor-prepush","actor-predispatch"):
        need(M["parse"](saved(label,["gh","api","user","--jq","{login,id}"])["stdout"])==M["ACTOR"],
             "original actor")
    template=M["pin"](Q["REMOTE_HOOK"])
    proof=M["hook_proof"](F,directory/"hooks",expected,M["OLD_TAGS"],M["TAGREF"],
        Q["CONTROL"]["tag_oid"],template,"trnm-r1-diagnostic-tag-prepush-v1")
    need(proof==r["hook_receipt"],"actual published owned hook")
    need(t["host"]=="mac" and t["session_id"]==SESSION and t["output_complete"] is True
         and t["truncated_before_offset"] is False and t["text_is_lossy"] is False and t["utf8_pending"] is False
         and t["status"]["state"]=="exited" and type(t["status"]["exit_code"]) is int and t["status"]["exit_code"]==1
         and t["status"]["output_complete"] is True and t["status"]["capture_error"] is None,"natural original terminal")
    tb=bytes.fromhex(t["bytes_hex"])
    need(len(tb)==1081 and M["sha"](tb)==t["chunk_sha256"]=="282c3395b5840318bbf65e86af501c546c004df24ae5a5782d3b8b49baa44474"
         and type(t["offset"]) is int and t["offset"]==0
         and all(type(n) is int and n==len(tb) for n in (t["next_offset"],t["available_end"],t["status"]["bytes_seen"],t["status"]["bytes_stored"])),
         "complete exact original terminal")
    fields=("schema","status","subject_commit","control","publication_confirmed","push_exit",
            "dispatch_started","dispatch_exit","dispatch_status","dispatch_response","qualification_granted")
    printed={k:r[k] for k in fields};printed["receipt"]=PUBLISHED["path"]
    need(len(tb.splitlines())==1 and M["encode"](M["parse"](tb.splitlines()[0]))==M["encode"](printed),"terminal/receipt equality")
    return {"receipt":PUBLISHED,"terminal":TERMINAL,"original_status":"UNKNOWN","push_exit":0,
        "publication_confirmed":True,"original_source_after_valid":False,
        "publication_phase_source_verified":True,"original_dispatch_started":False,
        "original_errors":r["errors"],"actual_hook":proof,"installed_hook_guard":guards[0]}

def closed_context(Q,M):
    rs=M["parse"](M["pin"](RESUME_SPEC))
    need(rs["schema"]=="trnm-r1-diagnostic-stage1-resume-spec-v3" and rs["producer_sha256"]==RESUME["sha256"]
         and rs["control"]==Q["CONTROL"] and rs["remote_hook"]==Q["REMOTE_HOOK"]
         and rs["reviewed_remote_drift"]==Q["DRIFT_INPUTS"] and rs["previous_local_ref_hold"]==Q["PRIOR_LOCAL_HOLD"],
         "fixed successful-publication producer/spec")
    old_spec=M["parse"](M["pin"](Q["ORIGINAL_SPEC"]))
    P,R,F,H,ctx,historical,closed_source=M["closed_archive"](old_spec["confirmed_archive_resume"])
    previous=Q["validate_original_failure"](M,F,H,ctx,historical,closed_source,old_spec,
        M["parse"](M["pin"](Q["ORIGINAL_RECEIPT"])),M["parse"](M["pin"](Q["ORIGINAL_TERMINAL"])))
    expected,drift,_=Q["validate_reviewed_remote_drift"](M,historical,rs["reviewed_remote_drift"])
    local_refs,local_hold,_=Q["validate_closed_local_ref_hold"](M,H,previous,closed_source,rs["previous_local_ref_hold"])
    published=M["parse"](M["pin"](PUBLISHED));terminal=M["parse"](M["pin"](TERMINAL))
    proof=validate_published(Q,M,F,H,ctx,expected,previous,local_refs,closed_source,published,terminal)
    return P,R,F,H,ctx,previous,expected,local_refs,closed_source,proof

def bind_helpers(Q,M,original,bindings):
    tree=ast.parse(original,Q["ORIGINAL"]["path"])
    main=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main"]
    need(len(main)==1,"one reviewed publisher main")
    found={n.name:n for n in main[0].body if isinstance(n,ast.FunctionDef)}
    need(tuple(found)==Q["HELPERS"] and set(REUSED)==set(found)-{"observe"},"exact reused helper roster")
    ns=dict(M);ns.update(bindings)
    exec(compile(ast.Module(body=[found[n] for n in REUSED],type_ignores=[]),Q["ORIGINAL"]["path"],"exec",optimize=0),ns)
    return ns

def api_json(M,raw):
    need(len(raw)<=M["MAX_META"],"bounded API JSON")
    header,sep,body=raw.replace(b"\r\n",b"\n").partition(b"\n\n")
    lines=header.splitlines()
    need(sep and lines and re.fullmatch(rb"HTTP/[0-9.]+ 200(?: [^\n]*)?",lines[0])
         and sum(x.startswith(b"HTTP/") for x in lines)==1,"single actual HTTP 200")
    need(not any(x.lower().startswith(b"link:") for x in lines[1:]),"unexpected pagination; cannot call partial result complete")
    return M["parse"](body)

def rest_refs(M,items,kind):
    need(type(items) is list and len(items)<=10000,"bounded complete matching-prefix array")
    out={};prefix="refs/"+kind+"/";base="https://api.github.com/repos/"+M["REPO"]+"/git/"
    for item in items:
        need(type(item) is dict and set(item)=={"ref","node_id","url","object"},"reference fields")
        ref=item["ref"];obj=item["object"]
        need(type(ref) is str and ref.startswith(prefix) and len(ref)>len(prefix) and ref not in out
             and type(item["node_id"]) is str and bool(item["node_id"]) and item["url"]==base+ref
             and type(obj) is dict and set(obj)=={"sha","type","url"}
             and type(obj["sha"]) is str and re.fullmatch(r"[0-9a-f]{40}",obj["sha"])
             and obj["type"] in (("commit",) if kind=="heads" else ("commit","tag"))
             and obj["url"]==base+("commits/" if obj["type"]=="commit" else "tags/")+obj["sha"],"typed immutable reference")
        out[ref]={"oid":obj["sha"],"type":obj["type"]}
    return out

def main():
    need(not sys.flags.optimize and pathlib.Path(__file__).resolve(strict=True)==SELF,"fixed nonoptimized dispatch producer")
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("--spec",required=True);ap.add_argument("--spec-bytes",type=int,required=True)
    ap.add_argument("--spec-sha256",required=True);args=ap.parse_args()
    Q,M,original=bootstrap()
    spin={"path":args.spec,"bytes":args.spec_bytes,"sha256":args.spec_sha256}
    raw=M["pin"](spin);spec=M["parse"](raw);own=M["stable"](SELF,128*1024)
    need(type(spec) is dict and set(spec)=={"schema","producer_sha256","evidence_dir","published_producer",
         "published_spec","published_receipt","published_terminal","closed_stream_index","control","remote_head","dispatch_timeout_seconds"}
         and spec["schema"]=="trnm-r1-diagnostic-stage1-dispatch-only-spec-v1"
         and spec["producer_sha256"]==M["sha"](own) and spec["published_producer"]==RESUME
         and spec["published_spec"]==RESUME_SPEC and spec["published_receipt"]==PUBLISHED
         and spec["published_terminal"]==TERMINAL and spec["closed_stream_index"]==CLOSED_INDEX
         and M["encode"](spec["control"])==M["encode"](Q["CONTROL"])
         and spec["remote_head"]==Q["REMOTE_HEAD"]
         and type(spec["dispatch_timeout_seconds"]) is int and spec["dispatch_timeout_seconds"]==180,"fixed dispatch-only spec")
    P,R,F,H,ctx,previous,expected,before_refs,closed_source,proof=closed_context(Q,M)
    ev=pathlib.Path(spec["evidence_dir"])
    need(ev.parent==ROOT and ROOT.resolve(strict=True)==ROOT
         and re.fullmatch(r"r1-diagnostic-stage1-dispatch-only-v1-[a-z0-9-]+",ev.name),"new evidence namespace")
    ev.mkdir(mode=0o700,exist_ok=False);os.umask(0o077)
    env=P["safe_environment"](H);env.pop("GH_DEBUG",None)
    env["GH_HOST"]="github.com";env["GIT_TERMINAL_PROMPT"]="0"
    need(env.get("GIT_OPTIONAL_LOCKS")=="0" and "GIT_INDEX_FILE" not in env,"read-only source index environment")
    state={"schema":"trnm-r1-diagnostic-stage1-dispatch-only-receipt-v1","status":"HOLD","started_at":M["now"](),
        "driver":{"path":str(SELF),"bytes":len(own),"sha256":M["sha"](own)},"spec":spin,
        "published_but_undispatched_proof":proof,"publication_confirmed":True,
        "subject_commit":M["HEAD"],"subject_tree":M["TREE"],"remote_candidate_head":Q["REMOTE_HEAD"],
        "control":Q["CONTROL"],"preserved_archive_tags":M["OLD_TAGS"],"dispatch_started":False,
        "dispatch_exit":None,"dispatch_status":"NOT_STARTED","dispatch_response":None,
        "source_after_valid":False,"source_index_unchanged":False,"local_ref_fence_valid":False,
        "installed_hooks_unchanged":False,"remote_before":None,"remote_final":None,"steps":[],"errors":[],
        "Git_objects_created":False,"Git_refs_written":False,"Git_push_started":False,
        "main_or_PR_or_policy_changed":False,"qualification_granted":False,"diagnostic_result_observed":False,
        "automatic_retry":False,"observations_non_atomic":True,"required_CI_replaced":False}
    ns=bind_helpers(Q,M,original,{"ev":ev,"env":env,"state":state,"H":H,"R":R,"F":F,"ctx":ctx,
        "expected":expected,"closed_source":closed_source,"initial_identity":previous["identity"]})
    emit,save=ns["emit"],ns["save"];original_run=ns["run"]
    control=Q["CONTROL"];tags=dict(M["OLD_TAGS"])
    tags.update({M["TAGREF"]:control["tag_oid"],M["TAGREF"]+"^{}":control["commit"]})
    objects={ref:oid for ref,oid in tags.items() if not ref.endswith("^{}")}
    need(len(objects)==4 and len(tags)==8 and len(expected)==908 and len(before_refs)==1028,"fixed source/reference cardinalities")
    git_exact=[
        ["rev-parse","HEAD"],["rev-parse","HEAD^{tree}"],["symbolic-ref","HEAD"],
        ["status","--porcelain=v1","--untracked-files=all"],
        ["for-each-ref","--format=%(refname) %(objectname)"],["config","--get-all","core.hooksPath"],
        ["remote","get-url","--push","--all","origin"],["remote","get-url","--all","origin"],
        ["rev-parse","--path-format=absolute","--git-path","hooks/pre-push"],
        ["rev-parse","--path-format=absolute","--git-path","index"],
        ["diff-tree","--no-commit-id","--name-only","-r",M["TREE"],control["tree"]],
        ["ls-tree",M["HEAD"],"--",M["WORKFLOW"]],["ls-tree",control["tree"],"--",M["WORKFLOW"]]]
    for ref,oid in objects.items():
        git_exact.extend([["rev-parse",ref],["rev-parse",ref+"^{}"],["cat-file","-s",oid],["cat-file","tag",oid]])
    for kind,oid in (("commit",control["commit"]),("blob",control["workflow_blob"])):
        git_exact.extend([["cat-file","-s",oid],["cat-file",kind,oid]])
    api_prefix=["gh","api","--method","GET","--include","-H","Accept: application/vnd.github+json",
                "-H","X-GitHub-Api-Version: "+M["API_VERSION"]]
    endpoint_prefix="repos/"+M["REPO"]+"/git/"
    endpoints={endpoint_prefix+"matching-refs/heads/",endpoint_prefix+"matching-refs/tags/"}
    endpoints.update(endpoint_prefix+"tags/"+oid for oid in objects.values())
    post_argv=["gh","api","--method","POST","--include","-H","Accept: application/vnd.github+json",
               "-H","X-GitHub-Api-Version: "+M["API_VERSION"],M["DISPATCH_ENDPOINT"],"--input","-"]
    post_count=0
    def checked_run(label,argv,data=None,timeout=180,must=True):
        nonlocal post_count
        argv=list(argv)
        if argv==post_argv:
            need(label=="dispatch-stage1-once" and post_count==0 and state["dispatch_started"] is True
                 and data==M["encode"]({"ref":M["TAG"]}) and timeout==180 and must is False,"single exact dispatch")
            post_count+=1
        else:
            permitted=(argv==["bash","scripts/project-preflight.sh"] or
                argv==["gh","api","user","--jq","{login,id}"] or
                (argv[:2]==["git","--no-replace-objects"] and argv[2:] in git_exact) or
                (argv[:-1]==api_prefix and argv[-1] in endpoints) or
                (argv[:8]==[H["PYTHON"],"-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",M["HEAD"],"--output"]
                 and len(argv)==9 and argv[8] in (str(ev/"source-before.json"),str(ev/"source-after.json"))))
            need(permitted and data is None and type(timeout) is int and 0<timeout<=180,"closed read-only command allowlist")
        return original_run(label,argv,data=data,timeout=timeout,must=must)
    ns["run"]=checked_run
    run=checked_run;git=ns["git"];value=ns["value"];identity=ns["identity"];refs=ns["refs"]
    hook_guard=ns["hook_guard"];actor=ns["actor"];object_raw=ns["object_raw"]
    verify_source=ns["verify_source"];input_fence=ns["input_fence"]
    def observe_api(label):
        out={"observed_from":M["now"](),"observed_to":None,"heads":None,"tags":None,"matches":False,
             "errors":[],"proof_kind":"REST_complete_matching_refs_and_four_annotated_tag_targets",
             "matching_prefix_endpoint_nonpaginated":True,"raw_Git_peel_claimed":False,"non_atomic":True}
        got={}
        for kind in ("heads","tags"):
            q=run(label+"-"+kind,api_prefix+[endpoint_prefix+"matching-refs/"+kind+"/"],must=False)
            got[kind]=q
        try:
            need(all(q.returncode==0 for q in got.values()),"complete fresh REST reference reads")
            hs=rest_refs(M,api_json(M,got["heads"].stdout),"heads")
            ts=rest_refs(M,api_json(M,got["tags"].stdout),"tags")
            heads={ref[len("refs/heads/"):]:v["oid"] for ref,v in hs.items()}
            need(heads==expected and len(heads)==908,"all 908 exact remote heads")
            need(all(ts.get(ref)=={"oid":oid,"type":"tag"} for ref,oid in objects.items()),"four exact annotated tag refs")
            resolved={}
            for number,(ref,oid) in enumerate(sorted(objects.items()),1):
                q=run(label+"-tag-object-"+str(number),api_prefix+[endpoint_prefix+"tags/"+oid],must=False)
                need(q.returncode==0,"fresh immutable tag object read")
                v=api_json(M,q.stdout)
                need(type(v) is dict and v.get("sha")==oid and v.get("tag")==ref[10:]
                     and v.get("url")=="https://api.github.com/"+endpoint_prefix+"tags/"+oid
                     and v.get("object")=={"type":"commit","sha":tags[ref+"^{}"],
                         "url":"https://api.github.com/"+endpoint_prefix+"commits/"+tags[ref+"^{}"]},
                     "actual annotated tag object target")
                resolved[ref]=oid;resolved[ref+"^{}"]=v["object"]["sha"]
            need(resolved==tags,"same owned tag/peeled map from REST targets")
            out.update(heads=heads,tags=resolved,matches=True,all_returned_tag_ref_count=len(ts),
                       unowned_tag_refs={k:v for k,v in ts.items() if k not in objects})
        except Exception as exc:
            out["errors"].append({"type":type(exc).__name__,"message":str(exc)})
        out["observed_to"]=M["now"]()
        return out
    emit("producer.py",own);emit("spec.json",raw)
    emit("published-original-receipt.json",M["pin"](PUBLISHED));emit("published-original-terminal.json",M["pin"](TERMINAL))
    emit("published-but-undispatched-proof.json",M["encode"](proof))
    before_index=previous["source_index"];index_path=pathlib.Path(before_index["path"]);guard=None
    state["source_index_before"]=before_index;save()
    try:
        run("project-preflight-before-dispatch",["bash","scripts/project-preflight.sh"])
        identity("source-before")
        need(refs("local-refs-before")==before_refs,"all 1028 local refs")
        need(pathlib.Path(value("source-index-path","rev-parse","--path-format=absolute","--git-path","index"))==index_path
             and M["index_snapshot"](index_path)==before_index,"original source index")
        guard=hook_guard("hook-before")
        need(guard==proof["installed_hook_guard"] and actor("actor-before")==M["ACTOR"],"original hook/origin/actor")
        verify_source("verify-source-before","source-before.json")
        for number,(ref,oid) in enumerate(sorted(objects.items()),1):
            need(value("existing-tag-"+str(number),"rev-parse",ref)==oid
                 and value("existing-target-"+str(number),"rev-parse",ref+"^{}")==tags[ref+"^{}"],"local existing tags unchanged")
            F["check_tag_object"](object_raw("existing-tag-object-"+str(number),"tag",oid,64*1024),oid,ref[10:],tags[ref+"^{}"])
        F["check_commit_object"](object_raw("existing-control","commit",control["commit"],128*1024),
            control["commit"],control["tree"],[M["HEAD"]])
        need(object_raw("existing-workflow","blob",control["workflow_blob"],64*1024)==M["pin"](M["WORKFLOW_PIN"]),"exact reviewed workflow")
        need(git("control-only-workflow","diff-tree","--no-commit-id","--name-only","-r",M["TREE"],control["tree"]).stdout.decode().splitlines()==[M["WORKFLOW"]]
             and git("control-workflow-entry","ls-tree",control["tree"],"--",M["WORKFLOW"]).stdout.decode()
                 =="100644 blob "+control["workflow_blob"]+"\t"+M["WORKFLOW"]+"\n","control exact tree/workflow")
        need(actor("actor-predispatch")==M["ACTOR"],"fresh dispatch actor")
        state["remote_before"]=observe_api("remote-predispatch");save()
        need(state["remote_before"]["matches"],"fresh API map differs or incomplete")
        identity("source-predispatch")
        need(hook_guard("hook-predispatch")==guard and refs("local-refs-predispatch")==before_refs
             and M["index_snapshot"](index_path)==before_index,"predispatch local identity")
        input_fence()
        body=M["encode"]({"ref":M["TAG"]});state["dispatch_request"]=emit("dispatch-request.json",body)
        state["dispatch_started"]=True;state["dispatch_status"]="UNKNOWN";state["status"]="UNKNOWN";save()
        q=run("dispatch-stage1-once",post_argv,data=body,timeout=180,must=False)
        state["dispatch_exit"]=q.returncode
        need(q.returncode==0,"dispatch nonzero/timeout is UNKNOWN; never resend")
        state["dispatch_response"]=M["dispatch_response"](q.stdout)
        state["dispatch_status"]="ACCEPTED_NOT_OBSERVED";save()
    except Exception as exc:
        state["errors"].append({"phase":"single-dispatch","type":type(exc).__name__,"message":str(exc)})
    finally:
        # Local final proof is attempted separately from remote observations.
        try:
            run("project-preflight-after-dispatch",["bash","scripts/project-preflight.sh"])
            verify_source("verify-source-after","source-after.json");identity("source-after")
            state["source_after_valid"]=True
            need(guard is not None and hook_guard("hook-after")==guard,"final installed hooks/origin")
            state["installed_hooks_unchanged"]=True
            need(refs("local-refs-after")==before_refs,"final local refs unchanged")
            state["local_ref_fence_valid"]=True
            need(M["index_snapshot"](index_path)==before_index,"final original source index")
            state["source_index_unchanged"]=True;input_fence()
        except Exception as exc:
            state["errors"].append({"phase":"final-local-source-ref-index-fence","type":type(exc).__name__,"message":str(exc)})
        if state["dispatch_started"]:
            try:
                state["remote_final"]=observe_api("remote-final")
                need(state["remote_final"]["matches"],"final API map differs or incomplete")
            except Exception as exc:
                state["errors"].append({"phase":"final-remote-reference-fence","type":type(exc).__name__,"message":str(exc)})
        state["status"]=("DISPATCH_ACCEPTED_NOT_OBSERVED" if not state["errors"] and
            state["dispatch_status"]=="ACCEPTED_NOT_OBSERVED" else ("UNKNOWN" if state["dispatch_started"] else "HOLD"))
        state["dispatch_attempt_count"]=post_count;state["finished_at"]=M["now"]();save()
    print(json.dumps({k:state[k] for k in ("schema","status","subject_commit","control","publication_confirmed",
        "dispatch_started","dispatch_exit","dispatch_status","dispatch_response","qualification_granted")}|{"receipt":str(ev/"summary.json")}),flush=True)
    return 0 if state["status"]=="DISPATCH_ACCEPTED_NOT_OBSERVED" else 1

if __name__=="__main__":
    sys.exit(main())
