import pathlib,os,subprocess,signal,json,hashlib,time,datetime,concurrent.futures,math,re
D=pathlib.Path("/private/tmp/chain-prci-remote-advance-5a4b7f-observation-20261114-v1")
WT=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
REPO="TrillionniumFoundation/Trillionnium-Chain"
NEW="5a4b7fe8de1adce803184f262fd9f704ead1930c"
OLD="dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
CAND="refs/heads/fix/chain-hepta-closure-candidate-20261109-481716"
MAIN="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
NEW_TAG="refs/tags/archive/execution-receipts-20261114-2a6206117785-v1"
GH="/opt/homebrew/bin/gh"
GIT="/usr/bin/git"
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(name,value):
 p=D/name;b=(json.dumps(value,indent=2)+"\n").encode()
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def info(p):
 b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
env=os.environ.copy();env.update(GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GH_PROMPT_DISABLED="1")
START=now()
commitq="{sha,url,html_url,commit:{author:.commit.author,committer:.commit.committer,message:.commit.message,tree:.commit.tree,comment_count:.commit.comment_count,verification:{verified:.commit.verification.verified,reason:.commit.verification.reason,verified_at:.commit.verification.verified_at}},author:(if .author then {login:.author.login,id:.author.id,html_url:.author.html_url} else null end),committer:(if .committer then {login:.committer.login,id:.committer.id,html_url:.committer.html_url} else null end),parents:[.parents[]|{sha,url,html_url}],stats,files:[.files[]|{sha,filename,status,additions,deletions,changes,previous_filename,blob_url,contents_url}]}"
compareq="{url,html_url,diff_url,patch_url,status,ahead_by,behind_by,total_commits,base_commit:{sha:.base_commit.sha,commit:.base_commit.commit,parents:.base_commit.parents},merge_base_commit:{sha:.merge_base_commit.sha,commit:.merge_base_commit.commit,parents:.merge_base_commit.parents},commits:[.commits[]|{sha,html_url,commit:{author:.commit.author,committer:.commit.committer,message:.commit.message,tree:.commit.tree},author:(if .author then .author.login else null end),committer:(if .committer then .committer.login else null end),parents:[.parents[]|{sha,url}]}],files:[.files[]?|{sha,filename,status,additions,deletions,changes,previous_filename}]}"
eventsq="[.[]|select(.type==\"PushEvent\")|{id,type,created_at,public,actor:{login:.actor.login,id:.actor.id},repo:.repo.name,payload}]"
def api(endpoint,jq=None):
 a=[GH,"api","--method","GET",endpoint]
 if jq:a+=["--jq",jq]
 return a
def run(label,argv,timeout=120):
 out=D/(label+".stdout");err=D/(label+".stderr");start=now();tick=time.monotonic();timed=False
 with out.open("xb") as so,err.open("xb") as se:
  p=subprocess.Popen(argv,cwd=WT,env=env,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True)
  try:code=p.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   timed=True
   try:os.killpg(p.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   try:code=p.wait(timeout=5)
   except subprocess.TimeoutExpired:
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    code=p.wait(timeout=5)
 row={"label":label,"argv":argv,"cwd":str(WT),"started_at":start,"finished_at":now(),"elapsed_seconds":round(time.monotonic()-tick,3),"exit":code,"timed_out":timed,"timeout_seconds":timeout,"stdout":info(out),"stderr":info(err)}
 raw=out.read_bytes()
 value=None
 if code==0 and not timed:
  if label.startswith("refs-"):
   value={}
   for line in raw.decode().splitlines():
    sha,ref=line.split("\t");assert re.fullmatch("[0-9a-f]{40}",sha) and ref not in value;value[ref]=sha
  else:value=json.loads(raw)
 return row,value
commands=[
 ("refs-heads",[GIT,"ls-remote","--heads","origin"]),
 ("refs-archive-tags",[GIT,"ls-remote","--tags","origin","refs/tags/archive/*"]),
 ("pr847",api("repos/"+REPO+"/pulls/847")),
 ("commit-5a4-page-001",api("repos/"+REPO+"/commits/"+NEW+"?per_page=100&page=1",commitq)),
 ("compare-C0-to-5a4-page-001",api("repos/"+REPO+"/compare/"+OLD+"..."+NEW+"?per_page=100&page=1",compareq)),
 ("recent-push-events",api("repos/"+REPO+"/events?per_page=100",eventsq)),
]
results={};failures=[];baseline=None;baseline_error=None
p=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/remote-readonly-refresh-0170-v1/branches.json")
try:
 b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=="e52bb1c8c0963b2ddd303761ffe7ba949c080b3a0f72983f508978f8971e7734"
 original=json.loads(b)
 if isinstance(original,list):entries=original
 elif isinstance(original,dict) and isinstance(original.get("branches"),list):entries=original["branches"]
 else:raise ValueError("unrecognized frozen branch manifest shape")
 baseline={"refs/heads/"+x["name"]:x["commit"]["sha"] for x in entries}
 assert len(baseline)==908
 baseline[CAND]=OLD
except Exception as error:baseline_error=type(error).__name__+": "+str(error)
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
 pending={pool.submit(run,l,a):(l,a) for l,a in commands}
 for fut in concurrent.futures.as_completed(pending):
  label,_=pending[fut]
  try:
   row,value=fut.result();results[label]={"receipt":row,"value":value}
   if row["exit"]!=0 or row["timed_out"]:failures.append(label)
   if label=="refs-heads" and value is not None:
    delta=None
    if baseline is not None:
     delta=[{"ref":k,"expected":baseline.get(k),"observed":value.get(k)} for k in sorted(set(baseline)|set(value)) if baseline.get(k)!=value.get(k)]
    v={"schema":"trnm-remote-5a4-immediate-heads-observation-v1","observed_started_at":row["started_at"],"observed_finished_at":row["finished_at"],"count":len(value),"unique_tips":len(set(value.values())),"candidate":value.get(CAND),"main":value.get("refs/heads/main"),"candidate_expected_old":OLD,"candidate_reported_new":NEW,"actual_candidate_equals_reported_new":value.get(CAND)==NEW,"frozen908_with_C0_candidate_differences":delta,"frozen_baseline_error":baseline_error,"raw":row["stdout"],"atomic_whole_ref_lock":False,"remote_mutation":False}
    identity=save("heads-summary.json",v)
    print(json.dumps({"phase":"actual_heads_ready","summary":identity,**v}),flush=True)
   else:print(json.dumps({"phase":"read_completed","label":label,"exit":row["exit"],"timed_out":row["timed_out"],"bytes":row["stdout"]["bytes"]}),flush=True)
  except Exception as error:
   failures.append(label);results[label]={"error":type(error).__name__+": "+str(error)}
# Bounded continuation only for pagination of the same fixed commit/compare read.
commit=results.get("commit-5a4-page-001",{}).get("value")
commit_files=[];commit_complete=False
if commit is not None:
 commit_files=list(commit["files"]);count=len(commit["files"]);page=2
 while count==100 and page<=30:
  label=f"commit-5a4-page-{page:03d}";row,value=run(label,api("repos/"+REPO+"/commits/"+NEW+f"?per_page=100&page={page}",commitq))
  results[label]={"receipt":row,"value":value}
  if value is None:failures.append(label);break
  assert value["sha"]==NEW and value["parents"]==commit["parents"] and value["commit"]["tree"]==commit["commit"]["tree"]
  commit_files.extend(value["files"]);count=len(value["files"]);page+=1
 commit_complete=count<100
 assert len({x["filename"] for x in commit_files})==len(commit_files)
compare=results.get("compare-C0-to-5a4-page-001",{}).get("value");compare_commits=[];compare_complete=False
if compare is not None:
 compare_commits=list(compare["commits"]);pages=math.ceil(compare["total_commits"]/100)
 for page in range(2,min(pages,10)+1):
  label=f"compare-C0-to-5a4-page-{page:03d}";row,value=run(label,api("repos/"+REPO+"/compare/"+OLD+"..."+NEW+f"?per_page=100&page={page}",compareq))
  results[label]={"receipt":row,"value":value}
  if value is None:failures.append(label);break
  assert value["total_commits"]==compare["total_commits"] and value["merge_base_commit"]["sha"]==compare["merge_base_commit"]["sha"]
  compare_commits.extend(value["commits"])
 compare_complete=len(compare_commits)==compare["total_commits"]
 assert len({x["sha"] for x in compare_commits})==len(compare_commits)
pr=results.get("pr847",{}).get("value");tags=results.get("refs-archive-tags",{}).get("value")
normalized_pr=None
if pr:
 normalized_pr={k:pr.get(k) for k in ("number","state","draft","created_at","updated_at","closed_at","merged_at","merge_commit_sha","mergeable","mergeable_state","html_url","title","auto_merge")}
 normalized_pr["head"]={k:pr["head"].get(k) for k in ("label","ref","sha")};normalized_pr["head"]["repo"]=pr["head"]["repo"]["full_name"]
 normalized_pr["base"]={k:pr["base"].get(k) for k in ("label","ref","sha")};normalized_pr["base"]["repo"]=pr["base"]["repo"]["full_name"]
cp=None
if commit:
 cp=dict(commit);cp["files"]=commit_files;cp["files_pagination_complete"]=commit_complete;cp["patches_requested_or_preserved"]=False
co=None
if compare:
 co=dict(compare);co["commits"]=compare_commits;co["commit_pagination_complete"]=compare_complete;co["compare_files_scope"]="GitHub compare metadata files field; API first-page limit applies";co["patches_requested_or_preserved"]=False
summary={"schema":"trnm-remote-advance-5a4-observation-v1","started_at":START,"finished_at":now(),"repo":REPO,"old_published_candidate":OLD,"reported_new_candidate":NEW,"main_expected":MAIN,"pr":normalized_pr,"commit":cp,"compare":co,"archive_tag_refs":tags,"new_execution_tag":NEW_TAG,"new_execution_tag_present":None if tags is None else NEW_TAG in tags,"recent_push_events_first_page":results.get("recent-push-events",{}).get("value"),"events_are_bounded_recent_window_not_exhaustive":True,"frozen_baseline_error":baseline_error,"failures":failures,"steps":[v["receipt"] for v in results.values() if "receipt" in v],"non_atomic_across_observations":True,"remote_mutations":False,"fetch_performed":False,"source_git_objects_or_refs_modified":False,"CI_actions":False}
m=save("summary.json",summary)
print(json.dumps({"phase":"completed","summary":m,"pr":normalized_pr,"commit_sha":None if cp is None else cp["sha"],"commit_tree":None if cp is None else cp["commit"]["tree"],"commit_parents":None if cp is None else cp["parents"],"commit_files":None if cp is None else len(cp["files"]),"compare_status":None if co is None else co["status"],"compare_total_commits":None if co is None else co["total_commits"],"compare_complete":compare_complete,"archive_tag_refs":tags,"failures":failures}),flush=True)
