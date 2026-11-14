import os,sys,stat,json,hashlib,difflib,datetime
from pathlib import Path
assert sys.flags.optimize==0
I=json.loads(sys.argv[1])
BASE=Path("/private/tmp/chain-prci-H5DF-pr-body-preparation-20261114-v1")
OUT=BASE/"body-proposal-v1";OUT.mkdir(exist_ok=False)
def stable(p,n=None,h=None):
 p=Path(p);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<8*1024*1024
  b=b""
  while True:
   c=os.read(fd,1048576)
   if not c:break
   b+=c
  z=os.fstat(fd);fp=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  assert fp(a)==fp(z)==fp(p.lstat())
 finally:os.close(fd)
 pin={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
 if n is not None:assert pin["bytes"]==n and pin["sha256"]==h
 return b,pin
made=[]
def put(name,b):
 p=OUT/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 pin=stable(p,len(b),hashlib.sha256(b).hexdigest())[1];made.append(pin);return pin
def js(name,x):return put(name,(json.dumps(x,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode())
pp=put("prepare-body-proposal.py",sys.argv[2].encode())
oldraw,prpin=stable("/private/tmp/chain-consolidation-20261114-root/H5DF-required-ci-progress-v1-ready-001/pr847.stdout",27631,"d823902b692fae24f6e9cf7fd576e50a6f6148b5081969ea99d741b2ed890629")
pr=json.loads(oldraw)
assert pr["head"]["sha"]=="5df7ae6f482157c5f7fdcbcd52222117a965053f"and pr["base"]["sha"]=="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"and pr["draft"]is False and pr["auto_merge"]is None
old=pr["body"];new=I["desired_body"]
assert old==I["original_body"]and new!=old
kept=["## Original system acceptance conditions remain\n","## History retention and remaining repository actions\n"]
a=old.index(kept[0]);b=old.index(kept[1]);aa=new.index(kept[0]);bb=new.index(kept[1]);assert old[a:b]==new[aa:bb]
for unchanged in ["Main integration must use the protected linear merge route after the required exact-head and prospective-merge acceptance checks. Branch cleanup follows a verified merge and a fresh complete reference inventory. The observed protection on \x60fix/chain-bulk-state-tree-20261017\x60 disallows deletion; that remains a distinct blocker to a one-branch result, and this update does not change protection.","The audit report also retains the unresolved macOS physical-retention observation and the 27 historical dependency registry/yank-query timeouts. Main integration and final branch cleanup are not completed by this PR metadata update."]:
 assert unchanged in old and unchanged in new
oldp=put("old-body.md",old.encode());newp=put("proposed-body.md",new.encode())
patch="".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile="PR847-old-body.md",tofile="PR847-proposed-body.md"))
patchp=put("old-to-proposed-body.patch",patch.encode())
payload=js("future-body-only-PATCH-payload.json",{"body":new})
wr,wrp=stable(BASE/"workflow-read-v2/workflow-trigger-review.json",117164,"659684c6810200582aaf55b00de4efd9ef86915c5389e568bb64873fd3998898")
w=json.loads(wr);assert w["parser"]=="PyYAML BaseLoader"and len(w["workflow_records"])==37
details=[]
for row in w["workflow_records"]:
 on=row["parsed_on"];evs=set(on)if isinstance(on,(dict,list))else{on}
 assert "pull_request_target"not in evs and "issues"not in evs
 prs=row["pull_request_events"]
 for event,spec in prs.items():
  assert event=="pull_request"
  assert not isinstance(spec,dict)or"types"not in spec
 details.append({"revision":row["revision"],"revision_label":row["revision_label"],"path":row["path"],"git_blob":row["oid"],"source":row["captured_source"],"on_lines":[row["on_start_line"],row["on_end_line"]],"events":sorted(evs),"pull_request_types":"default opened/synchronize/reopened"if"pull_request"in evs else"not configured"})
wf=js("workflow-trigger-facts.json",{"schema":"trnm-H5DF-body-only-edit-workflow-review-v1","source_review":wrp,"workflow_count":37,"H5DF_workflows":sum(x["revision_label"]=="current"for x in details),"base_B_workflows":sum(x["revision_label"]=="base"for x in details),"pull_request_edited_subscriptions":0,"pull_request_target_subscriptions":0,"issues_subscriptions":0,"conclusion":"A body-only PR edited event is outside these captured repository workflow trigger sets; this does not guarantee behavior of external applications or future workflow changes.","official_reference":"https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request","official_rule":"Without explicit types, pull_request runs for opened, synchronize, or reopened activity; edited requires an explicit activity subscription.","records":details})
js("first-local-workflow-read-failure.json",I["first_workflow_failure"])
js("workflow-read-v2-actual-terminal-pages.json",I["workflow_pages"])
js("workflow-read-v2-actual-launch.json",I["workflow_launch"])
factraw,factpin=stable("/private/tmp/chain-prci-H5DF-cross-cost-selected-artifact-20261114-v1/final-review-v1/exact-confirmation-facts.json",12884,"9da174ec8a4b5afe3ac151e4b7b81974addd1d4893f802500bc6fb9652bb9c6c")
fact=json.loads(factraw);assert fact["coverage"]["whole_ZIP_SHA_verified"]is False
plan={"schema":"trnm-pr847-body-only-edit-prepared-plan-v1","status":"PREPARED_ONLY_NOT_EXECUTED","repo":"TrillionniumFoundation/Trillionnium-Chain","pr_number":847,"actor":{"login":"ProfHepta","id":102159240},"expected":{"node_id":pr["node_id"],"state":"open","draft":False,"auto_merge":None,"title":pr["title"],"head":"5df7ae6f482157c5f7fdcbcd52222117a965053f","tree":"6be4940d38cc88782657f2684cbefe48866f8b9f","head_ref":pr["head"]["ref"],"base":"dd6e1c3cbeacbdc532b0679297835b3a0aac78f0","base_ref":"main","both_repository_id":1323087357,"old_body":oldp,"desired_body":newp},"observed_original_PR":prpin,"observed_updated_at":pr["updated_at"],"body_only_payload":payload,"workflow_trigger_review":wf,"facts":factpin,"postpublication_archive":{"commit":"ffc6e0ca4bfa7794ab6031a6e398dcd08b7a1982","tag_object":"894875e2161bea8f0d4a135879e687de78c1f18a","confirmed_fact_source":"root task states actual resume002 confirmed; exact closed receipt pin to be supplied by root before future execution","closed_receipt_pin":None,"scope":"Frozen R1 postpublication evidence, including ready019; no later H5DF source or executions"},"future_actions":[{"phase":"preflight","action":"Verify stable prepared body and payload byte/SHA pins; use existing bounded capture, unset GH_DEBUG and fix GH_HOST=github.com; do not change auth/config."},{"phase":"fresh_read","action":"GET actor and PR847; require exact actor id/login, repo/node/number/open/ready/no-auto, current title, head H5DF/base B and exact original body bytes. Record original GET argv/HTTP/exit/stdout/stderr/time. A changed body or identity is HOLD."},{"phase":"refs","action":"Use existing readonly ref reader to confirm candidate branch=H5DF and main=B immediately before update, and bind observed archive tag/object/peeled commit from root's confirmed archive proof. No source/ref write."},{"phase":"mutation","action":"At most one normal PATCH to repos/TrillionniumFoundation/Trillionnium-Chain/pulls/847 using only the exact body JSON payload. No title/ready/auto-merge/labels/policy/CI fields. Preserve actual HTTP, command exit and raw response separately."},{"phase":"readback","action":"Bounded GET PR847 and candidate/main refs again; require desired body exactly, unchanged title/draft/state/auto-merge and expected head/base/repo. A timeout or concurrent drift remains UNKNOWN/HOLD; no blind PATCH retry, forced overwrite, rollback or CI action."}],"concurrency_limit":"The normal PR PATCH API does not supply an expected-head/body compare-and-swap parameter. Fresh prechecks plus postchecks detect observed drift; they cannot lock a ref or rule against an interleaving update. Do not describe this as an atomic Git/ref CAS.","network_or_PR_mutation_executed":False,"source_refs_stage_changed":False,"qualification":False}
planp=js("future-execution-plan.json",plan)
summary=js("preparation.json",{"schema":"trnm-H5DF-pr847-body-preparation-v1","status":"PREPARED_ONLY","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"producer":pp,"old_body":oldp,"proposed_body":newp,"exact_patch":patchp,"payload":payload,"plan":planp,"source_PR":prpin,"workflow_review":wf,"selected_native_facts":factpin,"snapshot_used":"H5DF ready001 2026-11-14T17:41:47.229813+00:00 to 17:41:57.397390+00:00","later_ready002_not_read_or_inherited":True,"preserved_system_acceptance_section_byte_equal":True,"preserved_main_protection_cleanup_paragraphs_byte_equal":True,"title_ready_auto_merge_policy_not_modified":True,"postpublication_archive_pending_exact_root_receipt_pin":True,"not_applied":True})
files=list(made)
idx=js("EVIDENCE_INDEX.json",{"schema":"trnm-prepared-body-proposal-index-v1","files":files,"count":len(files),"bytes":sum(x["bytes"]for x in files),"self_excluded":True,"prepared_only":True})
print(json.dumps({"status":"PREPARED_ONLY","preparation":summary,"body":newp,"patch":patchp,"plan":planp,"trigger_facts":wf,"index":idx},sort_keys=True))
