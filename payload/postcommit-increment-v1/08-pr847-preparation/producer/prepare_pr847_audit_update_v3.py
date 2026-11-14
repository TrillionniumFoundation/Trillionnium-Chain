"""Prepare a reviewable PR847 update after confirmed publication. No remote writes."""
import pathlib,hashlib,json,os,sys,importlib.util
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
HEAD="dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
TREE="9fda17fed2542b2baccaa34585bb00afd699e12b"
REPO="TrillionniumFoundation/Trillionnium-Chain"
def require(ok,message):
 if not ok:raise ValueError(message)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 require(sys.flags.optimize==0,"optimized Python is not allowed")
 pubpath=ROOT/"resume-candidate-archive-publish-dc42ce-v2/summary.json"
 pubraw=pubpath.read_bytes();pub=json.loads(pubraw)
 require(pub.get("schema")=="trnm-candidate-archive-publication-resume-v2","unexpected resume receipt schema")
 require(pub.get("status") in ("confirmed","already_confirmed") and pub.get("source_after_valid") is True,"completed resume publication required")
 require(pub.get("head")==HEAD and pub.get("tree")==TREE,"resume source differs")
 require(isinstance(pub.get("finished_at"),str) and bool(pub["finished_at"]),"resume receipt is not terminal")
 require(pub.get("driver")=={"path":str(ROOT/"resume_candidate_archive_publish_v2.py"),"sha256":"d89b6f7b651d0422cd17fbd97ff6782996c9e3cdab163306f729109146560853"},"resume producer identity differs")
 archpath=ROOT/"publish-candidate-and-archive-dc42ce-v2/archive-local.json"
 archraw=archpath.read_bytes()
 require(len(archraw)==43199 and sha(archraw)=="7a5ead74ce076c3e8fd56cac61c22a380b660b7da4875a9259018e37e4c21aa6","original archive metadata changed")
 archive=json.loads(archraw)
 expectedpath=ROOT/"publish-candidate-and-archive-dc42ce-v2/hooks/expected.json"
 expectedraw=expectedpath.read_bytes()
 require(len(expectedraw)==83072 and sha(expectedraw)=="ee1e1fca066b62525016cd60803cadb3a2183cb8f9a5f367872341bd0ec2ca1a","original complete head map changed")
 expected=json.loads(expectedraw)["remote_heads"]
 candidate_name="fix/chain-hepta-closure-candidate-20261109-481716"
 require(isinstance(expected,dict) and len(expected)==908 and len(set(expected.values()))==892 and expected["main"]=="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0" and expected[candidate_name]=="e40d7071c4724e6600deef8a2820bf35c1982289","original branch scope differs")
 wanted=dict(expected);wanted[candidate_name]=HEAD
 parents=sorted(set(expected.values())|{HEAD})
 require(archive=={"tag":"archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2","tag_oid":"9dafd9192e4040fab530958ef71598aaec9265b9","commit":"5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b","tree":"b91f68e70a05e5475b850159033baffb0824c6ba","direct_parents":parents,"candidate_head":HEAD} and len(parents)==893,"archive parent/identity scope differs")
 require(pub.get("archive_tag")==archive["tag"] and pub.get("archive_tag_oid")==archive["tag_oid"] and pub.get("archive_commit")==archive["commit"],"resume/archive identity differs")
 if pub["status"]=="confirmed":
  observation_phase="after"
  require(pub.get("push_started") is True,"confirmed resume lacks push path")
 else:
  observation_phase="before"
  require(pub.get("push_started") is False,"already-confirmed resume must not push")
 require(pub.get("remote_"+observation_phase+"_classification")=="both_new","resume observation is not both_new")
 tagref="refs/tags/"+archive["tag"]
 require(pub.get("remote_"+observation_phase)=={"heads":wanted,"tags":{tagref:archive["tag_oid"],tagref+"^{}":archive["commit"]},"errors":[]},"complete 908-head/tag/peeled observation differs")
 gateraw=(ROOT/"final-prepublication-source-gates-dc42ce-v1/receipt.json").read_bytes()
 require(sha(gateraw)=="602cb049eabab6e5ce92639b69123caa55e6d0fab5bd7a69f8e6eaa1cb2639dc","gate receipt changed")
 path=ROOT/"publish_candidate_and_archive_v4.py"
 require(sha(path.read_bytes())=="4105cd1db2e5219deda83a881872c51ac5cf671f5caa367bc2ea8ae4d4495038","capture producer changed")
 spec=importlib.util.spec_from_file_location("reviewed_publisher",path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 env=os.environ.copy();env.update(module.GATE_ENV)
 ev=ROOT/"prepare-pr847-audit-update-v3";ev.mkdir(mode=0o700,exist_ok=False)
 steps=[]
 def run(label,argv):
  result=module.capture(argv,env,timeout=180)
  for suffix,data in (("stdout",result.stdout),("stderr",result.stderr)):
   with (ev/(label+"."+suffix)).open("xb") as f:f.write(data)
  steps.append({"label":label,"argv":argv,"exit":result.returncode,"stdout_sha256":sha(result.stdout),"stderr_sha256":sha(result.stderr)})
  (ev/"steps.json").write_text(json.dumps(steps,indent=2)+"\n")
  require(result.returncode==0,"read failed: "+label)
  return result.stdout
 actor=json.loads(run("actor",["gh","api","user","--jq","{login,id}"]))
 require(actor["login"]=="ProfHepta","unexpected actor")
 query="{number,state,draft,node_id,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,title,body,auto_merge}"
 before_raw=run("pr-before",["gh","api","repos/"+REPO+"/pulls/847","--jq",query])
 before=json.loads(before_raw)
 require(before["number"]==847 and before["state"]=="open" and before["head"]==HEAD and before["head_ref"]=="fix/chain-hepta-closure-candidate-20261109-481716" and before["base_ref"]=="main" and before["base"]=="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0" and before["auto_merge"] is None,"PR state changed")
 require(len(archive["direct_parents"])==893 and HEAD in archive["direct_parents"],"archive parent scope differs")
 templateraw=(ROOT/"pr847-audit-body-template-v1.md").read_bytes()
 require(sha(templateraw)=="5f5f68bbbfeff4afcce6acbc52b92a8bb9620abe5b7ae6a1ab9b93c6fdc5d6e3","reviewed body template changed")
 template=templateraw.decode("utf-8")
 body=template.format(head=HEAD,tree=TREE,url="https://github.com/"+REPO,archive_tag=archive["tag"],tag_oid=archive["tag_oid"],archive_commit=archive["commit"])
 title="Consolidate audited branch history and current runtime"
 bodypath=ev/"pr-body.md"
 with bodypath.open("x") as f:f.write(body)
 desired={"title":title,"body":body,"head":HEAD,"tree":TREE,"base":before["base"],"base_ref":"main","pr_number":847,"pr_node_id":before["node_id"],"mark_ready_after_metadata_verified":True}
 desiredpath=ev/"desired.json"
 desiredraw=(json.dumps(desired,indent=2)+"\n").encode()
 with desiredpath.open("xb") as f:f.write(desiredraw)
 summary={"schema":"prepared-pr847-audit-update-v3","remote_writes":False,"publication_receipt_path":str(pubpath),"publication_receipt_sha256":sha(pubraw),"publication_status":pub["status"],"remote_observation_phase":observation_phase,"archive_metadata_path":str(archpath),"archive_metadata_sha256":sha(archraw),"expected_head_map_input_path":str(expectedpath),"expected_head_map_input_sha256":sha(expectedraw),"before_raw_sha256":sha(before_raw),"before_title":before["title"],"before_draft":before["draft"],"before_body_bytes":len((before["body"] or "").encode()),"desired_title":title,"desired_body_path":str(bodypath),"desired_body_bytes":len(body.encode()),"desired_body_sha256":sha(body.encode()),"desired_path":str(desiredpath),"desired_sha256":sha(desiredraw),"head":HEAD,"tree":TREE,"archive_tag":archive["tag"],"archive_commit":archive["commit"],"steps":steps}
 (ev/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
 print(json.dumps({k:v for k,v in summary.items() if k!="steps"},indent=2),flush=True)
if __name__=="__main__":main()
