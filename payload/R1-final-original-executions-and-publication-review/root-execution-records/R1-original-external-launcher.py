import hashlib,json,os,pathlib,sys
assert sys.flags.optimize==0
base=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
inputs=json.loads(sys.argv[2]);HEAD="2a86462a1ab20c68151719ba4635e3c294391e64";TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
checks=[("final-repository-truth-offline-2a8646-v1",21354,"70e5dd235cf16b1ec3a0ba37da2a5c523cce3e97000a13de9fdd92e5e440ffef",18,("source-before.json","source-after.json","verify-source-before.stdout","verify-source-after.stdout")),("R1-original-w1-v2-controls-linux-v1",inputs["w1_summary_bytes"],inputs["w1_summary_sha256"],8,("source-before.json","source-after.json","source-before.stdout","source-after.stdout"))]
for name,size,digest,count,streams in checks:
 d=base/name;raw=(d/"summary.json").read_bytes();assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest
 j=json.loads(raw);assert j["status"]=="passed" and j["head"]==HEAD and j["tree"]==TREE and j["errors"]==[] and j["source_before_after_verified"] is True and len(j["steps"])==count and all(s["exit"]==0 for s in j["steps"])
 for n in streams:
  raw=(d/n).read_bytes();assert len(raw)==423 and hashlib.sha256(raw).hexdigest()=="1b8638f7d5e3fb28abc25c06208df4e189ba3b86c7d0d3a12fb2a431607b7e03"
 if name=="R1-original-w1-v2-controls-linux-v1":assert j["original_suite_result"]=="31 executed; OK; no skips"
driver=base/"run_final_rog_external_evidence_existing_source_v2.py"
raw=driver.read_bytes();assert len(raw)==16404 and hashlib.sha256(raw).hexdigest()=="d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a"
with (base/"launch-original-external-evidence-2a8646-v1.py").open("x") as f:f.write(sys.argv[1])
with (base/"launch-original-external-evidence-2a8646-v1-inputs.json").open("x") as f:f.write(json.dumps(inputs,indent=2,sort_keys=True)+"\n")
print(json.dumps({"preceding_original_repository_lane":"passed_for_R1","preceding_original_W1_controls":"31_passed_for_R1","next_lane":"external-evidence-contract","original_budget_seconds":2700}),flush=True)
python=base/"final-python312-env/bin/python"
os.execv(str(python),[str(python),"-B",str(driver),"--head",HEAD,"--tree",TREE,"--evidence-dir",str(base/"final-external-evidence-2a8646-v1")])
