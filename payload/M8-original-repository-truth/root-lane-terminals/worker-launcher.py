import hashlib,json,os,pathlib,sys
assert sys.flags.optimize==0
base=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
previous=base/"final-repository-truth-offline-ed0d35-v1"
raw=(previous/"summary.json").read_bytes()
assert len(raw)==21340 and hashlib.sha256(raw).hexdigest()=="61fd6d1d2054b78908d2caab5e3c946a4e32cef4dbbf082659a0b1f51427e806"
j=json.loads(raw);assert j["status"]=="passed" and j["head"]=="ed0d35487f2a67239e4d646fd41c2c7acb5cc740" and j["tree"]=="1aa9c21812489080980bdc3c1c2bb43611e88354" and j["errors"]==[] and j["source_before_after_verified"] is True and len(j["steps"])==18 and all(s["exit"]==0 for s in j["steps"])
for name in ("source-before.json","source-after.json","verify-source-before.stdout","verify-source-after.stdout"):
    raw=(previous/name).read_bytes();assert len(raw)==423 and hashlib.sha256(raw).hexdigest()=="a74be5eb0131658ed16c8e1988806ffa8886a3a6580a6cca2c5a41a1ee88538d"
driver=base/"run_final_rog_worker_artifact_existing_source_v2.py"
raw=driver.read_bytes();assert len(raw)==19501 and hashlib.sha256(raw).hexdigest()=="491ce4a207e722f47ef2174690de83678cfc39b59b82db048f22fb95db17c95f"
with (base/"launch-worker-artifact-ed0d35-v2.py").open("x") as f:f.write(sys.argv[1])
print(json.dumps({"preceding_original_repository_lane":"passed","worker_extra_component_only":True,"four_second_qualification":False}),flush=True)
python=base/"final-python312-env/bin/python"
os.execv(str(python),[str(python),"-B",str(driver),"--head","ed0d35487f2a67239e4d646fd41c2c7acb5cc740","--tree","1aa9c21812489080980bdc3c1c2bb43611e88354","--evidence-dir",str(base/"final-worker-artifact-existing-source-ed0d35-v2")])
