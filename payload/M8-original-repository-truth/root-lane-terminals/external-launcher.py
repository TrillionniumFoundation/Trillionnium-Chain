import hashlib,json,os,pathlib,sys
assert sys.flags.optimize==0
base=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
checks=[("final-repository-truth-offline-ed0d35-v1",21340,"61fd6d1d2054b78908d2caab5e3c946a4e32cef4dbbf082659a0b1f51427e806",18),("final-worker-artifact-existing-source-ed0d35-v2",20498,"b8e6e86e08e40df85b2bdf6e7cc40ede94256075d1d7bd56047a2310b779c026",12)]
for name,size,digest,count in checks:
    d=base/name;raw=(d/"summary.json").read_bytes()
    assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest
    j=json.loads(raw);assert j["status"]=="passed" and j["head"]=="ed0d35487f2a67239e4d646fd41c2c7acb5cc740" and j["tree"]=="1aa9c21812489080980bdc3c1c2bb43611e88354" and j["errors"]==[] and j["source_before_after_verified"] is True and len(j["steps"])==count and all(s["exit"]==0 for s in j["steps"])
    for n in ("source-before.json","source-after.json","verify-source-before.stdout","verify-source-after.stdout"):
        raw=(d/n).read_bytes();assert len(raw)==423 and hashlib.sha256(raw).hexdigest()=="a74be5eb0131658ed16c8e1988806ffa8886a3a6580a6cca2c5a41a1ee88538d"
driver=base/"run_final_rog_external_evidence_existing_source_v2.py"
raw=driver.read_bytes();assert len(raw)==16404 and hashlib.sha256(raw).hexdigest()=="d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a"
with (base/"launch-original-external-evidence-ed0d35-v2.py").open("x") as f:f.write(sys.argv[1])
print(json.dumps({"preceding_original_repository_lane":"passed","preceding_worker_component":"passed","next_lane":"external-evidence-contract","original_budget_seconds":2700}),flush=True)
python=base/"final-python312-env/bin/python"
os.execv(str(python),[str(python),"-B",str(driver),"--head","ed0d35487f2a67239e4d646fd41c2c7acb5cc740","--tree","1aa9c21812489080980bdc3c1c2bb43611e88354","--evidence-dir",str(base/"final-external-evidence-existing-source-ed0d35-v2")])
