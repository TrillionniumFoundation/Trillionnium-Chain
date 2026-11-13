import hashlib,json,os,shutil,subprocess
from pathlib import Path
root=Path("/home/qian-qi/work/chain-w1-c6-timeout-reorg-20261108-ec265b-01")
original=Path("/home/qian-qi/work/chain-w1-base62-m12-tools-20261108-ec265b/owner-import-c6-01")
driver=Path("/home/qian-qi/work/chain-w1-base62-m12-tools-20261108-ec265b/driver-v4.py")
def pin(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        before=os.fstat(f.fileno())
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
        after=os.fstat(f.fileno())
    assert (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(p),"bytes":after.st_size,"sha256":h.hexdigest()}
assert not root.exists()
assert pin(driver)["sha256"]=="b66019d2f47c225174de4f69c508e2b163d69f915b1e9eada59eef9368317464"
assert pin(original/"manifest.json")["sha256"]=="f49f20c8fd511bfad1c27e77c7d680b3002feff860fad9b344f8a0ca0a01d6c8"
gates=[
("backend","/home/qian-qi/work/chain-w1-c6-backend-qualification-20261108-ec265b-02/manifest.json","f7c538e360541f15ebea2f8aea7e2fc50bde53ee1cdcd1354b3624b042c2979c"),
("native","/home/qian-qi/work/chain-w1-c6-native-qualification-20261108-ec265b-01/manifest.json","1a7bec56da77f9d0fc0fc647adb618f705c42f03e7e40c2728773cc55844e352"),
("owner","/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/exact-owner-01/manifest.json","5a5b7d7ef41a5cf4f5429ef420326777706aae54e4bd88eabf83658530b85b3f"),
("receiver","/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/exact-receiver-01/manifest.json","e0109e80fbc0eb48f44fd5d91197d1b68c5476622a1408e8f9c9da8b9b820cdc"),
("staged-isolated","/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/exact-staged-isolated-01/manifest.json","930ca954936e198dfa3fdab2df0b2d4ca8438111f4e20042ae178c790b095103")]
gate_pins=[]
for role,path,digest in gates:
    observed=pin(Path(path));assert observed["sha256"]==digest
    q=json.loads(Path(path).read_text())
    assert q.get("qualification_complete") is True
    src=q.get("source") or {"commit":q["source_commit"],"tree":q["source_tree"]}
    assert src=={"commit":"2bdd252aa6c300b7431b9ee897b254b7953cf562","tree":"ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"}
    assert all(row["exit"]==row.get("expected_exit",0) for row in q["commands"])
    gate_pins.append({"role":role,"manifest":observed,"actual_command_count":len(q["commands"])})
root.mkdir()
shutil.copytree(original,root/"qualification")
assert pin(root/"qualification/manifest.json")["sha256"]==pin(original/"manifest.json")["sha256"]
with (root/"preparation-provenance.json").open("x") as f:
    json.dump({"schema":"TRNM-W1-C6-TIMEOUT-PREPARATION-PROVENANCE1","owner_schema_import_original":pin(original/"manifest.json"),"owner_schema_import_copy":pin(root/"qualification/manifest.json"),"gate_manifests":gate_pins,"source":{"commit":"2bdd252aa6c300b7431b9ee897b254b7953cf562","tree":"ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"},"original_core_failed_attempt_preserved":True,"original_backend_failed_attempt_preserved":True,"target_cache_origins":{"owner":"empty target at original qualification start, reused registry/toolchain","native":"empty03 target at original qualification start, reused registry/toolchain","backend":"copied C5 cache then failed C6 attempt01, reused by C6 attempt02"},"driver":pin(driver),"preparer":pin(Path(__file__).resolve()),"operation_created_before_prepare":False,"deadline_selected_before_launch":False},f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
argv=["/usr/bin/python3.12","-B",str(driver),"prepare",*["--repo","/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b","--root","/home/qian-qi/work/chain-w1-c6-timeout-reorg-20261108-ec265b-01","--expected-commit","2bdd252aa6c300b7431b9ee897b254b7953cf562","--owner-binary","/home/qian-qi/work/chain-w1-base62-owner-empty-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8","--target-dir","/home/qian-qi/work/chain-w1-base62-owner-empty-target-20261108-ec265b","--runner-binary","/home/qian-qi/work/chain-w1-base62-backend-target-20261108-ec265b/release/w1-staged-prover-v2","--runner-build-log","/home/qian-qi/work/chain-w1-c6-backend-qualification-20261108-ec265b-02/build.stdout","--native-qualification","/home/qian-qi/work/chain-w1-c6-native-qualification-20261108-ec265b-01/manifest.json"]]
result=subprocess.run(argv,cwd="/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b",env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"},check=False)
raise SystemExit(result.returncode)
