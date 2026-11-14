import hashlib,json,pathlib,sys
r=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root/external-evidence-object-import-1a7afc-v2/summary.json").read_bytes()
assert len(r)==114574 and hashlib.sha256(r).hexdigest()=="f91eb93242dcf20dbc4f02107f9b5c188a0a91aec7d17e5903dc5a53ff46e749"
j=json.loads(r);assert j["status"]=="IMPORTED_AND_VERIFIED" and j["errors"]==[] and j["import_exit"]==0 and j["source_unchanged"] and j["raw_object_readback_complete"] and j["fourteen_tree_closure_verified"] and j["source_before"]==j["source_after"]
assert j["expected_head"]=="1a7afcdb820b051d1e4bfde3d436f96fc050c487" and j["expected_tree"]=="18c3d20df915f5c31ee38c7037775c61e5c12e3f"
print(json.dumps({"preceding_import":j["status"],"verified_objects":3912,"source_unchanged":j["source_unchanged"],"summary_sha256":hashlib.sha256(r).hexdigest()}),flush=True)
p=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root/run_final_rog_repository_truth_offline_v4.py")
b=p.read_bytes();assert len(b)==15187 and hashlib.sha256(b).hexdigest()=="bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
sys.argv=[str(p),"--head","08c9becab740ab2c375b970f376a7638f44c9e8e","--tree","036868dfcc953b6f5574c627e0027c3d4e2d3523","--evidence-dir","/home/qian-qi/chain-final-consolidation-20261114-root/final-repository-truth-offline-08c9be-v1","--expected-start-head","1a7afcdb820b051d1e4bfde3d436f96fc050c487","--bundle-path","/home/qian-qi/chain-final-consolidation-20261114-root/offline-source-bundles-v3/closed-exec-gate-08c9beca-after-1a7afcdb.bundle","--bundle-bytes","182560","--bundle-sha256","8886a3acbe3ac3be04d70b0bf19b5310a4434ba1c78ec0c07f48b68099dd044a"]
exec(compile(b,str(p),"exec"),{"__name__":"__main__","__file__":str(p)})