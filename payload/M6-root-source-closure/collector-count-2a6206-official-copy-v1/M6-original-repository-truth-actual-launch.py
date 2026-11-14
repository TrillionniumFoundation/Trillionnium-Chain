import hashlib,json,pathlib,sys
r=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root/final-external-evidence-existing-source-08c9be-v2/summary.json").read_bytes()
assert len(r)==17801 and hashlib.sha256(r).hexdigest()=="624efff452b6bd0b2c6ebcf9a47abe3216999a7d051d1e7d0fb9e5ea86fb2ca3"
j=json.loads(r);assert j["status"]=="passed" and j["errors"]==[] and j["source_before_after_verified"] and j["historical_objects_prechecked"] and j["lane_prepare_fetched_nothing_verified"]
assert j["head"]=="08c9becab740ab2c375b970f376a7638f44c9e8e" and j["tree"]=="036868dfcc953b6f5574c627e0027c3d4e2d3523"
print(json.dumps({"preceding_external_lane":"passed_on_M5","summary_sha256":hashlib.sha256(r).hexdigest(),"new_candidate":"2a62061177852dc3ebd200fa8d7c66c661a119a1","new_candidate_result_not_claimed":True}),flush=True)
p=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root/run_final_rog_repository_truth_offline_v4.py")
b=p.read_bytes();assert len(b)==15187 and hashlib.sha256(b).hexdigest()=="bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
sys.argv=[str(p),"--head","2a62061177852dc3ebd200fa8d7c66c661a119a1","--tree","f8d170ff75990e879e93888a95e5408f36b36f6c","--evidence-dir","/home/qian-qi/chain-final-consolidation-20261114-root/final-repository-truth-offline-2a6206-v1","--expected-start-head","08c9becab740ab2c375b970f376a7638f44c9e8e","--bundle-path","/home/qian-qi/chain-final-consolidation-20261114-root/offline-source-bundles-v3/collector-count-2a620611-after-08c9beca.bundle","--bundle-bytes","3781","--bundle-sha256","14c7cd2f3ec12a60e06b097a77a4b7db76c51b85a681ed7e756233d99bfacd71"]
exec(compile(b,str(p),"exec"),{"__name__":"__main__","__file__":str(p)})