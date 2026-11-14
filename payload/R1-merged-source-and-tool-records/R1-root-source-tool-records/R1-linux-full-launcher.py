import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
base=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
driver=base/"run_final_rog_repository_truth_offline_v4.py"
raw=driver.read_bytes();assert len(raw)==15187 and hashlib.sha256(raw).hexdigest()=="bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
bundle=base/"offline-source-bundles-v3/concurrent-ci-2a86462a-after-6a8cd555.bundle"
raw=bundle.read_bytes();assert len(raw)==11223 and hashlib.sha256(raw).hexdigest()=="40de169595b8c51d0d549a277e24b76abad8fb6c0c58c4d8c555442d210101e4"
with (base/"launch-original-repository-truth-2a8646-v1.py").open("x") as f:f.write(sys.argv[1])
python=base/"final-python312-env/bin/python"
os.execv(str(python),[str(python),"-B",str(driver),"--head","2a86462a1ab20c68151719ba4635e3c294391e64","--tree","5c26776f96f15fd131e85a5c2d7c5e895ad7fab4","--expected-start-head","6a8cd55573065ceb50cdb65a7834615f79b521ae","--bundle-path",str(bundle),"--bundle-bytes","11223","--bundle-sha256","40de169595b8c51d0d549a277e24b76abad8fb6c0c58c4d8c555442d210101e4","--evidence-dir",str(base/"final-repository-truth-offline-2a8646-v1")])
