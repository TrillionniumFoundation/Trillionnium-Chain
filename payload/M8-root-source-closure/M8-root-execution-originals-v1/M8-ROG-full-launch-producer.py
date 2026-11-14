import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
base=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
driver=base/"run_final_rog_repository_truth_offline_v4.py"
raw=driver.read_bytes();assert len(raw)==15187 and hashlib.sha256(raw).hexdigest()=="bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
bundle=base/"offline-source-bundles-v3/concurrent-ed0d3548-after-2a620611.bundle"
raw=bundle.read_bytes();assert len(raw)==187605 and hashlib.sha256(raw).hexdigest()=="b201ddbd9684e2d2a8281b24e7798cf9b080b9085df81a9e2599e0f56b0973c5"
with (base/"launch-original-repository-truth-ed0d35-v1.py").open("x") as f:f.write(sys.argv[1])
python=base/"final-python312-env/bin/python"
os.execv(str(python),[str(python),"-B",str(driver),"--head","ed0d35487f2a67239e4d646fd41c2c7acb5cc740","--tree","1aa9c21812489080980bdc3c1c2bb43611e88354","--expected-start-head","2a62061177852dc3ebd200fa8d7c66c661a119a1","--bundle-path",str(bundle),"--bundle-bytes","187605","--bundle-sha256","b201ddbd9684e2d2a8281b24e7798cf9b080b9085df81a9e2599e0f56b0973c5","--evidence-dir",str(base/"final-repository-truth-offline-ed0d35-v1")])
