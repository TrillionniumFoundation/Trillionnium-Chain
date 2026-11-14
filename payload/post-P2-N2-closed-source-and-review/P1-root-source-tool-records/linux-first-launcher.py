import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
base=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
driver=base/"run_final_rog_repository_truth_offline_v4.py"
raw=driver.read_bytes();assert len(raw)==15187 and hashlib.sha256(raw).hexdigest()=="bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
bundle=base/"offline-source-bundles-v3/policy-prefix-6a8cd555-after-ed0d3548.bundle"
raw=bundle.read_bytes();assert len(raw)==8575 and hashlib.sha256(raw).hexdigest()=="cdd1ea4dd38a77c52fe7977ab2a8d7c8bea7f47d11f478b72887cd05afa96389"
with (base/"launch-original-repository-truth-6a8cd5-v1.py").open("x") as f:f.write(sys.argv[1])
python=base/"final-python312-env/bin/python"
os.execv(str(python),[str(python),"-B",str(driver),"--head","6a8cd55573065ceb50cdb65a7834615f79b521ae","--tree","cbd6b4552c87af27c72c0189806baeb33ecb8bf5","--expected-start-head","ed0d35487f2a67239e4d646fd41c2c7acb5cc740","--bundle-path",str(bundle),"--bundle-bytes","8575","--bundle-sha256","cdd1ea4dd38a77c52fe7977ab2a8d7c8bea7f47d11f478b72887cd05afa96389","--evidence-dir",str(base/"final-repository-truth-offline-6a8cd5-v1")])
