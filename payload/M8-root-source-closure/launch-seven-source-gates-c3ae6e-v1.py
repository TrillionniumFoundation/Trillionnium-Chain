import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
driver=root/"run_final_prepublication_gates_v1.py"
raw=driver.read_bytes()
assert len(raw)==10580 and hashlib.sha256(raw).hexdigest()=="e7bc466fcf570a20745954c8627b8af9227582484b251dfcf7900e7942fa7496"
with (root/"launch-seven-source-gates-c3ae6e-v1.py").open("x") as f:f.write(sys.argv[1])
os.execv("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(driver),"--head","c3ae6e71d7b0da4b43b0c7aa6df34aeabf838f47","--tree","9f24fd19d725f96e8ac42060054f1f8d4f3e57e9","--evidence-dir",str(root/"prepublication-source-gates-c3ae6e-v1")])
