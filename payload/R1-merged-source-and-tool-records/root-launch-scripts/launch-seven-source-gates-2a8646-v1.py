import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
driver=root/"run_final_prepublication_gates_v1.py"
raw=driver.read_bytes()
assert len(raw)==10580 and hashlib.sha256(raw).hexdigest()=="e7bc466fcf570a20745954c8627b8af9227582484b251dfcf7900e7942fa7496"
with (root/"launch-seven-source-gates-2a8646-v1.py").open("x") as f:f.write(sys.argv[1])
os.execv("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(driver),"--head","2a86462a1ab20c68151719ba4635e3c294391e64","--tree","5c26776f96f15fd131e85a5c2d7c5e895ad7fab4","--evidence-dir",str(root/"prepublication-source-gates-2a8646-v1")])
