import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
driver=root/"run_final_prepublication_gates_v1.py"
raw=driver.read_bytes()
assert len(raw)==10580 and hashlib.sha256(raw).hexdigest()=="e7bc466fcf570a20745954c8627b8af9227582484b251dfcf7900e7942fa7496"
with (root/"launch-seven-source-gates-6a8cd5-v1.py").open("x") as f:f.write(sys.argv[1])
os.execv("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(driver),"--head","6a8cd55573065ceb50cdb65a7834615f79b521ae","--tree","cbd6b4552c87af27c72c0189806baeb33ecb8bf5","--evidence-dir",str(root/"prepublication-source-gates-6a8cd5-v1")])
