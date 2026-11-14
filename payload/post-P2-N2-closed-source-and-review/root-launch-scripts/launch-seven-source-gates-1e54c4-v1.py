import hashlib,os,pathlib,sys
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
driver=root/"run_final_prepublication_gates_v1.py"
raw=driver.read_bytes()
assert len(raw)==10580 and hashlib.sha256(raw).hexdigest()=="e7bc466fcf570a20745954c8627b8af9227582484b251dfcf7900e7942fa7496"
with (root/"launch-seven-source-gates-1e54c4-v1.py").open("x") as f:f.write(sys.argv[1])
os.execv("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(driver),"--head","1e54c4ff66a92827c83bea8715f59f6b299e98cf","--tree","2c0716f9165f7cbc31ce8eae17f17bf2643d30cb","--evidence-dir",str(root/"prepublication-source-gates-1e54c4-v1")])
