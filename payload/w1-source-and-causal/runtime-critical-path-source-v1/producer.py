import os,json,pathlib,subprocess,hashlib,sys
G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";R="2a86462a1ab20c68151719ba4635e3c294391e64"
D=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/runtime-critical-path-source-v1");D.mkdir()
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
rows=[]
for p in ["trillionnium/crates/trnm-protocol/src/pon_wire.rs","trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs","trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs"]:
 q=subprocess.run(["/usr/bin/git","--git-dir="+G,"cat-file","blob",R+":"+p],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 assert q.returncode==0 and not q.stderr and len(q.stdout)<1000000
 b=q.stdout;f=D/p.replace("/","--")
 with f.open("xb") as o:o.write(b);o.flush();os.fsync(o.fileno())
 rows.append({"source":R,"path":p,"capture":str(f),"bytes":len(b),"lines":len(b.splitlines()),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()})
with (D/"source-index.json").open("x") as o:json.dump(rows,o,indent=2,sort_keys=True);o.write("\n")
with (D/"producer.py").open("x") as o:o.write(sys.argv[1])
print(json.dumps(rows,sort_keys=True))
