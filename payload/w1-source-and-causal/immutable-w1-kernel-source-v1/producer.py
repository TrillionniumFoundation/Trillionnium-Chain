import os,sys,json,pathlib,subprocess,hashlib
B=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/immutable-w1-kernel-source-v1");B.mkdir(exist_ok=False)
H="2a86462a1ab20c68151719ba4635e3c294391e64";G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
def git(*a):
 p=subprocess.run(["/usr/bin/git","--git-dir="+G,*a],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=30)
 if p.returncode or p.stderr:raise RuntimeError({"exit":p.returncode,"stderr":p.stderr.decode(errors="replace")})
 return p.stdout
rows=[]
for rel,ranges in [
("trillionnium/crates/trnm-pon-node/src/store.rs",[(1022,1085),(1190,1256)]),
("trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",[(90,135),(460,510),(680,910)])
]:
 oid=git("rev-parse",H+":"+rel).decode().strip();b=git("cat-file","blob",oid);assert len(b)<512*1024 and hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==oid
 dest=B/rel.replace("/","--");dest.write_bytes(b);row={"source":rel,"path":str(dest),"git_blob":oid,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()};rows.append(row);print(json.dumps(row))
 lines=b.decode().splitlines()
 for start,end in ranges:
  t="\n".join(str(i)+":"+lines[i-1] for i in range(start,min(end,len(lines))+1))+"\n";p=B/(rel.replace("/","--")+"."+str(start)+"-"+str(end)+".txt");p.write_text(t);print(t)
(B/"source-index.json").write_text(json.dumps({"head":H,"git_dir":G,"files":rows},indent=2,sort_keys=True)+"\n");(B/"producer.py").write_text(sys.argv[1])
