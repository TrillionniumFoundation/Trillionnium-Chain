from pathlib import Path
import hashlib,json,subprocess
repo=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
out=Path("/home/qian-qi/work/chain-w1-base96-impact-20261108-ec265b-01")
old="62d2d90c9e1f4c8450c89843f1e08360a24283ce";new="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75";c6="2bdd252aa6c300b7431b9ee897b254b7953cf562";merged="d73e57c9e7a5764a1ab33540c97af587bb6e4a69"
paths=[line.split("\t",1)[1] for line in (out/"base-name-status.stdout").read_text().splitlines()]
for label,args in [
 ("base-narrow-diff",["diff","--no-ext-diff","--no-renames","--unified=5",old,new,"--"]+paths),
 ("merged-vs-C6-name-status",["diff","--no-ext-diff","--no-renames","--name-status",c6,merged]),
 ("merged-vs-C6-diff",["diff","--no-ext-diff","--no-renames","--unified=5",c6,merged,"--"]+paths)]:
 p=subprocess.run(["git","--no-optional-locks"]+args,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 (out/(label+".stdout")).write_bytes(p.stdout);(out/(label+".stderr")).write_bytes(p.stderr)
 print(json.dumps({"label":label,"exit":p.returncode,"bytes":len(p.stdout),"sha256":hashlib.sha256(p.stdout).hexdigest(),"stderr":p.stderr.decode(),"stdout":p.stdout.decode() if label=="merged-vs-C6-name-status" else None}),flush=True)
for path in paths:
 p=subprocess.run(["git","--no-optional-locks","show",new+":"+path],cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 assert p.returncode==0
 dest=out/"new-base-files"/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.stdout)
 if path not in ["scripts/ci/run_history_diagnostic.py","trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs","config/pon/pq-cross-branch-corpus-v1.json"]:
  print(json.dumps({"path":path,"text":p.stdout.decode()}),flush=True)
print(json.dumps({"narrow_diff_text":(out/"base-narrow-diff.stdout").read_text() if (out/"base-narrow-diff.stdout").stat().st_size<70000 else None}),flush=True)
