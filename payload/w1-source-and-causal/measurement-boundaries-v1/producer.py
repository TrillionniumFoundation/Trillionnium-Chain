import os,sys,pathlib,subprocess,hashlib,json,zipfile,io
G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";H="2a86462a1ab20c68151719ba4635e3c294391e64"
O=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/measurement-boundaries-v1");O.mkdir(exist_ok=False)
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
rows=[]
for p in ["trillionnium/crates/trnm-pon-node/src/ingress/history_import/attribution.rs","trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs"]:
 r=subprocess.run(["/usr/bin/git","--git-dir="+G,"cat-file","blob",H+":"+p],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 assert r.returncode==0 and not r.stderr and len(r.stdout)<256000
 b=r.stdout;f=O/p.replace("/","--");f.write_bytes(b);rows.append({"path":p,"capture":str(f),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()})
 lines=b.decode().splitlines()
 hits=[]
 import re
 for i,line in enumerate(lines,1):
  if re.search(r"(fn observe_host|fn observe_submit_phase|struct ThreadCpuStamp|impl ThreadCpuStamp|fn checkpoint|fn measure|fn observe|fn sample|fn phase|fn finish|CPU_CLOCK)",line):hits.append({"line":i,"text":line})
 print(json.dumps({"source":p,"hits":hits}))
(O/"source-index.json").write_text(json.dumps({"head":H,"files":rows},indent=2,sort_keys=True)+"\n");(O/"producer.py").write_text(sys.argv[1])
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1")
for aid,sha in [(14117751904,"b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8"),(14117403147,"2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a")]:
 raw=(E/(str(aid)+".zip")).read_bytes();assert hashlib.sha256(raw).hexdigest()==sha
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  names=[x.filename for x in z.infolist() if any(t in x.filename for t in ["inside-before","inside-after","host-observation","host/","host-controller"])]
  print(json.dumps({"artifact":aid,"host_candidates":names}))
