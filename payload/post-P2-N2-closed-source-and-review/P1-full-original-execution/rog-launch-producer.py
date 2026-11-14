import pathlib,os,sys,json,hashlib,datetime,subprocess
D=json.loads(sys.argv[1]);SELF=sys.argv[2]
BASE=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
O=BASE/"package-original-repository-truth-6a8cd5-v2-prci"
L=BASE/"package-original-repository-truth-6a8cd5-launch-v2-prci"
assert not O.exists() and not L.exists()
def js(v):return (json.dumps(v,indent=2)+"\n").encode()
def save(p,raw):
 with p.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==raw
 return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
raw=D["producer"].encode();m=js(D["manifest"])
assert len(raw)==D["producer_bytes"] and hashlib.sha256(raw).hexdigest()==D["producer_sha256"]
assert len(m)==D["manifest_bytes"] and hashlib.sha256(m).hexdigest()==D["manifest_sha256"]
assert D["terminal_exit"]==0 and D["summary_sha256"]=="a61aca5c4745c4a4e6f89c8cdc18b489679662b135061bee1357ca4072ca0f3b"
O.mkdir(mode=0o700);L.mkdir(mode=0o700)
producer=save(O/"package_original_repository_truth_6a8cd5_v2.py",raw)
manifest=save(O/"closed-original-logs.json",m)
save(L/"launch-producer.py",SELF.encode())
save(L/"launch-inputs.json",js({k:v for k,v in D.items()if k not in ("producer","manifest")}))
argv=[sys.executable,"-B",producer["path"],"--terminal-summary-sha256",D["summary_sha256"],"--terminal-exit-code","0","--closed-log-manifest-sha256",D["manifest_sha256"]]
started=datetime.datetime.now(datetime.timezone.utc).isoformat();save(L/"launch.json",js({"argv":argv,"cwd":str(O),"timeout_seconds":180,"producer":producer,"manifest":manifest,"started_at":started,"kind":"package_closed_receipts_only"}))
result={"schema":"trnm-P1-original-full-package-launch-v2","started_at":started,"argv":argv,"cwd":str(O),"producer":producer,"manifest":manifest,"original_summary_sha256":D["summary_sha256"],"original_terminal_exit":0}
try:
 r=subprocess.run(argv,cwd=str(O),capture_output=True,timeout=180)
 result.update(exit=r.returncode,stdout=save(L/"package.stdout",r.stdout),stderr=save(L/"package.stderr",r.stderr),timed_out=False)
except subprocess.TimeoutExpired as e:
 result.update(exit=None,stdout=save(L/"package.stdout",e.stdout or b""),stderr=save(L/"package.stderr",e.stderr or b""),timed_out=True)
result.update(finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_git_lane_mutation=False)
receipt=save(L/"summary.json",js(result));print(json.dumps({"receipt":receipt,"package_exit":result["exit"],"timed_out":result["timed_out"]}),flush=True)
if result["exit"]!=0:sys.exit(1)
print((L/"package.stdout").read_text(),end="",flush=True)
