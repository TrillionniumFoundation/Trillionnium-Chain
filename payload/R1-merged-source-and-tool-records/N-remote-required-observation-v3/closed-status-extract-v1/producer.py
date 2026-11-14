import pathlib,os,stat,sys,json,hashlib
B=pathlib.Path("/private/tmp/chain-prci-remote-5a4b-required-jobs-observation-20261114-v3");P=B/"summary.json";O=B/"closed-status-extract-v1";O.mkdir(mode=0o700)
fd=os.open(P,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==109017
 raw=os.read(fd,a.st_size+1)
 z=os.fstat(fd);assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 assert len(raw)==109017 and hashlib.sha256(raw).hexdigest()=="31553ed8610a17457680962d4b2e60ce37c57c6d9ba52c7b9e70488a539fa302"
finally:os.close(fd)
d=json.loads(raw);jobs=d["fixed_required_jobs"]["jobs"]
selected=[]
for j in jobs:
 if j["status"]=="in_progress" or j["id"]in(132415017391,132415017476):
  selected.append({k:j[k]for k in("id","name","status","conclusion","started_at","completed_at")})
  selected[-1]["active_or_failed_steps"]=[x for x in j["steps"]if x["status"]=="in_progress"or x["conclusion"]in("failure","cancelled")]
v={"schema":"trnm-N-run-terminal-status-existing-response-extract-v1","source_summary":{"path":str(P),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"started_at":d["started_at"],"finished_at":d["finished_at"],"heads":d["heads"],"pr":d["pr"],"N_run_tested_head":d["fixed_required_run"]["head_sha"],"N_run_tested_tree":d["fixed_required_run"]["head_commit"]["tree_id"],"jobs":selected,"all_19_original_jobs_retained_in_summary":True,"new_remote_requests":False,"inner_failure_not_established_by_status":True}
def save(name,b):
 p=O/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return{"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
save("producer.py",sys.argv[2].encode());save("bounded-multifile-read-rejection.json",(json.dumps(json.loads(sys.argv[1]),indent=2)+"\n").encode())
p=save("status.json",(json.dumps(v,indent=2)+"\n").encode())
print(json.dumps({"file":p,"status":v}),flush=True)
