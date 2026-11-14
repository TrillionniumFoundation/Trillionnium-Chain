import pathlib,os,stat,sys,json,hashlib
B=pathlib.Path("/private/tmp/chain-prci-N-x64-native-artifact-14109658844-20261114-v1")
P=B/"selected-read-v1/originals/from-zero-native/manifest.json"
O=B/"manifest-observation-v1";O.mkdir(mode=0o700)
def read(p,n,h):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==n
  b=b""
  while len(b)<n+1:
   q=os.read(fd,min(65536,n+1-len(b)))
   if not q:break
   b+=q
  z=os.fstat(fd);assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  assert len(b)==n and hashlib.sha256(b).hexdigest()==h
  return b
 finally:os.close(fd)
def write(name,b):
 p=O/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
b=read(P,74003,"3362e60289fbf2268b0c9886f97a1b4958cbb095fbdf02c7349a986880ce0bf7")
m=json.loads(b);v={"schema":"trnm-N-x64-original-manifest-observation-extract-v1","source_path":str(P),"source_bytes":len(b),"source_sha256":hashlib.sha256(b).hexdigest(),"json_pointer":"/confirmation_observation","observation":m["confirmation_observation"],"all_named_tests_passed":m["all_named_tests_passed"],"passed":m["passed"],"failures":m["failures"],"source_before_equals_after":m["source_before"]==m["source_after"],"executed_artifact_code":False,"large_report_not_interpreted":True}
out=write("confirmation-observation.json",(json.dumps(v,indent=2)+"\n").encode())
write("producer.py",sys.argv[1].encode())
print(json.dumps({"file":out,"observation":v}),flush=True)
