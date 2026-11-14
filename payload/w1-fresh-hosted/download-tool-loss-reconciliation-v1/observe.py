import datetime,hashlib,json,os,pathlib,subprocess,sys
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1")
D=E/"R1-W1-complete-artifacts-v1"
O=E/"download-tool-loss-reconciliation-v1";O.mkdir(mode=0o700)
def put(p,b):
 with p.open("xb") as f:f.write(b)
def jb(x):return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
put(O/"tool-lost-original.json",sys.argv[1].encode())
put(O/"observe.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
r={"observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"read_only":True,"no_download_restarted":True,"steps":[],"files":[]}
for name,args in [("same-owned-process",["/bin/ps","-p","84900,84901","-o","pid=,ppid=,comm=,etime=,stat="]),("boot-observation",["/usr/sbin/sysctl","kern.boottime"])]:
 p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
 put(O/(name+".stdout"),p.stdout);put(O/(name+".stderr"),p.stderr)
 r["steps"].append({"argv":args,"exit_code":p.returncode,"stdout":p.stdout.decode(errors="replace"),"stderr":p.stderr.decode(errors="replace")})
for name in ["14117751904.zip","14117403147.zip","14117751904.zip.step.json","14117403147.zip.step.json","download-summary.json"]:
 p=D/name
 if not p.exists():r["files"].append({"path":str(p),"exists":False});continue
 s=p.stat();x={"path":str(p),"exists":True,"observed_bytes":s.st_size}
 if name.endswith(".json"):
  b=p.read_bytes();x["sha256"]=hashlib.sha256(b).hexdigest();x["value"]=json.loads(b)
 r["files"].append(x)
put(O/"summary.json",jb(r));b=(O/"summary.json").read_bytes()
print(json.dumps({"summary":{"path":str(O/"summary.json"),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()},"steps":r["steps"],"files":r["files"]},sort_keys=True))
