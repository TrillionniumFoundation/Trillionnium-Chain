import datetime,hashlib,json,pathlib,subprocess,sys
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3");O=E/"owner-observation-v1";O.mkdir(mode=0o700)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
put(O/"observe-original-owned-processes.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
rows=[]
for label,argv in [("boot",["/usr/sbin/sysctl","-n","kern.boottime"]),("owned",["/bin/ps","-p","7695,7702,7773,7782","-o","pid=,ppid=,uid=,comm=,etime=,stat=,lstart="])]:
 started=datetime.datetime.now(datetime.timezone.utc).isoformat()
 r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
 rows.append({"label":label,"argv":argv,"started_at":started,"exit_code":r.returncode,"stdout":put(O/(label+".stdout"),r.stdout),"stderr":put(O/(label+".stderr"),r.stderr),"stdout_text":r.stdout.decode(errors="replace")})
files=[]
for name in ["14119000610.zip","14119380013.zip","artifact-14119000610-zip.stderr","artifact-14119380013-zip.stderr"]:
 p=E/name;s=p.stat();files.append({"path":str(p),"bytes_at_observation":s.st_size,"device":s.st_dev,"inode":s.st_ino,"mtime_ns":s.st_mtime_ns,"observation_only_not_completed_file_pin":True})
s={"schema":"trnm-original-download-owner-readonly-observation-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"rows":rows,"live_file_sizes":files,"no_restart_no_retry_no_signal":True}
pin=put(O/"summary.json",jb(s));print(json.dumps({"summary":pin,"observation":s},sort_keys=True))
