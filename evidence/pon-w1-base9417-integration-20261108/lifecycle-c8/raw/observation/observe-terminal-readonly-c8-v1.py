#!/usr/bin/python3
"""One bounded read-only terminal observation; no signals, no dispatch, no DB reads."""
import os,json,stat,subprocess,time,hashlib
from pathlib import Path
ROOT=Path("/home/qian-qi/work/chain-w1-c8-timeout-reorg-20261108-ec265b-01")
OUT=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b/terminal-readonly-observation-01.json")
BOOT="14f92beb-43c6-4786-839e-b57307ae8048"
beg=time.monotonic_ns()
assert not OUT.exists()
boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
expected=[("owner",5213,121056721),("worker",5939,121058198),("direct-child",6070,121058338),("runner",6568,121059897),("r0vm",6749,121060474)]
obs=[]
for role,pid,birth in expected:
    row={"role":role,"expected":{"boot_id":BOOT,"pid":pid,"start_ticks":birth},"signals_sent":0}
    try:
        raw=Path(f"/proc/{pid}/stat").read_text(); fields=raw[raw.rindex(")")+2:].split()
        actual={"boot_id":boot,"pid":pid,"start_ticks":int(fields[19]),"state":fields[0],"ppid":int(fields[1])}
        row.update(observed=actual,same_identity=boot==BOOT and actual["start_ticks"]==birth,status="PRESENT")
    except FileNotFoundError: row.update(status="ABSENT",same_identity=False)
    obs.append(row)
cgbase="/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/hepta-runtime-job-1a1baa770fd-12894-1c3b.service"
cgroups=[]
for path,ino in [(cgbase,65616546),(cgbase+"/trnm-w1-generation-a35153e046b91421e3d8d67c0d5f053b88a87f4f8ac8213f8e3ee09f5f1be1e9",65617392)]:
    p=Path(path); row={"path":path,"expected_device":30,"expected_inode":ino,"all_history_reaped":None}
    try:
        st=p.stat(); row["current_identity"]={"device":st.st_dev,"inode":st.st_ino}
        row["same_identity"]=st.st_dev==30 and st.st_ino==ino
        groups={}; members=set()
        for base,dirs,files in os.walk(p):
            assert len(groups)<64,"bounded cgroup scope"
            q=Path(base); s=q.stat()
            procs=[int(x) for x in (q/"cgroup.procs").read_text().split()]
            ev=(q/"cgroup.events").read_text()
            groups[str(q)]={"device":s.st_dev,"inode":s.st_ino,"members":procs,"events":ev}
            members.update(procs)
        row.update(status="PRESENT",groups=groups,members=sorted(members),recursive_empty=not members)
    except FileNotFoundError:row.update(status="ABSENT",recursive_empty=None)
    cgroups.append(row)
units=[]
for job in ("1a1baa770fd-12894-1c3b","1a1baac4fa2-12894-1c66"):
    argv=["systemctl","--user","show","hepta-runtime-job-"+job+".service","--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,Result,ExecMainCode,ExecMainStatus"]
    p=subprocess.run(argv,capture_output=True,text=True,timeout=10)
    units.append({"job_id":job,"argv":argv,"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr})
inventory=[]
for base,dirs,files in os.walk(ROOT):
    dirs[:]=[d for d in dirs if d not in {"checkpoint","receipts","receipt","artifacts",".git"}]
    assert len(inventory)<2000
    for name in files:
        p=Path(base)/name; st=p.lstat()
        if not stat.S_ISREG(st.st_mode): continue
        rel=str(p.relative_to(ROOT))
        if name.endswith((".sqlite",".sqlite3",".db","-wal","-shm")):continue
        allowed=p.suffix in {".json",".log",".txt",".wire",".packet",".bin",".hex"} or name in {"stdout","stderr"}
        if not allowed:continue
        row={"relative":rel,"bytes":st.st_size,"nlink":st.st_nlink}
        if st.st_size<=262144 and st.st_nlink==1:
            row["sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
        inventory.append(row)
report={"schema":"TRNM-W1-C8-FINAL-READONLY-OBSERVATION1","root":str(ROOT),"source":{"commit":"4e007a87ceecbec8d265f6a70cfd71d512a514b5","tree":"19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"},"started_monotonic_ns":beg,"completed_monotonic_ns":time.monotonic_ns(),"current_boot_id":boot,"known_processes":obs,"owned_cgroups":cgroups,"exact_units":units,"inventory":sorted(inventory,key=lambda x:x["relative"]),"signals_sent":0,"new_dispatches":0,"private_databases_read":False,"environment_read":False,"all_history_reaped":None,"gpu_accounting":"UNKNOWN","observation_scope":"Only exact previously recorded identities, exact owned cgroups/units, and allowlisted small external evidence; absence is time-local, not a history claim"}
OUT.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
b=OUT.read_bytes()
print(json.dumps({"path":str(OUT),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"process_statuses":[{"role":x["role"],"status":x["status"],"same_identity":x["same_identity"]} for x in obs],"cgroup_statuses":[{"path":x["path"],"status":x["status"],"recursive_empty":x["recursive_empty"]} for x in cgroups],"inventory_count":len(inventory),"signals_sent":0,"all_history_reaped":None}))
