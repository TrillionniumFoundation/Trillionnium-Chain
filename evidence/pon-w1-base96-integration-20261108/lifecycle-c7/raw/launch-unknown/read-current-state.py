#!/usr/bin/env python3
import hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path("/home/qian-qi/work/chain-w1-c7-timeout-reorg-20261108-ec265b-01")
OUT=Path("/home/qian-qi/work/chain-w1-base96-m12-tools-20261108-ec265b/c7-launch-unknown-01/current-state.json")
JOB="1a1ba4cf251-12894-1994"
UNIT="hepta-runtime-job-"+JOB+".service"
jobdir=Path("/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs")/JOB
def identity(pid):
    p=Path("/proc")/str(pid)
    try:
        text=(p/"stat").read_text();fields=text.rsplit(") ",1)[1].split()
        return {"pid":pid,"start_ticks":int(fields[19]),"state":fields[0],"exe":os.readlink(p/"exe"),"cmdline":(p/"cmdline").read_bytes().split(b"\0")[:-1]}
    except (FileNotFoundError,PermissionError) as e:return {"pid":pid,"error":type(e).__name__}
show=subprocess.run(["/usr/bin/systemctl","--user","show",UNIT,"--no-pager","--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ControlGroup"],
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
fields=dict(line.split("=",1) for line in show.stdout.decode().splitlines() if "=" in line)
membership=Path("/proc/self/cgroup").read_text().strip()
assert membership.startswith("0::/")
self_cgroup=Path("/sys/fs/cgroup")/membership[3:].lstrip("/")
expected=self_cgroup.parent/UNIT
observed=Path("/sys/fs/cgroup")/fields.get("ControlGroup","").lstrip("/") if fields.get("ControlGroup") else expected
assert observed==expected
pid_refs=[]
if expected.exists():
    count=0
    for base,dirs,files in os.walk(expected):
        count+=1;assert count<=64
        path=Path(base)/"cgroup.procs"
        if path.is_file():
            for raw in path.read_text().split():
                pid=int(raw);value=identity(pid)
                if "cmdline" in value:value["cmdline"]=[x.decode(errors="replace") for x in value["cmdline"]]
                pid_refs.append({"cgroup":str(base),"process":value})
out={"schema":"TRNM-W1-C7-LAUNCH-UNKNOWN-CURRENT-STATE1","original_job_id":JOB,"observed_monotonic_ns":time.monotonic_ns(),
    "observed_unix_ns":time.time_ns(),"boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    "job_directory_exists":jobdir.exists(),"root":str(ROOT),
    "root_artifact_presence":{key:(ROOT/key).exists() for key in ("plan.json","config.json","launch-declaration.json","run","research-node","target-state")},
    "systemd":{"argv":show.args,"exit_code":show.returncode,"stdout":show.stdout.decode(),"stderr":show.stderr.decode(),"fields":fields},
    "expected_cgroup":str(expected),"expected_cgroup_exists":expected.exists(),"currently_observed_owned_processes":pid_refs,
    "signals_sent":0,"Node_opened":False,"Native_transactions_sent":0,"operation_or_deadline_modified":False,
    "launch_or_execution_history_remains_unknown":True,"complete_historical_reap_established":False,
    "scope":"One read-only current-state snapshot of the exact original job unit/cgroup and operation root; absence is not retrospective proof of no process history."}
with OUT.open("x") as f:json.dump(out,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
raw=OUT.read_bytes()
print(json.dumps({"record":{"path":str(OUT),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"observation":out}),flush=True)
