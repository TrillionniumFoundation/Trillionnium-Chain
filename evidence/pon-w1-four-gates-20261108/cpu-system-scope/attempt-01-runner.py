#!/usr/bin/env python3
"""One new transient system service; never changes existing task accounting."""
import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def run(argv, timeout=15):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=timeout, close_fds=True)
    return {"argv": argv, "returncode": p.returncode,
            "stdout": p.stdout, "stderr": p.stderr}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--unit", required=True)
    args = ap.parse_args()
    if not args.unit.startswith("w1-cpu-probe-ec265-") or "/" in args.unit:
        raise ValueError("new isolated probe unit required")
    args.out.mkdir(parents=True, exist_ok=False)
    nodes = []
    for pattern in ("/dev/nvidia*", "/dev/dri/*", "/dev/kfd"):
        for name in sorted(glob.glob(pattern)):
            p = Path(name)
            if p.is_char_device():
                s = p.stat()
                nodes.append({"path": name, "major": os.major(s.st_rdev),
                              "minor": os.minor(s.st_rdev),
                              "mode": oct(s.st_mode), "uid": s.st_uid, "gid": s.st_gid,
                              "alias": f"/run/w1-gpu-denial-probe/device-{len(nodes)}"})
    if not nodes:
        raise RuntimeError("actual host GPU character device controls required")
    properties = ["DynamicUser=yes", "PrivateDevices=yes", "DevicePolicy=strict",
                  "DeviceAllow=/dev/null rw", "DeviceAllow=/dev/zero r",
                  "DeviceAllow=/dev/random r", "DeviceAllow=/dev/urandom r",
                  "PrivateNetwork=yes", "RestrictAddressFamilies=none",
                  "PrivateIPC=yes", "PrivateTmp=yes", "ProtectProc=invisible",
                  "ProcSubset=pid", "ProtectSystem=strict", "ProtectHome=yes",
                  "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
                  "ProtectControlGroups=yes", "RestrictNamespaces=yes",
                  "RestrictSUIDSGID=yes", "NoNewPrivileges=yes",
                  "CapabilityBoundingSet=", "AmbientCapabilities=",
                  "SystemCallFilter=~@debug", "SystemCallErrorNumber=EPERM",
                  "LockPersonality=yes", "MemoryMax=268435456", "MemorySwapMax=0",
                  "TasksMax=16", "CPUQuota=25%", "RuntimeMaxSec=20s",
                  "TimeoutStopSec=5s", "KillMode=control-group"]
    properties += ["BindReadOnlyPaths=" + n["path"] + ":" + n["alias"] for n in nodes]
    payload = r'''
import ctypes,errno,json,os,socket,stat,time
from pathlib import Path
nodes=NODES
r={"schema":"TRNM-W1-CPU-DENIAL-PROBE1","uid":os.getuid(),"gid":os.getgid(),
   "groups":os.getgroups(),"pid":os.getpid(),"boot_id":None,
   "start_monotonic_ns":time.monotonic_ns(),"fd_inventory":[],"devices":[],"sockets":[]}
for f in sorted(Path('/proc/self/fd').iterdir()):
 try:
  s=f.stat();r['fd_inventory'].append({'fd':int(f.name),'target':os.readlink(f),'mode':oct(s.st_mode),
                                    'major':os.major(s.st_rdev),'minor':os.minor(s.st_rdev)})
 except FileNotFoundError:pass
r['status']={}
for line in Path('/proc/self/status').read_text().splitlines():
 k,_,v=line.partition(':')
 if k in ('Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters'):
  r['status'][k]=v.strip()
for n in nodes:
 for kind,p in [('original',n['path']),('bound-alias',n['alias'])]:
  q={'path':p,'kind':kind,'expected_major':n['major'],'expected_minor':n['minor']}
  try:
   s=os.stat(p);q['stat']={'character':stat.S_ISCHR(s.st_mode),'major':os.major(s.st_rdev),'minor':os.minor(s.st_rdev),'mode':oct(s.st_mode)}
  except OSError as e:q['stat_errno']=e.errno
  for mode,flags in [('read',os.O_RDONLY),('read-write',os.O_RDWR)]:
   try:
    fd=os.open(p,flags|os.O_NONBLOCK|os.O_CLOEXEC);os.close(fd);q[mode]={'opened':True}
   except OSError as e:q[mode]={'opened':False,'errno':e.errno}
  r['devices'].append(q)
for af in (socket.AF_UNIX,socket.AF_INET,socket.AF_INET6):
 q={'family':int(af)}
 try:
  s=socket.socket(af,socket.SOCK_STREAM);s.close();q['created']=True
 except OSError as e:q.update(created=False,errno=e.errno)
 r['sockets'].append(q)
try:
 os.stat('/proc/1/root');r['external_proc_root_visible']=True
except OSError as e:r.update(external_proc_root_visible=False,external_proc_errno=e.errno)
libc=ctypes.CDLL(None,use_errno=True)
ctypes.set_errno(0)
r['self_ptrace_traceme']={'returncode':libc.ptrace(0,0,None,None),'errno':ctypes.get_errno()}
with open('/dev/zero','rb') as f:r['dev_zero_positive']=f.read(4)==b'\0'*4
fd=os.open('/dev/null',os.O_WRONLY);r['dev_null_positive']=os.write(fd,b'control')==7;os.close(fd)
r['cgroup']=Path('/proc/self/cgroup').read_text()
relative=r['cgroup'].split('0::',1)[1].strip()
cg=Path('/sys/fs/cgroup')/relative.lstrip('/')
r['cgroup_before']={}
for n in ('cpu.max','cpu.stat','memory.max','memory.swap.max','memory.current','memory.peak','pids.max','pids.current','cgroup.events'):
 try:r['cgroup_before'][n]=(cg/n).read_text()
 except OSError as e:r['cgroup_before'][n]={'errno':e.errno}
time.sleep(2)
r['finished_monotonic_ns']=time.monotonic_ns()
aliases=[d for d in r['devices'] if d['kind']=='bound-alias']
r['checks']={
 'dynamic_unprivileged_uid':61184<=r['uid']<=65519,
 'no_inherited_device_or_socket_descriptors':all(d['fd'] in (0,1,2) and (d['target'].startswith('pipe:[') or d['target']=='/dev/null') for d in r['fd_inventory']),
 'no_capabilities':all(int(r['status'][k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),
 'no_new_privileges':r['status']['NoNewPrivs']=='1',
 'seccomp_filter_enabled':r['status']['Seccomp']=='2',
 'all_gpu_aliases_are_actual_host_character_devices':len(aliases)==len(nodes) and all(d.get('stat',{}).get('character') and d['stat']['major']==d['expected_major'] and d['stat']['minor']==d['expected_minor'] for d in aliases),
 'all_gpu_device_opens_denied':all(not d[m]['opened'] for d in r['devices'] for m in ('read','read-write')),
 'world_accessible_nvidia_device_open_denied_with_eperm':any(d['expected_major']==195 and d['stat']['mode'].endswith('666') and all(d[m].get('errno')==errno.EPERM for m in ('read','read-write')) for d in aliases),
 'all_tested_socket_families_denied':all(not s['created'] and s.get('errno') in (errno.EPERM,errno.EAFNOSUPPORT,errno.EACCES) for s in r['sockets']),
 'external_proc_hidden':not r['external_proc_root_visible'],
 'self_ptrace_denied':r['self_ptrace_traceme']=={'returncode':-1,'errno':errno.EPERM},
 'null_and_zero_positive_controls':r['dev_zero_positive'] and r['dev_null_positive']}
r['all_checks_passed']=all(r['checks'].values())
print(json.dumps(r,sort_keys=True),flush=True)
raise SystemExit(0 if r['all_checks_passed'] else 1)
'''.replace("nodes=NODES", "nodes=" + repr(nodes))
    intent = {"schema": "TRNM-W1-CPU-DENIAL-PROBE-INTENT1", "unit": args.unit,
              "nodes": nodes, "properties": properties,
              "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
              "scope": "one new short system-scope service only",
              "fresh_proofs": 0, "original_tasks_reassessed": False,
              "resource_billing_complete": False, "old_gpu_ns": None}
    (args.out / "intent.json").write_text(json.dumps(intent, indent=2) + "\n")
    (args.out / "payload.py").write_text(payload)
    before = run(["systemctl", "show", args.unit + ".service", "--property=LoadState"])
    if "LoadState=not-found" not in before["stdout"]:
        raise RuntimeError("unit name is not new")
    argv = ["sudo", "-n", "systemd-run", "--quiet", "--wait", "--pipe",
            "--unit=" + args.unit]
    for prop in properties:
        argv.extend(["--property", prop])
    argv.extend(["/usr/bin/python3", "-I", "-S", "-c", payload])
    started = time.monotonic_ns()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, close_fds=True)
    time.sleep(.7)
    show = run(["systemctl", "show", args.unit + ".service",
                "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,DynamicUser,User,PrivateDevices,DevicePolicy,DeviceAllow,PrivateNetwork,RestrictAddressFamilies,PrivateIPC,PrivateTmp,ProtectProc,ProcSubset,ProtectSystem,ProtectHome,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges,SystemCallFilter,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Result,ExecMainCode,ExecMainStatus,CPUUsageNSec,MemoryPeak"])
    try:
        stdout, stderr = proc.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        # The unique new unit has its own 20-second watchdog; stopping only it
        # preserves the failed experiment without touching prior operations.
        cleanup = run(["sudo", "-n", "systemctl", "stop", args.unit + ".service"])
        stdout, stderr = proc.communicate(timeout=10)
        (args.out / "timeout-cleanup.json").write_text(json.dumps(cleanup, indent=2))
    finished = time.monotonic_ns()
    (args.out / "stdout.json").write_text(stdout)
    (args.out / "stderr.txt").write_text(stderr)
    after = run(["systemctl", "show", args.unit + ".service",
                 "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,CPUUsageNSec,MemoryPeak"])
    journal = run(["journalctl", "--no-pager", "--unit", args.unit + ".service", "-n", "40", "-o", "short-iso"])
    record = {"intent": intent, "unit_before": before, "unit_during": show,
              "unit_after": after, "journal": journal, "actual_systemd_run_exit": proc.returncode,
              "started_monotonic_ns": started, "finished_monotonic_ns": finished,
              "boot_id": Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest()}
    try:
        record["probe"] = json.loads(stdout)
        record["probe_passed"] = proc.returncode == 0 and record["probe"]["all_checks_passed"] is True
    except (ValueError, KeyError):
        record["probe_passed"] = False
    (args.out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"probe_passed": record["probe_passed"], "exit": proc.returncode,
                      "checks": record.get("probe", {}).get("checks"),
                      "scope": intent["scope"], "old_gpu_ns": None}))
    return 0 if record["probe_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
