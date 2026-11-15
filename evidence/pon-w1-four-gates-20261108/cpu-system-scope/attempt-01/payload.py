
import ctypes,errno,json,os,socket,stat,time
from pathlib import Path
nodes=[{'path': '/dev/nvidia-modeset', 'major': 195, 'minor': 254, 'mode': '0o20666', 'uid': 0, 'gid': 0, 'alias': '/run/w1-gpu-denial-probe/device-0'}, {'path': '/dev/nvidia-uvm', 'major': 235, 'minor': 0, 'mode': '0o20666', 'uid': 0, 'gid': 0, 'alias': '/run/w1-gpu-denial-probe/device-1'}, {'path': '/dev/nvidia-uvm-tools', 'major': 235, 'minor': 1, 'mode': '0o20666', 'uid': 0, 'gid': 0, 'alias': '/run/w1-gpu-denial-probe/device-2'}, {'path': '/dev/nvidia0', 'major': 195, 'minor': 0, 'mode': '0o20666', 'uid': 0, 'gid': 0, 'alias': '/run/w1-gpu-denial-probe/device-3'}, {'path': '/dev/nvidiactl', 'major': 195, 'minor': 255, 'mode': '0o20666', 'uid': 0, 'gid': 0, 'alias': '/run/w1-gpu-denial-probe/device-4'}, {'path': '/dev/dri/card0', 'major': 226, 'minor': 0, 'mode': '0o20660', 'uid': 0, 'gid': 44, 'alias': '/run/w1-gpu-denial-probe/device-5'}, {'path': '/dev/dri/renderD128', 'major': 226, 'minor': 128, 'mode': '0o20660', 'uid': 0, 'gid': 992, 'alias': '/run/w1-gpu-denial-probe/device-6'}]
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
