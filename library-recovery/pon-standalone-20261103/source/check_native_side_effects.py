"""Independent kernel check of the HIA x86_64 BPF rule sequence.
No full Hepta repository available in this container. No repo suite claimed.
"""
import ctypes, json, os, pathlib, resource, signal, subprocess, tempfile, textwrap, sys

WORKER = r'''
import ctypes, json, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0,0))
resource.setrlimit(resource.RLIMIT_FSIZE, (4096,4096))
resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU, (10,10))
class _BpfRule(ctypes.Structure):
    _fields_ = [("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint32)]
class _BpfProgram(ctypes.Structure):
    _fields_ = [("len",ctypes.c_ushort),("filter",ctypes.POINTER(_BpfRule))]
_rules = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
          (0x06, 0, 0, 0x80000000),
          (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000),
          (0x06, 0, 0, 0x80000000)]
_FORBIDDEN_SYSCALLS = (
    56, 57, 58, 435, 59, 322, 109, 112, 272, 308, 101, 425,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    288, 299, 307,
    76, 77, 82, 83, 84, 85, 86, 87, 88, 90, 91, 92, 93, 94,
    132, 133, 235, 258, 259, 260, 261, 263, 264, 265, 266, 268,
    280, 316, 452,
    437, 438, 311, 62, 200, 129, 297, 424,
)
if len(_FORBIDDEN_SYSCALLS) != len(set(_FORBIDDEN_SYSCALLS)):
    raise RuntimeError("duplicated native evaluator syscall policy")
for _nr in _FORBIDDEN_SYSCALLS:
    _rules += [(0x15, 0, 1, _nr), (0x06, 0, 0, 0x80000000)]
_libc = ctypes.CDLL(None, use_errno=True)
_worker_pid = os.getpid()
_worker_tid = _libc.syscall(186)
if not 0 < _worker_pid < (1 << 32) or not 0 < _worker_tid < (1 << 32):
    raise RuntimeError("invalid exact worker PID/TID for seccomp")
_rules += [
    (0x15, 0, 9, 234),
    (0x20, 0, 0, 16),
    (0x15, 1, 0, _worker_pid),
    (0x06, 0, 0, 0x80000000),
    (0x20, 0, 0, 24),
    (0x15, 1, 0, _worker_tid),
    (0x06, 0, 0, 0x80000000),
    (0x20, 0, 0, 32),
    (0x15, 1, 0, 6),
    (0x06, 0, 0, 0x80000000),
    (0x20, 0, 0, 0),
]
_WRITE_OPEN_FLAGS = 0x3 | 0x40 | 0x200 | 0x400 | 0x400000
for _nr, _flags_offset in ((2, 24), (257, 32)):
    _rules += [
        (0x15, 0, 4, _nr),
        (0x20, 0, 0, _flags_offset),
        (0x54, 0, 0, _WRITE_OPEN_FLAGS),
        (0x15, 1, 0, 0),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
    ]
_rules.append((0x06, 0, 0, 0x7FFF0000))
_rules_array = (_BpfRule * len(_rules))(*(_BpfRule(*r) for r in _rules))
_filter = _BpfProgram(len(_rules), _rules_array)
if _libc.prctl(38, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "no_new_privs required")
if _libc.prctl(22, 2, ctypes.byref(_filter), 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "filter required")
lib,symbol=sys.argv[1:]
f=getattr(ctypes.CDLL(lib),symbol)
f.argtypes=[];f.restype=ctypes.c_int32
print(json.dumps({"value":int(f())},separators=(",", ":")),flush=True)
'''

with tempfile.TemporaryDirectory() as d:
    r=pathlib.Path(d)
    marker=r/'target_file'; marker.write_bytes(b'X')
    output=r/'bad_file'
    c=r/'oracle.c';lib=r/'oracle.so'
    c.write_text('#include <unistd.h>\n#include <fcntl.h>\n#include <stdlib.h>\n#include <sys/socket.h>\n#include <sys/syscall.h>\n'
        'int healthy(void){return 7;}\n'
        'int aborting(void){abort();}\n'
        f'int readonly(void){{int f=open({json.dumps(str(marker))},O_RDONLY);if(f<0)return 8;char c=0;int n=read(f,&c,1);close(f);return n==1&&c==\'X\'?7:9;}}\n'
        f'int create(void){{int f=open({json.dumps(str(output))},O_WRONLY|O_CREAT|O_EXCL,0600);if(f>=0)close(f);return 7;}}\n'
        f'int create_at(void){{int f=openat(AT_FDCWD,{json.dumps(str(output))},O_WRONLY|O_CREAT,0600);if(f>=0)close(f);return 7;}}\n'
        f'int remove(void){{unlink({json.dumps(str(marker))});return 7;}}\n'
        f'int readonly_dir(void){{int f=open({json.dumps(str(r))},O_RDONLY|O_DIRECTORY);if(f<0)return 8;close(f);return 7;}}\n'
        'int direct_tmpfile(void){syscall(257,AT_FDCWD,"/tmp",0x410000|O_RDWR,0600);return 7;}\n'
        'int socket_create(void){socket(AF_INET,SOCK_DGRAM,0);return 7;}\n'
        'int kill_parent(void){syscall(62,getppid(),0);return 7;}\n'
        'int tgkill_parent(void){syscall(234,getppid(),getppid(),0);return 7;}\n'
        'int tgkill_self_usr1(void){syscall(234,getpid(),syscall(186),10);return 7;}\n'
        'int openat2(void){syscall(437,AT_FDCWD,0,0,0);return 7;}\n')
    cp=subprocess.run(['/usr/local/swift/usr/bin/clang','-O0','-shared','-fPIC',str(c),'-o',str(lib)],capture_output=True,text=True)
    assert cp.returncode==0,cp.stderr
    checks=[('healthy',0),('readonly',0),('readonly_dir',0),('aborting',-signal.SIGABRT),('create',-signal.SIGSYS),('create_at',-signal.SIGSYS),('remove',-signal.SIGSYS),('socket_create',-signal.SIGSYS),('kill_parent',-signal.SIGSYS),('tgkill_parent',-signal.SIGSYS),('tgkill_self_usr1',-signal.SIGSYS),('openat2',-signal.SIGSYS),('direct_tmpfile',-signal.SIGSYS)]
    report=[]
    for fn,expected in checks:
        p=subprocess.run([sys.executable,'-I','-c',WORKER,str(lib),fn],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        report.append({'case':fn,'returncode':p.returncode,'expected':expected,'matched':p.returncode==expected,'stdout':p.stdout.decode('utf-8','replace').strip(),'stderr':p.stderr.decode('utf-8','replace')[:100]})
    report.append({'case':'file_integrity','matched':marker.read_bytes()==b'X' and not output.exists()})
    report.append({'case':'all_kernel_controls','matched':all(x['matched'] for x in report)})
    (pathlib.Path('/mnt/data/hia_seccomp_evidence')/'standalone-kernel-check.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
