"""Bounded observation transport. No store parsing, state, or authority lives here."""
from __future__ import annotations
import hashlib, json, os, select, shutil, signal, struct, subprocess, threading, time
from pathlib import Path
from hia.platform.build import sealed_executable
MAX = (1 << 64) - 1
TIMEOUT = 60
CLEANUP = 3

def word(n): return struct.pack('<Q', n)
def bootstrap(path, gate_write=MAX, gate_read=MAX):
    path = os.fsencode(path)
    return b'PLSTO001' + struct.pack('<3Q', len(path), gate_write, gate_read) + path

def command(op, payload=b''):
    return b'PLSC0001' + word(op) + payload

class Child:
    def __init__(self, executable: bytes, path, directory: Path, *, gates=False, preexec=None, sync_error=None, trace=False, inject=None):
        if directory.exists() or directory.is_symlink():
            raise FileExistsError(directory)
        directory.mkdir(parents=True, mode=0o700)
        self.directory = directory
        self.input = bytearray(); self.output = bytearray(); self.error = bytearray()
        self.gate_bytes = bytearray(); self.resume_bytes = bytearray(); self.closed = False
        self.started = time.monotonic_ns(); self.cleanup = None
        self.executable = {'bytes':len(executable), 'sha256':hashlib.sha256(executable).hexdigest()}
        self.read_gate = self.write_resume = None
        gate_write = gate_read = MAX
        passed=[]
        if gates:
            self.read_gate, gate_write=os.pipe()
            gate_read, self.write_resume=os.pipe()
            passed.extend((gate_write, gate_read))
        fd=sealed_executable(executable, 'trnm-peer-store-observed')
        passed.append(fd)
        argv=['/proc/self/fd/' + str(fd)]
        self.tracer=None
        if trace or inject:
            tracer=shutil.which('strace')
            if not tracer:raise RuntimeError('Actual strace is required; no simulated trace or skipped fault test')
            tracer=Path(tracer).resolve(strict=True)
            version=subprocess.run([str(tracer),'--version'],capture_output=True,timeout=10)
            if version.returncode:raise RuntimeError('Actual strace version failed')
            (directory/'tracer-version.stdout.raw').write_bytes(version.stdout)
            (directory/'tracer-version.stderr.raw').write_bytes(version.stderr)
            raw=tracer.read_bytes()
            self.tracer={'path':str(tracer),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                         'version_returncode':version.returncode,'injection':inject,
                         'physical_media_failure':False,'trace':'syscalls.raw'}
            (directory/'strace.elf').write_bytes(raw)
            argv=[str(tracer),'-f','-qq','-yy','-s','256',
                  '-e','trace=execve,openat,close,read,write,fsync,rename,flock,lseek,fstat,newfstatat,statx,chmod,mkdir,mkdirat',
                  '-o',str(directory/'syscalls.raw')]+(['--inject='+inject] if inject else [])+argv
        self.argv=argv
        self.kernel_fault=None
        before=preexec
        if sync_error is not None:
            from .kernel_faults import fsync_errno
            available=[i for i in range(3,64) if i not in passed]
            selected=available[2]  # retained directory, lock, then journal
            self.kernel_fault={'kind':'kernel-seccomp-errno','syscall':74,'fd':selected,'errno':sync_error,
                               'fd_domain':'predicted then verified by observed journal append/failure/recovery',
                               'no_new_privileges':True,'physical_media_failure':False}
            def before():
                if preexec:preexec()
                fsync_errno(selected,sync_error)
        try:
            self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=tuple(passed),cwd=directory,env={'PATH':''},start_new_session=True,umask=0o077,preexec_fn=before)
        finally:
            os.close(fd)
            if gates:
                os.close(gate_write);os.close(gate_read)
        def drain():
            while True:
                block=self.process.stderr.read(65536)
                if not block: break
                self.error.extend(block)
        self.drainer=threading.Thread(target=drain,daemon=True);self.drainer.start()
        self.send(bootstrap(path,gate_write,gate_read))
    def send(self, payload):
        self.input.extend(payload)
        self.process.stdin.write(payload);self.process.stdin.flush()
    def _read(self,fd,n,target):
        stop=time.monotonic()+TIMEOUT
        result=bytearray()
        while len(result)<n:
            left=stop-time.monotonic()
            if left<=0 or not select.select([fd],[],[],left)[0]:
                raise TimeoutError('real child response timeout')
            block=os.read(fd,n-len(result))
            if not block:
                raise EOFError('real child closed before complete observation')
            result.extend(block);target.extend(block)
        return bytes(result)
    def receive(self):
        raw=self._read(self.process.stdout.fileno(),40,self.output)
        if raw[:8]!=b'PLSR0001':raise ValueError('actual response magic')
        cmd,category,code,n=struct.unpack_from('<4Q',raw,8)
        if n>65536:raise ValueError('actual response extent')
        body=self._read(self.process.stdout.fileno(),n,self.output)
        return {'command':cmd,'category':category,'code':code,'body':body}
    def call(self,op,payload=b''):
        self.send(command(op,payload));return self.receive()
    def gate(self):
        raw=self._read(self.read_gate,56,self.gate_bytes)
        if raw[:8]!=b'PLSCUT01':raise ValueError('actual diagnostic gate magic')
        return dict(zip(('sequence','tag','opened','journal_fd','directory_fd','temporary_fd'),struct.unpack_from('<6Q',raw,8)))
    def resume(self):
        os.write(self.write_resume,b'\x01');self.resume_bytes.extend(b'\x01')
    def finish(self, *, kill=False):
        if self.closed:return
        self.closed=True
        if kill:
            os.killpg(self.process.pid,signal.SIGKILL)
        try:
            self.process.stdin.close()
        except BrokenPipeError:pass
        try:
            self.process.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            began=time.monotonic_ns()
            os.killpg(self.process.pid,signal.SIGKILL)
            self.process.wait(timeout=CLEANUP)
            self.cleanup={'reason':'deadline','signal':'SIGKILL','elapsed_ns':time.monotonic_ns()-began,'reaped':True}
        # Preserve any output beyond a framed response, including refusal bytes.
        while True:
            raw=self.process.stdout.read(65536)
            if not raw:break
            self.output.extend(raw)
        self.drainer.join(timeout=CLEANUP)
        if self.drainer.is_alive():raise RuntimeError('stderr drainer did not finish')
        for stream in (self.process.stdout,self.process.stderr):stream.close()
        for fd in (self.read_gate,self.write_resume):
            if fd is not None:os.close(fd)
        for name,data in (('stdin.raw',self.input),('stdout.raw',self.output),('stderr.raw',self.error),
                          ('gates.raw',self.gate_bytes),('resumes.raw',self.resume_bytes)):
            (self.directory/name).write_bytes(data)
        report={'argv':self.argv,'cwd':str(self.directory),'environment':{'PATH':''},'umask':'0077',
            'actual_exit_code':self.process.returncode,'actual_pid':self.process.pid,'executable':self.executable,
            'elapsed_ns':time.monotonic_ns()-self.started,'wall_limit_seconds':TIMEOUT,'cleanup':self.cleanup,
            'intentional_sigkill':kill,'kernel_fault':self.kernel_fault,'tracer':self.tracer,'streams':{n:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}
               for n,v in (('stdin',self.input),('stdout',self.output),('stderr',self.error),('gates',self.gate_bytes),('resumes',self.resume_bytes))}}
        (self.directory/'receipt.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        return report
