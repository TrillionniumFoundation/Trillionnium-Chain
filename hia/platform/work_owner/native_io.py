"""Qualification driver for the actual static native Work/Host owner.

Private Paid/Work observer: this process supplies proof bytes and fixture files.
Every authority syscall and arithmetic transition executes in the native ELF.
"""
from __future__ import annotations
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import struct
import subprocess
import time

from hia.platform.build import sealed_executable
from hia.platform.host_resource.native_io import provision, mutate

MAGIC=b'HIAPW001'
FIELDS=('magic','fixture','domain','code','work_code','progress_count',
    'worker_host_calls','pre_checks','post_checks','aggregate_samples',
    'main_tid','worker_tid','generation','joins','alive_clocks','gates',
    'post_sample_error','parent_dev','parent_ino','parent_uid','cpu_quota',
    'cpu_period','memory_limit','pids_limit','boot_bytes','host_fixture','acquirer_tid')

def require(condition, message):
    if not condition:
        raise ValueError(message)

def identity(path: Path):
    raw=path.read_bytes()
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def require_gate_owner(stage,tid,tgid,tasks,pgid,leader,number):
    """Bind each private gate to its actual phase and owned process group."""
    require(type(stage) is int and 1<=stage<=8
            and all(type(n) is int and 0<n<1<<31 for n in (tid,tgid,pgid,leader))
            and type(tasks) is list and all(type(n) is int and 0<n<1<<31 for n in tasks)
            and tasks==sorted(set(tasks)) and tgid in tasks and tid in tasks and pgid==leader,
            'Private gate is outside this actual owned process group')
    if stage in (1,2):
        require(tid==tgid and tasks==[tgid] and number is None,
                'Acquisition gate must precede worker creation on the main thread')
    elif stage==8:
        # clear_child_tid precedes final task removal; the retired worker may
        # still appear in /proc here. Bind that optional TID to the final frame.
        require(tid==tgid and len(tasks) in (1,2) and number is None,
                'Post-join gate must run on the owned main thread without a signal')
    else:
        require(tid!=tgid and tasks==sorted((tgid,tid))
                and (number is None or (type(number) in (int,signal.Signals)
                     and number in (signal.SIGUSR1,signal.SIGUSR2))),
                'Worker gate requires its exact live two-thread owner')

def require_gate_frame(stage,gate,decoded):
    """Bind the observed gate task roster to the actual returned native frame."""
    header=decoded['header'];main=header['main_tid'];worker=header['worker_tid']
    expected=main if stage in (1,2,8) else worker
    require(gate['actual_tgid']==main and gate['actual_tid']==expected
            and set(gate['actual_tasks'])<={main,worker},
            'Private gate TIDs differ from the actual native frame')
    if stage==8:
        require(worker>0 and worker!=main and header['joins']==1,
                'Post-join gate lacks the actual worker and completed join')

def send_worker_signal(tgid,tid,number):
    """Send this private gate control to its exact native working thread."""
    require(type(tgid) is int and type(tid) is int and 0<tgid<1<<31
            and 0<tid<1<<31 and tid!=tgid
            and type(number) in (int,signal.Signals)
            and number in (signal.SIGUSR1,signal.SIGUSR2),
            'Exact private worker/group and cancel/stop signal required')
    libc=ctypes.CDLL(None,use_errno=True)
    call=libc.tgkill
    call.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_int)
    call.restype=ctypes.c_int
    ctypes.set_errno(0)
    result=call(tgid,tid,int(number));error=ctypes.get_errno()
    if result!=0:
        raise OSError(error,'tgkill refused the actual owned working thread')
    return {'syscall':'tgkill','tgid':tgid,'tid':tid,'signal':int(number),'result':result}

def decode(raw: bytes) -> dict:
    require(len(raw)>=2304 and raw[:8]==MAGIC,'Complete Paid/Work frame')
    words=struct.unpack('<64Q',raw[:512]);header=dict(zip(FIELDS,words))
    require(words[1] in (0,1) and words[2]<=6,'Unknown Paid/Work result')
    count=words[5];product_bytes=words[44]
    require(count<=1355 and product_bytes in (0,16384) and words[45]==1024,'Bounded native sections')
    require(len(raw)==2304+count*40+product_bytes,'Complete exact native output')
    require((product_bytes==16384)==(words[2]==0),'Failure published a Work product')
    progress=[list(struct.unpack_from('<5Q',raw,2304+i*40)) for i in range(count)]
    require(all(r[4]==i+1 and 64<=r[0]<=69 for i,r in enumerate(progress)),'Ordered W1 continuations')
    if words[11]:
        require(words[10]>0 and words[11]!=words[10] and words[12:14]==(1,1),'Actual Work birth and join')
    else:
        require(words[13]==0 and count==0,'Unborn Work observations')
    receipts=[list(struct.unpack('<32Q',raw[p:p+256])) for p in (512,768,1024)]
    for receipt in receipts:
        if any(receipt):
            require(receipt[0]==int.from_bytes(b'HIAKR001','little') and receipt[1]==words[1],'Bound Host receipts')
            require(receipt[25:27]==[0,0],'Extra Host observer clocks')
    account=raw[1280:2304];a=struct.unpack('<128Q',account)
    require(account[:8]==b'PWPAY001' and a[1]==1024 and a[2:4]==(words[11],words[13]),'Actual Paid/Work owner binding')
    epoch=list(a[8:28]);owner=list(a[32:96]);binding=list(a[96:106]);meta=list(a[108:116])
    require(a[4]&0xffffffff==0 and a[6]&0xffffffff==0 and a[4]>>32 in (0,1) and a[6]>>32 in (0,1),'No held shared mutex after join')
    require(meta[0]==0 and meta[4]==0 and meta[2]==binding[2] and meta[3]==binding[1] and binding[0]==0,'Actual method fully returned')
    if owner[0]:
        require(owner[0]==int.from_bytes(b'PCOWN001','little') and owner[1]==0 and owner[20]==words[11] and owner[21]==2,'Native private Paid owner identity')
        require(binding[3]==2 and binding[8]==a[116]==1 and binding[9]==words[1],'Paid lifetime/proof/profile retired')
        require(binding[4]<=count+1,'Unexpected independent Paid checkpoint')
    product=raw[2304+count*40:]
    return {'header':header,'progress':progress,'host_before':receipts[0],
        'host_after':receipts[1],'host_worker_final':receipts[2],
        'product_sha256':hashlib.sha256(product).hexdigest() if product else None,
        'challenge_hex':raw[256:288].hex(),'task_hex':raw[288:320].hex(),
        'ticket_hex':raw[320:352].hex(),'product_bytes':product_bytes,
        'paid':{'raw_hex':account.hex(),'epoch':epoch,'owner':owner,'binding':binding,'meta':meta,
        'checkpoint_calls':binding[4],'global_poison':a[4]>>32,'request_poison':a[6]>>32,
        'remaining_public_intake_and_verified_completion_open':True}}

def run_case(image: bytes, request: bytes, directory: Path, *, fixture=True,
             gate_sequence=0, gate_stage=0, actions=(), signal_number=None,
             gate_ack=b'\x01', gate_delay=0, sealed=True, gate_alias=False,
             trace_argv=(), timeout=15, before=()) -> dict:
    require(not directory.exists(),'Fresh physical case output required')
    directory.mkdir(mode=0o700)
    if fixture:
        provision(directory)
        mutate(directory,list(before))
        payload=struct.pack('<8Q',int.from_bytes(b'WOFIX001','little'),gate_sequence,gate_stage,0,0,0,0,0)+request
    else:
        payload=request
    input_fd=os.memfd_create('hia-work-owner-input',os.MFD_ALLOW_SEALING)
    try:
        os.write(input_fd,payload)
        if sealed: fcntl.fcntl(input_fd,1033,15)
        executable=sealed_executable(image,'hia-work-owner-physical')
    except BaseException:
        os.close(input_fd);raise
    execution=fcntl.fcntl(executable,fcntl.F_DUPFD_CLOEXEC,20)
    observer_read,observer_write=os.pipe();gate_read,gate_write=os.pipe()
    writer=fcntl.fcntl(observer_write,fcntl.F_DUPFD_CLOEXEC,30)
    reader=fcntl.fcntl(gate_read,fcntl.F_DUPFD_CLOEXEC,30)
    descriptors={input_fd,executable,execution,observer_read,observer_write,gate_read,gate_write,writer,reader}
    # The private qualification adapter names only FD3/4. High duplicates avoid
    # aliasing either input or the sealed executable during the child remap.
    for fd in (3,4):
        try: os.fstat(fd)
        except OSError:
            null=os.open('/dev/null',os.O_RDONLY)
            if null!=fd: os.dup2(null,fd);os.close(null)
            descriptors.add(fd)
    def fd_map():
        os.dup2(1 if gate_alias else writer,3,inheritable=True)
        os.dup2(reader,4,inheritable=True)
    argv=[*trace_argv,'/proc/self/fd/'+str(execution)]
    start=time.monotonic_ns();before_cpu=resource.getrusage(resource.RUSAGE_CHILDREN)
    row={'schema':'trnm.hia.work-owner-physical-case.v1','status':'FAIL','argv':argv,
         'image_sha256':hashlib.sha256(image).hexdigest(),'fixture':fixture,
         'gate_sequence':gate_sequence,'gate_stage':gate_stage,'signal_number':signal_number,
         'actions':list(actions),'production_authority':False,'actual_original_rust':False}
    process=None;stdout=b'';stderr=b''
    try:
        process=subprocess.Popen(argv,cwd=directory,env={'PATH':''},stdin=input_fd,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            pass_fds=tuple({execution,writer,reader,3,4}),preexec_fn=fd_map,start_new_session=True)
        # Only the child's observer write end remains after this close.
        for fd in (writer,observer_write,reader,gate_read):
            os.close(fd);descriptors.remove(fd)
        if fixture and gate_stage and sealed and not gate_alias:
            gate=bytearray();end=time.monotonic()+timeout
            while len(gate)<32:
                left=end-time.monotonic();require(left>0,'Private gate not reached before timeout')
                ready,_,_=select.select([observer_read],[],[],left)
                require(bool(ready),'Private gate timeout')
                part=os.read(observer_read,32-len(gate));require(bool(part),'Native gate ended early')
                gate.extend(part)
            require(bytes(gate[:8])==b'WGATE001','Actual private gate magic')
            observed=struct.unpack('<4Q',gate)
            require(observed[1:3]==(gate_stage,gate_sequence) and observed[3]>0,'Actual gate identity')
            tid=observed[3];status=Path(f'/proc/{tid}/status').read_text()
            tgid=int(next(x.split()[1] for x in status.splitlines() if x.startswith('Tgid:')))
            task_ids=sorted(int(p.name) for p in Path(f'/proc/{tgid}/task').iterdir())
            pgid=os.getpgid(tgid)
            row['gate']={'raw_hex':bytes(gate).hex(),'actual_tid':tid,'actual_tgid':tgid,
                         'actual_tasks':task_ids,'actual_pgid':pgid,'owned_group_leader':process.pid}
            require_gate_owner(gate_stage,tid,tgid,task_ids,pgid,process.pid,signal_number)
            links={}
            for fd in Path(f'/proc/{tgid}/fd').iterdir():
                try: links[fd.name]=os.readlink(fd)
                except FileNotFoundError: pass
            require(not any(value.startswith(str(directory)) for value in links.values()),
                    'A Host/resource FD leaked across a complete boundary')
            row['gate']['descriptor_links']=links
            mutate(directory,list(actions))
            if signal_number is not None:
                row['gate']['signal_delivery']=send_worker_signal(tgid,tid,signal_number)
            if gate_delay: time.sleep(gate_delay)
            if gate_ack is not None: os.write(gate_write,gate_ack)
            os.close(gate_write);descriptors.remove(gate_write)
        stdout,stderr=process.communicate(timeout=timeout)
        row['exit_code']=process.returncode
        row['stderr_hex']=stderr.hex()
        row['decoded']=decode(stdout)
        if 'gate' in row: require_gate_frame(gate_stage,row['gate'],row['decoded'])
        expected_exit=0 if row['decoded']['header']['domain']==0 else 64+row['decoded']['header']['domain']
        require(process.returncode==expected_exit and not stderr,'Actual exit disagrees with complete native frame')
        row['status']='PHYSICAL_FRAME_PASS_SEMANTIC_EXPECTATIONS_PENDING'
    except BaseException as error:
        row['failure']=repr(error)
        if process is not None:
            if process.poll() is None:
                try: os.killpg(process.pid,signal.SIGKILL);outcome='sent'
                except ProcessLookupError: outcome='already_exited'
                row['cleanup']={'signal':'SIGKILL','result':outcome}
            # Even an already exited child still owns buffered stdout/stderr.
            # Always drain it after a gate/decode failure and retain the original
            # failure; captured output never turns that failed control into PASS.
            stdout,stderr=process.communicate(timeout=5)
            row['capture_after_failure']=True
            if 'cleanup' in row: row['cleanup']['reaped']=process.returncode is not None
            row['exit_code']=process.returncode
    finally:
        end=time.monotonic_ns();after_cpu=resource.getrusage(resource.RUSAGE_CHILDREN)
        row['wall_ns']=end-start
        row['aggregate_child_cpu_ns']=int((after_cpu.ru_utime+after_cpu.ru_stime-before_cpu.ru_utime-before_cpu.ru_stime)*1e9)
        for fd in descriptors: os.close(fd)
        for name,raw in [('stdin.raw',payload),('stdout.raw',stdout),('stderr.raw',stderr)]:
            (directory/name).write_bytes(raw)
        row['stdout']=identity(directory/'stdout.raw');row['stderr']=identity(directory/'stderr.raw')
        (directory/'physical.json').write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
    return row
