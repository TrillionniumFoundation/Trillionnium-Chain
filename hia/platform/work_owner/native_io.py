"""Qualification driver for the actual static native Work/Host owner.

This process supplies only untrusted proof bytes and private fixture files.
Every authority syscall and arithmetic transition executes in the native ELF.
"""
from __future__ import annotations
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

MAGIC=b'HIAWO001'
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

def decode(raw: bytes) -> dict:
    require(len(raw)>=1280 and raw[:8]==MAGIC,'Complete native owner frame magic/length')
    words=struct.unpack('<64Q',raw[:512]);header=dict(zip(FIELDS,words))
    require(words[1] in (0,1) and words[2]<=5,'Unknown native owner profile/result')
    count=words[5];product_bytes=words[44]
    require(count<=1355 and product_bytes in (0,16384),'Owner output bounded lengths')
    require(len(raw)==1280+count*40+product_bytes,'Owner output has missing or trailing bytes')
    require((product_bytes==16384)==(words[2]==0),'Failure emitted a qualified product')
    progress=[list(struct.unpack_from('<5Q',raw,1280+i*40)) for i in range(count)]
    require(all(row[4]==i+1 and 64<=row[0]<=69 for i,row in enumerate(progress)),
            'Progress sequence/kind discontinuity')
    if words[11]:
        require(words[10]>0 and words[11]!=words[10] and words[12:14]==(1,1),
                'Actual worker lifetime/join identity differs')
    else:
        require(words[13]==0 and count==0,'Unborn worker produced progress or join')
    receipts=[list(struct.unpack('<32Q',raw[p:p+256])) for p in (512,768,1024)]
    for receipt in receipts:
        if any(receipt):
            require(receipt[0]==int.from_bytes(b'HIAKR001','little') and receipt[1]==words[1],
                    'Unbound native Host/resource receipt')
            require(receipt[25:27]==[0,0],'Standalone Host observation clocks unexpectedly survived embedding')
    product=raw[1280+count*40:]
    return {'header':header,'progress':progress,'host_before':receipts[0],
        'host_after':receipts[1],'host_worker_final':receipts[2],
        'product_sha256':hashlib.sha256(product).hexdigest() if product else None,
        'challenge_hex':raw[256:288].hex(),'task_hex':raw[288:320].hex(),
        'ticket_hex':raw[320:352].hex(),'product_bytes':product_bytes}

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
            links={}
            for fd in Path(f'/proc/{tgid}/fd').iterdir():
                try: links[fd.name]=os.readlink(fd)
                except FileNotFoundError: pass
            require(not any(value.startswith(str(directory)) for value in links.values()),
                    'A Host/resource FD leaked across a complete boundary')
            row['gate']={'raw_hex':bytes(gate).hex(),'actual_tid':tid,'actual_tgid':tgid,
                         'actual_tasks':task_ids,'descriptor_links':links}
            mutate(directory,list(actions))
            if signal_number is not None: os.kill(tid,signal_number)
            if gate_delay: time.sleep(gate_delay)
            if gate_ack is not None: os.write(gate_write,gate_ack)
            os.close(gate_write);descriptors.remove(gate_write)
        stdout,stderr=process.communicate(timeout=timeout)
        row['exit_code']=process.returncode
        row['stderr_hex']=stderr.hex()
        row['decoded']=decode(stdout)
        expected_exit=0 if row['decoded']['header']['domain']==0 else 64+row['decoded']['header']['domain']
        require(process.returncode==expected_exit and not stderr,'Actual exit disagrees with complete native frame')
        row['status']='PHYSICAL_FRAME_PASS_SEMANTIC_EXPECTATIONS_PENDING'
    except BaseException as error:
        row['failure']=repr(error)
        if process is not None and process.poll() is None:
            try: os.killpg(process.pid,signal.SIGKILL);outcome='sent'
            except ProcessLookupError: outcome='already_exited'
            stdout,stderr=process.communicate(timeout=5)
            row['cleanup']={'signal':'SIGKILL','result':outcome,'reaped':process.returncode is not None}
        if process is not None:
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
