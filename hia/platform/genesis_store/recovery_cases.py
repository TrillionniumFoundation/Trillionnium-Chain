"""Real interruption, exact-prefix recovery, and native fsync boundaries."""
from __future__ import annotations
import ctypes,json,os,signal,stat,struct
from pathlib import Path
from .build import need
from . import native_io as module
from .native_io import request,snapshot,parse_success
def descriptor_allocation(directory_fd,inherited):
    live={0,1,2,*inherited}
    def free():
        value=3
        while value in live:value+=1
        live.add(value);return value
    retained_directory=free();live.remove(directory_fd);retained_lock=free();retained_file=free()
    return {"directory":retained_directory,"lock":retained_lock,"file":retained_file}
def install_fsync_eio(fd):
    class Insn(ctypes.Structure):
        _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[("length",ctypes.c_ushort),("instructions",ctypes.POINTER(Insn))]
    instructions=(Insn*9)(Insn(0x20,0,0,4),Insn(0x15,1,0,0xc000003e),Insn(0x06,0,0,0x80000000),
        Insn(0x20,0,0,0),Insn(0x15,0,3,74),Insn(0x20,0,0,16),Insn(0x15,0,1,fd),
        Insn(0x06,0,0,0x00050005),Insn(0x06,0,0,0x7fff0000))
    program=Program(len(instructions),instructions)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),"PR_SET_NO_NEW_PRIVS")
    if libc.prctl(22,2,ctypes.byref(program),0,0)!=0:raise OSError(ctypes.get_errno(),"SECCOMP_MODE_FILTER")
def assert_settled_trace(trace_path,directory,final_name):
    raw=trace_path.read_bytes();lines=raw.decode("utf-8").splitlines()
    opened=[i for i,line in enumerate(lines) if 'write(1<' in line and '"NGOPEN01' in line]
    syncs=[(i,line) for i,line in enumerate(lines) if "fsync(" in line]
    need(len(opened)==1 and len(syncs)==2,"Actual cold trace must contain exactly two syncs and one opened write")
    need(syncs[0][0]<syncs[1][0]<opened[0],"Actual fsync/opened syscall order differs")
    need(str(directory/final_name) in syncs[0][1] and syncs[0][1].rstrip().endswith("= 0"),"First fsync is not successful retained final")
    need("<"+str(directory)+">" in syncs[1][1] and syncs[1][1].rstrip().endswith("= 0"),"Second fsync is not successful retained directory")
    need(not any("renameat2(" in line for line in lines),"Cold open renamed state")
    return {"raw":module.identity(raw),"fsync_lines":[line for _,line in syncs],"opened_line":lines[opened[0]],
        "actual_syscall_order":"final-file fsync -> directory fsync -> opened","raw_path":str(trace_path)}

def recover_and_cold(suite,label,directory,mode):
    repaired,observed,record=suite.success(label+"-recover",directory,mode=mode)
    need(record==suite.record,label+": recovered complete State/catalog differs")
    before=snapshot(directory)
    cold,again,reread=suite.success(label+"-fresh-cold",directory,mode=1)
    need(reread==record and snapshot(directory)==before,label+": cold State or inode metadata changed")
    return {"recovered":repaired,"fresh_process_full_cold":cold,"record":module.identity(record),
        "full_record_equal":True,"cold_namespace_unchanged":True}

def crash_cases(suite):
    for method in ("SIGKILL","gate-EOF"):
        for tag in (1,10,11,12,13,14,15,20):
            label=method+"-tag-"+str(tag)
            if tag==12:
                directory=suite.fixture(label,pending=True,raw=suite.record[:2048]);mode=2
            else:
                directory=suite.fixture(label,lock=False);mode=0
            process=suite.process(label,directory,mode=mode,gate=True)
            try:
                event=process.advance(tag)
                if method=="SIGKILL":process.kill()
                else:process.gate_eof()
                stopped,stdout=process.finish()
                need(not stopped["timed_out"] and stdout==b"",label+": stop acknowledged or timed out")
                expected=-signal.SIGKILL if method=="SIGKILL" else (71 if tag==14 else 70)
                need(stopped["exit_code"]==expected,label+": incorrect stop result")
                after_stop=snapshot(directory)
                if tag==1:
                    need(set(after_stop)=={"ng1.owner.lock"},label+": unbound cut wrote state")
                    suite.refuse(label+"-no-unbound-recovery",directory,mode=2,expected=65)
                    repair_mode=0
                elif (directory/suite.pending_name).exists():
                    repair_mode=2
                else:
                    need((directory/suite.final_name).exists(),label+": no admissible physical outcome")
                    repair_mode=1
                repaired=recover_and_cold(suite,label,directory,repair_mode)
                suite.add(label,actual_stop=stopped,cut=event,after_stop=after_stop,repair_mode=repair_mode,
                    **repaired,physical_power_loss=False,os_page_cache_flushed=False)
            finally:
                suite.cleanup(process)
    for tag in (13,14):
        label="malformed-gate-resume-"+str(tag)
        directory=suite.fixture(label,lock=False)
        process=suite.process(label,directory,gate=True)
        try:
            event=process.advance(tag);process.resume(b"\0");stopped,stdout=process.finish()
            need(stopped["exit_code"]==(71 if tag==14 else 64) and stdout==b"" and not stopped["timed_out"],
                 label+": malformed resume lost publication boundary")
            repaired=recover_and_cold(suite,label,directory,1 if tag==14 else 2)
            suite.add(label,actual_stop=stopped,cut=event,**repaired)
        finally:suite.cleanup(process)
    directory=suite.fixture("opened-response-EPIPE",lock=False)
    stopped,stdout=suite.run("opened-response-EPIPE",directory,commands=(2,),stdout_closed=True)
    need(stopped["exit_code"]==70 and stopped["diagnostic"][2]==(1<<64)-32 and
         stopped["diagnostic"][3:5]==[0,1] and stdout==b"","Real post-durable response EPIPE classification")
    repaired=recover_and_cold(suite,"opened-response-EPIPE",directory,1)
    suite.add("opened-response-EPIPE",actual_response_failure=stopped,**repaired,
        durable_state_not_rolled_back=True)
    # An independent actual kill after rename gives the source for the traced cold settlement.
    directory=suite.fixture("traced-settlement-after-kill",lock=False)
    process=suite.process("traced-settlement-kill",directory,gate=True)
    try:
        process.advance(14);process.kill();killed,stdout=process.finish()
        need(killed["exit_code"]==-signal.SIGKILL and stdout==b"","Actual trace predecessor kill failed")
    finally:suite.cleanup(process)
    before=snapshot(directory);trace=suite.output/"settled-cold-syscalls.raw"
    process=suite.process("traced-settlement-cold",directory,mode=1,trace_path=trace)
    try:
        process.send(request(1)+request(2));settled,stdout=process.finish()
        need(settled["exit_code"]==0 and settled["stderr"]["bytes"]==0 and not settled["timed_out"],
             "Actual syscall trace did not establish a successful cold owner")
        _,record=parse_success(stdout)
        need(record==suite.record and snapshot(directory)==before,"Traced cold settlement changed stored bytes")
        traced=assert_settled_trace(trace,directory,suite.final_name)
        suite.add("actual-cold-file-fsync-directory-fsync-opened-order",predecessor=killed,
            process=settled,trace=traced,namespace_unchanged=True)
    finally:suite.cleanup(process)
    for kind,phase in (("file",67),("directory",68)):
        label="cold-"+kind+"-fsync-kernel-injected-EIO"
        def denial(directory_fd,inherited,selected=kind):
            install_fsync_eio(descriptor_allocation(directory_fd,inherited)[selected])
        before=snapshot(directory)
        process=suite.process(label,directory,mode=1,gate=True,before_exec=denial)
        process.send(request(2))
        try:
            event=process.advance(20)
            target=descriptor_allocation(process.transport["directory_fd"],process.transport["inherited_fds"])[kind]
            actual=(Path("/proc")/str(process.process.pid)/"fd"/str(target)).stat()
            expected=(directory/suite.final_name if kind=="file" else directory).stat()
            need((actual.st_dev,actual.st_ino,stat.S_IFMT(actual.st_mode))==
                 (expected.st_dev,expected.st_ino,stat.S_IFMT(expected.st_mode)),
                 "Kernel error filter does not target actual retained descriptor")
            fdinfo=(Path("/proc")/str(process.process.pid)/"fdinfo"/str(target)).read_bytes()
            (process.output/"target-fdinfo.raw").write_bytes(fdinfo)
            process.resume();failed,stdout=process.finish()
            need(failed["exit_code"]==71 and stdout==b"" and not failed["timed_out"],
                 "Failed cold synchronization returned an opened receipt")
            need(failed["diagnostic"][:5]==[71,phase,(1<<64)-5,1,1],"Native errno/phase/uncertainty mismatch")
            need(snapshot(directory)==before,"Cold sync error changed stored bytes or captured inode metadata")
            suite.add(label,process=failed,cut=event,target_fd=target,
                target_device_inode=[actual.st_dev,actual.st_ino],fdinfo=module.identity(fdinfo),
                namespace_unchanged=True,fault_origin="seccomp RET_ERRNO EIO on verified retained descriptor",
                physical_storage_device_failure=False)
        finally:suite.cleanup(process)

def prefix_cases(suite):
    at=struct.unpack_from("<Q",suite.record,416)[0]
    sizes=sorted({0,1,7,8,15,16,31,32,63,64,95,96,127,128,511,512,513,
        at-1,at,at+1,4095,4096,4097,len(suite.record)-2,len(suite.record)-1,len(suite.record)})
    need(all(0<=n<=len(suite.record) for n in sizes),"Selected prefix extent")
    for size in sizes:
        label="exact-prefix-"+str(size)
        directory=suite.fixture(label,pending=True,raw=suite.record[:size])
        prior=snapshot(directory)
        repaired=recover_and_cold(suite,label,directory,2)
        suite.add(label,prefix_bytes=size,before=prior,**repaired)
    for limit in (16,4096):
        label="real-RLIMIT_FSIZE-"+str(limit)
        directory=suite.fixture(label,lock=False)
        failed,stdout=suite.run(label,directory,commands=(2,),file_limit=limit)
        need(failed["exit_code"]==70 and failed["diagnostic"][2]==(1<<64)-27
             and failed["diagnostic"][3]==0 and stdout==b"" and not failed["timed_out"],
             "Actual kernel EFBIG did not stop initialization")
        pending=directory/suite.pending_name
        need(pending.is_file() and pending.read_bytes()==suite.record[:limit]
             and not (directory/suite.final_name).exists(),"EFBIG did not leave the exact actual written prefix")
        stopped=snapshot(directory)
        repaired=recover_and_cold(suite,label,directory,2)
        suite.add(label,actual_write_failure=failed,after_partial_write=stopped,
            actual_kernel_errno="EFBIG",**repaired)

def qualify(suite,group):
    suite.baseline()
    if group=="crash":crash_cases(suite)
    elif group=="prefix":prefix_cases(suite)
    else:raise ValueError("Unknown recovery group")
    return {"group":group,"physical_files":True,"fresh_process_full_cold_reads":True,
        "diagnostic_gate_is_request_cancellation":False,"late_cancel_after_commit_added":False,
        "actual_SIGKILL":group=="crash","actual_EFBIG":group=="prefix",
        "kernel_injected_fsync_errors":group=="crash","hardware_power_loss_test":False}
