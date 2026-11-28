"""Actual namespace, descriptor, and complete-record refusal controls."""
from __future__ import annotations
import fcntl,json,os,resource,signal,socket,stat,struct,subprocess,time
from pathlib import Path
from .build import need,identity
from .native_io import request,bootstrap,snapshot

def stdio_controls(suite):
    variants=("stdout-state-file","stderr-state-file","stdin-state-file","stdout-stderr-same-pipe",
      "stdin-stdout-same-pipe","stdout-rdwr-fifo","stderr-opath-fifo",
      "stdin-write-pipe","stdout-read-pipe","stderr-read-pipe","closed-stdin","closed-stdout","closed-stderr")
    image=os.memfd_create("native-genesis-stdio-control",os.MFD_ALLOW_SEALING)
    cursor=0
    while cursor<len(suite.executable):
        count=os.write(image,suite.executable[cursor:]);need(count>0,"Executable short write");cursor+=count
    need(os.pread(image,len(suite.executable),0)==suite.executable,"Executable readback differs")
    os.fchmod(image,0o500);fcntl.fcntl(image,1033,15)
    try:
        for variant in variants:
            label="stdio-"+variant
            directory=suite.fixture(label,raw=suite.record)
            before=snapshot(directory);fds=[];queued=None;queued_reader=None;offset_fd=None
            directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);fds.append(directory_fd)
            standard={"stdin":subprocess.PIPE,"stdout":subprocess.PIPE,"stderr":subprocess.PIPE}
            target=directory/suite.final_name;target_before=target.read_bytes()
            if variant.endswith("state-file"):
                role=variant.split("-")[0]
                change=os.open(target,(os.O_RDONLY if role=="stdin" else os.O_WRONLY)|os.O_CLOEXEC)
                fds.append(change);standard[role]=change;offset_fd=change
            elif variant=="stdout-stderr-same-pipe":
                standard["stderr"]=subprocess.STDOUT
            elif variant=="stdin-stdout-same-pipe":
                reader,writer=os.pipe();fds.extend((reader,writer))
                standard["stdin"]=reader;standard["stdout"]=writer;queued_reader=reader
            elif variant.endswith("fifo"):
                fifo=suite.output/(label+"-fifo");os.mkfifo(fifo,0o600)
                change=os.open(fifo,(os.O_RDWR|os.O_NONBLOCK) if variant.startswith("stdout") else os.O_PATH)
                fds.append(change);standard["stdout" if variant.startswith("stdout") else "stderr"]=change
            elif variant.endswith("pipe"):
                reader,writer=os.pipe();fds.extend((reader,writer))
                role=variant.split("-")[0];standard[role]=writer if role=="stdin" else reader
            payload=bootstrap(directory_fd,1)+request(2)
            if queued_reader is not None:
                os.write(standard["stdout"],payload);queued=payload
            def restrictions(selected=variant):
                resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
                if selected.startswith("closed-"):
                    os.close({"stdin":0,"stdout":1,"stderr":2}[selected.split("-")[1]])
            suite.counter+=1
            output=suite.output/("process-%04d-"%suite.counter+label);output.mkdir(mode=0o700)
            started=time.monotonic_ns()
            process=subprocess.Popen(["/proc/self/fd/"+str(image)],**standard,
                pass_fds=(image,directory_fd),env={"PATH":""},cwd=output,start_new_session=True,
                umask=0o077,preexec_fn=restrictions)
            try:
                stdout,stderr=process.communicate(payload if standard["stdin"]==subprocess.PIPE else None,timeout=240)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);stdout,stderr=process.communicate(timeout=3)
                (output/"stdout.raw").write_bytes(stdout or b"");(output/"stderr.raw").write_bytes(stderr or b"")
                raise ValueError(label+": actual process timed out")
            try:
                stdout=stdout or b"";stderr=stderr or b""
                (output/"stdin-offered.raw").write_bytes(payload)
                (output/"stdout.raw").write_bytes(stdout);(output/"stderr.raw").write_bytes(stderr)
                need(process.returncode==64 and not stdout and not stderr,label+": stdio was not silently refused")
                need(target.read_bytes()==target_before and snapshot(directory)==before,label+": unsafe descriptor wrote state")
                if offset_fd is not None:need(os.lseek(offset_fd,0,os.SEEK_CUR)==0,label+": unadmitted stream was consumed")
                if queued_reader is not None:
                    os.set_blocking(queued_reader,False)
                    actual=os.read(queued_reader,len(payload)+1)
                    need(actual==queued,label+": shared standard pipe was read or written")
                row={"executable":identity(suite.executable),"exit_code":process.returncode,
                    "elapsed_ns":time.monotonic_ns()-started,"stdout":identity(stdout),"stderr":identity(stderr),
                    "native_child_budget_seconds":240,"target_state":identity(target_before),
                    "namespace_unchanged":True,"standard_streams_silently_rejected":True,
                    "queued_shared_pipe_preserved":queued is not None,"path":str(output)}
                (output/"process.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
                suite.add(label,process=row)
            finally:
                for fd in fds:os.close(fd)
    finally:os.close(image)

def wire_controls(suite):
    def changed(index,value):
        def change(raw,pair,fd):
            out=bytearray(raw);struct.pack_into("<Q",out,index,value);return bytes(out)
        return change
    variants=[("bootstrap-truncated-"+str(n),lambda raw,pair,fd,n=n:raw[:n]) for n in (0,1,7,8,15,16,63)]
    variants.extend((
      ("bootstrap-magic",lambda raw,pair,fd:b"BADBOOT!"+raw[8:]),
      ("bootstrap-mode-3",changed(16,3)),("bootstrap-option-2",changed(24,2)),
      ("bootstrap-none-with-time",changed(32,1)),("bootstrap-fd-0",changed(8,0)),
      ("bootstrap-fd-u64max",changed(8,(1<<64)-1)),
      ("bootstrap-half-disabled-gate",changed(48,3)),
    ))
    for label,mutation in variants:
        directory=suite.fixture(label,lock=False)
        suite.refuse(label,directory,mode=0,expected=64,commands=(),boot_override=mutation)
    for label,operation in (("no-arbitrary-COMMIT-operation",3),("unknown-request-u64max",(1<<64)-1)):
        directory=suite.fixture(label,raw=suite.record)
        suite.refuse(label,directory,expected=64,stdout_bytes=256,commands=(operation,))
    for label,raw in (("request-truncated",request(1)[:8]),("request-wrong-magic",b"INVALID!"+struct.pack("<Q",1))):
        directory=suite.fixture(label,raw=suite.record);before=snapshot(directory)
        session=suite.process(label,directory,mode=1)
        try:
            session.send(raw);process,stdout=session.finish()
            need(process["exit_code"]==64 and len(stdout)==256 and not process["timed_out"],label+": invalid request accepted")
            need(snapshot(directory)==before,label+": invalid request changed namespace")
            suite.add(label,process=process,namespace_unchanged=True)
        finally:suite.cleanup(session)

def gate_capabilities(suite):
    for variant in ("write-regular","read-regular","write-read-end","read-write-end","same-pipe",
                    "write-alias-stdout","write-alias-stderr","read-alias-stdin","write-opath","read-opath"):
        label="gate-"+variant;directory=suite.fixture(label,lock=False);before=snapshot(directory)
        event_r,event_w=os.pipe();resume_r,resume_w=os.pipe();fds=[event_r,event_w,resume_r,resume_w]
        # A wrong implementation must not block forever on an accidentally accepted read capability.
        os.write(resume_w,b"\0")
        gw,gr=event_w,resume_r;before_exec=None
        target=suite.output/(label+"-target");target.write_bytes(b"UNMODIFIED");target.chmod(0o600)
        if variant=="write-regular":
            gw=os.open(target,os.O_WRONLY|os.O_CLOEXEC);fds.append(gw)
        elif variant=="read-regular":
            gr=os.open(target,os.O_RDONLY|os.O_CLOEXEC);fds.append(gr)
        elif variant=="write-read-end":gw=event_r
        elif variant=="read-write-end":gr=resume_w
        elif variant=="same-pipe":gr=event_r
        elif variant.startswith("write-alias"):
            source=1 if variant.endswith("stdout") else 2
            def before_exec(directory_fd,inherited,source=source,target=gw):
                os.dup2(source,target,inheritable=True)
        elif variant=="read-alias-stdin":
            def before_exec(directory_fd,inherited,target=gr):
                os.dup2(0,target,inheritable=True)
        elif variant.endswith("opath"):
            fifo=suite.output/(label+"-fifo");os.mkfifo(fifo,0o600)
            path_fd=os.open(fifo,os.O_PATH);fds.append(path_fd)
            if variant.startswith("write"):gw=path_fd
            else:gr=path_fd
        def change(raw,pair,fd,write_fd=gw,read_fd=gr):
            return raw[:48]+struct.pack("<2Q",write_fd,read_fd)
        session=suite.process(label,directory,boot_override=change,extra_pass_fds=tuple(fds),before_exec=before_exec)
        try:
            session.send(request(2));process,stdout=session.finish()
            need(process["exit_code"]==65 and not process["timed_out"] and stdout==b"",label+": invalid actual gate was admitted")
            need(process["events"]==[] and target.read_bytes()==b"UNMODIFIED" and snapshot(directory)==before,
                 label+": invalid gate wrote before admission")
            os.set_blocking(event_r,False);os.set_blocking(resume_r,False)
            try:event_bytes=os.read(event_r,4096)
            except BlockingIOError:event_bytes=b""
            try:resume_bytes=os.read(resume_r,4096)
            except BlockingIOError:resume_bytes=b""
            need(event_bytes==b"" and resume_bytes==b"\0",label+": gate bytes written or consumed before admission")
            suite.add(label,process=process,namespace_unchanged=True,gate_bytes_unchanged=True,
                target_file=identity(target.read_bytes()),actual_object_type_access_alias_controls=True)
        finally:
            suite.cleanup(session)
            for fd in fds:os.close(fd)

def namespace_entries(suite):
    foreign=("HEAD","FORMAT","txn","node.sqlite3","ng1."+"0"*64+".state",chr(0x3bb)+":foreign")
    for context in ("fresh","cold"):
        for index,name in enumerate(foreign):
            label=context+"-foreign-name-"+str(index)
            directory=suite.fixture(label,raw=suite.record if context=="cold" else None,lock=context=="cold")
            path=directory/name;path.write_bytes(b"UNTOUCHED");path.chmod(0o600)
            suite.refuse(label,directory,mode=1 if context=="cold" else 0)
    shapes=(
      ("open-lock-only",1,True,None,False,False),
      ("recover-lock-only",2,True,None,True,False),
      ("open-missing-lock",1,False,"complete",False,False),
      ("recover-missing-lock",2,False,"prefix",True,False),
      ("recover-final",2,True,"complete",False,False),
      ("fresh-final",0,True,"complete",False,False),
      ("fresh-pending",0,True,"prefix",True,False),
      ("open-pending",1,True,"prefix",True,False),
      ("ambiguous-pending-and-final",2,True,"prefix",True,True),
    )
    for label,mode,lock,kind,pending,both in shapes:
        raw=None if kind is None else suite.record if kind=="complete" else suite.record[:16]
        directory=suite.fixture(label,pending=pending,raw=raw,lock=lock)
        if both:
            (directory/suite.final_name).write_bytes(suite.record);(directory/suite.final_name).chmod(0o600)
        suite.refuse(label,directory,mode=mode)
    for which in ("lock","state","pending"):
        for kind in ("symlink","fifo","fifo-no-writer","directory","socket","hardlink","permissions"):
            label=which+"-"+kind;pending=which=="pending";mode=2 if pending else 1
            directory=suite.fixture(label,pending=pending,raw=suite.record[:512] if pending else suite.record)
            path=directory/("ng1.owner.lock" if which=="lock" else suite.pending_name if pending else suite.final_name)
            keeper=None;server=None;outside=None
            expected=path.read_bytes()
            if kind=="hardlink":
                outside=suite.output/(label+"-outside");os.link(path,outside)
            elif kind=="permissions":
                path.chmod(0o644)
            else:
                path.unlink()
                if kind=="symlink":
                    outside=suite.output/(label+"-outside");outside.write_bytes(expected);outside.chmod(0o600);path.symlink_to(outside)
                elif kind.startswith("fifo"):
                    os.mkfifo(path,0o600)
                    if kind=="fifo":
                        keeper=os.open(path,os.O_RDWR|os.O_NONBLOCK);os.write(keeper,b"KEEP-FIFO-BYTES")
                elif kind=="directory":path.mkdir(mode=0o700)
                else:
                    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    previous=Path.cwd()
                    try:
                        os.chdir(directory);server.bind(path.name)
                    finally:os.chdir(previous)
            try:
                suite.refuse(label,directory,mode=mode)
                if outside is not None:need(outside.read_bytes()==expected,label+": outside alias changed")
                if keeper is not None:need(os.read(keeper,64)==b"KEEP-FIFO-BYTES",label+": special-file bytes consumed")
            finally:
                if keeper is not None:os.close(keeper)
                if server is not None:server.close()
    for mode in (0o755,0o770):
        label="directory-mode-"+oct(mode);directory=suite.fixture(label,raw=suite.record);directory.chmod(mode)
        suite.refuse(label,directory)
    directory=suite.fixture("non-directory-capability",lock=False)
    target=suite.output/"not-a-directory";target.write_bytes(b"UNMODIFIED");target.chmod(0o600)
    fd=os.open(target,os.O_RDONLY|os.O_CLOEXEC)
    try:
        suite.refuse("non-directory-capability",directory,mode=0,fd_override=fd)
        need(target.read_bytes()==b"UNMODIFIED","Non-directory capability changed")
    finally:os.close(fd)

def corruption_cases(suite):
    positions={0,8,16,24,32,63,64,95,96,127,128,159,160,191,192,200,208,216,224,232,240,303,
      304,312,320,328,336,344,352,360,368,376,384,392,400,408,416,424,432,440,511}
    state_at=struct.unpack_from("<Q",suite.record,416)[0]
    positions.update((512,516,520,528,536,576,696,1088,state_at,state_at+4,state_at+8,len(suite.record)-1))
    for position in sorted(positions):
        label="complete-record-bitflip-"+str(position);raw=bytearray(suite.record);raw[position]^=1
        directory=suite.fixture(label,raw=bytes(raw))
        suite.refuse(label,directory,expected=66)
    for size in (0,1,511,512,len(suite.record)-1,len(suite.record)+1):
        label="record-size-"+str(size)
        raw=suite.record[:size] if size<=len(suite.record) else suite.record+b"x"
        directory=suite.fixture(label,raw=raw)
        suite.refuse(label,directory,expected=65)
    for size in (16,512,2048,len(suite.record)):
        label="bad-existing-prefix-"+str(size);raw=bytearray(suite.record[:size]);raw[-1]^=1
        directory=suite.fixture(label,pending=True,raw=bytes(raw))
        suite.refuse(label,directory,mode=2,expected=66)
    directory=suite.fixture("pending-over-complete-extent",pending=True,raw=suite.record+b"x")
    suite.refuse("pending-over-complete-extent",directory,mode=2,expected=65)
    directory=suite.fixture("wrong-default-context",raw=suite.record)
    suite.refuse("wrong-default-context",directory,mode=1,timestamp=1,expected=65)

def qualify(suite,group):
    suite.baseline()
    if group=="corruption":
        corruption_cases(suite)
    elif group=="namespace":
        stdio_controls(suite);wire_controls(suite);gate_capabilities(suite);namespace_entries(suite)
        from .interleaving_cases import qualify as interleavings,descriptor_lifetime
        interleavings(suite);descriptor_lifetime(suite)
    else:raise ValueError("Unknown namespace group")
    return {"group":group,"real_file_type_permission_link_controls":group=="namespace",
      "same_uid_wrong_uid_injection_claimed":False,"unknown_schema_recovered":False,
      "outside_finite_profile_refusals_are_original_Node_equivalence":False,
      "continuous_hostile_same_uid_safety":False,"failed_reads_return_partial_State":False}
