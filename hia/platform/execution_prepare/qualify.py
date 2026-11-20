"""Execute the real native preparation owner and retain complete physical evidence."""
from __future__ import annotations
import argparse,hashlib,json,lzma,os,shutil,struct,subprocess,time,traceback
from pathlib import Path
from .build import Build,ROOT
from .native_io import Session,frame,magic,words,need,identity
from .rust_oracle import (bound_corpus,complete_source_manifest,case_projection,validate_bundle,
                         COMP_SCHEMA,NATIVE_SCHEMA)

def save(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n")

def semantic(executable,output,build,sessions):
    corpus,inputs=bound_corpus(ROOT)
    session=Session.__new__(Session);sessions.append(session)
    Session.__init__(session,executable,output/"process")
    context=session.open();rows=[]
    for request in inputs:
        raw=bytes.fromhex(request["wire_hex"])
        result=session.prepare(raw,request["height"])
        value=session.value(result) if result["code"]==0 else None
        if value is not None:need(value["wire_hex"]==raw.hex(),"Private preparation retained another wire")
        rows.append({"name":request["name"],"result":result,"value":value,
                     "observation":case_projection(request["name"],result,value)})
    session.close()
    session.cleanup()
    process=session.snapshot()
    need(process["exit_code"]==0 and process["cleanup_errors"]==[] and not session.stderr,"Semantic process did not close")
    need(sum(r["result"]["code"]==0 for r in rows)>20,"No complete successful preparation coverage")
    bundle=output/"bundle";bundle.mkdir(mode=0o700);(bundle/"raw").mkdir(mode=0o700)
    for path in (output/"process").iterdir():
        if path.suffix in {".raw",".json"}:shutil.copyfile(path,bundle/"raw"/path.name)
    shutil.copyfile(executable,bundle/"native.elf")
    compressed=lzma.compress(corpus,preset=6)
    (bundle/"corpus.jsonl.xz").write_bytes(compressed)
    comparison={"schema":COMP_SCHEMA,"status":"PASS","build":build,"context":context,"cases":rows,
                "process":identity((bundle/"raw/process.json").read_bytes())}
    comparison_raw=json.dumps(comparison,sort_keys=True,indent=2,allow_nan=False).encode()+b"\n"
    (bundle/"native-comparison.json").write_bytes(comparison_raw)
    return {"native_cases":len(rows),"native_processes":1,"comparison":identity(comparison_raw),
      "process":comparison["process"],"corpus":{"raw":identity(corpus),"compressed":identity(compressed)},
      "semantic_histogram":{str(code):sum(r["result"]["code"]==code for r in rows) for code in range(10)},
      "bundle":str(bundle)}

def raw_control(executable,directory,name,input_bytes,*,stdin_override=None,stdout_override=None,
                stderr_override=None,passed=(),expected=0):
    path=directory/name;path.mkdir(mode=0o700)
    started=time.monotonic_ns();child=None;stdout=b"";stderr=b"";primary=None;cleanup=[]
    try:
        child=subprocess.Popen([str(executable)],
          stdin=subprocess.PIPE if stdin_override is None else stdin_override,
          stdout=subprocess.PIPE if stdout_override is None else stdout_override,
          stderr=subprocess.PIPE if stderr_override is None else stderr_override,
          pass_fds=tuple(passed),close_fds=True)
        try:
            out,err=child.communicate(input_bytes if stdin_override is None else None,timeout=240)
            stdout=out or b"";stderr=err or b""
        except BaseException as error:
            primary=repr(error);child.kill()
            try:
                out,err=child.communicate(timeout=3);stdout=out or b"";stderr=err or b""
            except BaseException as error:cleanup.append(repr(error))
        need(primary is None and not cleanup and child.returncode==expected,"Unexpected raw control result: "+name)
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try:child.wait(timeout=3)
            except BaseException as error:cleanup.append(repr(error))
        for stream in (getattr(child,"stdin",None),getattr(child,"stdout",None),getattr(child,"stderr",None)):
            if stream is not None:stream.close()
        report={"name":name,"expected_exit":expected,"actual_exit":child.returncode if child else None,
          "requested_input":identity(input_bytes),"actual_stdin_write_extent":"NOT_OBSERVED_BY_COMMUNICATE",
          "stdout":identity(stdout),"stderr":identity(stderr),"wall_ns":time.monotonic_ns()-started,
          "primary_error":primary,"cleanup_errors":cleanup}
        if len(stderr)==56:report["diagnostic"]=list(words(stderr))
        (path/"requested-stdin.raw").write_bytes(input_bytes);(path/"stdout.raw").write_bytes(stdout);(path/"stderr.raw").write_bytes(stderr)
        save(path/"process.json",report)
    return report,stdout,stderr

def physical(executable,output,build,sessions):
    from .cases import wire
    folder=output/"controls";folder.mkdir(mode=0o700)
    boot=struct.pack("<8Q",magic(b"MPBOOT01"),0,(1<<64)-1,(1<<64)-1,0,0,0,0)
    good=wire(1,bytes(40),expiry=10);bad=good[:-1]+bytes([good[-1]^1])
    prepare=frame(1,1,height=10,body_len=len(good))+good
    rows=[]
    def raw(name,body,code,**options):
        receipt,stdout,stderr=raw_control(executable,folder,name,body,expected=code,**options)
        need(receipt["primary_error"] is None and receipt["cleanup_errors"]==[],"Raw process evidence failed")
        rows.append({"name":name,"process":receipt})
        return receipt,stdout,stderr
    # Real pipe EOFs and malformed frames cannot become semantic output.
    for length in (0,1,7,8,63):
        _,stdout,_=raw("boot-eof-"+str(length),boot[:length],70)
        need(stdout==b"","Partial BOOT emitted context")
    changed=bytearray(boot);changed[0]^=1
    _,stdout,_=raw("boot-magic",bytes(changed),64);need(stdout==b"","Bad BOOT output")
    changed=bytearray(boot);changed[40]=1
    _,stdout,_=raw("boot-reserved",bytes(changed),64);need(stdout==b"","Reserved BOOT output")
    for length in (0,1,63):
        raw("request-eof-"+str(length),boot+frame(1,1,height=10,body_len=len(good))[:length],70)
    for length in (0,1,len(good)-1):
        receipt,stdout,_=raw("body-eof-"+str(length),boot+frame(1,1,height=10,body_len=len(good))+good[:length],70)
        need(b"MPRESULT" not in stdout,"Partial wire produced a result")
    raw("request-sequence",boot+frame(4,2),64)
    changed=bytearray(frame(4,1));changed[0]^=1
    raw("request-magic",boot+changed,64)
    changed=bytearray(frame(4,1));changed[-1]=1
    raw("request-reserved",boot+changed,64)
    raw("unknown-operation",boot+frame(5,1),64)
    raw("read-before-prepare",boot+frame(2,1,generation=1),67)
    raw("stale-generation",boot+prepare+frame(2,2,generation=99),67)
    raw("clear-destroys-value",boot+prepare+frame(3,2)+frame(2,3,generation=1),67)
    reject=frame(1,2,height=10,body_len=len(bad))+bad
    raw("rejection-destroys-old-value",boot+prepare+reject+frame(2,3,generation=1),67)
    # No standard descriptor may direct a startup/diagnostic write to a file.
    sentinel=b"unchanged-original-file-bytes"
    for standard in ("stdin","stdout","stderr"):
        target=folder/("sentinel-"+standard);target.write_bytes(sentinel)
        with target.open("r+b",buffering=0) as stream:
            _,stdout,stderr=raw("regular-"+standard,boot,64,**{standard+"_override":stream})
        need(target.read_bytes()==sentinel and stdout==stderr==b"","Invalid stdio mutated file or emitted bytes")
    for standard in ("stdin","stdout","stderr"):
        read_fd,write_fd=os.pipe()
        try:
            wrong=write_fd if standard=="stdin" else read_fd
            _,stdout,stderr=raw("wrong-pipe-access-"+standard,boot,64,**{standard+"_override":wrong})
            need(stdout==stderr==b"","Wrong standard pipe mode emitted bytes")
        finally:os.close(read_fd);os.close(write_fd)
    read_fd,write_fd=os.pipe()
    try:
        need(os.write(write_fd,boot)==len(boot),"Alias fixture write")
        raw("same-stdin-stdout-pipe",boot,64,stdin_override=read_fd,stdout_override=write_fd)
        os.set_blocking(read_fd,False)
        need(os.read(read_fd,1024)==boot,"Aliased standard pipe read or write occurred")
    finally:os.close(read_fd);os.close(write_fd)
    # Real control caps, their modes and object aliases are admitted before context/progress.
    for kind in ("write-regular","read-regular","write-readonly","read-writeonly","same-pipe","same-number","mixed-disabled","opath-write"):
        fds=[];targets=[];p=None
        try:
            wr,ww=os.pipe();rr,rw=os.pipe();fds=[wr,ww,rr,rw]
            gw,gr=ww,rr
            if kind in ("write-regular","read-regular"):
                target=folder/("sentinel-"+kind);target.write_bytes(sentinel)
                p=target.open("r+b",buffering=0);targets.append(target)
                if kind=="write-regular":gw=p.fileno()
                else:gr=p.fileno()
            if kind=="write-readonly":gw=wr
            if kind=="read-writeonly":gr=rw
            if kind=="same-pipe":gr=wr
            if kind=="same-number":gr=gw
            if kind=="mixed-disabled":gw=(1<<64)-1
            if kind=="opath-write":
                gw=os.open("/proc/self/fd/"+str(ww),os.O_PATH);fds.append(gw)
            body=struct.pack("<8Q",magic(b"MPBOOT01"),0,gw,gr,0,0,0,0)
            passed=tuple(sorted({fd for fd in (gw,gr) if fd!=(1<<64)-1}))
            _,stdout,_=raw("control-"+kind,body,65,passed=passed)
            need(stdout==b"","Control cap emitted opened bytes")
            for target in targets:need(target.read_bytes()==sentinel,"Control cap mutated a file")
        finally:
            if p is not None:p.close()
            for fd in fds:os.close(fd)
    for kind in ("stdout-alias","stdin-alias"):
        fds=[]
        try:
            a,b=os.pipe();c,d=os.pipe();fds=[a,b,c,d]
            if kind=="stdout-alias":
                gw=os.dup(b);gr=c;fds.append(gw)
                body=struct.pack("<8Q",magic(b"MPBOOT01"),0,gw,gr,0,0,0,0)
                raw("control-distinct-fd-"+kind,body,65,stdout_override=b,passed=(gw,gr))
                os.set_blocking(a,False)
                try:got=os.read(a,1024)
                except BlockingIOError:got=b""
                need(got==b"","Aliased stdout progress write occurred")
            else:
                gr=os.dup(a);gw=d;fds.append(gr)
                body=struct.pack("<8Q",magic(b"MPBOOT01"),0,gw,gr,0,0,0,0)
                need(os.write(b,body)==64,"Input alias fixture")
                _,stdout,_=raw("control-distinct-fd-"+kind,body,65,stdin_override=a,passed=(gw,gr))
                need(stdout==b"","Aliased stdin control accepted")
        finally:
            for fd in fds:os.close(fd)
    for kind in ("progress-epipe","reply-eof"):
        wr,ww=os.pipe();rr,rw=os.pipe();fds=[wr,ww,rr,rw]
        try:
            lost=wr if kind=="progress-epipe" else rw
            os.close(lost);fds.remove(lost)
            body=struct.pack("<8Q",magic(b"MPBOOT01"),0,ww,rr,0,0,0,0)+prepare
            receipt,stdout,_=raw("control-"+kind,body,70,passed=(ww,rr))
            diag=receipt.get("diagnostic")
            need(diag is not None and diag[5]==0 and b"MPRESULT" not in stdout,"Control transport failure became preparation")
            need(diag[2]==((1<<64)-32 if kind=="progress-epipe" else 0),"Wrong actual control errno/EOF")
            if kind=="reply-eof":
                os.set_blocking(wr,False);progress=os.read(wr,64)
                need(len(progress)==32 and progress[:8]==b"MPPROG01","Missing actual progress before reply EOF")
                (folder/("control-"+kind)/"actual-progress.raw").write_bytes(progress)
        finally:
            for fd in fds:os.close(fd)
    # The callbacks really surround a nonpreemptible actual prepare result.
    callback_inputs=(("success",good,0,1),("encoding",good[:-1],1,0),
                     ("signature",bad,9,1),("network",wire(1,bytes(40),net=bytes(32)),7,0))
    for label,payload,code,attempts in callback_inputs:
        for cancel_kind in (1,2):
            name="cancel-"+label+"-"+str(cancel_kind)
            session=Session.__new__(Session);sessions.append(session)
            Session.__init__(session,executable,folder/name,gate=lambda event,kind=cancel_kind:int(event["kind"]==kind))
            context=session.open();expected_eof=False
            try:session.prepare(payload,10)
            except EOFError:expected_eof=True
            need(expected_eof,"Cancellation produced a result")
            process=session.finish();session.cleanup();process=session.snapshot()
            need(process["exit_code"]==80 and len(process["events"])==cancel_kind and not session.pending,
                 "Cancellation failed to stop exact callback")
            diag=process.get("diagnostic")
            need(diag is not None and diag[0]==80 and diag[4]==(0 if cancel_kind==1 else code)
                 and diag[5]==(0 if cancel_kind==1 else attempts) and diag[6]==cancel_kind,"Original callback/attempt precedence")
            need(bytes(session.stdout)==bytes.fromhex(context["raw_hex"]),"Cancelled operation emitted partial result")
            rows.append({"name":name,"process":process})
    for kind in ("sequence","magic","classification"):
        name="reply-"+kind
        def reply(event,kind=kind):
            values=[magic(b"MPGO0001"),event["sequence"],0]
            values[{"magic":0,"sequence":1,"classification":2}[kind]]+=2
            return struct.pack("<3Q",*values)
        session=Session.__new__(Session);sessions.append(session)
        Session.__init__(session,executable,folder/name,gate=reply)
        context=session.open()
        try:session.prepare(good,10);raise ValueError("Malformed reply accepted")
        except EOFError:pass
        process=session.finish();session.cleanup();process=session.snapshot()
        need(process["exit_code"]==64 and process["diagnostic"][5]==0
             and bytes(session.stdout)==bytes.fromhex(context["raw_hex"]),"Malformed callback accepted")
        rows.append({"name":name,"process":process})
    # Continuation and exact private bytes after CLEAR, plus fragmented actual transfers.
    session=Session.__new__(Session);sessions.append(session)
    Session.__init__(session,executable,folder/"fragmented-reuse",gate=lambda event:0)
    session.open()
    for index,payload in enumerate((good,bad,good)):
        session.sequence+=1
        request=frame(1,session.sequence,height=10,body_len=len(payload))+payload
        for offset in range(0,len(request),3):session.write(request[offset:offset+3])
        from .native_io import parse_result
        result=parse_result(session.read(96))
        need(result["code"]==(9 if index==1 else 0),"Fragmented semantic result")
        if result["code"]==0:
            value=session.value(result);need(value["wire_hex"]==payload.hex(),"Private wire changed")
            session.clear()
    process=session.close();session.cleanup();process=session.snapshot()
    need(process["exit_code"]==0 and len(process["events"])==6,"Fragmented stream failed")
    rows.append({"name":"fragmented-reuse","process":process})
    return {"native_controls":len(rows),"native_processes":len(rows),"controls":rows}

def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--suite",choices=("semantic","physical"),default="semantic")
    args=parser.parse_args();output=args.output.absolute()
    need(not output.exists() and output.parent.resolve(strict=True)==output.parent,"Fresh canonical output required")
    need(ROOT not in output.parents,"Qualification output must be outside source")
    output.mkdir(mode=0o700);started=time.monotonic_ns()
    builder=None;build=None;sessions=[];primary=None;cleanup=[];after=None;result={}
    try:
        p=subprocess.run(["bash","scripts/project-preflight.sh","--audit"],cwd=ROOT,capture_output=True,timeout=60)
        (output/"preflight.stdout").write_bytes(p.stdout);(output/"preflight.stderr").write_bytes(p.stderr)
        need(p.returncode==0,"Project boundary refused")
        builder=Build.__new__(Build);Build.__init__(builder,output/"build")
        need(complete_source_manifest(ROOT)==builder.manifest,"Independent complete source closure differs")
        executable,build=builder.build()
        elf=output/"build/legacy-prepare-owner.elf";elf.chmod(0o700)
        result=(semantic if args.suite=="semantic" else physical)(elf,output,build,sessions)
    except BaseException as error:
        primary={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()}
    finally:
        for session in sessions:
            try:session.cleanup()
            except BaseException as error:cleanup.append({"phase":"session_cleanup","error":repr(error)})
            if hasattr(session,"child") and session.child is not None:
                try:session.snapshot()
                except BaseException as error:cleanup.append({"phase":"process_evidence","error":repr(error)})
            cleanup.extend({"phase":"session","error":error} for error in getattr(session,"cleanup_errors",[]))
        if builder is not None and hasattr(builder,"manifest"):
            try:
                builder.check_sources()
                need(complete_source_manifest(ROOT)==builder.manifest,"Independent final source closure differs")
                after={"status":"PASS","source_set_sha256":hashlib.sha256(json.dumps(builder.manifest,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                  "native_source_files":len(builder.manifest),"original_source_files":len(builder.original)}
            except BaseException as error:after={"status":"FAIL","error":repr(error)}
        passed=primary is None and not cleanup and after and after["status"]=="PASS"
        report={"schema":NATIVE_SCHEMA,"status":"PASS" if passed else "FAIL","suite":args.suite,
          "source_set_sha256":build["source_set_sha256"] if build else None,**result,
          "verification":{"source_after":after,"primary_error":primary,"cleanup_errors":cleanup},
          "wall_ns":time.monotonic_ns()-started,"original_rust":"NOT_RUN",
          "full_node_qualified":False,"durable_admission_qualified":False}
        if passed and args.suite=="semantic":
            # Process evidence is final only after all descriptor cleanup completes.
            bundle=output/"bundle"
            shutil.copyfile(output/"process/process.json",bundle/"raw/process.json")
            process_identity=identity((bundle/"raw/process.json").read_bytes())
            comparison=json.loads((bundle/"native-comparison.json").read_bytes())
            comparison["process"]=process_identity
            comparison_raw=json.dumps(comparison,sort_keys=True,indent=2,allow_nan=False).encode()+b"\n"
            (bundle/"native-comparison.json").write_bytes(comparison_raw)
            report["process"]=process_identity;report["comparison"]=identity(comparison_raw)
            save(bundle/"native-report.json",report)
            try:validate_bundle(ROOT,bundle)
            except BaseException as error:
                report["status"]="FAIL";report["verification"]["primary_error"]={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()}
                save(bundle/"native-report.json",report)
        save(output/"report.json",report)
        print(json.dumps({key:report.get(key) for key in ("status","suite","native_cases","native_controls","native_processes","source_set_sha256","wall_ns","verification")}))
        if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
