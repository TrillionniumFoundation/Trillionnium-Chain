"""Real-process qualification of the finite default-genesis native owner."""
from __future__ import annotations
import argparse,hashlib,json,lzma,os,resource,struct,sys,time,traceback
from pathlib import Path
from .build import Build,ROOT,need,identity
from .cases import cases,canonical_bytes
from .native_io import Session,request,snapshot,parse_success,parse_record
SUITES=("semantic","crash","prefix","namespace","corruption")

class Suite:
    def __init__(self,output,kind):
        self.output=output;self.kind=kind;self.started=time.monotonic_ns()
        self.controls=[];self.counter=0;self.builder=None;self.build=None;self.executable=None
        self.current=None;self.sessions=[];self.cleanup_errors=[]
        self.observations=output/"controls.jsonl"
        output.mkdir(mode=0o700)
    def prepare(self):
        self.builder=Build.__new__(Build)
        Build.__init__(self.builder,self.output/"build")
        self.executable,self.build=self.builder.build()
    def cleanup(self,session):
        try:return session.cleanup()
        except BaseException as error:
            process=getattr(session,"process",None)
            self.cleanup_errors.append({"error":repr(error),"traceback":traceback.format_exc(),
                "pid":getattr(process,"pid",None),"path":str(getattr(session,"output","UNKNOWN")),
                "process_returncode":getattr(process,"returncode",None)})
            return None
        finally:
            if self.current is session:self.current=None
    def process(self,label,directory,**kwargs):
        self.counter+=1
        result=Session(self.executable,self.output/("process-%04d-"%self.counter+label),directory,**kwargs)
        self.current=result;self.sessions.append(result)
        return result
    def add(self,name,**observed):
        row={"name":name,"status":"PASS",**observed}
        with self.observations.open("a",encoding="utf-8") as stream:
            stream.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");stream.flush()
        self.controls.append(row)
        print(json.dumps({"suite":self.kind,"control":name,"status":"PASS"}),flush=True)
    def run(self,label,directory,*,commands=(1,2),**kwargs):
        session=self.process(label,directory,**kwargs)
        try:
            session.send(b"".join(request(op) for op in commands))
            return session.finish()
        finally:
            self.cleanup(session)
    def success(self,label,directory,*,mode=0,timestamp=None,workers=1):
        process,stdout=self.run(label,directory,mode=mode,timestamp=timestamp,workers=workers)
        need(process["exit_code"]==0 and not process["timed_out"] and process["stderr"]["bytes"]==0,
             label+": actual native process refused")
        observed,record=parse_success(stdout)
        need(struct.unpack_from("<Q",stdout,8)[0]==mode and struct.unpack_from("<Q",stdout,24)[0]==workers,
             label+": actual receipt mode/workers differ")
        final=directory/("ng1."+observed["genesis"]+".state")
        need(final.is_file() and not final.is_symlink() and final.read_bytes()==record,
             label+": physical file differs from full native READ")
        return process,observed,record
    def baseline(self):
        directory=self.output/"baseline";directory.mkdir(mode=0o700)
        process,observed,record=self.success("baseline",directory)
        (self.output/"actual-default-record.raw").write_bytes(record)
        self.record=record;self.genesis=observed["genesis"];self.final_name="ng1."+self.genesis+".state"
        self.pending_name="ng1."+self.genesis+".pending"
        self.add("actual-native-baseline",process=process,observed=observed)
        return directory
    def fixture(self,label,*,pending=False,raw=None,lock=True):
        directory=self.output/(label+"-namespace");directory.mkdir(mode=0o700)
        if lock:
            path=directory/"ng1.owner.lock";path.write_bytes(b"");path.chmod(0o600)
        if raw is not None:
            path=directory/(self.pending_name if pending else self.final_name)
            path.write_bytes(raw);path.chmod(0o600)
        return directory
    def refuse(self,label,directory,*,expected=65,mode=1,stdout_bytes=0,commands=(2,),unchanged=True,**kwargs):
        before=snapshot(directory)
        process,stdout=self.run(label,directory,mode=mode,commands=commands,**kwargs)
        need(process["exit_code"]==expected and not process["timed_out"],label+": wrong native refusal")
        need(len(stdout)==stdout_bytes,label+": unexpected native receipt")
        after=snapshot(directory)
        if unchanged:need(after==before,label+": refusal changed stored bytes or captured inode metadata")
        self.add(label,process=process,namespace_before=before,namespace_after=after,
                 unchanged=after==before,receipt_bytes=len(stdout))
        return process,stdout

def observe_semantic(suite):
    results=[];raw=canonical_bytes()
    input_rows=list(cases())
    need(len(input_rows)==len({row["name"] for row in input_rows}),"Duplicate corpus name")
    need(raw==b"".join((json.dumps(row,separators=(",",":"))+"\n").encode() for row in input_rows),
         "Corpus bytes are not the canonical ordered rows")
    for index,item in enumerate(input_rows):
        name=item["name"];timestamp=item["timestamp"];workers=item["workers"]
        directory=suite.output/("case-%06d"%index);directory.mkdir(mode=0o700)
        expected_valid=(timestamp is None or 1<=timestamp<=(1<<63)-1) and workers in (1,2,4,8)
        before=snapshot(directory)
        session=suite.process("semantic-first-%06d"%index,directory,timestamp=timestamp,workers=workers)
        try:
            if not expected_valid:
                session.send(request(1)+request(2));process,stdout=session.finish()
                need(process["exit_code"]==68 and not process["timed_out"] and stdout==b"",
                     name+": expected real constructor/workers refusal")
                diagnostic=process["diagnostic"]
                need(diagnostic is not None and diagnostic[0]==68 and diagnostic[1]==2,
                     name+": missing exact constructor return diagnostic")
                phase="Settings::development" if diagnostic[2]>=4294967280 else "first.Node::open"
                need(phase==("Settings::development" if timestamp is not None and not 1<=timestamp<=(1<<63)-1
                             else "first.Node::open"),name+": wrong first error")
                need(snapshot(directory)==before,name+": invalid context mutated namespace")
                row={**item,"status":"ERR","error_phase":phase,"native_error_diagnostic":diagnostic,
                     "first":None,"reopened":None,"held_lock_probe":None,"processes":[process],
                     "namespace_unchanged":True,"original_error_strings_equivalent":False}
            else:
                opened=session.opened()
                session.send(request(1));header=session._read(session.process.stdout.fileno(),64)
                need(header[:8]==b"NGREAD01","Real first READ header")
                size=struct.unpack_from("<Q",header,8)[0]
                need(size<=16896,"Native record exceeds finite constructor record capacity")
                body=session._read(session.process.stdout.fileno(),size)
                first,record=parse_success(opened+header+body)
                need(struct.unpack_from("<Q",opened,8)[0]==0 and struct.unpack_from("<Q",opened,24)[0]==workers,
                     "Real opened mode/workers")
                state_path=directory/("ng1."+first["genesis"]+".state")
                need(state_path.read_bytes()==record,"First real file/read mismatch")
                stable=snapshot(directory)
                probe,probe_out=suite.run("held-lock-%06d"%index,directory,mode=1,
                    timestamp=timestamp,workers=workers,commands=(2,))
                need(probe["exit_code"]==67 and not probe["timed_out"] and probe_out==b"",
                     name+": actual held lock was not exclusive")
                need(snapshot(directory)==stable,name+": failed contender changed namespace")
                session.send(request(2));process,first_stdout=session.finish()
                need(process["exit_code"]==0 and process["stderr"]["bytes"]==0 and first_stdout==opened+header+body,
                     name+": first owner close failed")
                closed=snapshot(directory)
                cold,reopened,cold_record=suite.success("cold-%06d"%index,directory,mode=1,
                    timestamp=timestamp,workers=workers)
                need(cold_record==record and snapshot(directory)==closed,name+": fresh-process full cold read changed data")
                row={**item,"status":"OK","error_phase":None,"native_error_diagnostic":None,
                     "first":first,"reopened":reopened,"held_lock_probe":{"opened":False,"process":probe},
                     "processes":[process,probe,cold],"full_reopen_record_equal":True,
                     "cold_namespace_unchanged":True,"original_error_strings_equivalent":False}
            results.append(row)
            suite.add(name,case=row)
        finally:
            suite.cleanup(session)
    suite.builder.check_sources()
    bundle=suite.output/"bundle";bundle.mkdir(mode=0o700)
    compressed=lzma.compress(raw,preset=6)
    (bundle/"corpus.jsonl").write_bytes(raw);(bundle/"corpus.jsonl.xz").write_bytes(compressed)
    comparison={"schema":"trnm.native-default-genesis-comparison.v1","status":"PASS","build":suite.build,
        "cases":results,"case_count":len(results),"corpus":{"path":"corpus.jsonl.xz",
         "raw":identity(raw),"compressed":identity(compressed)},
        "scope":{"new_finite_genesis_profile":True,"logical_normal_domain_comparison":True,
          "original_rust":"NOT_RUN","original_error_display_code_kind_equivalence":False,
          "sqlite_schema_equivalence":False,"complete_node":False}}
    (bundle/"native-comparison.json").write_text(json.dumps(comparison,sort_keys=True,indent=2)+"\n")
    return {"semantic_cases":len(results),"comparison":str(bundle/"native-comparison.json"),"corpus":comparison["corpus"]}

def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise RuntimeError("Optimized Python is not admitted")
    parser=argparse.ArgumentParser()
    parser.add_argument("--suite",choices=SUITES,required=True);parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();suite=None;primary=None;result=None
    source_after={"status":"NOT_CAPTURED"};write_errors=[]
    try:
        suite=Suite(args.output,args.suite)
        suite.prepare()
        if args.suite=="semantic":
            result=observe_semantic(suite)
        elif args.suite in ("crash","prefix"):
            from .recovery_cases import qualify
            result=qualify(suite,args.suite)
        else:
            from .namespace_cases import qualify
            result=qualify(suite,args.suite)
    except BaseException as error:
        primary={"error":repr(error),"traceback":traceback.format_exc()}
    finally:
        if suite is not None:
            for session in suite.sessions:suite.cleanup(session)
            builder=suite.builder
            if builder is not None and all(hasattr(builder,name) for name in ("pinned","manifest","inputs","original")):
                try:
                    builder.check_sources()
                    source_after={"status":"PASS","source_set_sha256":hashlib.sha256(
                        json.dumps(builder.manifest,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                        "native_source_files":len(builder.manifest),"original_source_files":len(builder.original)}
                except BaseException as error:
                    source_after={"status":"FAIL","error":repr(error),"traceback":traceback.format_exc()}
            else:
                source_after={"status":"NOT_CAPTURED","reason":"Builder did not complete source capture"}
            status="PASS" if primary is None and not suite.cleanup_errors and source_after["status"]=="PASS" else "FAIL"
            report={"schema":"trnm.native-default-genesis-qualification.v1","status":status,"suite":args.suite,
              "build":suite.build,"controls":suite.controls,"controls_total":len(suite.controls),
              "real_native_processes":suite.counter,"elapsed_ns":time.monotonic_ns()-suite.started,
              "native_child_budget_seconds":240,"cleanup_budget_seconds":3,
              "scope":{"native_runtime":True,"runtime_host_proxy":False,"full_genesis_file_reads":True,
                "physical_power_loss":False,"os_page_cache_flushed":False,"continuous_hostile_same_uid_safety":False,
                "successor_admission":False,"arbitrary_commit":False,"complete_node":False,
                "original_rust":"NOT_RUN"},"details":result,
              "verification":{"source_after":source_after,"primary_error":primary,"cleanup_errors":suite.cleanup_errors}}
            try:
                with (args.output/"report.json").open("x",encoding="utf-8") as stream:
                    stream.write(json.dumps(report,sort_keys=True,indent=2)+"\n")
                if status=="PASS" and args.suite=="semantic":
                    with (args.output/"bundle/native-report.json").open("x",encoding="utf-8") as stream:
                        stream.write(json.dumps(report,sort_keys=True,indent=2)+"\n")
            except BaseException as error:
                write_errors.append({"error":repr(error),"traceback":traceback.format_exc()});status="FAIL"
            if status!="PASS":
                failure={"status":"FAIL","suite":args.suite,"primary_error":primary,
                    "cleanup_errors":suite.cleanup_errors,"source_after":source_after,"write_errors":write_errors,
                    "build":suite.build,"completed_controls":suite.controls,
                    "elapsed_ns":time.monotonic_ns()-suite.started}
                try:
                    with (args.output/"failure.json").open("x",encoding="utf-8") as stream:
                        stream.write(json.dumps(failure,sort_keys=True,indent=2)+"\n")
                except BaseException as error:
                    write_errors.append({"failure_report_error":repr(error)})
            print(json.dumps({"status":status,"suite":args.suite,"controls":len(suite.controls),
                "real_native_processes":suite.counter,"elapsed_seconds":(time.monotonic_ns()-suite.started)/1e9,
                "source_set_sha256":None if suite.build is None else suite.build["source_set_sha256"],
                "executable":None if suite.build is None else suite.build["executable"],
                "primary_error":primary,"cleanup_errors":suite.cleanup_errors,"source_after":source_after,
                "write_errors":write_errors}))
        else:
            status="FAIL"
            print(json.dumps({"status":"FAIL","suite":args.suite,"output_not_created":True,
                "primary_error":primary,"source_after":source_after}))
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
