"""Public finite Work/Paid clock qualification on owned native/original children.

The zero-target refusal is deliberate: it isolates begin/checkpoint/finish/Drop.
These fifteen Paid controls are separate from the eighteen dense Work clocks.
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import re
import struct
import traceback
from .build import ROOT, identity, need, read_json, source_manifest, write_json
from .primitive_evidence import same, raw_identity
from .cases import corpus, original_cases
from .native_io import decode
from hia.platform.build import sealed_executable
from hia.platform.host_resource.native_io import provision
from hia.platform.paid_cpu.owned_ptrace import run as trace_owned

TEST = "host_kernel_parent::kernel_parent::resource_tests::hia_work_owner_oracle::same_worker_fault_evaluate"
MARKER = b"HIA_WORK_OWNER_ORACLE:"
NATIVE_SCHEMA = "trnm.hia.work-owner-paid-native-faults.v1"
ORIGINAL_SCHEMA = "trnm.hia.work-owner-paid-original-faults.v1"
TRACE_SCHEMA = "trnm.hia.work-owner-paid-clock-trace.v1"
SCOPES = {"production_fixed_parent_authority": False, "whole_Node_or_public_intake_closed": False,
          "independent_CPU_nanoseconds_equal": False, "normal_vdso_fault_behavior_claimed": False}

# (name, exact injected call, result domain, global/request poison, in-flight,
#  complete worker syscall clock IDs). Counts follow current source, not old reports.
_SPECS = (
 ("normal-zero-target",None,1,(0,0),0,[3,1,1,3,1,3,1,3,1]),
 ("constructor-clock1-eio",{"clock_roles":[1],"clock_when":2,"clock_id":1,"clock_error":5},4,(0,0),0,[]),
 ("begin-clock3-einval",{"clock_roles":[2],"clock_when":1,"clock_id":3,"clock_error":22},6,(0,0),0,[3,1]),
 ("begin-clock3-eio-fallback",{"clock_roles":[2],"clock_when":1,"clock_id":3,"clock_error":5},1,(0,0),0,[3,3,1,1,3,1,3,1,3,1]),
 ("begin-clock3-persistent-eio",{"clock_roles":[2],"clock_ordinals":[1,2],"clock_id":3,"clock_error":5},6,(0,0),0,[3,3,1]),
 ("begin-clock3-invalid",{"clock_roles":[2],"clock_when":1,"clock_id":3,"clock_invalid":True},6,(0,0),0,[3,1]),
 ("reserve-clock1-eio",{"clock_roles":[2],"clock_when":2,"clock_id":1,"clock_error":5},4,(1,0),0,[3,1]),
 ("work-clock1-eio",{"clock_roles":[2],"clock_when":3,"clock_id":1,"clock_error":5},4,(0,0),0,[3,1,1,3,1,1]),
 ("live-clock3-einval",{"clock_roles":[2],"clock_when":4,"clock_id":3,"clock_error":22},6,(0,0),0,[3,1,1,3,3,1,3,1]),
 ("live-clock3-eio-fallback",{"clock_roles":[2],"clock_when":4,"clock_id":3,"clock_error":5},1,(0,0),0,[3,1,1,3,3,1,3,1,3,1]),
 ("live-clock3-invalid",{"clock_roles":[2],"clock_when":4,"clock_id":3,"clock_invalid":True},6,(0,0),0,[3,1,1,3,3,1,3,1]),
 ("live-clock1-eio",{"clock_roles":[2],"clock_when":5,"clock_id":1,"clock_error":5},4,(1,1),1,[3,1,1,3,1]),
 ("final-live-clock3-einval",{"clock_roles":[2],"clock_when":6,"clock_id":3,"clock_error":22},1,(0,0),0,[3,1,1,3,1,3,3,1]),
 ("final-live-clock1-eio",{"clock_roles":[2],"clock_when":7,"clock_id":1,"clock_error":5},4,(1,1),1,[3,1,1,3,1,3,1]),
 ("outer-clock3-einval",{"clock_roles":[2],"clock_when":8,"clock_id":3,"clock_error":22},1,(0,0),0,[3,1,1,3,1,3,1,3,1]),
 ("settlement-clock1-eio",{"clock_roles":[2],"clock_when":9,"clock_id":1,"clock_error":5},4,(1,0),1,[3,1,1,3,1,3,1,3,1]),
)

def profiles():
    return [{"name":name,"fault":fault,"domain":domain,"code":7 if domain==1 else 1,
             "poison":list(poison),"in_flight":inflight,"worker_clock_ids":list(ids)}
            for name,fault,domain,poison,inflight,ids in json.loads(json.dumps(_SPECS))]

def admit_profile(profile):
    need(any(same(profile,row) for row in profiles()), "Exact finite Paid clock profile required")
    return profile

def input_case():
    case = next(row for row in corpus() if row["name"]=="zero-target")
    original = next(row for row in original_cases() if row["name"]=="zero-target")
    need(case["progress"]==[] and case["domain"]==1 and case["code"]==7
         and len(bytes.fromhex(case["request_hex"]))==49284
         and same(original,{"name":case["name"],"request_hex":case["request_hex"],
            "gate_stage":0,"gate_sequence":0,"actions":[],"signal":0,"delay_ms":0}),
         "Exact original zero-target Paid input required")
    return case,original

def output_root(path):
    path=Path(path)
    need(path.is_absolute() and path.resolve()==path and not path.exists()
         and not path.is_symlink(),"Fresh canonical Paid qualification output required")
    return path

def original_arguments(argv,env,profile,disable_vdso,out):
    admit_profile(profile)
    need(type(argv) is list and len(argv)==5 and all(type(x) is str for x in argv)
         and argv[1:]==["--exact",TEST,"--nocapture","--test-threads=1"],
         "Exact original Paid clock test invocation required")
    executable=Path(argv[0])
    need(executable.is_absolute() and executable.resolve(strict=True)==executable
         and not executable.is_symlink(),"Canonical original Paid executable required")
    identity(executable)
    need(type(env) is dict and set(env)=={"PATH","TRNM_HIA_WORK_OWNER_CORPUS"}
         and env.get("PATH")=="/usr/bin:/bin" and type(env["TRNM_HIA_WORK_OWNER_CORPUS"]) is str,
         "Exact original Paid environment required")
    path=Path(env["TRNM_HIA_WORK_OWNER_CORPUS"])
    need(path.is_absolute() and path.resolve(strict=True)==path and not path.is_symlink(),
         "Canonical original Paid input required")
    need(path.read_bytes()==(json.dumps(input_case()[1],sort_keys=True,separators=(",",":"))+"\n").encode(),
         "Original Paid input changed or gained a control")
    need(type(disable_vdso) is bool and (disable_vdso or profile["fault"] is None),
         "Paid faults require the private raw-clock fixture")
    return output_root(out)

def native_one(image,request,out,profile):
    admit_profile(profile);out=output_root(out)
    need(type(image) is bytes and raw_identity(image)==read_json(ROOT/"hia/platform/work_owner/abi.json")["images"]["fixture"]["executable"],
         "Actual canonical Paid/Work fixture ELF required")
    need(request==bytes.fromhex(input_case()[0]["request_hex"]),"Exact native Paid zero-target input required")
    out.mkdir(mode=0o700);fixture=out/"native-root";fixture.mkdir(mode=0o700);provision(fixture)
    payload=struct.pack("<8Q",int.from_bytes(b"WOFIX001","little"),0,0,0,0,0,0,0)+request
    (out/"stdin.raw").write_bytes(payload)
    descriptors=set()
    try:
        source=os.memfd_create("hia-work-paid-input",os.MFD_ALLOW_SEALING);descriptors.add(source)
        need(os.write(source,payload)==len(payload),"Complete native Paid input write")
        fcntl.fcntl(source,1033,15);need(fcntl.fcntl(source,1034)==15,"Actual sealed Paid input required")
        executable=sealed_executable(image,"hia-work-paid-clock");descriptors.add(executable)
        execution=fcntl.fcntl(executable,fcntl.F_DUPFD_CLOEXEC,20);descriptors.add(execution);os.set_inheritable(execution,True)
        observer_read,observer_write=os.pipe();gate_read,gate_write=os.pipe()
        descriptors.update((observer_read,observer_write,gate_read,gate_write))
        input_fd=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,30)
        writer=fcntl.fcntl(observer_write,fcntl.F_DUPFD_CLOEXEC,30)
        reader=fcntl.fcntl(gate_read,fcntl.F_DUPFD_CLOEXEC,30);descriptors.update((input_fd,writer,reader))
        def setup():
            os.chdir(fixture);os.dup2(input_fd,0,inheritable=True)
            os.dup2(writer,3,inheritable=True);os.dup2(reader,4,inheritable=True)
            for fd in descriptors:
                if fd>4 and fd!=execution:os.close(fd)
        return trace_owned(["/proc/self/fd/"+str(execution)],out/"ptrace",env={"PATH":""},
            fault=profile["fault"],timeout=30,child_setup=setup,clean_environment=True,
            expected_exit=64+profile["domain"],native_roles=True,capture_writes=True)
    finally:
        for fd in descriptors:os.close(fd)

def run_native(image,output):
    from .paid_fault_evidence import audit, reader_controls
    output=output_root(output);output.mkdir(mode=0o700);before=source_manifest()
    case,_=input_case();request=bytes.fromhex(case["request_hex"])
    report={"schema":NATIVE_SCHEMA,"status":"FAIL","source_inputs":before,"source_after":"NOT_RUN",
            "image":raw_identity(image),"request":raw_identity(request),"rows":[],
            "fault_count":0,"positive_count":0,"actual_original_Rust":False,**SCOPES}
    try:
        for profile in profiles():
            directory=output/profile["name"]
            trace=native_one(image,request,directory,profile)
            observed=audit(directory/"ptrace",profile=profile,native=True,private=False,
                executable=report["image"],argv=trace["argv"],environment={"PATH":""},
                input_bytes=(directory/"stdin.raw").read_bytes())
            write_json(directory/"ptrace/audit.json",observed)
            row={"name":profile["name"],"profile":profile,"status":"PASS","audit":observed}
            report["rows"].append(row)
            report["fault_count" if profile["fault"] else "positive_count"]+=1
            print(json.dumps({"paid_native_clock":profile["name"],"status":"PASS"}),flush=True)
        report["reader_controls"]=reader_controls(output,report,native=True)
        need(report["fault_count"]==15 and report["positive_count"]==1,"Complete native Paid clock roster")
        report["status"]="PASS"
    except BaseException as error:
        report.update(failure=repr(error),traceback=traceback.format_exc())
    finally:
        if same(before,source_manifest()):report["source_after"]="MATCH"
        else:report.update(status="FAIL",source_after="FAIL",final_fence_failure="Paid source changed")
        write_json(output/"report.json",report)
    need(report["status"]=="PASS","Actual native Paid clock qualification failed: "+str(report.get("failure")))
    return report

def run_original(binary,executable,output,native,*,check):
    from .paid_fault_evidence import audit, reader_controls
    output=output_root(output);output.mkdir(mode=0o700)
    _,case=input_case();data=output/"case.jsonl"
    data.write_bytes((json.dumps(case,sort_keys=True,separators=(",",":"))+"\n").encode())
    before=source_manifest();input_id=identity(data)
    argv=[str(binary),"--exact",TEST,"--nocapture","--test-threads=1"]
    env={"PATH":"/usr/bin:/bin","TRNM_HIA_WORK_OWNER_CORPUS":str(data)}
    report={"schema":ORIGINAL_SCHEMA,"status":"FAIL","source_inputs":before,"source_after":"NOT_RUN",
            "original_sources":native["original_sources"],"binary_after":"NOT_RUN",
            "executable":executable,"argv":argv,"environment":env,"input":input_id,"rows":[],
            "fault_count":0,"positive_count":0,**SCOPES}
    def fence():
        check()
        need(same(before,source_manifest()) and same(identity(data),input_id)
             and same(identity(binary),executable),"Complete original Paid source/input/binary fence")
    native_rows={row["name"]:row for row in native["report"]["paid_clock_faults"]["rows"]}
    work=[("normal-vdso-positive",False,profiles()[0]),("private-raw-positive",True,profiles()[0])]
    work += [(p["name"],True,p) for p in profiles()[1:]]
    try:
        fence()
        for label,private,profile in work:
            directory=original_arguments(argv,env,profile,private,output/label)
            trace_owned(argv,directory,disable_vdso=private,env=env,fault=profile["fault"],timeout=60,
                        clean_environment=True,capture_writes=True)
            observed=audit(directory,profile=profile,native=False,private=private,
                executable=executable,argv=argv,environment=env,
                native_frame=native_rows[profile["name"]]["audit"]["frame"])
            write_json(directory/"audit.json",observed)
            report["rows"].append({"name":label,"profile":profile,"status":"PASS","audit":observed})
            report["fault_count" if profile["fault"] else "positive_count"]+=1
            print(json.dumps({"paid_original_clock":label,"status":"PASS"}),flush=True)
        report["reader_controls"]=reader_controls(output,report,native=False,native_report=native["report"]["paid_clock_faults"])
        need(report["fault_count"]==15 and report["positive_count"]==2,"Complete original Paid clock roster")
        fence();report["status"]="PASS"
    except BaseException as error:
        report.update(failure=repr(error),traceback=traceback.format_exc())
    finally:
        try:fence();report.update(source_after="MATCH",binary_after="MATCH")
        except BaseException as error:report.update(status="FAIL",source_after="FAIL",final_fence_failure=repr(error))
        write_json(output/"report.json",report)
    need(report["status"]=="PASS","Actual original Paid clock qualification failed: "+str(report.get("failure")))
    return report
