"""Mandatory actual native account, arithmetic, lifecycle and fault qualification."""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import time
import traceback

from hia.platform.build import new_output, run_native, require_success, sealed_executable
from hia.platform.thread_cpu.rust_oracle import original_manifest
from hia.platform.thread_cpu.trace_audit import complete_calls
from .build import ROOT, HERE, Build, need, digest, identity, read_json, write_json, source_manifest, validate_source_bindings
from .cases import owner_cases, boundary_cases, fault_cases
from .native_io import frame, plan_from_frame, positive_receipt, decode_boundary
from .trace_audit import audit as audit_positive
from .fault_audit import audit as audit_fault

def corpus():
 return {"owners":owner_cases(),"boundaries":boundary_cases(),"faults":fault_cases()}

def capture(image,payload,root,label,injection=(),timeout=60):
 folder=root/label;folder.mkdir(mode=0o700)
 (folder/"stdin.raw").write_bytes(payload)
 tracer=shutil.which("strace");need(tracer is not None,"Mandatory actual native trace requires strace")
 fd=sealed_executable(image,"paid-cpu-"+label)
 need(fcntl.fcntl(fd,1034)&15==15,"Native image capture is not sealed")
 argv=[tracer,"-f","-qq","-v","-s","65536","-o",str(folder/"syscalls.raw")]
 for item in injection:argv.extend(["-e","inject="+item])
 argv.extend(["--","/proc/self/fd/"+str(fd)])
 started=time.monotonic_ns();timed=False;cleanup=None
 try:process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  cwd=folder,env={"PATH":""},pass_fds=(fd,),start_new_session=True,umask=0o077)
 finally:os.close(fd)
 try:stdout,stderr=process.communicate(payload,timeout=timeout)
 except subprocess.TimeoutExpired:
  timed=True
  try:os.killpg(process.pid,signal.SIGKILL);sent="sent"
  except ProcessLookupError:sent="already_exited"
  stdout,stderr=process.communicate(timeout=3);cleanup={"signal":"SIGKILL","outcome":sent,"reaped":process.returncode is not None}
 (folder/"stdout.raw").write_bytes(stdout);(folder/"stderr.raw").write_bytes(stderr)
 row={"name":label,"argv":argv,"native_image_sha256":digest(image),"native_image_bytes":len(image),
  "input_sha256":digest(payload),"input_bytes":len(payload),"output_sha256":digest(stdout),"output_bytes":len(stdout),
  "stderr_sha256":digest(stderr),"stderr_hex":stderr.hex(),"exit_code":process.returncode,
  "timed_out":timed,"cleanup":cleanup,"wall_limit_seconds":timeout,
  "elapsed_ns":time.monotonic_ns()-started,"injection":list(injection)}
 write_json(folder/"physical.json",row)
 return folder,stdout,row

def raw_inputs(folder,names):
 return {name:identity(folder/name) for name in names}

def negative_traces(baselines,output):
 output.mkdir(mode=0o700)
 raw,stdin,stdout,plan=baselines["serial-owner"]
 calls,_=complete_calls(raw)
 birth=next(c for c in calls if c["name"]=="clone");child=birth["value"]
 death=next(c for c in calls if c["tid"]==child and c["name"]=="exit")
 lines=raw.splitlines();variants=[]
 a=lines.copy();a.insert(birth["start"]-1,f"{child} gettid() = {child}")
 variants.append(("child-before-birth","\n".join(a)+"\n",stdin,stdout,plan))
 a=lines.copy();a.insert(death["end"],f"{child} gettid() = {child}")
 variants.append(("child-after-retirement","\n".join(a)+"\n",stdin,stdout,plan))
 variants.append(("clock-id-substitution",raw.replace("CLOCK_THREAD_CPUTIME_ID","CLOCK_MONOTONIC",1),stdin,stdout,plan))
 changed=re.sub(r"(CLOCK_THREAD_CPUTIME_ID, \{tv_sec=\d+, tv_nsec=)(\d+)",lambda m:m[1]+str(int(m[2])+1),raw,count=1)
 variants.append(("one-nanosecond-unpaid-cpu",changed,stdin,stdout,plan))
 variants.append(("missing-clear-tid-flag",raw.replace("|CLONE_CHILD_CLEARTID","",1),stdin,stdout,plan))
 variants.append(("receipt-byte-substitution",raw.replace("PCACC001","PCACC002",1),stdin,stdout,plan))
 a=lines.copy();a.insert(death["start"]-1,f'{child} openat(AT_FDCWD, "/tmp/forbidden", O_RDONLY) = 4')
 variants.append(("extra-file-authority","\n".join(a)+"\n",stdin,stdout,plan))
 a=lines.copy();del a[death["start"]-1:death["end"]]
 variants.append(("missing-real-child-exit","\n".join(a)+"\n",stdin,stdout,plan))
 # These altered traces are concrete even when real children retired too fast
 # to require a join wait or a mutex happened to remain uncontended.
 cell=re.search(r"child_tidptr=(0x[0-9a-f]+)",birth["args"])
 need(cell is not None,"Actual clone omitted the clear-TID word")
 a=lines.copy();a.insert(birth["end"],f'{birth["tid"]} futex({cell[1]}, FUTEX_WAIT_PRIVATE, {child}, NULL) = -1 EAGAIN (Resource temporarily unavailable)')
 variants.append(("private-join-instead-of-clear-tid","\n".join(a)+"\n",stdin,stdout,plan))
 arena=next(c["value"] for c in calls if c["name"]=="mmap")
 a=lines.copy();a.insert(death["start"]-1,f"{child} futex({hex(arena)}, FUTEX_WAIT_PRIVATE, 2, NULL) = -1 EAGAIN (Resource temporarily unavailable)")
 variants.append(("wrong-contended-mutex-profile","\n".join(a)+"\n",stdin,stdout,plan))
 results=[]
 for label,changed,ins,outs,pl in variants:
  need(changed!=raw,"Trace negative control did not alter the actual baseline")
  path=output/(label+".trace");path.write_text(changed)
  try:audit_positive(changed,ins,outs,pl)
  except (ValueError,KeyError) as error:
   results.append({"name":label,"status":"REJECTED","reason":str(error),"trace":identity(path)})
  else:raise ValueError("Altered account trace accepted: "+label)
 return results

def protocol_inputs(valid):
 result=[]
 for length in (0,1,7,8,64,191):result.append(("truncated-"+str(length),valid[:length]))
 result.append(("trailing-byte",valid+b"\0"))
 w=list(struct.unpack("<24Q",valid))
 edits=[("wrong-magic",0,0),("invalid-cold",1,2),("zero-requests",2,0),("too-many-requests",2,3),("reserved-header",3,1)]
 for offset in (4,8):
  edits.extend((f"workers-{offset}-{value}",offset,value) for value in (0,3,5,6,7,9))
 edits.extend([("too-many-transactions",5,33),("excess-work-units",6,1_000_001)])
 edits.extend((f"reserved-tail-{offset}",offset,1) for offset in range(12,24))
 for name,index,value in edits:
  row=w.copy();row[index]=value;result.append((name,struct.pack("<24Q",*row)))
 need(len({name for name,_ in result})==len(result),"Duplicate protocol refusal")
 return result

def qualify(output,original_root):
 before=source_manifest();original=original_manifest(original_root)
 report={"schema":"trnm.hia.paid-cpu-native-comparison.v1","status":"FAIL","source_inputs":before,
  "original_sources":original,"owners":[],"boundaries":[],"faults":[],"protocol_controls":[],
  "trace_negative_controls":[],"actual_original_execution":"NOT_RUN",
  "whole_paid_account_or_node_closed":False}
 try:
  build=Build(output/"build");built=build.build();report["build"]=built
  need(built["source_inputs"]==before,"Native build used a different source closure")
  images={name:(output/"build"/(name+".elf")).read_bytes() for name in ("owner","arithmetic")}
  data=corpus();write_json(output/"cases.json",data);report["corpus"]=identity(output/"cases.json")
  rawroot=output/"raw";rawroot.mkdir(mode=0o700)
  for name in ("owners","boundaries","faults","protocol"):(rawroot/name).mkdir(mode=0o700)
  baselines={}
  for case in data["owners"]:
   name=case["name"];plan=case["plan"];payload=frame(plan)
   folder,stdout,physical=capture(images["owner"],payload,rawroot/"owners",name)
   need(not physical["timed_out"] and physical["exit_code"]==0 and physical["stderr_hex"]=="","Actual owner failed: "+name)
   reduced=positive_receipt(stdout,plan)
   raw=(folder/"syscalls.raw").read_text();trace=audit_positive(raw,payload,stdout,plan)
   write_json(folder/"trace-audit.json",trace)
   report["owners"].append({"name":name,"status":"PASS","plan":plan,"account":reduced,"trace":trace,
    "physical":physical,"raw_inputs":raw_inputs(folder,("stdin.raw","stdout.raw","stderr.raw","syscalls.raw","physical.json","trace-audit.json"))})
   baselines[name]=(raw,payload,stdout,plan)
  for case in data["boundaries"]:
   payload=bytes.fromhex(case["frame_hex"])
   need(len(payload)==512 and list(struct.unpack("<64Q",payload))==case["seed_words"],"Boundary frame differs")
   stdout,physical=run_native(images["arithmetic"],payload,rawroot/"boundaries",case["name"],timeout=10)
   require_success(physical);folder=rawroot/"boundaries"/case["name"]
   report["boundaries"].append({"name":case["name"],"status":"PASS","comparison":decode_boundary(stdout),
    "physical":physical,"raw_inputs":raw_inputs(folder,("stdin.raw","stdout.raw","stderr.raw","receipt.json"))})
  for case in data["faults"]:
   plan={"cold":0,"requests":1,"profiles":[{"workers":case["workers"],"txs":case["txs"],"units":1000,"seed":19},
     {"workers":1,"txs":0,"units":0,"seed":0}]}
   folder,stdout,physical=capture(images["owner"],frame(plan),rawroot/"faults",case["name"],case["injection"],timeout=20)
   need(not physical["timed_out"] and physical["exit_code"]==case["expected_exit"] and physical["stderr_hex"]=="",
        "Actual fault termination differs: "+case["name"])
   context={"name":case["name"],"plan":{"workers":case["workers"],"txs":case["txs"]},
      "injection":case["injection"],"expected_exit_for_capture":case["expected_exit"]}
   trace=audit_fault(folder,context);write_json(folder/"trace-audit.json",trace)
   report["faults"].append({"name":case["name"],"status":"PASS","context":context,"trace":trace,"physical":physical,
    "raw_inputs":raw_inputs(folder,("stdin.raw","stdout.raw","stderr.raw","syscalls.raw","physical.json","trace-audit.json"))})
  valid=frame(data["owners"][0]["plan"])
  controls=[(name,images["owner"],payload) for name,payload in protocol_inputs(valid)]
  controls.extend([("production-rejects-private-counters",images["owner"],bytes.fromhex(data["boundaries"][0]["frame_hex"])),
   ("private-fixture-refuses-production-plan",images["arithmetic"],valid)])
  for name,image,payload in controls:
   stdout,physical=run_native(image,payload,rawroot/"protocol",name,timeout=10)
   need(not physical["timed_out"] and physical["exit_code"]==65 and stdout==b"" and physical["stderr_hex"]=="",
        "Actual protocol refusal missing: "+name)
   report["protocol_controls"].append({"name":name,"status":"REJECTED","physical":physical,
    "raw_inputs":raw_inputs(rawroot/"protocol"/name,("stdin.raw","stdout.raw","stderr.raw","receipt.json"))})
  report["trace_negative_controls"]=negative_traces(baselines,output/"negative-traces")
  need(len(report["owners"])==6 and len(report["boundaries"])==67 and len(report["faults"])==13
       and len(report["trace_negative_controls"])==10,"Mandatory native corpus incomplete")
  build.check_pin()
  report.update(status="NATIVE_PASS_ORIGINAL_NOT_RUN",native_owner_histories=6,native_boundary_cases=67,native_fault_histories=13,
    actual_budget_operations=sum(len(r["trace"]["replay"]["operations"]) for r in report["owners"]),
    mandatory_actual_trace=True,production_counter_abi=False)
 except BaseException as error:report.update(failure=repr(error),traceback=traceback.format_exc())
 finally:
  try:
   need(source_manifest()==before,"PaidCPU source changed during qualification")
   need(original_manifest(original_root)==original,"Original graph changed during native qualification")
   report["source_after"]="MATCH";report["original_source_after"]="MATCH"
  except BaseException as error:report.update(status="FAIL",source_after="FAIL",source_after_failure=repr(error))
  write_json(output/"native-comparison.json",report)
 return report

def check_raw(folder,row,names,physical_name):
 need(set(row["raw_inputs"])==set(names),"Raw evidence member set differs")
 need(raw_inputs(folder,names)==row["raw_inputs"],"Complete raw native evidence changed")
 physical=read_json(folder/physical_name)
 need(physical==row["physical"],"Recorded physical receipt differs from raw evidence")
 ins=(folder/"stdin.raw").read_bytes();outs=(folder/"stdout.raw").read_bytes();err=(folder/"stderr.raw").read_bytes()
 need(physical["input_sha256"]==digest(ins) and physical["output_sha256"]==digest(outs)
      and physical["stderr_hex"]==err.hex(),"Native physical input/output digest differs")
 return ins,outs,physical

def validate_bundle(bundle,original_root):
 bundle=Path(bundle).resolve(strict=True)
 need(bundle.is_dir() and not bundle.is_symlink(),"Native bundle is not a directory")
 native=read_json(bundle/"native-comparison.json")
 validate_source_bindings(native)
 need(native.get("status")=="NATIVE_PASS_ORIGINAL_NOT_RUN" and native.get("source_after")=="MATCH"
      and native.get("original_source_after")=="MATCH" and native.get("mandatory_actual_trace") is True,
      "Complete actual native qualification did not pass")
 need(native.get("original_sources")==original_manifest(original_root),"Original graph differs from native binding")
 data=corpus()
 need(read_json(bundle/"cases.json")==data and identity(bundle/"cases.json")==native["corpus"],"Complete fixed native corpus differs")
 abi=read_json(HERE/"abi.json")
 for name in ("owner","arithmetic"):
  path=bundle/"build"/(name+".elf");actual=identity(path)
  need(actual==abi["images"][name]["executable"],"Native runtime image differs from reviewed HIA")
  need({key:native["build"]["images"][name][key] for key in ("bytes","sha256")}==actual,"Native image build identity differs")
 baselines={}
 need([r["name"] for r in native["owners"]]==[r["name"] for r in data["owners"]],"Native owner cases missing/reordered")
 for case,row in zip(data["owners"],native["owners"],strict=True):
  folder=bundle/"raw/owners"/case["name"]
  ins,outs,physical=check_raw(folder,row,("stdin.raw","stdout.raw","stderr.raw","syscalls.raw","physical.json","trace-audit.json"),"physical.json")
  need(row["status"]=="PASS" and row["plan"]==case["plan"] and ins==frame(case["plan"]),"Native owner input changed")
  need(physical["native_image_sha256"]==abi["images"]["owner"]["executable"]["sha256"] and physical["exit_code"]==0
       and not physical["timed_out"] and physical["stderr_hex"]=="","Owner did not actually complete")
  need(row["account"]==positive_receipt(outs,case["plan"]),"Owner reduced diagnostic differs")
  raw=(folder/"syscalls.raw").read_text();trace=audit_positive(raw,ins,outs,case["plan"])
  need(trace==row["trace"]==read_json(folder/"trace-audit.json"),"Owner trace audit differs")
  baselines[case["name"]]=(raw,ins,outs,case["plan"])
 need([r["name"] for r in native["boundaries"]]==[r["name"] for r in data["boundaries"]],"Native private boundaries missing/reordered")
 for case,row in zip(data["boundaries"],native["boundaries"],strict=True):
  folder=bundle/"raw/boundaries"/case["name"]
  ins,outs,physical=check_raw(folder,row,("stdin.raw","stdout.raw","stderr.raw","receipt.json"),"receipt.json")
  need(ins.hex()==case["frame_hex"] and row["status"]=="PASS" and decode_boundary(outs)==row["comparison"],"Boundary frame or raw comparison differs")
  need(physical["executable_sha256"]==abi["images"]["arithmetic"]["executable"]["sha256"],"Boundary used another image");require_success(physical)
 need([r["name"] for r in native["faults"]]==[r["name"] for r in data["faults"]],"Native fault corpus missing/reordered")
 for case,row in zip(data["faults"],native["faults"],strict=True):
  folder=bundle/"raw/faults"/case["name"]
  ins,outs,physical=check_raw(folder,row,("stdin.raw","stdout.raw","stderr.raw","syscalls.raw","physical.json","trace-audit.json"),"physical.json")
  context={"name":case["name"],"plan":{"workers":case["workers"],"txs":case["txs"]},
    "injection":case["injection"],"expected_exit_for_capture":case["expected_exit"]}
  need(row["context"]==context and row["status"]=="PASS" and physical["injection"]==case["injection"],"Native fault profile differs")
  expected={"cold":0,"requests":1,"profiles":[{"workers":case["workers"],"txs":case["txs"],"units":1000,"seed":19},{"workers":1,"txs":0,"units":0,"seed":0}]}
  need(ins==frame(expected) and not physical["timed_out"] and physical["exit_code"]==case["expected_exit"]
       and physical["stderr_hex"]=="" and physical["native_image_sha256"]==abi["images"]["owner"]["executable"]["sha256"],"Fault execution evidence differs")
  need(audit_fault(folder,context)==row["trace"]==read_json(folder/"trace-audit.json"),"Native fault trace audit differs")
 expected_controls=protocol_inputs(frame(data["owners"][0]["plan"]))
 expected_controls.extend([("production-rejects-private-counters",bytes.fromhex(data["boundaries"][0]["frame_hex"])),
  ("private-fixture-refuses-production-plan",frame(data["owners"][0]["plan"]))])
 need([r["name"] for r in native["protocol_controls"]]==[n for n,_ in expected_controls],"Protocol negative corpus missing/reordered")
 for (name,payload),row in zip(expected_controls,native["protocol_controls"],strict=True):
  folder=bundle/"raw/protocol"/name
  ins,outs,physical=check_raw(folder,row,("stdin.raw","stdout.raw","stderr.raw","receipt.json"),"receipt.json")
  image="arithmetic" if name=="private-fixture-refuses-production-plan" else "owner"
  need(ins==payload and outs==b"" and row["status"]=="REJECTED" and not physical["timed_out"]
    and physical["exit_code"]==65 and physical["stderr_hex"]=="" and physical["executable_sha256"]==abi["images"][image]["executable"]["sha256"],
    "Actual protocol refusal changed")
 negatives=native["trace_negative_controls"]
 names=["child-before-birth","child-after-retirement","clock-id-substitution","one-nanosecond-unpaid-cpu",
  "missing-clear-tid-flag","receipt-byte-substitution","extra-file-authority","missing-real-child-exit",
  "private-join-instead-of-clear-tid","wrong-contended-mutex-profile"]
 need([row["name"] for row in negatives]==names,"Trace refusal corpus missing/reordered")
 raw,ins,outs,plan=baselines["serial-owner"]
 for row in negatives:
  path=bundle/"negative-traces"/(row["name"]+".trace")
  need(identity(path)==row["trace"] and row["status"]=="REJECTED","Altered trace evidence changed")
  try:audit_positive(path.read_text(),ins,outs,plan)
  except (ValueError,KeyError):pass
  else:raise ValueError("Changed trace accepted during bundle admission")
 need(native["actual_budget_operations"]==sum(len(r["trace"]["replay"]["operations"]) for r in native["owners"]),
      "Actual native method event count differs")
 return native

def main():
 need(__debug__,"PaidCPU qualification refuses optimized Python")
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--output",type=Path,required=True);parser.add_argument("--require-trace",action="store_true")
 parser.add_argument("--original-root",type=Path,default=ROOT)
 args=parser.parse_args();need(args.require_trace,"Actual trace is mandatory; pass --require-trace")
 out=new_output(args.output);report=qualify(out,args.original_root.resolve(strict=True))
 print(json.dumps({"status":report["status"],"owners":len(report["owners"]),"boundaries":len(report["boundaries"]),
  "faults":len(report["faults"]),"protocol_controls":len(report["protocol_controls"]),
  "trace_negative_controls":len(report["trace_negative_controls"]),"actual_budget_operations":report.get("actual_budget_operations"),
  "failure":report.get("failure"),"report":str(out/"native-comparison.json")},sort_keys=True))
 if report["status"]!="NATIVE_PASS_ORIGINAL_NOT_RUN":raise SystemExit(1)
if __name__=="__main__":main()
