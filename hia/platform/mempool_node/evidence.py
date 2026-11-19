"""Complete build and native artifact binding, without executing a runtime."""
from pathlib import Path
from . import safe
from .build import ROOT,validate_build,source_manifest

_NATIVE_SCHEMAS={
 "smoke":"trnm.production-m05-runtime-smoke.v1",
 "boundaries":"trnm.production-m05-runtime-boundaries.v1",
 "capacity":"trnm.production-m05-runtime-capacity.v2",
 "node":"trnm.node-canonical-parent-private-semantic.v1",
 "cross":"trnm.single-node-m05-C-cross-lifecycle.v1",
}
_NATIVE_COMMON_FIELDS={"schema","status","failure","cleanup_errors","source_after","build","executable","real_processes","elapsed_ns","scope"}
_NATIVE_EXTRA_FIELDS={
 "smoke":{"controls","controls_total","script"},
 "boundaries":{"controls","controls_total","script"},
 "capacity":{"controls","controls_total","script"},
 "node":{"source_inputs","corpus","controls","controls_total"},
 "cross":{"source_inputs","m05_controls","observations"},
}
_M05_SCOPE={
 "held_disk_owned_state":True,"actual_pnx_sha_ed25519":True,
 "private_ready_consumed":True,"actual_prefix":True,
 "caller_state_or_verified":False,"production_permit":False,
 "complete_checked_parent":False,"local_pool_durable":False,"node_commit":False,
}
_NODE_SCOPE={
 "actual_private_disk_state_source":True,"actual_settings_some":True,
 "caller_state_or_root":False,"runtime_host_proxy":False,"original_rust":"NOT_RUN",
 "successor_admission":False,"node_commit":False,"complete_node":False,
 "private_finalized_state_ownership":True,"prepared_commitment_none_prior":True,
 "full_prepared_observation":True,"canonical_parent_owned_once_per_prefix":True,
 "prepared_retains_before_map":False,"checked_apply_some_prior":False,
}
_CROSS_SCOPE="Actual one-Node cross-method Parent/Prepared/Ready ownership; standalone original cross-history NOT_RUN"

def native_report_contract(report,group):
 """Reject altered qualification scope before consuming native observations.

 This checks the producer's fixed report contract only. The caller still has to
 verify the actual source, build, complete processes and every native outcome.
 """
 safe.need(type(group) is str and group in _NATIVE_SCHEMAS,"Unknown native report group")
 safe.need(type(report) is dict and set(report)==_NATIVE_COMMON_FIELDS|_NATIVE_EXTRA_FIELDS[group],
           "Exact native "+group+" report fields")
 safe.need(type(report["schema"]) is str and report["schema"]==_NATIVE_SCHEMAS[group],
           "Exact native "+group+" report schema")
 expected=_NODE_SCOPE if group=="node" else _CROSS_SCOPE if group=="cross" else _M05_SCOPE
 safe.need(safe.same(report["scope"],expected),"Native "+group+" qualification scope differs")

def partition(artifact,group,inputs):
 from .observations import read,load
 artifact=Path(artifact).absolute();build_dir=artifact/"build"
 build=validate_build(build_dir,ROOT)
 for path,row in build["source_inputs"].items():
  safe.need(safe.same(safe.identity(read(ROOT/path,inputs)),row),"Current complete source differs")
 for row in build["stages"]:
  for name in ("stdin.raw","stdout.raw","stderr.raw","receipt.json"):read(build_dir/"compiler"/row["stage"]/name,inputs)
 build_raw=read(build_dir/"build.json",inputs);read(build_dir/"owner.elf",inputs)
 outer=load(read(artifact/"report.json",inputs));raw=read(artifact/"native/report.json",inputs);report=load(raw)
 native_report_contract(report,group)
 safe.need(outer["schema"]=="trnm.mempool-node-partition.v1" and outer["group"]==group and outer["status"]=="PASS" and outer["failure"] is None,"Whole successful partition required")
 safe.need(safe.same(outer["source_after"],{"status":"MATCH","errors":[]}) and safe.same(outer["source_inputs"],build["source_inputs"]) and outer["source_set_sha256"]==build["source_set_sha256"],"Partition source closure mismatch")
 safe.need(safe.same(outer["native_report"],safe.identity(raw)) and safe.same(outer["native_build"],safe.identity(build_raw)),"Complete native artifact identities")
 safe.need(report["status"]=="PASS" and report["failure"] is None and safe.same(report["cleanup_errors"],[]) and safe.same(report["source_after"],{"status":"MATCH","errors":[]}),"Native suite or cleanup failed")
 safe.need(safe.same(report["build"],safe.identity(build_raw)) and safe.same(report["executable"],build["executable"]),"Suite native machinecode binding")
 safe.need(type(report["elapsed_ns"]) is int and report["elapsed_ns"]>0,"Actual suite elapsed observation")
 return artifact/"native",build,report

def process(folder,inputs):
 from .observations import read,load,frames
 row=load(read(folder/"receipt.json",inputs))
 safe.need(type(row["exit_code"]) is int and row["exit_code"]==0 and type(row["expected_exit"]) is int and row["expected_exit"]==0 and row["cleanup"] is None,"Actual process did not close")
 streams={k:read(folder/(k+".raw"),inputs) for k in ("stdin","stdout","stderr")}
 for k,v in streams.items():safe.need(safe.same(safe.identity(v),row[k]),"Actual process stream differs")
 safe.need(not streams["stderr"] and type(row["elapsed_ns"]) is int and 0<row["elapsed_ns"]<=243_000_000_000,"Child diagnostic/budget")
 namespace(folder,row,inputs)
 out=frames(streams["stdout"]);safe.need(safe.same([r.hex() for r in out],row["frames_hex"]),"Complete process frame order")
 trace_capture(folder,inputs)
 return row,streams,out

def namespace(folder,row,inputs):
 """Bind both observed namespace snapshots and every retained regular file."""
 from .observations import read,load
 import stat
 folder=Path(folder)
 before_raw=read(folder/"namespace-before.json",inputs)
 safe.need(safe.same(safe.identity(before_raw),row["namespace_before"]),"Actual initial namespace identity")
 before=load(before_raw)
 safe.need(type(before) is dict and before and safe.same(before,row["namespace"]),"Actual namespace changed during live owner")
 relative=safe.relative(row["namespace_directory"]);root=folder.parent/relative
 names=sorted(p.name for p in root.iterdir())
 safe.need(names==sorted(before),"Whole retained namespace roster")
 for name,entry in before.items():
  safe.need(safe.relative(name).name==name and set(entry)=={"identity","inode","device","mode","size"},"Exact namespace metadata")
  for field in ("inode","device","mode","size"):safe.need(type(entry[field]) is int and entry[field]>=0,"Exact observed namespace integer")
  safe.need(entry["inode"]>0 and stat.S_ISREG(entry["mode"]),"Observed regular namespace")
  raw=read(root/name,inputs)
  safe.need(safe.same(safe.identity(raw),entry["identity"]) and len(raw)==entry["size"],"Retained namespace bytes differ")

def admit(group,artifacts):
 if group=="node":
  from .node_observations import collect
  safe.need(set(artifacts)=={"node"},"Exact Node native partition")
  cases,rows,bound=collect(artifacts["node"])
  return {"histories":len(cases),"methods":sum(len(c["actions"]) for c in cases),"validations":0,"cross_histories":0,"cross_methods":0},bound
 from .observations import collect
 from .cross_observations import collect as cross
 safe.need(group=="m05" and set(artifacts)=={"smoke","boundaries","capacity","cross"},"Exact M05 native partitions")
 cases,rows,bound=collect({k:artifacts[k] for k in ("smoke","boundaries","capacity")})
 case,observed,extra=cross(artifacts["cross"])
 for path,row in extra.items():
  if path in bound:safe.need(safe.same(bound[path],row),"Native partitions disagree on input bytes")
  bound[path]=row
 return {"histories":len(cases),"methods":sum(len(c["actions"]) for c in cases),"validations":sum(a["op"]=="validate" for c in cases for a in c["actions"]),"cross_histories":1,"cross_methods":len(case["actions"])},bound

def main(argv=None):
 import argparse,json,time,traceback
 safe.need(__debug__,"Optimized Python is not admitted")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--group",required=True,choices=("m05","node"))
 for name in ("smoke","boundaries","capacity","node","cross"):p.add_argument("--"+name,type=Path)
 p.add_argument("--report",required=True,type=Path);a=p.parse_args(argv)
 safe.need(not a.report.exists() and not a.report.is_symlink() and ROOT not in a.report.absolute().parents,"Fresh independent native admission report")
 captured=None;bound={};counts=None;failure=None;after=[];start=time.monotonic_ns()
 try:
  captured=source_manifest()
  counts,bound=admit(a.group,{k:getattr(a,k) for k in ("smoke","boundaries","capacity","node","cross") if getattr(a,k) is not None})
 except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
 finally:
  if captured is not None:
   try:safe.need(safe.same(source_manifest(),captured),"Native reader source changed")
   except BaseException as e:after.append(repr(e))
  for path,row in bound.items():
   try:safe.need(safe.same(safe.file_identity(path),row),"Observed native input changed "+path)
   except BaseException as e:after.append(repr(e))
  report={"schema":"trnm.mempool-node-native-admission.v1","group":a.group,"status":"PASS" if failure is None and not after else "FAIL",
   "failure":failure,"source_inputs":captured,"source_set_sha256":None if captured is None else safe.identity(safe.canonical(captured))["sha256"],
   "source_after":{"status":"NOT_CAPTURED" if captured is None else ("MATCH" if not after else "FAIL"),"errors":after},
   "counts":counts,"actual_input_files":bound,"elapsed_ns":time.monotonic_ns()-start,"native_execution":False,"original_execution":False}
  safe.write_json(a.report,report)
 print(json.dumps({k:report[k] for k in ("schema","group","status","failure","counts","source_after")},sort_keys=True))
 if report["status"]!="PASS":raise SystemExit(1)

def trace_capture(folder,inputs):
 """Require the captured traced process to start and retire; not a syscall policy oracle."""
 from .observations import read
 import re
 raw=read(Path(folder)/"syscalls.raw",inputs)
 safe.need(raw and raw.endswith(b"\n"),"Complete actual trace capture")
 lines=raw.decode("ascii").splitlines()
 first=re.fullmatch(r"(?:(\d+)\s+)?execve\(.*\)\s+=\s+0",lines[0])
 safe.need(first is not None,"Actual traced executable start")
 tail=lines[-1]
 annotation=re.fullmatch(r"(?:(\d+)\s+)?\+\+\+ exited with 0 \+\+\+",tail)
 if annotation is not None:
  safe.need(annotation.group(1)==first.group(1) and len(lines)>1,"Traced exit annotation")
  tail=lines[-2]
 last=re.fullmatch(r"(?:(\d+)\s+)?exit(?:_group)?\(0\)\s+=\s+\?",tail)
 safe.need(last is not None and last.group(1)==first.group(1),"Actual traced owner retirement")
 return {"bytes":len(raw),"sha256":safe.identity(raw)["sha256"],"owner_pid":first.group(1)}

if __name__=="__main__":main()
