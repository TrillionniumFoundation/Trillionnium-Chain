"""Run unchanged original PaidCPU methods and actual scoped threads on a complete native bundle."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import traceback
from hia.platform.build import new_output
from hia.platform.transport_request.rust_oracle import command
from hia.platform.thread_cpu.rust_oracle import original_manifest,locked_clock_dependency
from .build import ROOT,HERE,need,digest,identity,read_json,write_json,source_manifest,unique
from .qualify import validate_bundle
from .dependency import captured_std,environment,bound_build_environment,executable_interpreter
from .fault_oracle import compare_original_faults

ORIGINAL="trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs"
ORIGINAL_SHA="799cfe0fab3fb8e0b3796eee7748cb63a98c02b74d3083af98b4368c5895e384"
HOOK="hia_paid_cpu_account_oracle.rs"
DECLARATION=b'\n#[cfg(all(test, target_os = "linux"))]\nmod hia_paid_cpu_account_oracle {\n    include!("hia_paid_cpu_account_oracle.rs");\n}\n'
PREFIX="ingress::public_v3::scalar_cpu::hia_paid_cpu_account_oracle::"
MARKER="HIA_PAID_CPU_ORACLE:"
sha=digest
def records(raw):
 return [json.loads(line.split(MARKER,1)[1],object_pairs_hook=unique) for line in raw.decode().splitlines() if MARKER in line]
def expected_operation(event,index):
 result={'settled':event['expected_settled']} if event['kind']=='settle_observed' else {'error':event['expected_error']}
 return {'index':index,'kind':event['kind'],'result':result}
def compare_real(value,case,bundle):
 need(value['kind']=='domain-positive' and value['label']==case['label']
      and value['actual_original_domain_and_scoped_intervals'] is True
      and value['complete_original_block_executor'] is False,'Original real fixture identity differs')
 plan=case['plan'];owners=value['owners']
 need([o['request'] for o in owners]==list(range(plan['requests'])),'Original actual owner roster differs')
 comparisons=[]
 for owner in owners:
  request=owner['request'];p=plan['profiles'][request];receipt=owner['receipt']
  count=min(p['workers'],p['txs']);count=count if count>1 else 0
  need(all(receipt[k]==count for k in ('spawned_workers','started_workers','finished_workers','known_workers')),'Original real worker lifecycle count differs')
  need(receipt['accounting_unavailable'] is False and receipt['live_refused'] is False,'Original real positive accounting unknown')
  cpu=receipt['owner_cpu_ns'];workers=receipt['scoped_worker_cpu_ns'];full=receipt['total_cpu_ns'];live=receipt['live_paid_cpu_ns'];residual=receipt['residual_cpu_ns']
  need(all(type(x) is int and 0<=x<(1<<64) for x in (cpu,workers,full,live,residual)) and cpu>0,'Original actual CPU unavailable')
  need((workers>0)==(count>0) and full==cpu+workers and residual==full-live,'Original unique residual accounting differs')
  native=struct.unpack('<192Q',(bundle/'raw/owners'/case['label']/'stdout.raw').read_bytes())[(request+1)*64:(request+2)*64]
  need(owner['work_rows']==[[i,native[24+i]] for i in range(p['txs'])],'Original and actual HIA body work differs')
  comparisons.append({'request':request,'status':'PASS','actual_original_cpu_ns':cpu,
    'actual_original_worker_cpu_ns':workers,'actual_original_total_ns':full,'actual_original_live_ns':live,
    'actual_original_residual_ns':residual,'scoped_workers':count,
    'same_work_bytes_and_accounting_invariants':True,'exact_ns_equal_to_independent_native':False})
 flow=value['flow']
 need(flow['balance_identity_verified'] is True and flow['live_owners']==0
      and flow['booked_reservation_ns']==0 and flow['unsettled_known_live_cpu_ns']==0,'Original real shared account did not settle')
 need(flow['paid_cpu_debit_ns']==sum(r['actual_original_total_ns'] for r in comparisons)
      and flow['settled_full_cpu_ns']==flow['paid_cpu_debit_ns'],'Original actual shared debit differs')
 return {'label':case['label'],'status':'PASS','owners':comparisons,'actual_original_flow':flow}



def target_directory(target_dir,repository,output):
 target=(target_dir or output/"cargo-target").resolve()
 isolated=(output/"isolated-source").resolve()
 for forbidden in (repository.resolve(),ROOT.resolve(),isolated):
  need(target!=forbidden and forbidden not in target.parents,
       "Original Cargo target must be outside source repositories and isolated source")
 return target

def original_comparison(repository,bundle,output,target_dir=None):
 report={"schema":"trnm.hia.paid-cpu-original-comparison.v1","status":"FAIL","stages":[],
  "whole_paid_account_closed":False,"public_request_node_service_closed":False,
  "complete_original_block_executor_executed":False,"original_production_source_changed":False}
 fence=None;binary=None;binary_identity=None;dependency=None;events=None;stages=report["stages"]
 try:
  # Admit complete current source sets and every raw native case before Cargo,
  # dependency discovery, an original source copy, or any reference execution.
  environment()
  target=target_directory(target_dir,repository,output)
  native=validate_bundle(bundle,repository)
  sources=source_manifest();original=original_manifest(repository)
  need(original[ORIGINAL]["sha256"]==ORIGINAL_SHA,"Complete original budget source differs")
  standard=captured_std();env=bound_build_environment(standard)
  report["actual_build_tools"]={key:standard[key] for key in ("compiler_executable","cargo_executable")}
  report["explicit_compiler_environment"]={key:env[key] for key in ("RUSTUP_TOOLCHAIN","RUSTC","CARGO","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER")}
  cases=[{"label":row["name"],"plan":row["plan"],**row["trace"]["replay"]} for row in native["owners"]]
  exact_input={"schema":"trnm.hia.paid-cpu-original-replay.v1","cases":cases,
   "boundaries":read_json(bundle/"cases.json")["boundaries"],
   "native_public_abi_accepts_counters":False,"full_node_or_public_intake_closed":False}
  write_json(output/"inputs.json",exact_input)
  hook=(HERE/"rust_reference.rs").read_bytes()
  original_head=subprocess.check_output(["git","-C",str(repository),"rev-parse","HEAD"],text=True,timeout=20).strip()
  isolated=output/"isolated-source";isolated.mkdir(mode=0o700)
  for relative,expected in original.items():
   src=repository/relative;need(identity(src)==expected,"Original source changed before copy: "+relative)
   dest=isolated/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
  inclusion=isolated/ORIGINAL;prefix=inclusion.read_bytes()
  need(digest(prefix)==ORIGINAL_SHA and b"mod hia_paid_cpu_account_oracle" not in prefix,"Original production prefix was already changed")
  need(not (inclusion.parent/HOOK).exists(),"Private child would replace an original file")
  (inclusion.parent/HOOK).write_bytes(hook);inclusion.write_bytes(prefix+DECLARATION)
  native_identity=identity(bundle/"native-comparison.json");input_identity=identity(output/"inputs.json")
  before={"schema":"trnm.hia.paid-cpu-original-source-binding.v1","source_inputs":sources,
   "original_sources":original,"original_repository_head":original_head,"standard_library":standard,
   "native_comparison":native_identity,"input":input_identity,
   "private_hook":{"bytes":len(hook),"sha256":digest(hook)},
   "original_production_prefix":original[ORIGINAL],"appended_private_cfg_test_child_hex":DECLARATION.hex()}
  write_json(output/"source-before.json",before)
  def check():
   need(source_manifest()==sources,"Current PaidCPU complete source closure changed")
   need(original_manifest(repository)==original,"Original complete graph changed")
   need(captured_std()==standard,"Actual original standard-library sources or binaries changed")
   need(identity(bundle/"native-comparison.json")==native_identity,"Admitted native report changed")
   validate_bundle(bundle,repository)
   need(identity(output/"inputs.json")==input_identity,"Original comparison inputs changed")
   need((HERE/"rust_reference.rs").read_bytes()==hook,"Private original adapter changed")
   for relative,expected in original.items():
    path=isolated/relative
    if relative==ORIGINAL:
     raw=path.read_bytes();need(raw==prefix+DECLARATION,"Complete isolated original prefix/declaration changed")
    else:need(identity(path)==expected,"Isolated original graph changed: "+relative)
   need((inclusion.parent/HOOK).read_bytes()==hook,"Compiled private child differs from source binding")
   if binary is not None:need(identity(binary)==binary_identity,"Independent original executable changed")
   if dependency is not None:need(locked_clock_dependency(isolated,events)==dependency,"Actual locked rustix dependency changed")
  fence=check;check()
  def call(argv,label,timeout=180,runtime=None):
   try:
    raw,row=command(argv,isolated,output,label,timeout=timeout,env=env if runtime is None else runtime)
    stages.append(row);return raw
   except BaseException:
    path=output/label/"receipt.json"
    if path.exists():stages.append(read_json(path))
    raise
  need(target_directory(target_dir,repository,output)==target,"Original target changed after source admission")
  raw=call([standard["cargo_executable"]["path"],"test","--locked","--manifest-path",str(isolated/"trillionnium/Cargo.toml"),
   "-p","trnm-pon-node","--lib","--no-run","--message-format=json","--target-dir",str(target)],
   "cargo-original-test-build",900)
  events=[json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
  artifacts=[e for e in events if e.get("reason")=="compiler-artifact" and e.get("target",{}).get("name")=="trnm_pon_node"
             and e.get("executable") and e["profile"].get("test")]
  need(len(artifacts)==1,"No unique complete original Node test executable")
  compiled=Path(artifacts[0]["executable"]).resolve(strict=True);binary_identity=identity(compiled)
  binary=output/"original-test-binary";shutil.copyfile(compiled,binary);binary.chmod(0o500)
  need(identity(binary)==binary_identity and binary.stat().st_nlink==1,"Independent original binary copy differs")
  report["executable"]={"path":str(binary),**binary_identity};report["compiled_executable"]={"path":str(compiled),**binary_identity}
  report["original_interpreter"]=executable_interpreter(binary,standard)
  dependency=locked_clock_dependency(isolated,events);report["locked_clock_dependency"]=dependency
  crate=Path(dependency["crate"]["path"]);retained=output/("locked-rustix-"+dependency["version"]+".crate")
  shutil.copyfile(crate,retained);need(identity(retained)=={key:dependency["crate"][key] for key in ("bytes","sha256")},"Locked dependency archive copy differs")
  report["retained_clock_dependency_crate"]={"path":str(retained),**identity(retained)}
  check()
  listed=call([str(binary),"--list"],"list-original-tests",30)
  tests={line.removesuffix(": test") for line in listed.decode().splitlines() if line.endswith(": test")}
  required={PREFIX+suffix for suffix in ("original_budget_trace_replays","original_real_scoped_profiles",
   "linux_clocks_are_mandatory","original_private_arithmetic_boundaries","original_actual_fault_profile")}
  need(required<=tests,"Actual original comparison tests were not linked")
  retained_groups=[]
  runtime={"PATH":env.get("PATH","/usr/bin:/bin"),"TRNM_HIA_PAID_CPU_REPLAYS":str(output/"inputs.json")}
  for prefix_name,label in [
   ("ingress::public_v3::scalar_cpu::tests::","retained-original-scalar-tests"),
   ("ingress::public_v3::scalar_cpu::flow_tests::","retained-original-flow-tests")]:
   names=sorted(name for name in tests if name.startswith(prefix_name));need(names,"Original retained test group missing")
   observed=call([str(binary),prefix_name,"--nocapture","--test-threads=1"],label,240,runtime)
   summary=re.search(r"test result: ok\. (\d+) passed; 0 failed;",observed.decode())
   need(summary is not None and int(summary[1])==len(names),"Original retained tests did not all execute")
   retained_groups.append({"prefix":prefix_name,"names":names,"passed":len(names)})
  report["retained_original_tests"]=retained_groups;report["retained_original_passed"]=sum(g["passed"] for g in retained_groups)
  raw=call([str(binary),"--exact",PREFIX+"linux_clocks_are_mandatory","--nocapture","--test-threads=1"],
   "mandatory-original-linux-clocks",30,runtime)
  available=records(raw);need(len(available)==1 and available[0]["kind"]=="linux-positive"
    and available[0]["clock_failure_cannot_skip"] is True,"Mandatory original Linux clocks did not execute")
  report["mandatory_original_linux_positive"]=available[0]
  raw=call([str(binary),"--exact",PREFIX+"original_budget_trace_replays","--nocapture","--test-threads=1"],
   "actual-original-budget-replays",90,runtime)
  observed=records(raw);need([r["label"] for r in observed]==[r["label"] for r in cases],"Original budget replay corpus missing/reordered")
  comparisons=[]
  for actual,case in zip(observed,cases,strict=True):
   expected=[expected_operation(event,index) for index,event in enumerate(case["operations"])]
   same=actual["kind"]=="budget-replay" and actual["operations"]==expected and actual["final"]==case["expected_final"]
   comparisons.append({"label":case["label"],"status":"PASS" if same else "FAIL","actual_original":actual,
    "expected_native_final":case["expected_final"],"expected_native_operation_results":expected})
  write_json(output/"budget-comparison.json",{"cases":comparisons});report["budget_comparisons"]=comparisons
  need(all(r["status"]=="PASS" for r in comparisons),"Actual original complete budget method differential failed")
  report["actual_original_budget_calls"]=sum(len(case["operations"]) for case in cases)
  need(report["actual_original_budget_calls"]==native["actual_budget_operations"],"Actual original/native method event count differs")
  raw=call([str(binary),"--exact",PREFIX+"original_private_arithmetic_boundaries","--nocapture","--test-threads=1"],
   "actual-original-arithmetic-boundaries",90,runtime)
  observed=records(raw);need([r["name"] for r in observed]==[r["name"] for r in native["boundaries"]],"Original boundary corpus missing/reordered")
  boundaries=[]
  for actual,expected in zip(observed,native["boundaries"],strict=True):
   need(actual["kind"]=="private-boundary" and actual["original_complete_methods_executed"] is True
        and actual["production_runtime_counter_abi"] is False,"Private arithmetic fixture was relabeled runtime authority")
   boundaries.append({"name":actual["name"],"status":"PASS" if actual["comparison"]==expected["comparison"] else "FAIL",
    "actual_original":actual,"actual_native":expected["comparison"]})
  write_json(output/"boundary-comparison.json",{"cases":boundaries});report["boundary_comparisons"]=boundaries
  need(all(r["status"]=="PASS" for r in boundaries),"Actual original 128-bit arithmetic differential failed")
  report["actual_original_boundary_cases"]=len(boundaries)
  trace=output/"actual-original-scoped-clocks.trace";tracer=shutil.which("strace");need(tracer is not None,"Original actual working-thread trace requires strace")
  raw=call([tracer,"-f","-qq","-v","-s","65536","-o",str(trace),"--",str(binary),
   "--exact",PREFIX+"original_real_scoped_profiles","--nocapture","--test-threads=1"],
   "actual-original-real-scoped-profiles",240,runtime)
  observed=records(raw);warm=[case for case in cases if not case["cold"]]
  need([r["label"] for r in observed]==[r["label"] for r in warm],"Original real scoped profiles missing/reordered")
  real=[compare_real(actual,case,bundle) for actual,case in zip(observed,warm,strict=True)]
  write_json(output/"real-scope-comparison.json",{"cases":real});report["actual_original_real_profiles"]=real
  clock_rows=re.findall(r"^(\d+)[ \t]+clock_gettime\(CLOCK_THREAD_CPUTIME_ID,",trace.read_text(),re.M)
  need(len(set(clock_rows))>=8,"Actual original CPU calls not observed in its working threads")
  report["actual_original_trace"]={"path":str(trace),**identity(trace),"direct_clock3_call_starts":len(clock_rows),
   "actual_clock3_tids":sorted(set(map(int,clock_rows))),"clock1_vdso_may_not_emit_syscalls":True,
   "complete_original_runtime_syscall_whitelist_claimed":False}
  check()
  faults=compare_original_faults(binary,output/"fault-differential",bundle,repository)
  report["actual_original_faults"]={"path":str(output/"fault-differential/report.json"),**identity(output/"fault-differential/report.json"),
   "status":faults["status"],"cases":len(faults["cases"]),"private_no_vdso_platform_fixture":True}
  need(faults["status"]=="PASS" and len(faults["cases"])==13,"Actual original fault differential failed")
  check()
  report.update(status="PASS",source_inputs=sources,original_sources=original,standard_library=standard,
   native_owner_histories=len(cases),actual_original_owner_profiles=len(real),actual_original_fault_histories=13,
   input=input_identity,native_comparison=native_identity,source_before=identity(output/"source-before.json"),
   original_production_prefix=original[ORIGINAL],appended_private_cfg_test_child_hex=DECLARATION.hex(),
   private_reference_sha256=digest(hook),original_repository_modified=False,
   ordinary_vdso_negatives_not_claimed=True)
 except BaseException as error:report.update(failure=repr(error),traceback=traceback.format_exc())
 finally:
  if fence is not None:
   try:fence();report["source_after"]="MATCH";report["binary_after"]="MATCH" if binary is not None else "NOT_BUILT"
   except BaseException as error:report.update(status="FAIL",source_after="FAIL",source_after_failure=repr(error))
  else:report["source_after"]="ADMISSION_DID_NOT_COMPLETE"
  write_json(output/"report.json",report)
 return report

def main():
 need(__debug__,"PaidCPU original comparison refuses optimized Python")
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--output",type=Path,required=True)
 parser.add_argument("--original-root","--repository",dest="original_root",type=Path,default=ROOT)
 parser.add_argument("--target-dir",type=Path)
 args=parser.parse_args();output=new_output(args.output)
 result=original_comparison(args.original_root.resolve(strict=True),args.bundle.resolve(strict=True),output,args.target_dir)
 print(json.dumps({key:result.get(key) for key in ("status","actual_original_budget_calls","actual_original_boundary_cases",
  "actual_original_owner_profiles","actual_original_fault_histories","retained_original_passed","source_after","binary_after","failure")},sort_keys=True))
 if result["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
