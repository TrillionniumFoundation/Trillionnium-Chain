"""Actual held Node / Parent / Prepared qualification; all four Settings."""
from pathlib import Path
import argparse,json,struct,time,traceback
from . import safe,suite_smoke as io
from .build import ROOT,validate_build,source_manifest
from .node_cases import histories,canonical_bytes,transaction
from .node_observers import *
identity=safe.identity

def fence():
 safe.need(safe.same(source_manifest(),observed_sources),"Native source changed")
 validate_build(BUILD.parent)

def execute(case):
 owned=OUT/(case["name"]+"-owned");owned.mkdir(mode=0o700)
 s=Session(case["name"],owned,0,case["timestamp"],case["workers"])
 first=ready(s.frame());ctx=first[160:];actual_context=context(ctx)
 s.command(1);base=state(s.frame())[16:]
 s.command(3);actual_parent=parent(s.frame())
 rows=[];last=None;seq=0;retained_prepared=None;retained_raw=None;parent_map=None;parent_payload=None
 for index,action in enumerate(case["actions"]):
  op=action["op"];raws=[]
  if op=="new":
   ts=action["timestamp"];input_frame(s,4,struct.pack("<QQ",int(ts is not None),0 if ts is None else ts)+bytes.fromhex(action["miner_hex"]));code=5
  elif op=="drop":input_frame(s,7);code=4
  elif op=="execute":
   raws=[transaction(k,bytes.fromhex(actual_context["network_hex"])) for k in action["transactions"]]
   input_frame(s,5,struct.pack("<Q",len(raws))+b"".join(struct.pack("<Q",len(r))+r for r in raws));code=2
  else:raise ValueError("Source case operation")
  seq+=1;row=parse_prefix(s.frame(),code,ctx,seq);row.update(index=index,op=op,transactions=[r.hex() for r in raws])
  if row["outcome"]!="ok" and last is not None:
   need((row["held_state_hex"],row["length"],row["header"][9],row["private_receipts"])==(last["held_state_hex"],last["length"],last["header"][9],last["private_receipts"]),"Full retained state rollback")
  if op=="drop":need(row["header"][28]==2 and not row["ready"],"Scoped drop snapshot contains base and its Node-owned canonical parent before Node retirement")
  if op=="new" and row["outcome"]=="ok":
   parent_map,parent_payload=observed_parent_map(s,actual_parent)
   need(parent_map["bind_seq"]==seq,"Parent bound to actual constructor sequence")
  if op=="execute":
   if row["outcome"]=="ok":
    retained_prepared,retained_raw=observed_prepared(s,parent_map["rows"])
    need(retained_prepared["root_hex"]==row["root_hex"],"Actual Prepared and Output root differ")
   elif retained_prepared is not None:
    unchanged,unchanged_raw=observed_prepared(s,parent_map["rows"])
    need(unchanged==retained_prepared and unchanged_raw==retained_raw,"Failed Prefix replaced prior actual Prepared owner")
  elif op=="drop":
   retained_prepared=None;retained_raw=None
  if row["ready"]:
   actual_map,actual_map_payload=observed_parent_map(s,actual_parent)
   need(actual_map==parent_map and actual_map_payload==parent_payload,"Fixed parent map changed or borrow survived")
  if op=="drop" or (op=="new" and not row["ready"]):parent_map=None;parent_payload=None
  row["canonical_parent"]=parent_map
  row["canonical_parent_payload_hex"]=None if parent_payload is None else parent_payload.hex()
  row["prepared"]=retained_prepared
  row["prepared_owner_payload_hex"]=None if retained_raw is None else retained_raw.hex()
  rows.append(row);last=row
  print(json.dumps({"case":case["name"],"index":index,"outcome":row["outcome"],"error":row["error"],"length":row["length"]}),flush=True)
 s.command(1);need(state(s.frame())[16:]==base,"Canonical actual base changed")
 s.command(3);need(parent(s.frame())==actual_parent,"Actual parent source changed")
 s.command(2);need(s.frame()==b"NBCLOSE1"+bytes(8),"Complete owner retirement")
 receipt=s.finish(0)
 cold=Session(case["name"]+"-cold",owned,1,case["timestamp"],case["workers"])
 cold_ready=ready(cold.frame());need(cold_ready==first,"Cold context differs")
 cold.command(1);need(state(cold.frame())[16:]==base,"Actual cold State changed")
 cold.command(3);need(parent(cold.frame())==actual_parent,"Actual cold parent changed")
 cold.command(2);need(cold.frame()==b"NBCLOSE1"+bytes(8),"Cold complete close")
 cold_receipt=cold.finish(0)
 return {"name":case["name"],"status":"PASS","context":actual_context,"base_hex":base.hex(),"parent":actual_parent,
         "actions":rows,"base_unchanged":True,"cold_source_equal":True,"first_process":receipt,"cold_process":cold_receipt}

def main(argv=None):
 global OUT,BUILD,build,elf_path,elf,sessions,cleanup_errors,failure,after_errors,controls,start,Session,ready,state,input_frame,observed_sources
 safe.need(__debug__,"Optimized Python refused")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",required=True,type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args(argv)
 OUT=safe.new_output(a.output,ROOT);BUILD=a.build.absolute()/"build.json";build=validate_build(BUILD.parent)
 elf_path=BUILD.parent/"owner.elf";elf=safe.read(BUILD.parent,"owner.elf")
 sessions=[];cleanup_errors=[];failure=None;after_errors=[];controls=[];start=time.monotonic_ns()
 observed_sources=source_manifest()
 io.OUT=OUT;io.build_path=BUILD;io.build=build;io.elf_path=elf_path;io.elf=elf;io.sessions=sessions;io.cleanup_errors=cleanup_errors
 Session=io.Session;ready=io.ready;state=io.state;input_frame=io.input_frame
 try:
  fence();(OUT/"corpus.jsonl").write_bytes(canonical_bytes())
  for case in histories():controls.append(execute(case))
  need(len(controls)==4 and sum(len(c["actions"]) for c in controls)==96 and len(sessions)==8,"Complete four Settings / 96 methods")
 except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
 finally:
  for session in sessions:
   try:session.abort()
   except BaseException as e:cleanup_errors.append({"name":session.directory.name,"error":repr(e)})
  try:fence()
  except BaseException as e:after_errors.append(repr(e))
  report={"schema":"trnm.node-canonical-parent-private-semantic.v1","status":"PASS" if failure is None and not cleanup_errors and not after_errors else "FAIL",
   "failure":failure,"cleanup_errors":cleanup_errors,"source_after":{"status":"MATCH" if not after_errors else "FAIL","errors":after_errors},
   "source_inputs":observed_sources,"build":identity(BUILD.read_bytes()),"executable":identity(elf),"corpus":identity(canonical_bytes()),
   "controls":controls,"controls_total":len(controls),"real_processes":len(sessions),"elapsed_ns":time.monotonic_ns()-start,
   "scope":{"actual_private_disk_state_source":True,"actual_settings_some":True,"caller_state_or_root":False,"runtime_host_proxy":False,
   "original_rust":"NOT_RUN","successor_admission":False,"node_commit":False,"complete_node":False,"private_finalized_state_ownership":True,
   "prepared_commitment_none_prior":True,"full_prepared_observation":True,"canonical_parent_owned_once_per_prefix":True,"prepared_retains_before_map":False,"checked_apply_some_prior":False}}
  safe.write_json(OUT/"report.json",report)
  print(json.dumps({k:report[k] for k in ("status","controls_total","real_processes","failure","cleanup_errors","source_after")}),flush=True)
  if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
