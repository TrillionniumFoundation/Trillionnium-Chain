"""Actual one-Node M05 / Parent / Prepared cross lifecycle."""
from pathlib import Path
import argparse,json,struct,traceback,time
from . import safe,suite_smoke as m
from .build import ROOT,source_manifest,validate_build
def node(s,op,payload=b"",method=None):
 m.input_frame(s,op,payload)
 if method is None:return s.frame()
 r=m.prefix_frame(s,method,ctx);observations.append({"name":"node-op"+str(op),"result":r});return r

def observe_parent_and_prepared(s,result):
 parent=node(s,10);prepared=node(s,9)
 m.need(parent[:8]==b"NPCPARV1" and struct.unpack_from("<Q",parent,8)[0]==len(parent)-16,"Actual canonical Parent observation")
 m.need(prepared[:8]==b"NPCVIEW1" and struct.unpack_from("<Q",prepared,8)[0]==len(prepared)-16,"Actual Prepared observation")
 m.need(parent[16:24]==b"NPCPAR01" and prepared[16:24]==b"NPCDATA2","Typed owner observations")
 m.need(struct.unpack_from("<Q",parent,176)[0]==1,"Returned Prepared retained Parent borrow")
 prefix=bytes.fromhex(result["raw_hex"])
 m.need(prepared[144:176]==prefix[168:200],"Actual Prepared root differs from final Output")
 observations.append({"name":"real-parent-and-prepared","parent_hex":parent.hex(),"prepared_hex":prepared.hex()})

def main(argv=None):
 global observations,failure,after,start,ctx
 safe.need(__debug__,"Optimized Python refused")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",required=True,type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args(argv)
 m.OUT=safe.new_output(a.output,ROOT);m.build_path=a.build.absolute()/"build.json";m.build=validate_build(m.build_path.parent)
 m.elf_path=m.build_path.parent/"owner.elf";m.elf=safe.read(m.build_path.parent,"owner.elf")
 m.sessions=[];m.controls=[];m.cleanup_errors=[];m.driver_sources=source_manifest()
 observations=[];failure=None;after=[];start=time.monotonic_ns()
 try:
  m.sources();owned=m.OUT/"owned";owned.mkdir(mode=0o700)
  s=m.PoolSession("single-owner-cross-lifecycle",owned,0,None)
  first=m.ready(s.frame());ctx=first[160:]
  s.command(1);base=m.state(s.frame());disk=m.snapshot(owned)
  parent_record=node(s,3)
  node(s,4,struct.pack("<QQ",0,0)+m.public(0),5)
  result=node(s,5,struct.pack("<Q",0),2);observe_parent_and_prepared(s,result)
  dropped=node(s,7,b"",4);m.need(dropped["header"][28]==2,"Node drop retained base and Parent until actual Node retirement")
  s.start_action("pool-open-after-real-node-prefix-drop");m.pool_open(s,m.public(0))
  m.validate(s,"cancel-new-drops-real-parent",[],expected=3,error=0,calls=0,reused=0,signatures=0,cancel={"magic":"PXPROG01","kind":10,"class":1,"token":6101})
  m.validate(s,"retry-after-parent-consumed",[],calls=0,reused=0,signatures=0)
  raw=m.wire(1,m.public(1)+struct.pack("<Q",7),nonce=1,network=ctx[24:56])
  m.validate(s,"real-ready-on-rebound-parent",[raw],calls=1,reused=0,signatures=1)
  s.start_action("pool-drop-before-node-prefix-reentry");m.input_frame(s,8,struct.pack("<Q",3));pooldrop=m.pool_result(s.frame(),3,1)
  m.need(pooldrop["header"][6]==0,"Pool did not release View")
  node(s,4,struct.pack("<QQ",0,0)+m.public(0),5)
  result=node(s,5,struct.pack("<Q",1)+struct.pack("<Q",len(raw))+raw,2);observe_parent_and_prepared(s,result)
  node(s,7,b"",4)
  s.start_action("pool-fresh-for-panic");m.pool_open(s,m.public(0))
  m.validate(s,"panic-new-drops-real-parent",[],expected=4,error=0,calls=0,reused=0,signatures=0,cancel={"magic":"PXPROG01","kind":10,"class":2,"token":6102})
  m.validate(s,"retry-after-parent-panic",[],calls=0,reused=0,signatures=0)
  s.start_action("last-pool-drop");m.input_frame(s,8,struct.pack("<Q",3));m.pool_result(s.frame(),3,1)
  s.command(1);m.need(m.state(s.frame())==base,"Cross-method canonical base mutated")
  m.need(node(s,3)==parent_record,"Held parent record changed")
  s.command(2);m.need(s.frame()==b"NBCLOSE1"+bytes(8),"Whole owner failed to retire")
  receipt=s.finish(0);m.need(m.snapshot(owned)==disk,"Cross-method persistent namespace changed")
  observations.append({"name":"complete-retirement-and-source-unchanged","receipt":receipt,"base_hex":base.hex(),"record_hex":parent_record.hex()})
  m.need([x["name"] for x in observations]==["node-op4","node-op5","real-parent-and-prepared","node-op7","node-op4","node-op5","real-parent-and-prepared","node-op7","complete-retirement-and-source-unchanged"],"Exact actual cross-method observation roster")
  m.need(len(m.controls)==5,"Exact joint pool control roster")
 except BaseException as e:
  failure={"error":repr(e),"traceback":traceback.format_exc()}
 finally:
  for s in m.sessions:
   try:s.abort()
   except BaseException as e:m.cleanup_errors.append({"error":repr(e)})
  try:m.sources()
  except BaseException as e:after.append(repr(e))
  report={"schema":"trnm.single-node-m05-C-cross-lifecycle.v1","status":"PASS" if failure is None and not m.cleanup_errors and not after else "FAIL","failure":failure,"cleanup_errors":m.cleanup_errors,"source_after":{"status":"MATCH" if not after else "FAIL","errors":after},"build":m.identity(m.build_path.read_bytes()),"executable":m.identity(m.elf),"source_inputs":m.driver_sources,"m05_controls":m.controls,"observations":observations,"real_processes":len(m.sessions),"elapsed_ns":time.monotonic_ns()-start,"scope":"Actual one-Node cross-method Parent/Prepared/Ready ownership; standalone original cross-history NOT_RUN"}
  (m.OUT/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:report[k] for k in ("status","failure","cleanup_errors","source_after","real_processes","elapsed_ns")},sort_keys=True),flush=True)
  if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
