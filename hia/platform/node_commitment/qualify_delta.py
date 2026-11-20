"""Actual 65,536/65,537 delta boundary with the original 240-second runtime contract.

Bulk construction calls native State allocation/insertion. Complete State rows,
changes, shared tree leaves, root inputs and final retirement are observed.
"""
from pathlib import Path
import argparse,ctypes,json,zlib,struct,time,traceback,mmap,hashlib,re
from hia.platform.execution_state.physical import Guarded
from hia.platform.execution_state.native_io import command,decode
from hia.platform.execution_state.cases import tape
from hia.platform.mempool_node.build import ROOT,validate_build,functions
from hia.platform.mempool_node.safe import new_output
from hia.platform.build import Build
from .qualify_snapshot import Image,public_snapshot,public_prepared
from hia.platform.mempool_node.node_observers import srv,value_capacity,charges,state_hash,lift,parse_shared,parse_snapshot,parse_some_prepared,EMPTY
ident=lambda b:{"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def need(condition,message):
 if not condition:raise AssertionError(message)
from .bounded import enter
enter("hia.platform.node_commitment.qualify_delta")
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build",required=True,type=Path);parser.add_argument("--output",required=True,type=Path)
parser.add_argument("--changes",required=True,type=int,choices=(65536,65537))
parser.add_argument("--sha-check",required=True,type=Path);parser.add_argument("--method-check",required=True,type=Path)
args=parser.parse_args();need(__debug__,"Optimized Python refused")
BUILD=args.build.absolute();OUT=new_output(args.output,ROOT);(OUT/"blobs").mkdir()
BEFORE=1;AFTER=args.changes-1;prior=validate_build(BUILD)
inputs={str(ROOT/name):value for name,value in prior["source_inputs"].items()}
inputs[str(BUILD/"build.json")]=ident((BUILD/"build.json").read_bytes())
for path,field,count in [(args.sha_check,"actual_calls",78),(args.method_check,"semantic_methods",94)]:
 raw=path.read_bytes();report=json.loads(raw)
 need(report["status"]=="PASS" and report[field]==count and report["build"]==inputs[str(BUILD/"build.json")],"Actual SHA/checked prequalification must bind the same complete Node build")
 inputs[str(path)]=ident(raw)
IMAGE_FILES={"state":"state","root":"root","prepared":"snapshot","legacy":"prepared","bulk":"bulk","tree":"tree"}
for role,file in IMAGE_FILES.items():
 if role=="bulk":continue
 path=BUILD/(file+".flat");need(ident(path.read_bytes())==prior["images"][file],"Exact actual Node image")
 inputs[str(path)]=ident(path.read_bytes())
table=functions((BUILD/"state-composed.hepta").read_bytes())
table["f0"]=functions((ROOT/"hia/platform/mempool_node/snapshot_capacity.hepta").read_bytes())["f0"]
used=set();todo=["f0"]
while todo:
 name=todo.pop()
 if name in used:continue
 used.add(name);todo.extend(m[1].decode() for m in re.finditer(rb'"function":"([^"]+)"',table[name]))
source=b"hia-asm.v1 hepta.hia.program.v8 trnm_snapshot_capacity_qualification\n"+b"".join(table[n] for n in ["f0"]+sorted(used-{"f0"}))
(OUT/"bulk-composed.hepta").write_bytes(source)
builder=Build(OUT/"compiler");flat=builder.stage(builder.compiler,source,"compile-bulk");builder.check_pin()
(OUT/"bulk.flat").write_bytes(flat)
fixture_build={"source":ident(source),"image":ident(flat),"stages":builder.stages,"compiler_sha256":hashlib.sha256(builder.compiler).hexdigest()}
for path in [OUT/"bulk-composed.hepta",OUT/"bulk.flat"]:inputs[str(path)]=ident(path.read_bytes())
def fence():
 validate_build(BUILD)
 for path,value in inputs.items():need(ident(Path(path).read_bytes())==value,"Source drift "+path)
fence()

class Actual:
 def __init__(self):
  self.images={k:Image((OUT/"bulk.flat" if k=="bulk" else BUILD/(IMAGE_FILES[k]+".flat")).read_bytes()) for k in IMAGE_FILES}
  self.heap=Guarded(65536);self.stream=open(OUT/"native-journal.jsonl","xb");self.blobs={};self.root_inputs=[];self.calls=0;self.roots=0;self.records=0;self.fixture=0
 def blob(self,raw):
  spec=ident(raw);name=spec["sha256"]+".zlib"
  if name not in self.blobs:
   compressed=zlib.compress(raw,1);p=OUT/"blobs"/name
   with p.open("xb") as f:f.write(compressed)
   self.blobs[name]={"raw":spec,"compressed":ident(compressed)}
  return {"path":"blobs/"+name,**self.blobs[name]}
 def log(self,row):
  if row.get("kind")=="root-start":self.root_inputs.append(row["input_bytes"])
  row=dict(row)
  for key in list(row):
   if key.endswith("_bytes") and isinstance(row[key],bytes):row[key[:-6]+"_raw"]=self.blob(row.pop(key))
   elif key.endswith("_hex"):row[key[:-4]+"_raw"]=self.blob(bytes.fromhex(row.pop(key)))
  raw=(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode()
  self.stream.write(raw);self.stream.flush();self.records+=1
 def q(self,o):return struct.unpack("<Q",ctypes.string_at(self.heap.address+o,8))[0]
 def invoke(self,role,raw,cap=512):
  e=Guarded(len(raw),raw,True);o=Guarded(cap,b"\x5b"*cap)
  try:
   active=role
   for iteration in range(64):
    hb=self.heap.read();ob=o.read();index=self.calls+1
    self.log({"kind":"call-start","index":index,"role":active,"input_bytes":raw,"output_before_bytes":ob,"heap_before_bytes":hb,"heap_capacity":self.heap.n})
    rc=self.images[active].fn(e.address,e.n,o.address,o.n,self.heap.address,self.heap.n);self.calls+=1
    self.log({"kind":"call-complete","index":index,"role":active,"return":rc,"input_after_bytes":e.read(),"output_after_bytes":o.read(),"heap_after_bytes":self.heap.read()})
    e.check();o.check();self.heap.check();need(e.read()==raw,"Readonly command changed")
    if rc==8:
     need(active=="prepared" and self.q(112)==8,"Actual private tree request source")
     active="tree";continue
    if rc==9:
     need(active=="tree" and self.q(112)==8 and self.q(136) not in (0,(1<<64)-1),"Actual private tree completion source")
     active="prepared";continue
    if rc==7:
     need(active=="prepared" and self.heap.read()==hb and o.read()==ob,"Fixed legacy delegation mutated capabilities")
     active="legacy";continue
    if rc==2:
     requested=self.q(80);need(requested>self.heap.n,"Actual growth request")
     n=(requested+65535)//65536*65536;new=Guarded(n);before=self.heap.read();ctypes.memmove(new.address,before,len(before));self.log({"kind":"actual-capability-grow","old_bytes":len(before),"new_bytes":n,"copied":ident(before),"prefix_equal":new.read()[:len(before)]==before});self.heap.close();self.heap=new;continue
    if rc==3:
     requested=self.q(88);need(requested>o.n,"Actual output request");o.close();o=Guarded(requested,b"\x5b"*requested);continue
    if rc==5:
     off=self.q(120);n=self.q(128);scratch_n=self.q(144);need(off+n<=self.heap.n and o.n>=96,"Actual root extent")
     root_in=self.heap.read()[off:off+n];ri=Guarded(n,root_in,True);ro=Guarded(32,b"\x7c"*32);rs=Guarded(scratch_n)
     try:
      self.log({"kind":"root-start","input_bytes":root_in,"scratch_bytes":scratch_n,"output_before_bytes":ro.read(),"pending_kind":self.q(112),"pending_owner":self.q(152),"changes_pointer":self.q(self.q(152)+88) if self.q(112) in (3,6) else 0})
      if self.q(112)==3:need(self.q(self.q(152)+88)==0,"Fallback changes allocated before actual complete root")
      if self.q(112)==6:need(self.q(self.q(152)+88)!=0,"Internal mismatch lost already allocated changes")
      root_start_ns=time.monotonic_ns()
      rr=self.images["root"].fn(ri.address,ri.n,ro.address,ro.n,rs.address,rs.n);root_elapsed_ns=time.monotonic_ns()-root_start_ns;self.roots+=1
      self.log({"kind":"root-complete","return":rr,"elapsed_ns":root_elapsed_ns,"output_bytes":ro.read(),"input_after":ident(ri.read()),"scratch_after":ident(rs.read())})
      ri.check();ro.check();rs.check();need(ri.read()==root_in,"Readonly root input changed")
      # The native caller trampoline performs these two exact moves after the real root returns.
      ctypes.memmove(o.address+64,ro.read(),32);ctypes.memmove(self.heap.address+136,struct.pack("<Q",rr),8)
      self.log({"kind":"native-root-return-trampoline","actual_root_return":rr,"actual_root_output_hex":ro.read().hex(),"heap_result_offset":136,"output_offset":64})
     finally:ri.close();ro.close();rs.close()
     continue
    output=o.read()
    if rc not in (1,4):return rc,output
    n=self.q(96) if rc==1 else 64
    need(64<=n<=len(output),"Actual reply extent")
    return rc,output[:n]
   raise AssertionError("Continuation did not settle")
  finally:e.close();o.close()
 def state(self,op,a=0,b=0,arg=0,key=b"",data=b"",status=0):
  rc,raw=self.invoke("state",command(op,a,b,arg,key,data)[8:])
  need(rc==(4 if op==26 else 1),("State native return",op,rc));out=decode(raw);need(out["status"]==status,("State status",op,out,status));return out
 def put(self,state,key,value):
  v=self.state(1,data=tape(value))["result"];old=self.state(8,a=state,b=v,key=key)["result"]
  if old:self.state(4,a=old)
 def state_rows(self,rows):
  s=self.state(5)["result"]
  for k,v in rows:self.put(s,k,v)
  return s
 def prepare(self,op,a,b=0,epoch=7,seq=11,height=1,status=0,limits=(65536,8388608,536870912),key=b"",override=None):
  if op==5:b=len(key)
  raw=b"NPCREQ01"+struct.pack("<7Q",op,a,b,epoch,seq,height,0)
  if op==1:raw+=struct.pack("<3Q",*limits)
  if op==5:raw+=key
  if override is not None:raw=override
  rc,out=self.invoke("prepared",raw);need(rc==1,("Prepared native return",rc));d=decode(out);need(d["status"]==status,("Prepared status",op,d,status));return d
 def finish(self):
  self.stream.close()
  for v in self.images.values():v.close()
  self.heap.close()

actual=None;failure=None;errors=[];observations={};started=time.monotonic_ns()
def call(op,a,b=0,seq=21,height=1,binding=0,root=None):
 raw=b"NPCREQ01"+struct.pack("<7Q",op,a,b,7,seq,height,binding)
 if op in (1,10,21):raw+=struct.pack("<3Q",65536,8388608,536870912)
 if op==21:raw+=root
 rc,out=actual.invoke("prepared",raw);need(rc==1,"Actual prepared settled")
 d=decode(out);need(d["status"]==0,("Actual prepared status",op,d));return d
def bulk(value,prefix,count):
 raw=b"NDBULK01"+struct.pack("<7Q",1,value,0,count,prefix,0,0)
 rc,out=actual.invoke("bulk",raw);d=decode(out)
 need(rc==1 and d["status"]==0,"Actual fixture construct failed")
 print(json.dumps({"stage":"bulk-state","prefix":prefix,"count":count,"serial":d["result"]}),flush=True)
 return d["result"]
def rows(prefix,count):return [(bytes([prefix])+format(i,"08x").encode(),b"7") for i in range(count)]
def srv_expected(rs):return b"SRV1"+struct.pack("<I",len(rs))+b"".join(struct.pack("<II",len(k),len(v))+k+v for k,v in rs)
try:
 actual=Actual();actual.state(0)
 value=actual.state(1,data=tape(7))["result"];empty=actual.state(5)["result"]
 before=bulk(value,97,BEFORE);after=bulk(value,98,AFTER);actual.state(4,a=value)
 b_rows=rows(97,BEFORE);a_rows=rows(98,AFTER)
 seed=call(1,empty,before)["result"]
 snapshot=call(17,seed)["result"]
 snap=parse_snapshot(bytes.fromhex(call(18,snapshot)["data_hex"]))
 need(snap["rows"]==b_rows,"Actual fixture all keys and values from State")
 observations["before_snapshot"]=public_snapshot(snap)
 parent=call(21,before,snapshot,seq=31,root=bytes.fromhex(snap["root_hex"]))["result"]
 roots_before=actual.roots;prepared=call(10,parent,after,seq=41,height=2,binding=31)["result"]
 expected_roots=int(AFTER==65536)
 need(actual.roots-roots_before==expected_roots,"Exact full-root versus CheckedApply")
 print(json.dumps({"stage":"prepare-returned","after":AFTER,"actual_full_root_calls":actual.roots-roots_before,"elapsed_ns":time.monotonic_ns()-started}),flush=True)
 raw=bytes.fromhex(call(2,prepared,seq=41,height=2)["data_hex"]);result=parse_some_prepared(raw)
 method="CheckedApply" if AFTER==65535 else "FullRoot(DeltaBudget)"
 need(result["observation"]["method"]==method,"Exact inclusive DeltaBudget boundary")
 expected_changes=[{"key_hex":k.hex(),"before_hex":v.hex(),"after_hex":None} for k,v in b_rows]+[{"key_hex":k.hex(),"before_hex":None,"after_hex":v.hex()} for k,v in a_rows]
 need(result["changes"]==expected_changes and result["observation"]["changed_keys"]==BEFORE+AFTER,"Every actual change, no synthetic count")
 c=charges(a_rows);b=charges(b_rows)
 workspace=3*(max(c["map"],b["map"])+max(c["tree"],b["tree"]))+2*max(c["payload"],b["payload"])+256*(BEFORE+AFTER)
 need(result["observation"]=={"method":method,"actual_keys":AFTER,"actual_payload_bytes":10*AFTER,"changed_keys":BEFORE+AFTER,"changed_payload_bytes":10*(BEFORE+AFTER),"compressed_nodes":c["nodes"] if AFTER==65535 else None,"workspace_charge_bytes":workspace},"Complete original observation")
 if AFTER==65535:need(result["tree"]["rows"]==a_rows,"All post-apply tree leaves")
 else:need(result["snapshot"] is None and actual.root_inputs[-1]==srv_expected(a_rows),"Delta fallback root and no snapshot")
 need(result["root_hex"]==result["tree"]["root_hex"] if result["tree"] else result["snapshot"] is None,"Complete actual hash relation retained")
 observations["prepared"]=public_prepared(result)
 observations["all_source_rows_verified"]=True
 (OUT/"observations.json").write_text(json.dumps(observations,sort_keys=True,separators=(",",":"))+"\n")
 call(3,prepared,seq=41,height=2);call(8,parent,seq=31);call(20,snapshot)
 for s in (empty,before,after):actual.state(7,a=s)
 stats=actual.state(0);need(stats["live_objects"]==0 and actual.q(24)==0 and actual.q(32)==0,"All large map/tree/delta owners freed")
 actual.state(26);need(actual.heap.read()==bytes(actual.heap.n),"Complete arena erase")
except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
finally:
 if actual is not None:
  try:actual.finish()
  except BaseException as e:errors.append({"cleanup":repr(e)})
 try:fence()
 except BaseException as e:errors.append({"source_after":repr(e)})
 report={"schema":"trnm.actual-delta-boundary-native.v1","status":"PASS" if failure is None and not errors else "FAIL","before_keys":BEFORE,"after_keys":AFTER,"expected_changes":BEFORE+AFTER,"source_inputs":inputs,"build":ident((BUILD/"build.json").read_bytes()),"fixture_build":fixture_build,"failure":failure,"errors":errors,"source_after":"MATCH" if not errors else "FAIL","native_calls":None if actual is None else actual.calls,"full_roots":None if actual is None else actual.roots,"journal_records":None if actual is None else actual.records,"blobs":{} if actual is None else actual.blobs,"elapsed_ns":time.monotonic_ns()-started,"scope":{"actual_state_insert":True,"host_state_layout_import":False,"legacy_exact_prior_role":True,"new_prepared_private_tree_continuation":True,"actual_tree_backend":True,"unique_path_copy_on_write":True,"new_hia_sha_root":True,"raw_full_heap_and_frames":True,"full_bytes_direct_journal_no_hex_roundtrip":True,"original_rust":"NOT_RUN","checked_snapshot":False,"node_commit":False}}
 if (OUT/"observations.json").is_file():report["observations"]=ident((OUT/"observations.json").read_bytes())
 (OUT/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:report[k] for k in ("status","before_keys","after_keys","expected_changes","native_calls","full_roots","journal_records","failure","errors","elapsed_ns")}),flush=True)
 if report["status"]!="PASS":raise SystemExit(1)
