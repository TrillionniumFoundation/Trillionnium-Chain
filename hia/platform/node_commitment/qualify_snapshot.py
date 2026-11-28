"""Native Some and checked-snapshot method qualification against the real Node images.

This fixture calls typed native operations, records complete before/after heaps,
verifies actual retained nodes/refcounts, and never computes runtime results.
Each group keeps its exact method roster; Rust comparison is a separate gate.
"""
from pathlib import Path
from collections import Counter
import argparse,ctypes,json,lzma,struct,time,traceback,mmap,hashlib
from hia.platform.execution_state.physical import Guarded
from hia.platform.execution_state.native_io import command,decode
from hia.platform.execution_state.cases import tape
from hia.platform.mempool_node.build import ROOT,validate_build
from hia.platform.mempool_node.safe import new_output
from hia.platform.mempool_node.node_observers import (srv,value_capacity,charges,state_hash,lift,parse_shared,parse_snapshot,parse_some_prepared,EMPTY)
DEFAULT=(65536,8388608,536870912)
ident=lambda b:{"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def need(condition,message):
 if not condition:raise AssertionError(message)
def fence():
 validate_build(BUILD)
 for p,value in inputs.items():need(ident(Path(p).read_bytes())==value,"Source drift "+p)

class Image:
 def __init__(self,raw):
  self.memory=mmap.mmap(-1,len(raw),prot=3);self.memory.write(raw);a=ctypes.addressof(ctypes.c_ubyte.from_buffer(self.memory));c=ctypes.CDLL(None,use_errno=True);c.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];need(c.mprotect(a,len(raw),5)==0,"image RX")
  self.fn=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(a)
 def close(self):self.memory.close()


class Actual:
 def __init__(self):
  self.images={k:Image((BUILD/(v+".flat")).read_bytes()) for k,v in {"state":"state","root":"root","prepared":"snapshot","legacy":"prepared","checked":"checked","tree":"tree"}.items()}
  self.heap=Guarded(65536);self.stream=open(OUT/"native-journal.jsonl.xz","xb");self.calls=0;self.roots=0;self.records=0;self.fixture=0
 def log(self,row):
  raw=(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode();self.stream.write(lzma.compress(raw,preset=1));self.stream.flush();self.records+=1
 def q(self,o):return struct.unpack("<Q",ctypes.string_at(self.heap.address+o,8))[0]
 def invoke(self,role,raw,cap=512):
  e=Guarded(len(raw),raw,True);o=Guarded(cap,b"\x5b"*cap)
  try:
   active="checked" if role=="prepared" else role
   for iteration in range(64):
    hb=self.heap.read();ob=o.read();index=self.calls+1
    self.log({"kind":"call-start","index":index,"role":active,"input_hex":raw.hex(),"output_before_hex":ob.hex(),"heap_before_hex":hb.hex(),"heap_capacity":self.heap.n})
    rc=self.images[active].fn(e.address,e.n,o.address,o.n,self.heap.address,self.heap.n);self.calls+=1
    self.log({"kind":"call-complete","index":index,"role":active,"return":rc,"input_after_hex":e.read().hex(),"output_after_hex":o.read().hex(),"heap_after_hex":self.heap.read().hex()})
    e.check();o.check();self.heap.check();need(e.read()==raw,"Readonly command changed")
    if rc==8:
     need(active in ('prepared','checked') and self.q(112) in (8,9),'Actual private tree request')
     active='tree';continue
    if rc==9:
     need(active=='tree' and self.q(136) not in (0,(1<<64)-1),'Actual tree completion')
     active='checked';continue
    if rc==7:
     need(active in ("checked","prepared") and self.heap.read()==hb and o.read()==ob,"Fixed image delegation mutated capabilities")
     active="prepared" if active=="checked" else "legacy";continue
    if rc==2:
     requested=self.q(80);need(requested>self.heap.n,"Actual growth request")
     n=(requested+65535)//65536*65536;new=Guarded(n);before=self.heap.read();ctypes.memmove(new.address,before,len(before));self.log({"kind":"actual-capability-grow","old_bytes":len(before),"new_bytes":n,"copied":ident(before),"prefix_equal":new.read()[:len(before)]==before});self.heap.close();self.heap=new;continue
    if rc==3:
     requested=self.q(88);need(requested>o.n,"Actual output request");o.close();o=Guarded(requested,b"\x5b"*requested);continue
    if rc==5:
     off=self.q(120);n=self.q(128);scratch_n=self.q(144);need(off+n<=self.heap.n and o.n>=96,"Actual root extent")
     root_in=self.heap.read()[off:off+n];ri=Guarded(n,root_in,True);ro=Guarded(32,b"\x7c"*32);rs=Guarded(scratch_n)
     try:
      self.log({"kind":"root-start","input_hex":root_in.hex(),"scratch_bytes":scratch_n,"output_before_hex":ro.read().hex(),"pending_kind":self.q(112),"pending_owner":self.q(152),"changes_pointer":self.q(self.q(152)+88) if self.q(112) in (3,6,7) else 0})
      if self.q(112)==3:need(self.q(self.q(152)+88)==0,"Fallback changes allocated before actual complete root")
      if self.q(112)==6:need(self.q(self.q(152)+88)!=0,"Internal mismatch lost already allocated changes")
      if self.q(112)==7:
       pending=self.q(152);method=self.q(self.q(pending+32)+168)
       need((self.q(pending+88)!=0)==(method==5),"checked_snapshot root-before-changes order")
      rr=self.images["root"].fn(ri.address,ri.n,ro.address,ro.n,rs.address,rs.n);self.roots+=1
      self.log({"kind":"root-complete","return":rr,"output_hex":ro.read().hex(),"input_after":ident(ri.read()),"scratch_after":ident(rs.read())})
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


def parse(raw,limits):
 need(len(raw)>=256 and raw[:8]==b"NPCDATA1","Prepared header")
 q=lambda at:struct.unpack_from("<Q",raw,at)[0]
 need(q(8)==len(raw),"Prepared extent")
 bn,an,dn,tn=q(48),q(80),q(56),q(240);need(256+bn+an+dn+tn==len(raw),"Prepared sections")
 before=srv(raw[256:256+bn]);after=srv(raw[256+bn:256+bn+an]);p=256+bn+an
 need(raw[p:p+8]==b"NDELTA01","Changes magic");count=struct.unpack_from("<Q",raw,p+8)[0];p+=16;changes=[]
 for _ in range(count):
  kn,bn,an,flags=struct.unpack_from("<4Q",raw,p);p+=32;k=raw[p:p+kn];p+=kn;b=raw[p:p+bn];p+=bn;a=raw[p:p+an];p+=an
  need(flags in (1,2,3),"Change flags");changes.append({"key_hex":k.hex(),"before_hex":b.hex() if flags&1 else None,"after_hex":a.hex() if flags&2 else None})
 need(p==q(248) and count==q(64),"Changes complete")
 bm=dict(before);am=dict(after);expected=[{"key_hex":k.hex(),"before_hex":bm[k].hex() if k in bm else None,"after_hex":am[k].hex() if k in am else None} for k in sorted(bm.keys()|am.keys()) if bm.get(k)!=am.get(k)]
 need(changes==expected,"Every canonical change")
 c=charges(after);b=charges(before);workspace=3*(max(c["map"],b["map"])+max(c["tree"],b["tree"]))+2*max(c["payload"],b["payload"])+256*len(changes)
 need((q(184),q(192),q(200))==(c["map"],c["tree"],c["capacities"]),"Current actual Vec charges")
 need((q(208),q(216),q(224))==(b["map"],b["tree"],b["capacities"]),"Parent actual Vec charges")
 need(q(176)==workspace,"Full workspace")
 payload=sum(len(bytes.fromhex(x["key_hex"]))+sum(len(bytes.fromhex(x[v])) for v in ("before_hex","after_hex") if x[v] is not None) for x in changes)
 need(q(72)==payload and q(88)==b["payload"] and q(96)==c["payload"],"Logical payload")
 method=1 if len(after)>limits[0] else 2 if c["payload"]>limits[1] else 3 if workspace>limits[2] else 0
 need(q(168)==method,"Fallback order")
 methods=["RebuiltTree","FullRoot(KeyBudget)","FullRoot(PayloadBudget)","FullRoot(WorkspaceBudget)"]
 snapshot=None
 if method==0:
  need(tn>=128+8224 and raw[p+96:p+104]==b"NPCTREE1","Real retained tree")
  t=lambda at:struct.unpack_from("<Q",raw,p+at)[0]
  need(t(0)==len(after) and t(8)==c["nodes"] and t(56)==c["nodes"],"Exact compressed nodes")
  need(raw[p+64:p+96]==raw[128:160],"Retained tree actual root")
  need(q(232)==c["nodes"],"Snapshot observation nodes")
  snapshot={"keys":len(after),"payload_bytes":c["payload"],"retained_charge_bytes":c["map"]+c["tree"],"canonical_values":[[k.hex(),v.hex()] for k,v in after],"root_hex":raw[128:160].hex(),"allocated_nodes":c["nodes"]}
 else:need(tn==0 and q(232)==(1<<64)-1,"Fallback falsely retained snapshot")
 return {"root_hex":raw[128:160].hex(),"changes":changes,"observation":{"method":methods[method],"actual_keys":len(after),"actual_payload_bytes":c["payload"],"changed_keys":len(changes),"changed_payload_bytes":payload,"compressed_nodes":None if snapshot is None else c["nodes"],"workspace_charge_bytes":workspace},"snapshot":snapshot,"value_capacities":[[k.hex(),value_capacity(v)] for k,v in after],"parent_capacities":[[k.hex(),value_capacity(v)] for k,v in before],"before":[[k.hex(),v.hex()] for k,v in before],"after":[[k.hex(),v.hex()] for k,v in after],"reference_count":q(160)}


def object_at(actual,serial):
 at=actual.q(56)
 while at:
  if actual.q(at)==serial:return at
  at=actual.q(at+16)
 raise AssertionError(("Real serial is not live",serial))


def parse_parent(raw):
 need(len(raw)>=264 and raw[:8]==b"NPCPAR01","Parent actual header")
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 need(q(8)==len(raw) and q(48)==len(raw)-256,"Parent exact extent")
 rows=srv(raw[256:]);c=charges(rows)
 need(q(32)==len(rows) and q(88)==c["payload"],"Parent full canonical values")
 need((q(208),q(216),q(224))==(c["map"],c["tree"],c["capacities"]),"Parent actual charges")
 return {"root_hex":raw[128:160].hex(),"rows":[[k.hex(),v.hex()] for k,v in rows],"refs":q(160),"base":q(16),"epoch":q(104),"bind_seq":q(112),"height":q(120)}


def passed(name,**kw):
 controls.append({"name":name,"status":"PASS",**kw});print(json.dumps({"name":name,"status":"PASS"}),flush=True)


def semantic(op,observation=None,**kw):
 row={"index":len(semantics),"op":op,**kw,"observation":observation,"native_call_end":actual.calls};semantics.append(row)
 actual.log({"kind":"semantic-observation","row":row})
 with (OUT/"semantic-history.jsonl").open("ab") as stream:stream.write((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode())


def call(op,a,b=0,epoch=7,seq=21,height=1,status=0,limits=DEFAULT,binding=0,root=None,key=b""):
 if op==5:b=len(key)
 raw=b"NPCREQ01"+struct.pack("<7Q",op,a,b,epoch,seq,height,binding)
 if op in (1,6,10,21,22,23):raw+=struct.pack("<3Q",*limits)
 if op in (6,21,22,23):
  need(root is not None and len(root)==32,"Actual owner expected root");raw+=root
 if op==5:raw+=key
 rc,out=actual.invoke("prepared",raw);need(rc==1,("Actual Some return",op,rc));d=decode(out);need(d["status"]==status,("Actual Some status",op,d,status))
 return d


def public_snapshot(x):
 return {"canonical_values":[[k.hex(),v.hex()] for k,v in x["rows"]],"root_hex":x["root_hex"],"keys":len(x["rows"]),"payload_bytes":x["charges"]["payload"],"retained_charge_bytes":x["charges"]["map"]+x["charges"]["tree"],"allocated_nodes":x["charges"]["nodes"],"map_refs":x["map_refs"]}


def public_prepared(x):
 return {k:x[k] for k in ("root_hex","changes","observation","snapshot")}


def inspect_snapshot(name,record=False):
 item=snaps[name];x=parse_snapshot(bytes.fromhex(call(18,item["id"],**item["context"])["data_hex"]))
 if record:semantic("snapshot_inspect",public_snapshot(x),name=name)
 return x


def inspect_parent(name,record=False):
 item=parents[name];x=parse_snapshot(bytes.fromhex(call(7,item["id"],**item["context"])["data_hex"]))
 if record:semantic("parent_inspect",public_snapshot(x),name=name)
 return x


def inspect_prepared(name,record=False):
 item=prepared[name];x=parse_some_prepared(bytes.fromhex(call(2,item["id"],**item["context"])["data_hex"]))
 if record:semantic("prepared_inspect",public_prepared(x),name=name)
 return x


def state_new(name,rows):
 need(name not in states,"Unique state name");serial=actual.state_rows(rows);states[name]=serial;state_inputs[name]=rows
 semantic("state",None,name=name,rows=[{"key_hex":k.hex(),"value_tape_hex":tape(v).hex()} for k,v in rows]);return serial


def state_drop(name):
 actual.state(7,a=states.pop(name));semantic("state_drop",None,name=name)


def seed(name,state,seq=21,height=1):
 p=call(1,states["empty"],states[state],seq=seq,height=height)["result"]
 result=parse(bytes.fromhex(call(2,p,seq=seq,height=height)["data_hex"]),DEFAULT)
 s=call(17,p,seq=seq,height=height)["result"];snaps[name]={"id":s,"context":{"epoch":7,"seq":seq,"height":height}}
 x=inspect_snapshot(name);need(x["root_hex"]==result["root_hex"] and [[k.hex(),v.hex()] for k,v in x["rows"]]==result["after"],"Snapshot consumed actual prepared tree/map")
 call(2,p,seq=seq,height=height,status=65)
 semantic("seed",public_snapshot(x),name=name,state=state);return x


def snapshot_clone(src,dst):
 old=snaps[src];id=call(19,old["id"],**old["context"])["result"];snaps[dst]={"id":id,"context":dict(old["context"])}
 semantic("snapshot_clone",None,source=src,name=dst)


def snapshot_drop(name):
 old=snaps.pop(name);call(20,old["id"],**old["context"]);call(18,old["id"],status=65,**old["context"])
 semantic("snapshot_drop",None,name=name)


def bind(name,state,snapshot,seq=31,limits=DEFAULT,status=0,root_mode="snapshot"):
 sn=inspect_snapshot(snapshot);ctx={"epoch":sn["epoch"],"seq":seq,"height":sn["height"]}
 root=bytes.fromhex(sn["root_hex"])
 if root_mode=="wrong":root=bytes([root[0]^1])+root[1:]
 out=call(21,states[state],snaps[snapshot]["id"],limits=limits,root=root,status=status,**ctx)
 if status==0:parents[name]={"id":out["result"],"context":ctx,"limits":limits,"state":state,"before":sn["rows"]}
 semantic("bind",{"status":status},name=name,state=state,snapshot=snapshot,limits=list(limits),root_mode=root_mode)
 return out


def parent_drop(name):
 old=parents.pop(name);call(8,old["id"],**old["context"]);call(7,old["id"],status=65,**old["context"]);semantic("parent_drop",None,name=name)


def parent_prepare(name,parent,after,seq,status=0):
 p=parents[parent];ctx={"epoch":p["context"]["epoch"],"seq":seq,"height":p["context"]["height"]+1};before_roots=actual.roots
 out=call(10,p["id"],states[after],limits=p["limits"],binding=p["context"]["seq"],status=status,**ctx)
 roots=actual.roots-before_roots
 if status!=0:
  semantic("prepare",{"status":status},name=name,parent=parent,after=after);return None
 prepared[name]={"id":out["result"],"context":ctx};x=inspect_prepared(name)
 if x["observation"]["method"]=="CheckedApply":need(roots==0,"CheckedApply called independent full builder")
 else:need(roots==1,"Fallback did not execute exactly one actual root")
 need(bytes.fromhex(actual.state(24,a=states[after])["data_hex"]).hex()==x["root_hex"],"Prepared root differs from actual State root")
 semantic("prepare",{"status":0,**public_prepared(x)},name=name,parent=parent,after=after)
 return x


def prepared_clone(src,dst):
 p=prepared[src];out=call(4,p["id"],**p["context"]);prepared[dst]={"id":out["result"],"context":dict(p["context"])}
 semantic("prepared_clone",None,name=dst,source=src)


def prepared_drop(name):
 p=prepared.pop(name);call(3,p["id"],**p["context"]);call(2,p["id"],status=65,**p["context"]);semantic("prepared_drop",None,name=name)


def take(src,dst,status=0):
 p=prepared[src];out=call(17,p["id"],status=status,**p["context"])
 if status==0:
  prepared.pop(src);snaps[dst]={"id":out["result"],"context":dict(p["context"])};call(2,p["id"],status=65,**p["context"])
  semantic("take",public_snapshot(inspect_snapshot(dst)),source=src,name=dst,status=0)
 else:semantic("take",{"status":status},source=src,name=dst,status=status)


def lookup(name,key):
 p=prepared[name];out=call(5,p["id"],key=key,**p["context"])
 observation={"found":out["result"],"value_hex":out["data_hex"]};semantic("get",observation,name=name,key_hex=key.hex());return observation


def verify_arcs():
 objects=[];at=actual.q(56)
 while at:
  objects.append(at);at=actual.q(at+16)
 live_trees=[];maprefs=Counter()
 for obj in objects:
  kind=actual.q(obj+8)
  if kind==9:
   maprefs[actual.q(obj+32)]+=1;live_trees.append(actual.q(obj+40))
   owner=actual.q(obj+72)
   if owner:
    prep=object_at(actual,owner);need(actual.q(prep+8)==6 and actual.q(prep+200)==obj,"Internal Snapshot owner identity")
  elif kind==7:
   if actual.q(obj+200):
    maprefs[actual.q(obj+32)]+=2;live_trees.append(actual.q(obj+200))
   else:maprefs[actual.q(obj+32)]+=1
  elif kind==6:need(actual.q(obj+160)==0,"Returned Prepared retained Parent map borrow")
 for ptr,refs in maprefs.items():need(actual.q(ptr+160)==refs,("Actual complete canonical Map Arc count",ptr,refs,actual.q(ptr+160)))
 nodes={};refs=Counter();emptyrefs=Counter()
 for tree in live_trees:
  root=actual.q(tree+16);empty=actual.q(tree+32);emptyrefs[empty]+=1
  if root:refs[root]+=1
  stack=[root] if root else []
  visited=set()
  while stack:
   ptr=stack.pop();need(ptr not in visited,"Tree cyclic/duplicate");visited.add(ptr)
   body=actual.heap.read()[ptr:ptr+208]
   if ptr in nodes:need(nodes[ptr]==body,"Shared node changed")
   nodes[ptr]=body
   if actual.q(ptr+72)==2:stack.extend([actual.q(ptr+80),actual.q(ptr+88)])
 for ptr in nodes:
  if actual.q(ptr+72)==2:refs[actual.q(ptr+80)]+=1;refs[actual.q(ptr+88)]+=1
 for ptr,expected in refs.items():need(actual.q(ptr+192)==expected,("Actual Some node refs",ptr,expected,actual.q(ptr+192)))
 for ptr,expected in emptyrefs.items():need(actual.q(ptr)==expected,("Actual empty refs",ptr,expected,actual.q(ptr)))
 return {"map_count":len(maprefs),"tree_headers":len(live_trees),"nodes":len(nodes),"map_refs":sorted(maprefs.values())}


def allocation():
 return actual.state(0)["live_objects"],actual.q(24),actual.q(32)


def fixture(label,at,data):
 old=actual.heap.read()[at:at+len(data)]
 actual.log({"kind":"private-fixture-mutation","name":label,"offset":at,"before_hex":old.hex(),"after_hex":data.hex()});ctypes.memmove(actual.heap.address+at,data,len(data));return old


def restore(label,at,data):
 actual.log({"kind":"private-fixture-restore","name":label,"offset":at,"bytes_hex":data.hex()});ctypes.memmove(actual.heap.address+at,data,len(data))


def canonical_rows(name):
 return sorted((k,json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()) for k,v in state_inputs[name])


def expected_changes(before,after):
 bm=dict(before);am=dict(after)
 return [{"key_hex":k.hex(),"before_hex":None if k not in bm else bm[k].hex(),"after_hex":None if k not in am else am[k].hex()} for k in sorted(bm.keys()|am.keys()) if bm.get(k)!=am.get(k)]


def expected_observation(before,after,method):
 b=charges(before);a=charges(after);changes=expected_changes(before,after)
 payload=sum(len(bytes.fromhex(x["key_hex"]))+sum(len(bytes.fromhex(x[k])) for k in ("before_hex","after_hex") if x[k] is not None) for x in changes)
 workspace=3*(max(a["map"],b["map"])+max(a["tree"],b["tree"]))+2*max(a["payload"],b["payload"])+256*len(changes)
 return {"method":method,"actual_keys":len(after),"actual_payload_bytes":a["payload"],"changed_keys":len(changes),"changed_payload_bytes":payload,"compressed_nodes":a["nodes"] if method in ("RebuiltTree","CheckedApply") else None,"workspace_charge_bytes":workspace}


def root_argument(state,prior,mode):
 if mode=="zero":return bytes(32)
 if mode=="prior":return bytes.fromhex(inspect_snapshot(prior)["root_hex"])
 raw=bytes.fromhex(actual.state(24,a=states[state])["data_hex"]);need(len(raw)==32,"Actual State expected root")
 if mode=="wrong":raw=bytes([raw[0]^1])+raw[1:]
 return raw


def checked(name,state,prior=None,seq=101,height=1,limits=DEFAULT,status=0,root_mode="actual",record=True,observed_before=None):
 ctx={"epoch":7,"seq":seq,"height":height}
 root=root_argument(state,prior,root_mode);before=(canonical_rows(state) if prior is None else inspect_snapshot(prior)["rows"]) if observed_before is None else observed_before
 count=actual.roots;allocated=allocation()
 out=call(22,states[state],0 if prior is None else snaps[prior]["id"],limits=limits,status=status,root=root,**ctx)
 roots=actual.roots-count
 observation={"status":status}
 if status==0:
  prepared[name]={"id":out["result"],"context":ctx};x=inspect_prepared(name)
  after=canonical_rows(state);method=x["observation"]["method"]
  need(x["changes"]==expected_changes(before,after),"checked_snapshot complete original transition")
  need(x["observation"]==expected_observation(before,after,method),"checked_snapshot complete charge observation")
  need(x["root_hex"]==root.hex(),"checked_snapshot actual root disagrees with expected")
  need(roots==(0 if x["snapshot"] is not None else 1),"checked_snapshot real full-root call count")
  observation.update(public_prepared(x))
 else:
  need(allocation()==allocated,"checked_snapshot ordinary error leaked an owned object/map/tree/delta")
 if record:semantic("checked_snapshot",observation,name=name,state=state,prior=prior,limits=list(limits),root_mode=root_mode)
 return None if status else x


def parse_bind_observation(raw):
 need(len(raw)==96 and raw[:8]==b"NDBIND01","Actual complete bind observation")
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 methods=["RebuiltTree","FullRoot(KeyBudget)","FullRoot(PayloadBudget)","FullRoot(WorkspaceBudget)","FullRoot(DeltaBudget)","FullRoot(InternalSnapshotMismatch)","CheckedApply"]
 need(q(8)<len(methods),"Actual bind method")
 return {"method":methods[q(8)],"actual_keys":q(16),"actual_payload_bytes":q(24),"changed_keys":q(32),"changed_payload_bytes":q(40),"compressed_nodes":None if q(48)==(1<<64)-1 else q(48),"workspace_charge_bytes":q(56)}


def inspect_parent_full(name):
 p=parents[name];raw=bytes.fromhex(call(7,p["id"],**p["context"])["data_hex"])
 if raw[:8]==b"NPCSNP01":
  x=parse_snapshot(raw);return {"root_hex":x["root_hex"],"canonical_values":[[k.hex(),v.hex()] for k,v in x["rows"]],"map_refs":x["map_refs"],"predecessor_present":True,"snapshot":public_snapshot(x)},x
 x=parse_parent(raw);return {"root_hex":x["root_hex"],"canonical_values":x["rows"],"map_refs":x["refs"],"predecessor_present":False,"snapshot":None},x


def check_bind(name,state,prior=None,seq=201,height=1,limits=DEFAULT,status=0,root_mode="actual"):
 ctx={"epoch":7,"seq":seq,"height":height};root=root_argument(state,prior,root_mode)
 before=canonical_rows(state) if prior is None else inspect_snapshot(prior)["rows"];allocated=allocation();count=actual.roots
 out=call(23,states[state],0 if prior is None else snaps[prior]["id"],limits=limits,status=status,root=root,**ctx)
 roots=actual.roots-count;observation={"status":status}
 if status==0:
  obs=parse_bind_observation(bytes.fromhex(out["data_hex"]));need(obs==expected_observation(before,canonical_rows(state),obs["method"]),"check_and_bind full observation")
  parents[name]={"id":out["result"],"context":ctx,"limits":limits,"state":state,"before":canonical_rows(state)}
  parent,x=inspect_parent_full(name);need(parent["root_hex"]==root.hex() and parent["canonical_values"]==[[k.hex(),v.hex()] for k,v in canonical_rows(state)],"check_and_bind actual complete canonical parent")
  need(roots==(0 if parent["predecessor_present"] else 1),"check_and_bind recomputed a second full root")
  owner=object_at(actual,out["result"]);map=actual.q(owner+32)
  need(actual.q(owner+72)==states[state] and actual.q(owner+48)==7 and actual.q(owner+56)==seq and actual.q(owner+64)==height,"check_and_bind actual private binding")
  need(bool(actual.q(owner+200))==parent["predecessor_present"],"Parent predecessor ownership")
  observation.update(parent=parent,preparation=obs);verify_arcs()
 else:need(allocation()==allocated,"check_and_bind root/canonical error leaked")
 semantic("check_and_bind",observation,name=name,state=state,prior=prior,limits=list(limits),root_mode=root_mode)
 return observation


def checked_internal(name,state,prior,seq=170):
 before=inspect_snapshot(prior)["rows"]
 item=snaps[prior];obj=object_at(actual,item["id"]);map=actual.q(obj+32)
 old=actual.heap.read()[map+128:map+160]
 changed=bytes([old[0]^1])+old[1:]
 fixture("checked-snapshot-private-root-mismatch",map+128,changed)
 try:x=checked(name,state,prior,seq=seq,record=False,observed_before=before)
 finally:restore("checked-snapshot-private-root-mismatch",map+128,old)
 need(x["observation"]["method"]=="FullRoot(InternalSnapshotMismatch)" and x["snapshot"] is None,"Real checked_snapshot internal mismatch fallback")
 semantic("checked_internal_mismatch",{"status":0,**public_prepared(x)},name=name,state=state,prior=prior,limits=list(DEFAULT),root_mode="actual")
 return x


def run_some():
 global actual
 actual=Actual();actual.state(0)
 state_new("empty",[])
 base_rows=[(f"key{i:03}".encode(),{"n":i,"text":"a"*(i%5),"unknown":[None,False,i]}) for i in range(18)]
 invalid_rows=base_rows+[(b"number-float",-0.0),(b"number-u64",(1<<64)-1),(b"unicode","\u6c49\u5b57/\u00e9\n"+"q"*180)]
 state_new("original-invalid-seed",invalid_rows)
 call(1,states["empty"],states["original-invalid-seed"],status=70)
 semantic("standalone_prepare_error",{"status":70},before="empty",after="original-invalid-seed")
 state_new("non-ascii-seed",[(b"unicode","\u6c49\u5b57/\u00e9\n"+"q"*180)])
 call(1,states["empty"],states["non-ascii-seed"],status=71)
 semantic("standalone_prepare_error",{"status":71},before="empty",after="non-ascii-seed")
 passed("original-float-range-before-nonascii-canonical-error")
 base_rows.extend([(b"number-integer",0),(b"number-u64",(1<<64)-1),(b"ascii","quote \\\" slash \\\\ newline\\n"+"q"*180)])
 state_new("base",base_rows)
 first=seed("initial","base");snapshot_clone("initial","initial-copy")
 need(inspect_snapshot("initial")["tree"]["root_pointer"]==inspect_snapshot("initial-copy")["tree"]["root_pointer"],"Snapshot clone copied immutable root")
 inspect_snapshot("initial",True);inspect_snapshot("initial-copy",True);verify_arcs()
 passed("actual-cached-prepared-consumed-into-snapshot-and-cloned")
 bind("parent","base","initial",seq=31);inspect_parent("parent",True);verify_arcs()
 need(inspect_snapshot("initial")["map_refs"]==4,"Bound Some must hold actual map plus predecessor map")
 p=parents["parent"];cloned=call(9,p["id"],**p["context"])["result"];verify_arcs()
 call(8,cloned,**p["context"]);call(7,cloned,status=65,**p["context"]);verify_arcs()
 passed("bind-some-complete-canonical-match-two-map-references")
 after_one=dict(base_rows);after_one.pop(b"key003");after_one[b"key007"]={"n":777,"extra":[1,0,None]};after_one[b"new"]={"text":"z"*300}
 state_new("after-one",sorted(after_one.items()))
 bind("bad-mismatch","after-one","initial",status=79,root_mode="wrong")
 bind("bad-root","base","initial",status=76,root_mode="wrong")
 state_new("late-limit",[(b"a",1),(b"z"*161,2)])
 bind("bad-limits","late-limit","initial",status=74,limits=(65537,8388608,536870912))
 bind("late-encoding-limit","late-limit","initial",status=69,root_mode="wrong")
 verify_arcs();passed("bind-limit-canonical-mismatch-and-expected-root-error-order")
 x=parent_prepare("result-one","parent","after-one",41);need(x["observation"]["method"]=="CheckedApply","Some path rebuilt full tree")
 before=inspect_snapshot("initial");need(set(before["tree"]["nodes"])&set(x["tree"]["nodes"]),"Some replaced all unaffected nodes")
 obj=object_at(actual,prepared["result-one"]["id"]);hidden=actual.q(obj+200)
 before_alloc=allocation()
 for op in (18,19,20):call(op,actual.q(hidden),status=68,**prepared["result-one"]["context"])
 need(allocation()==before_alloc,"Internal Snapshot borrow accepted ownership operation")
 verify_arcs();passed("actual-some-checked-apply-full-map-delta-root-and-hidden-snapshot")
 prepared_clone("result-one","result-one-copy");verify_arcs()
 one=inspect_prepared("result-one",True);copy=inspect_prepared("result-one-copy",True)
 need(one["tree"]["root_pointer"]==copy["tree"]["root_pointer"],"Prepared clone did not share actual immutable root")
 o1=object_at(actual,prepared["result-one"]["id"]);o2=object_at(actual,prepared["result-one-copy"]["id"])
 need(actual.q(o1+88)!=actual.q(o2+88),"Prepared clone did not own independent change Vec")
 for key in (b"key000",b"key003",b"new",b"x"*161,b"x"*200000):
  actual_value=lookup("result-one",key);expected=dict(one["tree"]["rows"]).get(key)
  need(actual_value=={"found":int(expected is not None),"value_hex":"" if expected is None else expected.hex()},"Actual lookup")
 passed("prepared-clone-shares-map-tree-owns-delta-and-full-key-lookup")
 take("result-one","next");verify_arcs()
 inspect_snapshot("next",True);prepared_drop("result-one-copy");verify_arcs()
 after_two=dict(base_rows);after_two[b"key009"]=False;after_two[b"other"]=b"".hex()
 state_new("after-two",sorted(after_two.items()))
 two=parent_prepare("result-two","parent","after-two",42)
 need({r["key_hex"] for r in two["changes"]}=={b"key009".hex(),b"other".hex()},"Parent before was replaced by previous Prefix output")
 same=parent_prepare("same-parent","parent","base",43)
 need(same["changes"]==[] and same["tree"]["root_pointer"]==inspect_snapshot("initial")["tree"]["root_pointer"],"Unchanged Some path must share original root")
 verify_arcs();passed("each-prepare-uses-fixed-parent-and-empty-delta-shares-root")
 bind("parent-next","after-one","next",seq=51)
 second=parent_prepare("second-generation","parent-next","after-two",52)
 need(second["changes"]!=two["changes"] and second["root_hex"]==two["root_hex"],"Next actual Snapshot not used as predecessor")
 verify_arcs();passed("snapshot-transfer-rebind-and-next-height-checked-apply")
 before=allocation();parent_prepare("bad-state","parent","late-limit",44,status=69);need(allocation()==before,"Ordinary canonical error allocated or leaked")
 parent_prepare("bad-range","parent","original-invalid-seed",44,status=70)
 parent_prepare("bad-nonascii","parent","non-ascii-seed",44,status=71)
 need(allocation()==before,"Range/noncanonical error allocated or leaked")
 p=parents["parent"];before=allocation()
 call(10,p["id"],states["after-one"],epoch=8,seq=45,height=2,binding=31,status=64)
 call(10,p["id"],states["after-one"],seq=45,height=3,binding=31,status=64)
 call(10,p["id"],states["after-one"],seq=45,height=2,binding=30,status=64)
 call(10,p["id"],states["after-one"],seq=45,height=2,binding=31,limits=(0,0,0),status=64)
 need(allocation()==before,"Private owner binding rejection mutated allocation")
 passed("canonical-error-before-allocation-and-private-epoch-sequence-height-gates")
 for label,limits,method in (
  ("key",(0,0,0),"FullRoot(KeyBudget)"),
  ("payload",(65536,0,0),"FullRoot(PayloadBudget)"),
  ("workspace",(65536,8388608,0),"FullRoot(WorkspaceBudget)"),
 ):
  bind("fallback-"+label,"base","initial",seq=60,limits=limits)
  result=parent_prepare("fallback-result-"+label,"fallback-"+label,"after-one",61)
  need(result["observation"]["method"]==method and result["snapshot"] is None,"Fallback order or retained snapshot")
  take("fallback-result-"+label,"not-created",status=73)
  inspect_prepared("fallback-result-"+label,True)
  parent_drop("fallback-"+label);prepared_drop("fallback-result-"+label);verify_arcs()
 passed("key-payload-workspace-fallback-full-root-before-changes-and-no-snapshot")
 p=parents["parent"];owner=object_at(actual,p["id"]);map=actual.q(owner+32);root=actual.heap.read()[map+128:map+160]
 old=fixture("internal-predecessor-root-mismatch",map+128,bytes([root[0]^1])+root[1:])
 try:
  prior_roots=actual.roots;ctx={"epoch":7,"seq":71,"height":2}
  out=call(10,p["id"],states["after-one"],seq=71,height=2,binding=31);prepared["internal-fallback"]={"id":out["result"],"context":ctx}
  bad=parse_some_prepared(bytes.fromhex(call(2,out["result"],**ctx)["data_hex"]))
  need(bad["observation"]["method"]=="FullRoot(InternalSnapshotMismatch)" and bad["snapshot"] is None and actual.roots-prior_roots==1,"Actual internal mismatch fallback")
 finally:restore("internal-predecessor-root-mismatch",map+128,old)
 semantic("internal_mismatch",{"status":0,**public_prepared(bad)},name="internal-fallback",parent="parent",after="after-one")
 verify_arcs();prepared_drop("internal-fallback");passed("real-predecessor-tree-root-mismatch-keeps-required-delta-and-full-root-fallback")
 parent_drop("parent");parent_drop("parent-next")
 for name in list(states):state_drop(name)
 for name in list(snaps):inspect_snapshot(name,True)
 for name in list(prepared):
  inspect_prepared(name,True)
  tree=inspect_prepared(name)["tree"]
  if tree and tree["rows"]:lookup(name,tree["rows"][0][0])
 verify_arcs();passed("parent-and-all-source-states-retire-before-live-snapshots-prepared")
 for name in list(prepared):prepared_drop(name);verify_arcs()
 for name in list(snaps):snapshot_drop(name);verify_arcs()
 need(allocation()==(0,0,0),"Some map/tree/header/delta leaked")
 actual.state(26);need(actual.heap.read()==bytes(actual.heap.n),"Final native arena erase")
 passed("all-actual-snapshot-map-tree-shared-owners-retired")


def run_checked():
 global actual
 actual=Actual();actual.state(0)
 state_new("empty",[])
 base_rows=[(b"a",1),(b"b",{"unknown":[None,False,2],"text":"z"*129}),(b"c","slash \\\\ quote \\\" line\\n"),(b"d",(1<<64)-1)]
 state_new("base",base_rows)
 fresh=checked("fresh","base");need(fresh["observation"]["method"]=="RebuiltTree","None checked_snapshot did not rebuild")
 take("fresh","initial")
 initial=inspect_snapshot("initial");verify_arcs()
 passed("checked-none-builds-real-map-and-shared-tree-before-expected-root")
 same=checked("same","base","initial",seq=102)
 same_obj=object_at(actual,prepared["same"]["id"]);same_snap=actual.q(same_obj+200)
 need(actual.q(same_snap+32)==initial["map_pointer"] and same["tree"]["root_pointer"]==initial["tree"]["root_pointer"] and same["changes"]==[],"Unchanged candidate failed to share actual immutable map/tree")
 prepared_clone("same","same-copy");take("same","same-snapshot");inspect_snapshot("same-snapshot",True);verify_arcs()
 need(inspect_snapshot("same-snapshot")["map_pointer"]==initial["map_pointer"],"Consumed unchanged snapshot lost shared Map Arc")
 prepared_drop("same-copy");snapshot_drop("same-snapshot")
 passed("unchanged-candidate-reuses-actual-arc-and-tree-with-empty-delta")
 changed=dict(base_rows);changed.pop(b"a");changed[b"b"]={"unknown":[None,True,3],"text":"y"*257};changed[b"new"]=[1,2,3]
 state_new("changed",sorted(changed.items()))
 next_result=checked("next-result","changed","initial",seq=103)
 need(next_result["observation"]["method"]=="CheckedApply" and set(next_result["tree"]["nodes"])&set(initial["tree"]["nodes"]),"Changed snapshot did not preserve real unaffected nodes")
 take("next-result","next")
 checked("wrong-current-root","changed","initial",status=76,root_mode="wrong")
 checked("wrong-prior-root","changed","initial",status=76,root_mode="prior")
 checked("wrong-none-root","base",status=76,root_mode="wrong")
 verify_arcs();passed("checked-apply-complete-transition-and-post-computation-root-refusal")
 count_same=dict(base_rows);count_same[b"a"]=9
 state_new("same-count-changed",sorted(count_same.items()))
 checked("candidate-declines","same-count-changed","initial",status=76,root_mode="prior")
 late_bad=[(b"a",9),(b"z-late",{"bad":0.0})]
 state_new("late-range",late_bad)
 state_new("late-key",[(b"a",9),(b"z"*161,2)])
 state_new("late-unicode",[(b"a",9),(b"z","\u6c49")])
 for state,status in (("late-range",70),("late-key",69),("late-unicode",71)):
  checked("invalid-"+state,state,"initial",status=status,root_mode="prior",limits=(65537,8388608,536870912))
  checked("invalid-none-"+state,state,status=status,root_mode="zero")
 checked("invalid-limits-valid-state","base","initial",status=74,root_mode="wrong",limits=(65537,8388608,536870912))
 verify_arcs();passed("full-canonical-pass-before-invalid-limits-and-wrong-root")
 for label,limits,method in (
  ("key",(0,0,0),"FullRoot(KeyBudget)"),
  ("payload",(65536,0,0),"FullRoot(PayloadBudget)"),
  ("workspace",(65536,8388608,0),"FullRoot(WorkspaceBudget)")
 ):
  result=checked("fallback-"+label,"base","initial",seq=110,limits=limits)
  need(result["observation"]["method"]==method and result["changes"]==[] and result["snapshot"] is None,"Unchanged candidate ignored cache budget")
  take("fallback-"+label,"absent",status=73);prepared_drop("fallback-"+label)
  obs=check_bind("fallback-parent-"+label,"base","initial",seq=210,limits=limits)
  need(not obs["parent"]["predecessor_present"] and obs["parent"]["map_refs"]==1,"Fallback parent retained fake snapshot or extra map reference")
  parent_prepare("fallback-prepare-"+label,"fallback-parent-"+label,"changed",211)
  prepared_drop("fallback-prepare-"+label);parent_drop("fallback-parent-"+label);verify_arcs()
 passed("budget-refusal-full-root-before-delta-and-fallback-bind-without-second-root")
 checked("fallback-wrong-root","base","initial",status=76,root_mode="wrong",limits=(0,0,0))
 check_bind("bad-bind-root","base","initial",status=76,root_mode="wrong")
 check_bind("bad-bind-limits","late-range","initial",status=70,root_mode="zero",limits=(65537,8388608,536870912))
 verify_arcs();passed("fallback-and-bind-errors-clean-up-without-exported-authority")
 bound=check_bind("parent-none","base",seq=220)
 need(bound["preparation"]["method"]=="RebuiltTree" and bound["parent"]["predecessor_present"],"check_and_bind(None) did not keep rebuilt snapshot")
 p=parents["parent-none"];clone=call(9,p["id"],**p["context"])["result"];verify_arcs()
 call(8,clone,**p["context"]);verify_arcs()
 none_next=parent_prepare("none-parent-next","parent-none","changed",221)
 need(none_next["observation"]["method"]=="CheckedApply","Real newly bound parent lost predecessor")
 take("none-parent-next","bound-next");parent_drop("parent-none")
 passed("check-and-bind-none-transfers-snapshot-plus-real-actual-map-reference")
 bound=check_bind("parent-some","base","initial",seq=230)
 need(bound["preparation"]["method"]=="CheckedApply" and bound["parent"]["predecessor_present"],"check_and_bind(Some) wrong method")
 po=object_at(actual,parents["parent-some"]["id"]);need(actual.q(po+32)==initial["map_pointer"],"Some checked parent copied unchanged map")
 parent_prepare("parent-result-one","parent-some","changed",231)
 same_again=parent_prepare("parent-result-two","parent-some","base",232);need(same_again["changes"]==[],"Parent was advanced to previous output")
 verify_arcs();passed("check-and-bind-some-reuses-map-and-keeps-fixed-parent-across-preparations")
 empty=checked("empty-result","empty",seq=120);need(empty["observation"]["method"]=="RebuiltTree" and empty["snapshot"]["keys"]==0,"Empty real rebuilt Snapshot")
 take("empty-result","empty-snapshot")
 empty_same=checked("empty-same","empty","empty-snapshot",seq=121,limits=(0,0,536870912));need(empty_same["observation"]["method"]=="CheckedApply","Empty exact key/payload boundary")
 prepared_drop("empty-same")
 empty_budget=checked("empty-budget","empty","empty-snapshot",seq=122,limits=(0,0,0));need(empty_budget["observation"]["method"]=="FullRoot(WorkspaceBudget)","Empty zero workspace priority")
 prepared_drop("empty-budget")
 passed("empty-root-and-exact-zero-key-payload-budget-boundaries")
 c=charges(canonical_rows("base"));workspace=3*(c["map"]+c["tree"])+2*c["payload"]
 exact=checked("exact-budget","base","initial",seq=123,limits=(len(base_rows),c["payload"],workspace));need(exact["observation"]["method"]=="CheckedApply","Exact unchanged workspace boundary")
 prepared_drop("exact-budget")
 under=checked("under-budget","base","initial",seq=124,limits=(len(base_rows),c["payload"],workspace-1));need(under["observation"]["method"]=="FullRoot(WorkspaceBudget)","One-below unchanged workspace")
 prepared_drop("under-budget");verify_arcs()
 passed("unchanged-candidate-uses-real-retained-charges-at-exact-workspace-edge")
 checked_internal("internal-fallback","changed","initial");take("internal-fallback","never-created",status=73);prepared_drop("internal-fallback");verify_arcs()
 passed("checked-internal-snapshot-mismatch-real-full-root-and-retained-required-changes")
 root=root_argument("base",None,"actual");before=allocation()
 call(22,states["base"],snaps["initial"]["id"],epoch=8,root=root,status=64)
 call(22,states["base"],states["changed"],root=root,status=68)
 invalid=call(22,states["base"],999999999,root=root,status=65)
 pp=checked("hidden-gate","base","initial",seq=131);pobj=object_at(actual,prepared["hidden-gate"]["id"]);hidden=actual.q(pobj+200)
 hidden_serial=actual.q(hidden);snap_alloc=allocation()
 call(22,states["base"],hidden_serial,root=root,status=68)
 need(allocation()==snap_alloc,"Hidden Snapshot accepted as caller-owned prior")
 prepared_drop("hidden-gate");need(allocation()==before,"Private type/epoch rejection changed ownership")
 passed("private-epoch-type-and-hidden-snapshot-capabilities-refused")
 for name in list(parents):parent_drop(name);verify_arcs()
 for name in list(states):state_drop(name)
 for name in list(prepared):inspect_prepared(name,True)
 for name in list(snaps):inspect_snapshot(name,True)
 verify_arcs();passed("checked-parent-dropped-before-source-state-and-result-survival")
 for name in list(prepared):prepared_drop(name);verify_arcs()
 for name in list(snaps):snapshot_drop(name);verify_arcs()
 need(allocation()==(0,0,0),"Checked Snapshot/Parent leaked any owned allocation")
 actual.state(26);need(actual.heap.read()==bytes(actual.heap.n),"Actual final arena erase")
 passed("all-checked-snapshot-map-tree-delta-and-parent-owners-retired")


def main(argv=None):
 from .bounded import enter
 enter("hia.platform.node_commitment.qualify_snapshot",argv)
 global BUILD,OUT,report0,inputs,actual,states,snaps,parents,prepared,semantics,controls,state_inputs
 need(__debug__,"Optimized Python refused")
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--build",required=True,type=Path)
 parser.add_argument("--output",required=True,type=Path)
 parser.add_argument("--group",required=True,choices=("some","checked"))
 args=parser.parse_args(argv);BUILD=args.build.absolute();OUT=new_output(args.output,ROOT)
 report0=validate_build(BUILD)
 inputs={str(ROOT/name):value for name,value in report0["source_inputs"].items()}
 inputs[str(BUILD/"build.json")]=ident((BUILD/"build.json").read_bytes())
 for role in ("state","root","prepared","snapshot","checked","tree"):
  path=BUILD/(role+".flat");value=ident(path.read_bytes());need(value==report0["images"][role],"Exact actual Node image")
  inputs[str(path)]=value
 actual=None;states={};snaps={};parents={};prepared={};semantics=[];controls=[];state_inputs={}
 start=time.monotonic_ns();failure=None;errors=[]
 try:
  fence();(run_some if args.group=="some" else run_checked)()
  need((len(controls),len(semantics))==((13,82) if args.group=="some" else (14,94)),"Exact finite method roster")
 except BaseException as error:failure={"error":repr(error),"traceback":traceback.format_exc()}
 finally:
  if actual is not None:
   try:actual.finish()
   except BaseException as error:errors.append({"cleanup":repr(error)})
  try:fence()
  except BaseException as error:errors.append({"source_after":repr(error)})
  report={"schema":"trnm.native-snapshot-methods.v1","group":args.group,"status":"PASS" if failure is None and not errors else "FAIL",
   "build":ident((BUILD/"build.json").read_bytes()),"source_inputs":inputs,"controls":controls,"controls_total":len(controls),
   "semantic_methods":len(semantics),"semantic_history":semantics,"native_calls":0 if actual is None else actual.calls,
   "actual_full_roots":0 if actual is None else actual.roots,"journal_records":0 if actual is None else actual.records,
   "failure":failure,"source_after":{"status":"MATCH" if not errors else "FAIL","errors":errors},"elapsed_ns":time.monotonic_ns()-start,
   "scope":{"native_node_images":True,"actual_shared_map_and_tree":True,"full_canonical_bytes":True,"all_owners_retired":failure is None,
    "private_fixture_edits_explicit":True,"original_rust":"SEPARATE_GATE","node_lifecycle":"SEPARATE_GATE","capacity":"SEPARATE_GATE"}}
  (OUT/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:report[k] for k in ("status","group","controls_total","semantic_methods","native_calls","actual_full_roots","failure","source_after","elapsed_ns")}),flush=True)
  if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
