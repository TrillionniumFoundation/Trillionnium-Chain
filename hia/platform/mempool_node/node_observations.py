"""Read every actual Node request/response and all four canonical histories."""
from pathlib import Path
import struct
from . import safe,evidence
from .build import ROOT
from .node_cases import histories,canonical_bytes,transaction
from .node_observers import context,parent,parse_prefix,parse_parent,parse,DEFAULT,immutable_parent_payload
from .observations import read,load
need=safe.need;same=safe.same

def collect(artifact):
 bound={};directory,build,report=evidence.partition(artifact,"node",bound)
 need(same(report["source_inputs"],build["source_inputs"]),"Actual Node source map")
 cases=histories();raw=canonical_bytes();need(read(directory/"corpus.jsonl",bound)==raw,"Full Node case input bytes")
 need(same(report["corpus"],safe.identity(raw)) and type(report["controls_total"]) is int and report["controls_total"]==4 and type(report["real_processes"]) is int and report["real_processes"]==8,"Full Node roster")
 need(len(report["controls"])==4 and [c["name"] for c in report["controls"]]==[c["name"] for c in cases],"Node result order")
 folders=sorted(p.parent.name for p in directory.glob("*/receipt.json"))
 need(folders==sorted([n for c in cases for n in (c["name"],c["name"]+"-cold")]),"Whole actual eight Node processes")
 observed=[]
 for case,control in zip(cases,report["controls"],strict=True):
  hot=None
  for cold in (False,True):
   folder=directory/(case["name"]+("-cold" if cold else ""))
   receipt,streams,frames=evidence.process(folder,bound);wire=streams["stdin"]
   need(same(receipt,control["cold_process" if cold else "first_process"]),"Inline actual process differs")
   need(len(wire)>=64 and wire[:8]==b"NGBOOT01","Node bootstrap")
   b=struct.unpack_from("<7Q",wire,8);ts=case["timestamp"]
   need(b[1:5]==(int(cold),int(ts is not None),0 if ts is None else ts,case["workers"]) and b[5:]==((1<<64)-1,)*2,"Actual Node bootstrap context")
   first=frames[0];need(first[:8]==b"NBBASE01" and struct.unpack_from("<QQ",first,8)==(1,7) and len(first)==160+struct.unpack_from("<Q",first,24)[0],"Actual base response")
   ctx=first[160:];actual_context=context(ctx);need(first[128:160].hex()==actual_context["initial_root_hex"],"Actual State root/context")
   at=64;oi=1
   def call(op,payload=b""):
    nonlocal at,oi
    request=b"NBINPUT1"+struct.pack("<Q",op)+payload
    packet=struct.pack("<Q",len(request))+request
    need(wire[at:at+len(packet)]==packet,"Actual canonical Node request/order");at+=len(packet)
    need(oi<len(frames),"Missing Node response");result=frames[oi];oi+=1;return result
   def state_read():
    value=call(1);need(value[:8]==b"NBSTATE1" and len(value)>=24 and struct.unpack_from("<Q",value,16)[0]==7 and len(value)==16+struct.unpack_from("<Q",value,8)[0],"Actual State extent");return value[16:].hex()
   base=state_read();actual_parent=parent(call(3))
   if not cold:
    need(same(actual_context,control["context"]) and base==control["base_hex"] and same(actual_parent,control["parent"]),"Actual base/context/parent mismatch")
    need(len(control["actions"])==len(case["actions"])==24,"Complete 24 Node methods")
    retained=None;retained_raw=None;parent_map=None;parent_raw=None;seq=0;last=None
    for index,(action,row) in enumerate(zip(case["actions"],control["actions"],strict=True)):
     op=action["op"];raws=[]
     if op=="new":
      ts2=action["timestamp"];response=call(4,struct.pack("<QQ",int(ts2 is not None),0 if ts2 is None else ts2)+bytes.fromhex(action["miner_hex"]));code=5
     elif op=="drop":response=call(7);code=4
     else:
      raws=[transaction(k,bytes.fromhex(actual_context["network_hex"])) for k in action["transactions"]]
      response=call(5,struct.pack("<Q",len(raws))+b"".join(struct.pack("<Q",len(r))+r for r in raws));code=2
     seq+=1;actual=parse_prefix(response,code,ctx,seq);actual.update(index=index,op=op,transactions=[r.hex() for r in raws])
     if op=="drop":need(actual["header"][28]==3 and actual["ready"] is False,"Actual scoped drop retained base, Parent and cached Snapshot before retirement")
     if actual["outcome"]!="ok" and last is not None:
      need(same([actual[k] for k in ("held_state_hex","length","private_receipts")],[last[k] for k in ("held_state_hex","length","private_receipts")]) and actual["header"][9]==last["header"][9],"Actual failed Prefix rollback differs")
     def get_parent():
      r=call(10);need(r[:8]==b"NPCPARV1" and len(r)==16+struct.unpack_from("<Q",r,8)[0],"Actual parent map extent")
      p=parse_parent(r[16:]);need(r[16:24]==b"NPCSNP01" and p["refs"]>=2 and p["root_hex"]==actual_parent["root_hex"] and p["height"]==actual_parent["height"] and p["epoch"]==actual_parent["epoch"] and p["base"]!=0 and p["bind_seq"]!=0,"Actual Some Parent and retained Node Snapshot ownership/source")
      return p,r[16:]
     def get_prepared():
      r=call(9);need(r[:8]==b"NPCVIEW1" and len(r)==16+struct.unpack_from("<Q",r,8)[0],"Actual Prepared extent")
      v=parse(r[16:],DEFAULT,parent_map["rows"]);ss=v["snapshot"]
      need(r[16:24]==b"NPCDATA3" and v["observation"]["method"]=="CheckedApply" and ss is not None,"Actual healthy Some branch must perform CheckedApply")
      public={k:v[k] for k in ("root_hex","changes","observation","before","after")}
      public["snapshot"]=None if ss is None else {k:ss[k] for k in ("keys","payload_bytes","retained_charge_bytes","root_hex")}
      return public,r[16:]
     if op=="new" and actual["outcome"]=="ok":
      parent_map,parent_raw=get_parent();need(parent_map["bind_seq"]==seq,"Actual Parent sequence")
     if op=="execute":
      if actual["outcome"]=="ok":
       retained,retained_raw=get_prepared();need(retained["root_hex"]==actual["root_hex"],"Prepared/Output root")
      elif retained is not None:
       v,vr=get_prepared();need(same(v,retained) and vr==retained_raw,"Failed Prefix replaced prior Prepared")
     elif op=="drop":retained=None;retained_raw=None
     if actual["ready"]:
      v,vr=get_parent();need(same({k:x for k,x in v.items() if k!="refs"},{k:x for k,x in parent_map.items() if k!="refs"}) and immutable_parent_payload(vr)==immutable_parent_payload(parent_raw),"Actual fixed parent canonical bytes, root, context or shared tree mutated")
      parent_map,parent_raw=v,vr
     if op=="drop" or (op=="new" and not actual["ready"]):parent_map=None;parent_raw=None
     actual.update(canonical_parent=parent_map,canonical_parent_payload_hex=None if parent_raw is None else parent_raw.hex(),
       prepared=retained,prepared_owner_payload_hex=None if retained_raw is None else retained_raw.hex())
     need(same(actual,row),"Every reported Node method must equal actual pipe decoding")
     last=actual
    need(state_read()==base and same(parent(call(3)),actual_parent),"Actual canonical source changed")
    hot=(first,base,actual_parent)
   else:need(hot is not None and first==hot[0] and base==hot[1] and same(actual_parent,hot[2]),"Actual cold source changed")
   need(call(2)==b"NBCLOSE1"+bytes(8) and at==len(wire) and oi==len(frames),"Whole actual Node retirement/pipes")
  need(control["status"]=="PASS" and control["base_unchanged"] is True and control["cold_source_equal"] is True,"Actual Node result annotations")
  observed.append(control)
 need(sum(len(c["actions"]) for c in observed)==96,"All 96 actual methods")
 return cases,observed,bound
