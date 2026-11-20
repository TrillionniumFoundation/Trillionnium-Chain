"""Full actual Node/Parent/Prepared readback; observation only."""
import json,struct
from .safe import need,same
from hia.platform.execution_batch.prefix_observations import expected_error
DEFAULT=(65536,8388608,536870912)
def srv(raw):
 need(raw[:4]==b"SRV1","Canonical State magic");n=struct.unpack_from("<I",raw,4)[0];p=8;rows=[]
 for _ in range(n):
  kn,vn=struct.unpack_from("<II",raw,p);p+=8;k=raw[p:p+kn];p+=kn;v=raw[p:p+vn];p+=vn
  need(len(k)==kn and len(v)==vn,"Canonical row bounds");rows.append((k,v))
 need(p==len(raw),"Canonical trailing");need(all(rows[i-1][0]<rows[i][0] for i in range(1,len(rows))),"Canonical order");return rows

def value_capacity(raw):
 cap=128;n=0;i=0
 def write(k):
  nonlocal cap,n
  if n+k>cap:cap=max(cap*2,n+k)
  n+=k
 while i<len(raw):
  c=raw[i]
  if c==34:
   write(1);i+=1
   while raw[i]!=34:
    start=i
    while raw[i] not in (34,92):i+=1
    write(i-start)
    if raw[i]==92:k=6 if raw[i+1]==117 else 2;write(k);i+=k
   write(1);i+=1
  elif c in b"[]{},:":write(1);i+=1
  else:
   start=i
   while i<len(raw) and raw[i] not in b",]}":i+=1
   write(i-start)
 need(n==len(raw),"Independent canonical writer accounting")
 return cap

def charges(rows):
 count=len(rows);payload=sum(len(k)+len(v) for k,v in rows);caps=sum(len(k)+value_capacity(v) for k,v in rows);nodes=max(2*count-1,0)
 return {"payload":payload,"capacities":caps,"map":caps+1024*count,"tree":caps+256*nodes+8224,"nodes":nodes}
def parse_parent(raw):
 need(len(raw)>=264 and raw[:8]==b"NPCPAR01","Parent actual header")
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 need(q(8)==len(raw) and q(48)==len(raw)-256,"Parent exact extent")
 rows=srv(raw[256:]);c=charges(rows)
 need(q(32)==len(rows) and q(88)==c["payload"],"Parent full canonical values")
 need((q(208),q(216),q(224))==(c["map"],c["tree"],c["capacities"]),"Parent actual charges")
 return {"root_hex":raw[128:160].hex(),"rows":[[k.hex(),v.hex()] for k,v in rows],"refs":q(160),"base":q(16),"epoch":q(104),"bind_seq":q(112),"height":q(120)}

def parse(raw,limits,parent_rows):
 need(len(raw)>=256 and raw[:8]==b"NPCDATA2","Prepared header")
 q=lambda at:struct.unpack_from("<Q",raw,at)[0]
 need(q(8)==len(raw),"Prepared extent")
 bn,an,dn,tn=q(48),q(80),q(56),q(240);need(256+bn+an+dn+tn==len(raw),"Prepared sections")
 need(bn==0 and an>=8,"Returned Prepared may not retain parent map; this Node corpus takes cached path")
 before=[(bytes.fromhex(k),bytes.fromhex(v)) for k,v in parent_rows];after=srv(raw[256:256+an]);p=256+an
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

def observed_parent_map(s,actual_parent):
 s.command(10);raw=s.frame()
 need(raw[:8]==b"NPCPARV1" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Full owned canonical parent frame")
 payload=raw[16:];actual=parse_parent(payload)
 need(actual["root_hex"]==actual_parent["root_hex"] and actual["height"]==actual_parent["height"] and actual["epoch"]==actual_parent["epoch"],"Parent map actual disk/context source")
 need(actual["refs"]==1 and actual["base"]!=0 and actual["bind_seq"]!=0,"Returned Prepared must have released parent borrow")
 return actual,payload

def observed_prepared(s,parent_rows):
 s.command(9);raw=s.frame()
 need(raw[:8]==b"NPCVIEW1" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Full Prepared owner frame")
 payload=raw[16:];actual=parse(payload,DEFAULT,parent_rows)
 snapshot=actual["snapshot"]
 public=None if snapshot is None else {k:snapshot[k] for k in ("keys","payload_bytes","retained_charge_bytes","root_hex")}
 return {"root_hex":actual["root_hex"],"changes":actual["changes"],"observation":actual["observation"],"snapshot":public,
         "before":actual["before"],"after":actual["after"]},payload

def context(raw):
 need(raw[:4]==b"SDO1" and len(raw)>=576 and struct.unpack_from("<I",raw,4)[0]==len(raw),"SDO1 complete")
 ec,sc,pl,ml,sl=struct.unpack_from("<5I",raw,448)
 need((ec,sc)==(3,7) and 576+pl+ml+sl==len(raw) and raw[8:16]==bytes(8) and raw[468:480]==bytes(12),"SDO1 structure")
 return {"timestamp":struct.unpack_from("<Q",raw,16)[0],"network_hex":raw[24:56].hex(),"parameters_hex":raw[56:88].hex(),
         "family_hex":raw[88:120].hex(),"plan_hex":raw[120:152].hex(),"genesis_hex":raw[152:184].hex(),"initial_root_hex":raw[184:216].hex(),
         "fees":list(struct.unpack_from("<25Q",raw,248)),"evaluators":[raw[480+32*i:512+32*i].hex() for i in range(3)],
         "params_canonical_hex":raw[576:576+pl].hex(),"model_registry_canonical_hex":raw[576+pl:576+pl+ml].hex()}

def parent(raw):
 need(raw[:8]==b"NBPAR001" and len(raw)==536 and struct.unpack_from("<Q",raw,8)[0]==520,"Actual parent frame")
 record=raw[24:];need(record[:8]==b"NGSTATE1","Actual held record")
 q=lambda off:struct.unpack_from("<Q",record,off)[0]
 need(q(208)==1 and q(224)==0 and q(232)==0 and q(344)==1 and q(384)==7,"Original genesis closed catalog")
 return {"tip_hex":record[160:192].hex(),"generation":q(192),"slot":q(200),"height":q(216),
         "parent_hex":None,"work_hex":record[240:304].hex(),"root_hex":record[128:160].hex(),"record_hex":record.hex(),"epoch":struct.unpack_from("<Q",raw,16)[0]}

def parse_prefix(raw,opcode,ctx,sequence):
 need(raw[:8]==b"NBPFX001" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Node prefix complete framing")
 data=raw[16:];need(len(data)>=256 and data[:8]==b"BRGOUT01","Scoped prefix framing")
 q=list(struct.unpack_from("<32Q",data))
 need(q[1]==sequence and q[2]==opcode and q[3] in (1,2,3,4),"Actual private call identity")
 need(len(data)==256+q[18]+q[16]+q[17]+q[15],"Complete prefix extent")
 need(data[256:256+q[18]]==ctx and q[18]==len(ctx) and q[27]==1 and q[31]==1,"Actual bound context/base")
 at=256+q[18];held=data[at:at+q[16]];at+=q[16];output=data[at:at+q[17]];at+=q[17]
 receipts=[]
 for _ in range(q[14]):
  need(at+8<=len(data),"Receipt length");n=struct.unpack_from("<Q",data,at)[0];at+=8
  need(n<=len(data)-at,"Receipt bytes");receipts.append(data[at:at+n].hex());at+=n
 need(at==len(data),"Receipt suffix")
 if q[3]!=1:need(not output and data[168:200]==bytes(32),"Failure successor")
 metrics=None
 if opcode==2 and q[3]==1:
  metrics={"workers":1,"workers_spawned":0,"peak_inflight":q[13],"committed_without_replay":q[12],"speculative":0,"reexecuted":0,"serial_conflict_batches":0,"signature_verifications":q[11]}
 return {"header":q,"outcome":{1:"ok",2:"error",3:"cancelled",4:"panic"}[q[3]],"error":expected_error(q[4],q[5]) if q[3]==2 else None,
         "state_hex":output.hex() if opcode==2 and q[3]==1 else None,"root_hex":data[168:200].hex() if opcode==2 and q[3]==1 else None,
         "receipts":receipts if opcode==2 and q[3]==1 else None,"metrics":metrics,"held_state_hex":held.hex(),
         "private_receipts":receipts,"length":q[8],"ready":bool(q[25]),"raw_hex":data.hex()}
