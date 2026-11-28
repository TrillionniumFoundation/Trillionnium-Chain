"""Full actual Node/Parent/Prepared readback; observation only."""
import json,struct,hashlib
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
def parse_parent_legacy(raw):
 need(len(raw)>=264 and raw[:8]==b"NPCPAR01","Parent actual header")
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 need(q(8)==len(raw) and q(48)==len(raw)-256,"Parent exact extent")
 rows=srv(raw[256:]);c=charges(rows)
 need(q(32)==len(rows) and q(88)==c["payload"],"Parent full canonical values")
 need((q(208),q(216),q(224))==(c["map"],c["tree"],c["capacities"]),"Parent actual charges")
 return {"root_hex":raw[128:160].hex(),"rows":[[k.hex(),v.hex()] for k,v in rows],"refs":q(160),"base":q(16),"epoch":q(104),"bind_seq":q(112),"height":q(120)}

def parse_legacy(raw,limits,parent_rows):
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


def state_hash(tag,*parts):
 raw=b"TRNM-PON1\0"+struct.pack("<H",len(tag))+tag+b"".join(struct.pack("<I",len(p)&0xffffffff)+p for p in parts)
 return hashlib.sha256(raw).digest()
EMPTY=[b"\0"]*257;EMPTY[256]=state_hash(b"state-empty")
for depth in range(255,-1,-1):EMPTY[depth]=state_hash(b"state-node",EMPTY[depth+1],EMPTY[depth+1])

def lift(path,digest,start,end=0):
 for depth in range(start-1,end-1,-1):
  other=EMPTY[depth+1]
  digest=state_hash(b"state-node",other,digest) if (path[depth//8]>>(7-depth%8))&1 else state_hash(b"state-node",digest,other)
 return digest

def parse_shared(raw):
 need(len(raw)>=128 and raw[:8]==b"NPCSHR01","Shared tree real header")
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 need(q(8)==len(raw),"Exact tree export extent")
 count,node_count,root,empty,emptyrefs=q(16),q(24),q(32),q(40),q(48)
 need(node_count==max(count*2-1,0) and (root!=0)==(count!=0) and empty!=0 and emptyrefs>0,"Actual compressed tree/empty owner")
 at=128;nodes={};rows=[]
 for _ in range(node_count):
  need(at+216<=len(raw),"Node extent")
  pointer=struct.unpack_from("<Q",raw,at)[0];body=raw[at+8:at+216];at+=216
  n=lambda off:struct.unpack_from("<Q",body,off)[0]
  need(pointer>4096 and pointer not in nodes and n(192)>0,"Unique live actual node")
  row={"path":body[:32],"digest":body[32:64],"depth":n(64),"kind":n(72),"left":n(80),"right":n(88),"left_hash":body[128:160],"right_hash":body[160:192],"refs":n(192)}
  if row["kind"]==1:
   kn,vn=n(104),n(120);key=raw[at:at+kn];value=raw[at+kn:at+kn+vn];at+=kn+vn
   need(len(key)==kn and len(value)==vn and n(96)==pointer+208 and n(112)==pointer+208+kn and n(200)==208+kn+vn,"Actual leaf owned bytes")
   need(row["depth"]==256 and row["path"]==state_hash(b"state-key",key) and row["digest"]==state_hash(b"state-leaf",key,value),"Full leaf hash grammar")
   row.update(key=key,value=value);rows.append((key,value))
  else:need(row["kind"]==2 and n(200)==208 and row["depth"]<256,"Fork extent")
  nodes[pointer]=row
 need(at==len(raw) and len(rows)==count and len(dict(rows))==count,"Every actual node and leaf consumed")
 visited=set()
 def visit(pointer):
  need(pointer in nodes and pointer not in visited,"No missing/cyclic/shared-within-tree node")
  visited.add(pointer);node=nodes[pointer]
  if node["kind"]==1:return
  visit(node["left"]);visit(node["right"]);left=nodes[node["left"]];right=nodes[node["right"]];d=node["depth"]
  need(left["depth"]>d and right["depth"]>d and node["path"]==left["path"],"Compressed parent depths/path")
  need(((left["path"][d//8]>>(7-d%8))&1)==0 and ((right["path"][d//8]>>(7-d%8))&1)==1,"Actual fork branch")
  need(lift(left["path"],left["digest"],left["depth"],d+1)==node["left_hash"] and lift(right["path"],right["digest"],right["depth"],d+1)==node["right_hash"],"Both actual cached child hashes")
  need(state_hash(b"state-node",node["left_hash"],node["right_hash"])==node["digest"],"Actual fork hash")
 if root:visit(root)
 need(len(visited)==node_count,"All exported nodes reachable")
 root_hash=EMPTY[0] if not root else lift(nodes[root]["path"],nodes[root]["digest"],nodes[root]["depth"])
 need(root_hash==raw[64:96],"Complete sparse root")
 return {"count":count,"root_pointer":root,"empty_pointer":empty,"empty_refs":emptyrefs,"root_hex":root_hash.hex(),"nodes":nodes,"rows":sorted(rows)}

def parse_snapshot(raw):
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 need(len(raw)>=392 and raw[:8]==b"NPCSNP01" and q(8)==len(raw),"Actual Snapshot complete frame")
 need(q(16) in (7,9) and q(48)>0 and q(56)>4096,"Actual map ownership")
 mn,tn=q(32),q(40);need(256+mn+tn==len(raw),"Snapshot sections")
 rows=srv(raw[256:256+mn]);tree=parse_shared(raw[256+mn:]);c=charges(rows)
 need(tree["rows"]==rows and tree["root_hex"]==raw[64:96].hex(),"Real map/tree/root agree")
 need(q(24)==len(rows) and (q(96),q(104),q(112),q(120))==(c["map"],c["tree"],c["capacities"],c["payload"]),"Actual Snapshot Vec charges")
 return {"rows":rows,"tree":tree,"root_hex":raw[64:96].hex(),"map_pointer":q(56),"map_refs":q(48),"charges":c,"epoch":q(128),"seq":q(136),"height":q(144),"source_state":q(152),"serial":q(160),"kind":q(16)}

def parse_some_prepared(raw):
 q=lambda n:struct.unpack_from("<Q",raw,n)[0]
 need(len(raw)>=272 and raw[:8] in (b"NPCDATA2",b"NPCDATA3") and q(8)==len(raw) and q(48)==0,"Actual Prepared compact frame")
 an,dn,tn=q(80),q(56),q(240);need(256+an+dn+tn==len(raw) and q(248)==256+an+dn,"Actual Prepared complete sections")
 at=256+an;end=at+dn;need(raw[at:at+8]==b"NDELTA01","Actual required delta");n=struct.unpack_from("<Q",raw,at+8)[0];at+=16;changes=[]
 for _ in range(n):
  kn,bn,vn,flags=struct.unpack_from("<4Q",raw,at);at+=32
  need(flags in (1,2,3) and at+kn+bn+vn<=end,"Delta bounds")
  key=raw[at:at+kn];before=raw[at+kn:at+kn+bn];after=raw[at+kn+bn:at+kn+bn+vn];at+=kn+bn+vn
  changes.append({"key_hex":key.hex(),"before_hex":before.hex() if flags&1 else None,"after_hex":after.hex() if flags&2 else None})
 need(at==end and n==q(64),"Actual delta roster")
 methods=["RebuiltTree","FullRoot(KeyBudget)","FullRoot(PayloadBudget)","FullRoot(WorkspaceBudget)","FullRoot(DeltaBudget)","FullRoot(InternalSnapshotMismatch)","CheckedApply"]
 need(q(168)<len(methods),"Actual method enum")
 observation={"method":methods[q(168)],"actual_keys":q(40),"actual_payload_bytes":q(96),"changed_keys":q(64),"changed_payload_bytes":q(72),"compressed_nodes":None if q(232)==(1<<64)-1 else q(232),"workspace_charge_bytes":q(176)}
 snapshot=None;tree=None
 if q(168) in (0,6):
  need(raw[:8]==b"NPCDATA3" and an>=8 and tn>=128,"CheckedApply has actual full Snapshot")
  rows=srv(raw[256:256+an]);tree=parse_shared(raw[end:]);c=charges(rows)
  need(rows==tree["rows"] and tree["root_hex"]==raw[128:160].hex(),"Prepared full actual map/tree/root")
  need((q(184),q(192),q(200))==(c["map"],c["tree"],c["capacities"]) and q(232)==c["nodes"],"Prepared actual charges")
  snapshot={"keys":len(rows),"payload_bytes":c["payload"],"retained_charge_bytes":c["map"]+c["tree"],"canonical_values":[[k.hex(),v.hex()] for k,v in rows],"root_hex":tree["root_hex"],"allocated_nodes":c["nodes"]}
 else:need(raw[:8]==b"NPCDATA2" and an==0 and tn==0 and q(232)==(1<<64)-1,"Fallback retained Snapshot or map")
 return {"root_hex":raw[128:160].hex(),"changes":changes,"observation":observation,"snapshot":snapshot,"tree":tree}

def immutable_parent_payload(raw):
    """Preserve every exported byte except live Arc reference counters."""
    body=bytearray(raw)
    if raw[:8]==b"NPCPAR01":
        parse_parent_legacy(raw)
        body[160:168]=bytes(8)
        return bytes(body)
    parse_snapshot(raw)
    q=lambda at:struct.unpack_from("<Q",raw,at)[0]
    body[48:56]=bytes(8)
    tree=256+q(32);body[tree+48:tree+56]=bytes(8)
    at=tree+128
    for _ in range(q(tree+24)):
        kind=q(at+80);kn=q(at+112);vn=q(at+128)
        body[at+200:at+208]=bytes(8)
        at+=216
        if kind==1:at+=kn+vn
    need(at==len(raw),"Full retained parent observation")
    return bytes(body)

def parse_parent(raw):
    if raw[:8]==b"NPCPAR01":return parse_parent_legacy(raw)
    x=parse_snapshot(raw)
    need(x["kind"]==7 and x["source_state"]!=0,"Actual Parent retained Snapshot")
    return {"root_hex":x["root_hex"],"rows":[[k.hex(),v.hex()] for k,v in x["rows"]],
            "refs":x["map_refs"],"base":x["source_state"],"epoch":x["epoch"],"bind_seq":x["seq"],"height":x["height"]}

def parse(raw,limits,parent_rows):
    need(len(raw)>=272,"Complete Prepared header")
    q=lambda at:struct.unpack_from("<Q",raw,at)[0]
    if raw[:8]==b"NPCDATA2" and q(168)==0:return parse_legacy(raw,limits,parent_rows)
    actual=parse_some_prepared(raw)
    before=[(bytes.fromhex(k),bytes.fromhex(v)) for k,v in parent_rows]
    bm=dict(before);am=dict(before);seen=set()
    for change in actual["changes"]:
        key=bytes.fromhex(change["key_hex"])
        old=None if change["before_hex"] is None else bytes.fromhex(change["before_hex"])
        new=None if change["after_hex"] is None else bytes.fromhex(change["after_hex"])
        need(key not in seen and bm.get(key)==old and old!=new,"Actual change against immutable original parent")
        seen.add(key)
        if new is None:am.pop(key)
        else:am[key]=new
    after=sorted(am.items())
    expected=[{"key_hex":k.hex(),"before_hex":bm[k].hex() if k in bm else None,"after_hex":am[k].hex() if k in am else None} for k in sorted(bm.keys()|am.keys()) if bm.get(k)!=am.get(k)]
    need(actual["changes"]==expected,"Every canonical change in original order")
    c=charges(after);b=charges(before)
    workspace=3*(max(c["map"],b["map"])+max(c["tree"],b["tree"]))+2*max(c["payload"],b["payload"])+256*len(expected)
    payload=sum(len(bytes.fromhex(x["key_hex"]))+sum(len(bytes.fromhex(x[v])) for v in ("before_hex","after_hex") if x[v] is not None) for x in expected)
    need((q(184),q(192),q(200))==(c["map"],c["tree"],c["capacities"]),"Complete current capacity charges")
    need((q(208),q(216),q(224))==(b["map"],b["tree"],b["capacities"]),"Complete immutable parent capacity charges")
    need(q(176)==workspace and q(72)==payload and q(88)==b["payload"] and q(96)==c["payload"] and q(40)==len(after),"Complete actual observation accounting")
    method=1 if len(after)>limits[0] else 2 if c["payload"]>limits[1] else 3 if workspace>limits[2] else 4 if len(expected)>65536 else 6
    need(q(168)==method or (method==6 and q(168)==5),"Original budget order and internal mismatch fallback")
    if actual["snapshot"] is not None:
        need(actual["snapshot"]["canonical_values"]==[[k.hex(),v.hex()] for k,v in after],"Actual complete successor values")
    return {**{k:actual[k] for k in ["root_hex","changes","observation","snapshot"]},
            "value_capacities":[[k.hex(),value_capacity(v)] for k,v in after],
            "parent_capacities":[[k.hex(),value_capacity(v)] for k,v in before],
            "before":[[k.hex(),v.hex()] for k,v in before],"after":[[k.hex(),v.hex()] for k,v in after],"reference_count":q(160)}


def observed_parent_map(s,actual_parent):
 s.command(10);raw=s.frame()
 need(raw[:8]==b"NPCPARV1" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Full owned canonical parent frame")
 payload=raw[16:];actual=parse_parent(payload)
 need(actual["root_hex"]==actual_parent["root_hex"] and actual["height"]==actual_parent["height"] and actual["epoch"]==actual_parent["epoch"],"Parent map actual disk/context source")
 need(payload[:8]==b"NPCSNP01" and actual["refs"]>=2 and actual["base"]!=0 and actual["bind_seq"]!=0,"Actual Some Parent and Node Snapshot retain canonical bytes")
 return actual,payload

def observed_prepared(s,parent_rows):
 s.command(9);raw=s.frame()
 need(raw[:8]==b"NPCVIEW1" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Full Prepared owner frame")
 payload=raw[16:];actual=parse(payload,DEFAULT,parent_rows)
 snapshot=actual["snapshot"]
 need(payload[:8]==b"NPCDATA3" and actual["observation"]["method"]=="CheckedApply" and snapshot is not None,"Healthy Node Some branch must perform actual CheckedApply")
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
