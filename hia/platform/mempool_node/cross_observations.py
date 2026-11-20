"""Strictly read the actual 24-command joint one-Node lifecycle."""
from pathlib import Path
import ast,sys,json,struct,hashlib,traceback
from . import observations as obs,safe,evidence
from .build import ROOT,validate_build
from .node_observers import parse_parent,parse,parent,parse_prefix
need=obs.need;identity=obs.ident;same=obs.same;DEFAULT=(65536,8388608,536870912)
def collect(artifact):
 bound={};artifact=Path(artifact).absolute();directory,_,_=evidence.partition(artifact,"cross",bound);folder=directory/"single-owner-cross-lifecycle"
 report_path=folder.parent/"report.json";report=obs.load(obs.read(report_path,bound))
 need(report["status"]=="PASS" and report["failure"] is None and same(report["cleanup_errors"],[]) and same(report["source_after"],{"status":"MATCH","errors":[]}),"Actual cross owner lifecycle incomplete")
 build=validate_build(artifact/"build",ROOT)
 need(same(report["build"],identity(obs.read(artifact/"build/build.json",bound))) and same(report["executable"],build["executable"]),"Actual joint runtime source binding")
 for path,row in build["source_inputs"].items():need(same(identity(obs.read(ROOT/path,bound)),row),"Joint build source drift")
 need(same(report["source_inputs"],build["source_inputs"]),"Complete cross suite source map")
 for path,row in report["source_inputs"].items():need(same(identity(obs.read(ROOT/path,bound)),row),"Actual lifecycle source drift")
 receipt=obs.load(obs.read(folder/"receipt.json",bound))
 need(type(receipt["exit_code"]) is int and receipt["exit_code"]==0 and type(receipt["expected_exit"]) is int and receipt["expected_exit"]==0 and receipt["cleanup"] is None,"Actual cross process did not close")
 streams={k:obs.read(folder/(k+".raw"),bound) for k in ("stdin","stdout","stderr")}
 for k,raw in streams.items():need(same(identity(raw),receipt[k]),"Actual cross raw identity")
 need(not streams["stderr"] and type(receipt["elapsed_ns"]) is int and 0<receipt["elapsed_ns"]<=243_000_000_000,"Actual successful cross process diagnostics/budget")
 evidence.namespace(folder,receipt,bound)
 evidence.trace_capture(folder,bound)
 fs=obs.frames(streams["stdout"]);need([f.hex() for f in fs]==receipt["frames_hex"],"Full cross actual frame roster")
 wire=streams["stdin"];need(wire[:8]==b"NGBOOT01" and len(wire)>=64,"Actual bootstrap")
 boot=struct.unpack_from("<7Q",wire,8);need(boot[1:5]==(0,0,0,1) and boot[5:]==((1<<64)-1,)*2,"Exact joint lifecycle context")
 first=fs[0];need(first[:8]==b"NBBASE01" and struct.unpack_from("<QQ",first,8)==(1,7) and len(first)==160+struct.unpack_from("<Q",first,24)[0],"Actual private State producer")
 ctx=first[160:];context=obs.context(ctx);need(first[128:160].hex()==context["initial_root_hex"],"Actual source root")
 actions=[];native=[];at=64;oi=1;base=None;actual_parent=None;parent_rows=None;last_output=None;pool=False;closed=False
 while at<len(wire):
  need(not closed and at+8<=len(wire),"Command after close")
  n=struct.unpack_from("<Q",wire,at)[0];at+=8;need(16<=n<1<<24 and n<=len(wire)-at,"Whole command extent")
  request=wire[at:at+n];at+=n;need(request[:8]==b"NBINPUT1","Actual command magic")
  opcode=struct.unpack_from("<Q",request,8)[0];events=[];cancel=None;progress_raw=[]
  while True:
   need(oi<len(fs),"Missing actual response");response=fs[oi];oi+=1
   if response[:8] not in (b"M05PROG1",b"PXPROG01"):break
   need(len(response)==64 and at+48<=len(wire),"Whole callback")
   q=struct.unpack("<8Q",response);ack=wire[at:at+48];at+=48;a=struct.unpack("<6Q",ack)
   need(q[2]==q[7]==0 and a[1:4]==q[1:4] and a[4] in (0,1,2) and (a[4]!=0 or a[5]==0),"Exact callback identity")
   need(ack[:8]==(b"M05ACK01" if response[:8]==b"M05PROG1" else b"PXGO0001"),"Callback domain")
   events.append({"kind":q[4],"index":q[5]})
   progress_raw.append({"observed_hex":response.hex(),"ack_hex":ack.hex(),"kind":q[4],"index":q[5],"height":q[6],"classification":a[4]})
   if a[4]:need(cancel is None,"Multiple injected refusals");cancel={"ordinal":len(events)-1,"class":a[4],"token":a[5],"kind":q[4],"index":q[5]}
  item={"index":len(actions),"cancel":cancel};row={"index":len(actions),"progress":events,"progress_raw":progress_raw,"input_hex":request.hex(),"output_hex":response.hex(),"outcome":"ok","error":None}
  if opcode==1:
   need(n==16 and response[:8]==b"NBSTATE1" and len(response)>=24 and struct.unpack_from("<Q",response,16)[0]==7 and len(response)==16+struct.unpack_from("<Q",response,8)[0] and not events,"Actual State read")
   value=response[16:].hex()
   if base is None:base=value
   need(base==value,"Actual shared base changed");item["op"]="read";row["base_unchanged"]=True
  elif opcode==2:
   need(n==16 and response==b"NBCLOSE1"+bytes(8) and not events and not pool,"Complete owner close")
   item["op"]="close";closed=True
  elif opcode==3:
   need(n==16 and not events,"Parent read shape")
   observed=parent(response)
   if actual_parent is None:actual_parent=observed
   need(same(observed,actual_parent),"Held actual parent changed");item["op"]="record";row["parent"]={k:v for k,v in observed.items() if k not in ("epoch","record_hex")}
  elif opcode in (4,5,7):
   need(not pool and not events,"Public Prefix used while pool lease alive")
   name={4:"node_new",5:"node_execute",7:"node_drop"}[opcode];item["op"]=name
   if opcode==4:
    need(n==64,"Node new extent");flag,ts=struct.unpack_from("<QQ",request,16);need(flag in (0,1) and (flag or ts==0),"Node timestamp")
    item.update(timestamp=ts if flag else None,miner_hex=request[32:64].hex());parent_rows=None;last_output=None
   elif opcode==5:
    need(n>=24,"Actual execute extent");count=struct.unpack_from("<Q",request,16)[0];pos=24;raws=[]
    for _ in range(count):
     need(pos+8<=n,"Transaction extent");size=struct.unpack_from("<Q",request,pos)[0];pos+=8;need(size<=n-pos,"Transaction body");raws.append(request[pos:pos+size].hex());pos+=size
    need(pos==n,"Trailing input");item["transactions"]=raws
   else:need(n==16,"Node drop extent");parent_rows=None;last_output=None
   seq=struct.unpack_from("<Q",response,24)[0]
   parsed=parse_prefix(response,{4:5,5:2,7:4}[opcode],ctx,seq)
   if opcode==7:need(parsed["header"][28]==3 and parsed["ready"] is False,"Actual cross scoped drop retains Node Snapshot before retirement")
   need(parsed["outcome"]=="ok","Bound joint public Prefix method failed")
   for key in ("outcome","error","state_hex","root_hex","receipts","metrics","length","ready"):row[key]=parsed[key]
   if opcode==5:last_output=parsed
  elif opcode==10:
   need(n==16 and not pool and not events and response[:8]==b"NPCPARV1" and len(response)==16+struct.unpack_from("<Q",response,8)[0],"Canonical Parent observation")
   parsed=parse_parent(response[16:]);need(response[16:24]==b"NPCSNP01" and parsed["refs"]>=2 and parsed["root_hex"]==actual_parent["root_hex"],"Actual fixed Some Parent and Node cache retain original Snapshot")
   parent_rows=parsed["rows"];item["op"]="canonical_parent";row.update(rows=parent_rows,root_hex=parsed["root_hex"])
  elif opcode==9:
   need(n==16 and not pool and not events and response[:8]==b"NPCVIEW1" and len(response)==16+struct.unpack_from("<Q",response,8)[0],"Actual Prepared observation")
   need(parent_rows is not None and last_output is not None,"No actual staged owner")
   value=parse(response[16:],DEFAULT,parent_rows);need(value["root_hex"]==last_output["root_hex"],"Actual Prepared/Output mismatch")
   need(response[16:24]==b"NPCDATA3" and value["observation"]["method"]=="CheckedApply" and value["snapshot"] is not None,"Actual cross Some branch must perform CheckedApply")
   # Preserve every private field/raw byte, while comparing the same public
   # PreparedCommitment observation as the qualified C Node observer.
   row["prepared_private"]=value
   snap=value["snapshot"]
   public_snapshot=None if snap is None else {k:snap[k] for k in ("keys","payload_bytes","retained_charge_bytes","root_hex")}
   item["op"]="prepared";row["prepared"]={k:value[k] for k in ("root_hex","changes","observation","before","after")}
   row["prepared"]["snapshot"]=public_snapshot
  elif opcode==8:
   need(n>=24 and response[:8]==b"NMPRES02" and len(response)>=64,"Actual pool result")
   sub=struct.unpack_from("<Q",request,16)[0];q=struct.unpack_from("<8Q",response)
   need(sub in (1,2,3) and q[1]==sub and q[2] in (1,2,3,4) and q[6] in (0,1) and len(response)==64+q[4]+q[5],"Pool header")
   outcome={1:"ok",2:"error",3:"cancelled",4:"panic"}[q[2]];error=None;mh=None;ph=None
   if outcome=="error" and q[3]:error="POOL_LIMITS" if 31<=q[3]<=36 else obs.ERRORS[q[3]]
   if q[4]:
    m=response[64:64+q[4]];need(m[:8]==b"M05OUT01" and len(m)>=128,"Actual admission")
    mh=struct.unpack_from("<16Q",m);need(len(m)==128+mh[15] and mh[13]==0,"Complete admission/no value leak")
   if q[5]:
    px=response[64+q[4]:];need(px[:8]==b"BRGOUT01" and len(px)>=256,"Actual Prefix")
    ph=struct.unpack_from("<32Q",px);need(ph[3]==q[2] and len(px)==256+ph[18]+ph[16]+ph[17]+ph[15],"Complete Prefix result")
    if outcome=="error":need(error is None,"Two error domains");error=obs.prefix_error(ph)
   if sub==1:
    need(n==104 and not pool and not events,"Real pool open")
    vals=struct.unpack_from("<7Q",request,16);need(vals[6]==0,"Pool policy reserved")
    item.update(op="open",policy={"max_records":vals[1],"max_bytes":vals[2],"critical_reserve":vals[3],"max_group_members":vals[4],"max_removals":vals[5],"preview_miner_hex":request[72:104].hex()})
   elif sub==2:
    need(n>=32 and pool and mh is not None,"Validation without actual lease")
    count=struct.unpack_from("<Q",request,24)[0];pos=32;tx=[]
    for _ in range(count):
     need(pos+8<=n,"Whole wire extent");size=struct.unpack_from("<Q",request,pos)[0];pos+=8;need(size<=n-pos,"Whole wire body");tx.append(request[pos:pos+size].hex());pos+=size
    need(pos==n,"Trailing wire input");item.update(op="validate",transactions=tx)
    need(ph is None or ph[25] in (0,1),"Actual Prefix ready word")
    if ph is not None and ph[25]==0:need(ph[8]==0,"Absent Prefix has a nonzero length")
    row.update(main_validations=mh[5],reused=mh[7],native_strict_signatures=mh[6],ready_count=mh[4],prefix_length=None if ph is None or ph[25]==0 else ph[8],prefix_observed=ph is not None,prefix_ready=None if ph is None else bool(ph[25]))
   else:need(n==24 and pool and not events and outcome=="ok" and q[6]==0,"Actual pool drop");item["op"]="drop"
   pool=bool(q[6]);row.update(outcome=outcome,error=error,active=pool)
  else:raise ValueError("Unknown actual joint public command")
  row["op"]=item["op"];actions.append(item);native.append(row)
 expected=["read","record","node_new","node_execute","canonical_parent","prepared","node_drop","open","validate","validate","validate","drop","node_new","node_execute","canonical_parent","prepared","node_drop","open","validate","validate","drop","read","record","close"]
 need(at==len(wire) and oi==len(fs) and closed and not pool and [x["op"] for x in actions]==expected,"Whole exact one-Node lifecycle")
 need(sum(x["op"]=="validate" for x in actions)==5 and len(actions)==24,"Actual fixed cross roster")
 for p in (Path(__file__),Path(obs.__file__),ROOT/"hia/platform/execution_batch/prefix_observations.py"):obs.read(p,bound)
 case={"schema":"trnm.single-node-m05-C-cross-history.v1","name":"single-owner-cross-lifecycle","timestamp":None,"workers":1,"actions":actions}
 observed={"name":case["name"],"context":context,"base_hex":base,"parent":{k:v for k,v in actual_parent.items() if k not in ("epoch","record_hex")},"actions":native,"receipt":receipt}
 need(obs.canonical(case)+b"\n"==obs.read(ROOT/"hia/platform/mempool_node/cross_corpus.jsonl",bound),"Exact whole canonical 24-command input")
 need(type(report["real_processes"]) is int and report["real_processes"]==1,"Actual cross process count")
 need(sorted(p.parent.name for p in directory.glob("*/receipt.json"))==["single-owner-cross-lifecycle"],"Whole cross process roster")
 obs.read(folder/"syscalls.raw",bound)
 expected_observations=[]
 for i,row in enumerate(native):
  if row["op"] in ("node_new","node_execute","node_drop"):
   data=bytes.fromhex(row["output_hex"])[16:];header=list(struct.unpack_from("<32Q",data))
   expected_observations.append({"name":"node-op"+str({"node_new":4,"node_execute":5,"node_drop":7}[row["op"]]),"result":{"header":header,"record":identity(data),"raw_hex":data.hex()}})
  elif row["op"]=="prepared":
   need(native[i-1]["op"]=="canonical_parent","Actual paired observation order")
   expected_observations.append({"name":"real-parent-and-prepared","parent_hex":native[i-1]["output_hex"],"prepared_hex":row["output_hex"]})
 expected_observations.append({"name":"complete-retirement-and-source-unchanged","receipt":receipt,"base_hex":native[-3]["output_hex"],"record_hex":native[-2]["output_hex"]})
 need(same(report["observations"],expected_observations),"Whole cross observation report differs from actual pipes")
 from .suite_smoke import pool_result
 validations=[(a,r) for a,r in zip(actions,native,strict=True) if a["op"]=="validate"]
 names=["cancel-new-drops-real-parent","retry-after-parent-consumed","real-ready-on-rebound-parent","panic-new-drops-real-parent","retry-after-parent-panic"]
 from .native_contract import fixed_validations,validation
 fixed=fixed_validations("cross");need(list(fixed)==names,"Actual fixed cross validation predicates")
 need(type(report["m05_controls"]) is list and len(report["m05_controls"])==5,"Whole cross M05 control roster")
 for (a,r),control,name in zip(validations,report["m05_controls"],names,strict=True):
  need(control["name"]==name and same(control["input_hex"],a["transactions"]),"Actual cross control input")
  raw=bytes.fromhex(r["output_hex"]);decoded=validation(control,fixed[name])
  need(control["raw_hex"]==r["output_hex"],"Fixed cross predicate was not the actual response")
  for key,value in decoded.items():need(same(control.get(key),value),"Cross control result differs from actual bytes")
  progress=[{k:p[k] for k in ("observed_hex","ack_hex","kind","index","height","classification")} for p in control["progress"]]
  need(same(progress,r["progress_raw"]),"Cross control callback bytes differ")
 return case,observed,bound
