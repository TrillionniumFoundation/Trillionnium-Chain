"""Read complete actual M05 owner pipes; no Node/State/signature authority."""
from pathlib import Path
import json,struct,hashlib,stat
from . import safe
from .build import ROOT,validate_build,source_manifest
ERRORS={1:"POOL_BODY_LIMIT",2:"POOL_ENCODING",3:"POOL_SIGNER",4:"POOL_TAG",5:"CONFIG",6:"POOL_FEE",7:"POOL_DUPLICATE_MEMBER",8:"POOL_RECORD_LIMIT",9:"NONCE_OVERFLOW",10:"STATE_NONCE",11:"POOL_BACKPRESSURED",12:"POOL_TYPED_BINDING",113:"POOL_TYPED:SignatureRejected",115:"POOL_TYPED:Replay",117:"POOL_TYPED:RecheckFailed"}
PREP={1:"ENCODING",2:"SERVICE_CONTRACT_PROFILE",3:"WORK_TASK_PROFILE",4:"PUBLIC_EVAL_PROFILE",5:"FACTOR_PROFILE",6:"EVOLUTION_PROFILE",7:"NETWORK",8:"EXPIRED",9:"SIGNATURE"}
APP={1:"RANGE",2:"STATE",3:"NONCE",4:"FEE",5:"FUNDS",6:"EXPIRED",7:"LIMIT",8:"RESOURCE_ID",9:"DUPLICATE",10:"AUTHORITY",11:"EVIDENCE",12:"SUBMISSION_ROUND",13:"ROOT",14:"CANDIDATE_WINDOW_FULL",15:"NONCANONICAL",16:"SIGNATURE",17:"LENGTH",18:"ENCODING",19:"VERSION",20:"EVALUATION_POLICY",21:"CONSERVATION"}
def need(c,m):
 if not c:raise ValueError(m)
def ident(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def same(a,b):
 if type(a) is not type(b):return False
 if isinstance(a,dict):return set(a)==set(b) and all(same(a[k],b[k]) for k in a)
 if isinstance(a,list):return len(a)==len(b) and all(same(x,y) for x,y in zip(a,b))
 return a==b
def unique(items):
 out={}
 for k,v in items:
  need(k not in out,"Duplicate JSON key");out[k]=v
 return out
def load(raw):return safe.parse(raw)
def read(path,inputs):
 path=Path(path).absolute();raw=safe.read(path.parent,path.name);row=ident(raw)
 if str(path) in inputs:need(same(inputs[str(path)],row),"Read changed input")
 inputs[str(path)]=row;return raw

def frames(raw):
 at=0;out=[]
 while at<len(raw):
  need(at+8<=len(raw),"Partial frame word");n=struct.unpack_from("<Q",raw,at)[0];at+=8
  need(0<n<1<<24 and n<=len(raw)-at,"Partial/oversized frame");out.append(raw[at:at+n]);at+=n
 return out
def context(raw):
 need(len(raw)>=576 and raw[:4]==b"SDO1" and struct.unpack_from("<I",raw,4)[0]==len(raw),"Actual SDO1 extent")
 need(raw[8:16]==bytes(8) and struct.unpack_from("<II",raw,448)==(3,7) and raw[468:480]==bytes(12),"Actual default SDO1 fixed fields")
 pl,ml,sl=struct.unpack_from("<III",raw,456);need(576+pl+ml+sl==len(raw),"Actual SDO1 subspans")
 return {"timestamp":struct.unpack_from("<Q",raw,16)[0],"network_hex":raw[24:56].hex(),"parameters_hex":raw[56:88].hex(),
  "family_hex":raw[88:120].hex(),"plan_hex":raw[120:152].hex(),"genesis_hex":raw[152:184].hex(),"initial_root_hex":raw[184:216].hex(),
  "fees":list(struct.unpack_from("<25Q",raw,248)),"evaluators":sorted(raw[480+i*32:512+i*32].hex() for i in range(3)),
  "params_canonical_hex":raw[576:576+pl].hex(),"model_registry_canonical_hex":raw[576+pl:576+pl+ml].hex()}
def prefix_error(h):
 stage,code=h[4:6]
 if stage==0:return {11:"LIMIT",15:"PREFIX_BINDING"}[code]
 if stage==1:return PREP[code]
 if stage in (2,3,4):return APP[code]
 if stage==5:return {69:"LIMIT",70:"RANGE",71:"NONCANONICAL"}[code]
 raise ValueError("Unknown actual Prefix error")
def decode_process(folder,suite,inputs):
 receipt=load(read(folder/"receipt.json",inputs))
 need(receipt["exit_code"]==0 and type(receipt["exit_code"]) is int and type(receipt["expected_exit"]) is int and receipt["expected_exit"]==0 and receipt["cleanup"] is None,"Actual successful process required")
 streams={k:read(folder/(k+".raw"),inputs) for k in ("stdin","stdout","stderr")}
 for k,v in streams.items():need(same(ident(v),receipt[k]),"Actual stream identity")
 need(not streams["stderr"] and type(receipt["elapsed_ns"]) is int and 0<receipt["elapsed_ns"]<=243_000_000_000,"Successful owner diagnostics/budget")
 from .evidence import namespace
 namespace(folder,receipt,inputs)
 fs=frames(streams["stdout"]);need([v.hex() for v in fs]==receipt["frames_hex"],"Complete actual frame roster")
 wire=streams["stdin"];need(len(wire)>=64 and wire[:8]==b"NGBOOT01","Actual bootstrap")
 b=struct.unpack_from("<7Q",wire,8);need(b[1]==0 and b[2] in (0,1) and b[4] in (1,2,4,8) and b[5:]==((1<<64)-1,)*2,"Default owner bootstrap profile")
 need((b[2]==1) or b[3]==0,"Absent timestamp payload")
 first=fs[0];need(first[:8]==b"NBBASE01" and struct.unpack_from("<QQ",first,8)==(1,7),"Actual private base producer")
 n=struct.unpack_from("<Q",first,24)[0];need(len(first)==160+n,"Actual context response extent")
 ctx=context(first[160:]);need(first[128:160].hex()==ctx["initial_root_hex"],"Private root")
 at=64;oi=1;actions=[];native=[];base=None;active=False;closed=False
 while at<len(wire):
  need(not closed and at+8<=len(wire),"Commands after owner close")
  n=struct.unpack_from("<Q",wire,at)[0];at+=8;need(16<=n<1<<24 and n<=len(wire)-at,"Whole Node command")
  request=wire[at:at+n];at+=n;need(request[:8]==b"NBINPUT1","Node input magic")
  op=struct.unpack_from("<Q",request,8)[0];need(op in (1,2,8),"Explicit production pool subprofile")
  events=[];cancel=None;progress_raw=[]
  while True:
   need(oi<len(fs),"No actual response");response=fs[oi];oi+=1
   if response[:8] not in (b"M05PROG1",b"PXPROG01"):break
   need(len(response)==64 and at+48<=len(wire),"Whole callback/reply")
   q=struct.unpack("<8Q",response);ack=wire[at:at+48];at+=48;a=struct.unpack("<6Q",ack)
   need(q[2]==q[7]==0 and a[1:4]==q[1:4] and a[4] in (0,1,2) and (a[4]!=0 or a[5]==0),"Callback reply binding")
   need(ack[:8]==(b"M05ACK01" if response[:8]==b"M05PROG1" else b"PXGO0001"),"Callback domain")
   events.append({"kind":q[4],"index":q[5]})
   progress_raw.append({"observed_hex":response.hex(),"ack_hex":ack.hex(),"kind":q[4],"index":q[5],"height":q[6],"classification":a[4]})
   if a[4]:
    need(cancel is None,"Multiple refusal actions")
    cancel={"ordinal":len(events)-1,"class":a[4],"token":a[5],"kind":q[4],"index":q[5]}
  row={"index":len(actions),"progress":events,"progress_raw":progress_raw,"input_hex":request.hex(),"output_hex":response.hex()}
  item={"index":len(actions),"cancel":cancel}
  if op==1:
   need(n==16 and response[:8]==b"NBSTATE1" and len(response)==16+struct.unpack_from("<Q",response,8)[0],"Actual full parent read")
   value=response[16:].hex()
   if base is None:base=value
   need(base==value and not events,"Actual canonical base changed")
   item["op"]="read";row.update(op="read",outcome="ok",error=None,base_unchanged=True)
  elif op==2:
   need(n==16 and response==b"NBCLOSE1"+bytes(8) and not events,"Actual complete close")
   item["op"]="close";row.update(op="close",outcome="ok",error=None);closed=True;active=False
  else:
   need(n>=24 and response[:8]==b"NMPRES02" and len(response)>=64,"Actual pool response")
   sub=struct.unpack_from("<Q",request,16)[0];q=struct.unpack_from("<8Q",response)
   need(sub in (1,2,3) and q[1]==sub and q[2] in (1,2,3,4) and q[6] in (0,1) and len(response)==64+q[4]+q[5],"Pool response header")
   outcome={1:"ok",2:"error",3:"cancelled",4:"panic"}[q[2]]
   error=None
   if outcome=="error" and q[3]:error="POOL_LIMITS" if 31<=q[3]<=36 else ERRORS[q[3]]
   mh=None;ph=None
   if q[4]:
    m=response[64:64+q[4]];need(m[:8]==b"M05OUT01" and len(m)>=128,"Actual admission output")
    mh=struct.unpack_from("<16Q",m);need(len(m)==128+mh[15] and mh[13]==0,"Complete admission and no Value leak")
   if q[5]:
    px=response[64+q[4]:];need(px[:8]==b"BRGOUT01" and len(px)>=256,"Actual Prefix output")
    ph=struct.unpack_from("<32Q",px);need(ph[3]==q[2] and ph[25] in (0,1) and len(px)==256+ph[18]+ph[16]+ph[17]+ph[15],"Complete private Prefix")
    if outcome=="error":need(error is None,"Two competing error domains");error=prefix_error(ph)
   if sub==1:
    need(n==104 and not active and not events,"Pool policy/open shape")
    vals=struct.unpack_from("<7Q",request,16);need(vals[6]==0,"Policy reserved")
    item.update(op="open",policy={"max_records":vals[1],"max_bytes":vals[2],"critical_reserve":vals[3],"max_group_members":vals[4],"max_removals":vals[5],"preview_miner_hex":request[72:104].hex()})
    need(outcome in ("ok","error") and bool(q[6])==(outcome=="ok"),"Open lifecycle")
   elif sub==2:
    need(n>=32 and active and mh is not None,"Validation without real owner")
    count=struct.unpack_from("<Q",request,24)[0];pos=32;tx=[]
    for _ in range(count):
     need(pos+8<=n,"Raw extent word");size=struct.unpack_from("<Q",request,pos)[0];pos+=8
     need(size<=n-pos,"Whole exact raw body");tx.append(request[pos:pos+size].hex());pos+=size
    need(pos==n,"Trailing transaction bytes")
    item.update(op="validate",transactions=tx)
    row.update(main_validations=mh[5],reused=mh[7],native_strict_signatures=mh[6],ready_count=mh[4],prefix_length=None if ph is None or ph[25]==0 else ph[8],prefix_observed=ph is not None,prefix_ready=None if ph is None else bool(ph[25]))
   else:
    need(n==24 and active and not events and outcome=="ok" and q[6]==0,"Actual release")
    item["op"]="drop"
   active=bool(q[6]);row.update(op=item["op"],outcome=outcome,error=error,active=active)
  actions.append(item);native.append(row)
 need(at==len(wire) and oi==len(fs) and closed and base is not None and not active,"Whole input/output/owner retirement")
 return {"schema":"trnm.production-m05-original-history.v1","name":suite+"/"+folder.name,"timestamp":b[3] if b[2] else None,"workers":b[4],"actions":actions},{"name":suite+"/"+folder.name,"context":ctx,"context_hex":first[160:].hex(),"timestamp":b[3] if b[2] else None,"workers":b[4],"base_hex":base,"actions":native,"receipt":receipt,"process_directory":str(folder)}
def collect(suites,repository=ROOT):
 inputs={};cases=[];observations=[];roster=safe.read_json(repository,"hia/platform/mempool_node/case_roster.json")
 need(type(suites) is dict and set(suites)=={"smoke","boundaries","capacity"},"All original native partitions are required")
 labels={"smoke":"runtime-smoke-v3","boundaries":"runtime-boundaries-v3","capacity":"runtime-capacity-v2"};source_set=None
 for group in ("smoke","boundaries","capacity"):
  artifact=Path(suites[group]).absolute();build_dir=artifact/"build";build=validate_build(build_dir,repository)
  build_path=build_dir/"build.json";read(build_path,inputs)
  for name,row in build["source_inputs"].items():need(same(ident(read(Path(repository)/name,inputs)),row),"Bound current source drift")
  if source_set is None:source_set=build["source_set_sha256"]
  need(build["source_set_sha256"]==source_set,"Partitions used different complete source graphs")
  read(build_dir/"owner.elf",inputs)
  # Preserve every compiler raw stage as a required observed input.
  for stage in build["stages"]:
   for filename in ("stdin.raw","stdout.raw","stderr.raw","receipt.json"):read(build_dir/"compiler"/stage["stage"]/filename,inputs)
  outer=load(read(artifact/"report.json",inputs))
  need(outer["schema"]=="trnm.mempool-node-partition.v1" and outer["status"]=="PASS" and outer["group"]==group and outer["failure"] is None and same(outer["source_after"],{"status":"MATCH","errors":[]}),"Incomplete native partition")
  need(same(outer["source_inputs"],build["source_inputs"]) and outer["source_set_sha256"]==source_set and same(outer["native_build"],ident(build_path.read_bytes())),"Partition source/build binding")
  directory=artifact/"native";raw=read(directory/"report.json",inputs);report=load(raw)
  from .evidence import native_report_contract
  native_report_contract(report,group)
  need(same(outer["native_report"],ident(raw)),"Actual native report binding")
  need(report["status"]=="PASS" and report["failure"] is None and report["cleanup_errors"]==[] and same(report["source_after"],{"status":"MATCH","errors":[]}),"Incomplete native suite")
  need(type(report["controls_total"]) is int and report["controls_total"]==len(roster[group]["controls"]) and [r["name"] for r in report["controls"]]==roster[group]["controls"],"Whole control roster")
  need(same(report["build"],ident(build_path.read_bytes())) and same(report["executable"],build["executable"]),"Suite bound another native image")
  folders=sorted(p.parent for p in directory.glob("*/receipt.json"))
  need(type(report["real_processes"]) is int and report["real_processes"]==roster[group]["processes"] and [p.name for p in folders]==roster[group]["process_names"],"Actual complete process roster")
  from .native_contract import fixed_validations,validation,nonvalidation
  fixed=fixed_validations(group,repository)
  need([r["name"] for r in report["controls"] if r["name"] in fixed]==list(fixed),"All statically fixed validation predicates")
  all_observed=[]
  for folder in folders:
   case,observed=decode_process(folder,labels[group],inputs);cases.append(case);observations.append(observed);all_observed.append(observed)
   trace=folder/"syscalls.raw"
   if group!="capacity":
    from .evidence import trace_capture
    trace_capture(folder,inputs)
  from .suite_smoke import pool_result
  actual_validations=[a for row in all_observed for a in row["actions"] if a["op"]=="validate"]
  pending=list(actual_validations)
  actual_opens=[(r,a) for r in all_observed for a in r["actions"] if a["op"]=="open"]
  for control in report["controls"]:
   if control["name"] not in fixed:
    nonvalidation(group,control)
    if "process" in control:
     candidates=[r for r in all_observed if same(control["process"],r["receipt"])]
     need(len(candidates)==1,"Detached process control")
     expected=[p for a in candidates[0]["actions"] for p in a["progress_raw"]]
     got=[{k:p[k] for k in ("observed_hex","ack_hex","kind","index","height","classification")} for p in control["progress"]]
     need(same(got,expected),"Complete process callback observations differ")
    result=control.get("result",control.get("pool_open"))
    if result is not None:
     candidates=[(r,a) for r,a in actual_opens if a["output_hex"]==result.get("raw_hex")]
     need(candidates,"Open/policy control has no actual response")
     decoded=None
     for r,a in candidates:
      raw=bytes.fromhex(a["output_hex"]);h=struct.unpack_from("<8Q",raw);value=pool_result(raw,1,h[2],h[3])
      if same(value,result) and ("context_hex" not in control or control["context_hex"]==r["context_hex"]) and ("timestamp" not in control or same(control["timestamp"],r["timestamp"])) and ("workers" not in control or same(control["workers"],r["workers"])):decoded=value;break
     need(decoded is not None,"Open/policy metadata differs from actual response/context")
    continue
   decoded=validation(control,fixed[control["name"]])
   raw=bytes.fromhex(control["raw_hex"])
   for key,value in decoded.items():need(same(control.get(key),value),"Reported control differs from full raw outcome")
   matches=[(i,a) for i,a in enumerate(pending) if a["output_hex"]==control["raw_hex"]]
   found=None
   for i,a in matches:
    request=bytes.fromhex(a["input_hex"]);count=struct.unpack_from("<Q",request,24)[0];at=32;tx=[]
    for _ in range(count):
     size=struct.unpack_from("<Q",request,at)[0];at+=8;tx.append(request[at:at+size].hex());at+=size
    need(all(type(p.get("action")) is str and p["action"]==control["name"] for p in control["progress"]),"Callback action label differs")
    progress=[{k:p[k] for k in ("observed_hex","ack_hex","kind","index","height","classification")} for p in control["progress"]]
    if same(tx,control["input_hex"]) and same(progress,a["progress_raw"]):found=i;break
   need(found is not None,"Control lacks an exact actual request/output/progress");pending.pop(found)
  need(not pending,"Actual validation omitted from control roster")
  need(same(report["script"],ident(read(Path(repository)/("hia/platform/mempool_node/suite_"+group+".py"),inputs))),"Actual suite source differs")
  need(type(report["elapsed_ns"]) is int and report["elapsed_ns"]>0,"Actual wall time")
 need(len(cases)==11 and len({c["name"] for c in cases})==11,"Whole unique history roster")
 raw=b"".join(canonical(c)+b"\n" for c in cases)
 expected=safe.read(repository,"hia/platform/mempool_node/corpus.jsonl")
 need(raw==expected,"Complete original 11/122/58 input bytes/order differ")
 need(sum(len(c["actions"]) for c in cases)==122 and sum(a["op"]=="validate" for c in cases for a in c["actions"])==58,"Whole method and validation roster")
 return cases,observations,inputs
