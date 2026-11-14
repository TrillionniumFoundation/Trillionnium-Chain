#!/usr/bin/env python3
"""Fixed PR847 body-only maintenance. Prepared separately; main alone writes one PATCH."""
import argparse,concurrent.futures,datetime,hashlib,json,os,pathlib,re,signal,stat,subprocess,sys,time
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
HERE=pathlib.Path("/private/tmp/chain-prci-H5DF-pr-body-preparation-20261114-v1/body-proposal-v2")
SELF=HERE/"execute_pr847_body_only_v1.py"
REPO="TrillionniumFoundation/Trillionnium-Chain"
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
BASE="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
BRANCH="fix/chain-hepta-closure-candidate-20261109-481716"
TITLE="Consolidate audited branch history and current runtime"
GH="/opt/homebrew/bin/gh"
def need(v,m):
 if not v:raise ValueError(m)
def digest(b):return hashlib.sha256(b).hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pairs(xs):
 d={}
 for k,v in xs:
  need(k not in d,"duplicate JSON key");d[k]=v
 return d
def parse(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError("nonfinite JSON")))
def version(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def main():
 need(sys.flags.optimize==0 and pathlib.Path(__file__).resolve(strict=True)==SELF,"fixed unoptimized producer required")
 ap=argparse.ArgumentParser(allow_abbrev=False);ap.add_argument("--spec-sha256",required=True);a=ap.parse_args()
 seen={}
 def read(p,n=None,h=None):
  p=pathlib.Path(p);need(p.resolve(strict=True)==p and(p.is_relative_to(HERE)or p.is_relative_to(ROOT)or str(p).startswith("/private/tmp/chain-prci-H5DF-")),"unexpected input path")
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=8*1024*1024,"input not bounded regular file")
   raw=b""
   while True:
    b=os.read(fd,1048576)
    if not b:break
    raw+=b
   need(version(s)==version(os.fstat(fd))==version(p.lstat()),"input changed while reading")
  finally:os.close(fd)
  pin={"path":str(p),"bytes":len(raw),"sha256":digest(raw)}
  if n is not None:need(type(n)is int and n==len(raw)and h==pin["sha256"],"input pin mismatch")
  seen[str(p)]=(pin,version(s));return raw,pin
 def pinread(p):need(set(p)=={"path","bytes","sha256"}and re.fullmatch("[0-9a-f]{64}",p["sha256"]),"invalid pin");return read(p["path"],p["bytes"],p["sha256"])[0]
 raw,sp=read(HERE/"execution-spec.json");need(re.fullmatch("[0-9a-f]{64}",a.spec_sha256)and sp["sha256"]==a.spec_sha256,"spec digest mismatch")
 spec=parse(raw);need(set(spec)=={"schema","producer","output","old_body","desired_body","body_payload","source_PR","evidence"}and spec["schema"]=="trnm-H5DF-pr847-body-only-spec-v1","spec keys/schema mismatch")
 need(pinread(spec["producer"])==read(SELF)[0],"producer mismatch")
 old=pinread(spec["old_body"]).decode();desired=pinread(spec["desired_body"]).decode()
 payload=pinread(spec["body_payload"]);need(parse(payload)=={"body":desired}and old!=desired,"body payload mismatch")
 original=parse(pinread(spec["source_PR"]));need(original["body"]==old,"original body differs")
 for p in spec["evidence"]:pinread(p)
 out=pathlib.Path(spec["output"]);need(out.parent==ROOT and out.name=="H5DF-pr847-body-only-update-v1-actual-001"and ROOT.resolve(strict=True)==ROOT,"wrong create-only output")
 os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
 def save(name,value):
  b=value if isinstance(value,bytes)else encode(value);p=out/name
  with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
  need(p.read_bytes()==b,"output readback differs");return{"path":str(p),"bytes":len(b),"sha256":digest(b)}
 save("producer.py",read(SELF)[0]);save("actual-spec.json",raw);pp=save("body-only-payload.json",payload)
 env=os.environ.copy();env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com";env["GH_PROMPT_DISABLED"]="1"
 for k in tuple(env):
  if k.startswith("GIT_TRACE")or k=="GIT_CURL_VERBOSE":del env[k]
 deadline=time.monotonic()+600;steps=[];errors=[];started=utc();patch_started=False;patch_accepted=False;desired_observed=False;prevalid=False;already=False;status="HOLD"
 def capture(label,method,endpoint,body_path=None):
  argv=[GH,"api","--hostname","github.com","--include","--method",method,endpoint]
  if body_path:argv+=["--input",body_path]
  op=out/(label+".stdout");ep=out/(label+".stderr");began=utc();t=time.monotonic();budget=min(120,max(0,deadline-t));p=None;rc=None;reason=None
  with op.open("xb")as so,ep.open("xb")as se:
   try:
    need(budget>0,"overall budget exhausted")
    p=subprocess.Popen(argv,cwd="/private/tmp",env=env,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True)
    while True:
     try:rc=p.wait(timeout=min(.2,max(.001,budget-(time.monotonic()-t))));break
     except subprocess.TimeoutExpired:
      if time.monotonic()-t>=budget or os.fstat(so.fileno()).st_size>2*1024*1024 or os.fstat(se.fileno()).st_size>512*1024:reason="TIME_OR_OUTPUT_BOUND";break
   except Exception as ex:reason=type(ex).__name__+": "+str(ex)
   finally:
    if p is not None and p.returncode is None:
     try:os.killpg(p.pid,signal.SIGTERM)
     except ProcessLookupError:pass
     try:rc=p.wait(timeout=5)
     except subprocess.TimeoutExpired:
      if p.returncode is None:
       try:os.killpg(p.pid,signal.SIGKILL)
       except ProcessLookupError:pass
      try:rc=p.wait(timeout=5)
      except subprocess.TimeoutExpired:reason=(reason or"")+";owned child not reaped within bound"
    if p is not None and p.returncode is not None:rc=p.returncode
  def output_pin(path):
   b=path.read_bytes();need(len(b)<=3*1024*1024,"metadata stream too large")
   return b,{"path":str(path),"bytes":len(b),"sha256":digest(b)}
  ob,opin=output_pin(op);eb,epin=output_pin(ep);value=None;http=None;pe=None
  if rc==0 and reason is None:
   try:
    split=re.split(rb"\r?\n\r?\n",ob,maxsplit=1);need(len(split)==2,"HTTP header boundary missing")
    match=re.match(rb"HTTP/\S+\s+([0-9]{3})(?:\s|$)",split[0]);need(match is not None,"HTTP status missing")
    http=int(match.group(1));need(http==200,"HTTP status not 200");value=parse(split[1])
   except Exception as ex:pe=type(ex).__name__+": "+str(ex)
  row={"label":label,"argv":argv,"method":method,"endpoint":endpoint,"started_at":began,"finished_at":utc(),"timeout_seconds":budget,"elapsed_seconds":round(time.monotonic()-t,6),"owned_pid":None if p is None else p.pid,"exit":rc,"termination_or_error":reason,"http_status":http,"parse_error":pe,"stdout":opin,"stderr":epin,"GH_DEBUG_removed":True,"GH_HOST":"github.com","group_cleanup_completeness":"not_proven"}
  save(label+".step.json",row);return row,value
 endpoints={"actor":"user","pr":"repos/"+REPO+"/pulls/847","candidate-ref":"repos/"+REPO+"/git/ref/heads/"+BRANCH,"main-ref":"repos/"+REPO+"/git/ref/heads/main"}
 def batch(phase,labels):
  with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:
   fs={k:pool.submit(capture,phase+"-"+k,"GET",endpoints[k])for k in labels};ret={};bad=[]
   for k in labels:
    row,v=fs[k].result();steps.append(row);ret[k]=v
    if not(row["exit"]==0 and row["http_status"]==200 and row["parse_error"]is None and row["termination_or_error"]is None):bad.append(k)
  need(not bad,"GET not complete: "+",".join(bad));return ret
 def pr_ok(pr):
  need(type(pr)is dict and pr.get("number")==847 and pr.get("node_id")==original["node_id"]and pr.get("state")=="open"and pr.get("draft")is False and pr.get("auto_merge")is None and pr.get("title")==TITLE,"PR metadata changed")
  for side,sha,ref in[("head",HEAD,BRANCH),("base",BASE,"main")]:
   v=pr[side];need(v["sha"]==sha and v["ref"]==ref and v["repo"]["full_name"]==REPO and type(v["repo"]["id"])is int and v["repo"]["id"]==1323087357,"PR source identity changed")
 def refs_ok(v):
  for key,ref,sha in[("candidate-ref",BRANCH,HEAD),("main-ref","main",BASE)]:
   x=v[key];need(x["ref"]=="refs/heads/"+ref and x["object"]["type"]=="commit"and x["object"]["sha"]==sha,"branch ref changed")
 try:
  before=batch("before",["actor","pr","candidate-ref","main-ref"])
  need(type(before["actor"].get("id"))is int and before["actor"]["id"]==102159240 and before["actor"]["login"]=="ProfHepta","actor changed")
  pr_ok(before["pr"]);refs_ok(before)
  need(before["pr"]["body"]in(old,desired),"concurrent body edit")
  already=before["pr"]["body"]==desired;prevalid=True
  if not already:
   need(pinread(spec["desired_body"]).decode()==desired and parse(pinread(pp))=={"body":desired},"payload changed before PATCH")
   patch_started=True;status="UNKNOWN"
   row,pr=capture("body-PATCH-once","PATCH",endpoints["pr"],pp["path"]);steps.append(row)
   if row["exit"]==0 and row["http_status"]==200 and row["parse_error"]is None and row["termination_or_error"]is None:
    pr_ok(pr);need(pr["body"]==desired,"PATCH response body mismatch");patch_accepted=True
 except Exception as ex:errors.append(type(ex).__name__+": "+str(ex))
 finally:
  if prevalid:
   try:
    after=batch("after",["pr","candidate-ref","main-ref"]);pr_ok(after["pr"]);refs_ok(after);need(after["pr"]["body"]==desired,"readback body mismatch");desired_observed=True
    if already:status="already_confirmed"
    elif patch_accepted:status="confirmed"
   except Exception as ex:errors.append("readback: "+type(ex).__name__+": "+str(ex));status="UNKNOWN"if patch_started else"HOLD"
  try:
   for path,(pin,ident)in list(seen.items()):pinread(pin);need(version(pathlib.Path(path).lstat())==ident,"input changed after observation")
  except Exception as ex:errors.append("input fence: "+type(ex).__name__+": "+str(ex));status="UNKNOWN"if patch_started else"HOLD"
  if errors and status in("confirmed","already_confirmed"):status="UNKNOWN"if patch_started else"HOLD"
  receipt={"schema":"trnm-H5DF-pr847-body-only-receipt-v1","status":status,"started_at":started,"finished_at":utc(),"spec":sp,"producer":spec["producer"],"old_body":spec["old_body"],"desired_body":spec["desired_body"],"patch_started":patch_started,"patch_accepted":patch_accepted,"desired_body_observed_after":desired_observed,"already_desired_before":already,"head":HEAD,"base":BASE,"steps":steps,"errors":errors,"normal_PATCH_no_atomic_expected_head_or_body_CAS":True,"title_ready_auto_merge_policy_CI_refs_source_modified":False}
  rp=save("summary.json",receipt);print(json.dumps({"status":status,"receipt":rp,"patch_started":patch_started,"patch_accepted":patch_accepted,"desired_body_observed_after":desired_observed}),flush=True)
 return 0 if status in("confirmed","already_confirmed")else 1
if __name__=="__main__":sys.exit(main())
