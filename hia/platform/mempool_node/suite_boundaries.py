"""Actual boundaries qualification; fixed original case set, 240-second child and 3-second cleanup."""
from pathlib import Path
import argparse,os,sys,json,struct,hashlib,subprocess,signal,select,time,traceback,re,shutil
from hia.platform.build import sealed_executable
from .build import ROOT,validate_build
from . import safe
from .suite_smoke import Session as BoundedSession
R=ROOT;HERE=Path(__file__).absolute().parent
def identity(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def need(c,m):
 if not c:raise AssertionError(m)

def sources():
 validate_build(build_path.parent,R)
 need(identity(elf_path.read_bytes())==build["executable"],"ELF changed")

def snapshot(directory):
 rows={}
 for p in sorted(directory.iterdir()):
  st=p.lstat();need(p.is_file() and not p.is_symlink(),"Nonregular fixture "+str(p))
  rows[p.name]={"identity":identity(p.read_bytes()),"inode":st.st_ino,"device":st.st_dev,"mode":st.st_mode,"size":st.st_size}
 return rows

class Session:
 def __init__(self,name,owned,mode,timestamp=None,workers=1):
  self.directory=OUT/name;self.directory.mkdir();self.owned=owned;self.frames=[];self.input=bytearray();self.output=bytearray();self.finished=False
  fd=sealed_executable(elf,"native-node-held-disk");directoryfd=os.open(owned,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  self.argv=["/usr/bin/strace","-qq","-f","-xx","-s","65536","-o",str(self.directory/"syscalls.raw"),"-e","trace=all","/proc/self/fd/"+str(fd)]
  self.p=subprocess.Popen(self.argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,directoryfd),cwd=self.directory,env={"PATH":""},start_new_session=True,umask=0o077)
  os.close(fd);os.close(directoryfd);self.started=time.monotonic();self.deadline=self.started+240
  sessions.append(self)
  self.write(b"NGBOOT01"+struct.pack("<7Q",directoryfd,mode,int(timestamp is not None),0 if timestamp is None else timestamp,workers,(1<<64)-1,(1<<64)-1))
 # All Node qualification partitions share the same absolute-deadline writer.
 write=BoundedSession.write
 def command(self,op):self.write(struct.pack("<Q",16)+b"NBINPUT1"+struct.pack("<Q",op))
 def read_exact(self,n):
  out=bytearray()
  while len(out)<n:
   left=self.deadline-time.monotonic();need(left>0,"Native process deadline")
   ready=select.select([self.p.stdout.fileno()],[],[],left)[0];need(bool(ready),"Native stdout deadline")
   part=os.read(self.p.stdout.fileno(),n-len(out));need(bool(part),"Native EOF before complete frame")
   out.extend(part);self.output.extend(part)
  return bytes(out)
 def frame(self):
  n=struct.unpack("<Q",self.read_exact(8))[0];need(0<n<1<<24,"Observed frame extent")
  raw=self.read_exact(n);self.frames.append(raw)
  if len(self.frames)==1:
   self.namespace_before=snapshot(self.owned)
   safe.write_json(self.directory/"namespace-before.json",self.namespace_before)
  return raw
 def finish(self,code):
  if self.p.stdin is not None:
   self.p.stdin.close();self.p.stdin=None
  try:tail,err=self.p.communicate(timeout=max(1,self.deadline-time.monotonic()))
  except subprocess.TimeoutExpired:
   os.killpg(self.p.pid,signal.SIGKILL);tail,err=self.p.communicate(timeout=3);raise
  self.output.extend(tail);self.finished=True
  self.result={"argv":self.argv,"pid":self.p.pid,"exit_code":self.p.returncode,"expected_exit":code,"cleanup":None,"elapsed_ns":int((time.monotonic()-self.started)*1e9),"stdin":identity(bytes(self.input)),"stdout":identity(bytes(self.output)),"stderr":identity(err),"frames_hex":[r.hex() for r in self.frames],"namespace":snapshot(self.owned),"namespace_directory":self.owned.relative_to(OUT).as_posix(),"namespace_before":identity(safe.read(self.directory,"namespace-before.json"))}
  for name,raw in [("stdin.raw",bytes(self.input)),("stdout.raw",bytes(self.output)),("stderr.raw",err)]: (self.directory/name).write_bytes(raw)
  (self.directory/"receipt.json").write_text(json.dumps(self.result,sort_keys=True,indent=2)+"\n")
  need(self.p.returncode==code,"Native exit "+repr((self.p.returncode,code,err.hex())))
  if code==0:need(not err and not tail,"Unexpected success output tail or diagnostic")
  else:need(len(err)==56 and struct.unpack_from("<Q",err)[0]==code,"Expected real Genesis failure diagnostic")
  return self.result
 def abort(self):
  if self.finished:return
  if self.p.poll() is None:os.killpg(self.p.pid,signal.SIGKILL)
  try:tail,err=self.p.communicate(timeout=3)
  except BaseException as e:cleanup_errors.append({"name":self.directory.name,"error":repr(e)});return
  self.output.extend(tail)
  for name,raw in [("stdin.raw",bytes(self.input)),("stdout.raw",bytes(self.output)),("stderr.raw",err)]: (self.directory/name).write_bytes(raw)
  (self.directory/"failure-receipt.json").write_text(json.dumps({"exit_code":self.p.returncode,"cleanup":"owned SIGKILL if still alive","frames_hex":[r.hex() for r in self.frames]},sort_keys=True,indent=2)+"\n")
  self.finished=True

def ready(raw):
 need(raw[:8]==b"NBBASE01" and struct.unpack_from("<QQ",raw,8)==(1,7),"No held-disk private State")
 n=struct.unpack_from("<Q",raw,24)[0];need(len(raw)==160+n and raw[160:164]==b"SDO1","Context shape")
 need(raw[128:160]==raw[344:376],"Actual State root differs")
 return raw

def state(raw):
 need(raw[:8]==b"NBSTATE1" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Full State output")
 need(struct.unpack_from("<Q",raw,16)[0]==7,"State row count")
 return raw

def input_frame(session,op,payload=b""):
 raw=b"NBINPUT1"+struct.pack("<Q",op)+payload
 session.write(struct.pack("<Q",len(raw))+raw)
def prefix_frame(session,op,ctx):
 raw=session.frame()
 need(raw[:8]==b"NBPFX001" and len(raw)==16+struct.unpack_from("<Q",raw,8)[0],"Node Prefix frame")
 data=raw[16:];need(len(data)>=256,"Prefix result extent")
 q=struct.unpack_from("<32Q",data)
 need(data[:8]==b"BRGOUT01" and q[2]==op and q[3]==1,"Actual Prefix operation failed "+repr(q))
 need(q[18]==len(ctx) and data[256:256+len(ctx)]==ctx,"Prefix did not use actual Node Config")
 need(q[27]==1 and q[31]==1,"Prefix did not borrow actual retained base")
 need(len(data)==256+q[18]+q[16]+q[17]+q[15],"Prefix complete result extent")
 return {"header":list(q),"record":identity(data),"raw_hex":data.hex()}

from hia.platform.execution_application.cases import wire,public
class PoolSession(Session):
 def __init__(self,*args,**kwargs):
  self.progress=[];self.action="bootstrap";self.cancel=None;self.progress_start=0
  super().__init__(*args,**kwargs)
 def frame(self):
  while True:
   raw=super().frame()
   if raw[:8] not in (b"M05PROG1",b"PXPROG01"):return raw
   need(len(raw)==64,"Progress frame extent")
   q=struct.unpack("<8Q",raw);need(q[2]==0 and q[7]==0,"Progress reserved bits")
   classification=0;token=0
   if self.cancel and self.cancel["magic"]==raw[:8].decode() and self.cancel["kind"]==q[4] and (self.cancel.get("index") is None or self.cancel["index"]==q[5]):
    classification=self.cancel["class"];token=self.cancel["token"];self.cancel=None
   ack=(b"M05ACK01" if raw[:8]==b"M05PROG1" else b"PXGO0001")+struct.pack("<5Q",q[1],0,q[3],classification,token)
   self.progress.append({"action":self.action,"observed_hex":raw.hex(),"ack_hex":ack.hex(),"kind":q[4],"index":q[5],"height":q[6],"classification":classification})
   self.write(ack)
 def start_action(self,name,cancel=None):
  self.action=name;self.cancel=cancel;self.progress_start=len(self.progress)
def pool_result(raw,op,outcome,error=0):
 need(raw[:8]==b"NMPRES02" and len(raw)>=64,"Missing actual M05 owner result "+raw[:64].hex())
 q=struct.unpack_from("<8Q",raw)
 need(q[1]==op and q[2]==outcome and q[3]==error,"Pool result mismatch "+repr(q))
 need(q[4]+q[5]+64==len(raw),"Pool result complete extent")
 data={"header":list(q),"identity":identity(raw),"raw_hex":raw.hex()}
 if q[4]:
  m=raw[64:64+q[4]];need(m[:8]==b"M05OUT01" and len(m)>=128,"Missing complete admission receipt")
  h=struct.unpack_from("<16Q",m);need(h[15]+128==len(m),"Admission receipt complete extent")
  need(h[13]==0,"Temporary Value leaked into result")
  cursor=128;rows=[]
  for i in range(h[4]):
   need(cursor+160<=len(m),"Ready metadata extent")
   meta=m[cursor:cursor+160];n=struct.unpack_from("<Q",meta,128)[0]
   body=m[cursor+160:cursor+160+n];need(len(body)==n,"Ready body extent")
   rows.append({"metadata_hex":meta.hex(),"body_hex":body.hex()});cursor+=160+n
  need(cursor==len(m),"Trailing Ready bytes")
  data["mempool"]={"header":list(h),"ready":rows}
 if q[5]:
  px=raw[64+q[4]:];need(px[:8]==b"BRGOUT01" and len(px)>=256,"Missing actual Prefix output")
  h=struct.unpack_from("<32Q",px);need(h[3]==outcome,"Actual Prefix outcome differs")
  need(len(px)==256+h[18]+h[16]+h[17]+h[15],"Complete Prefix result extent")
  data["prefix"]={"header":list(h),"raw_hex":px.hex()}
 return data
def pool_open(s,miner,cap=8,reserve=0):
 input_frame(s,8,struct.pack("<7Q",1,cap,524288,reserve,min(cap,16),4096,0)+miner)
 return pool_result(s.frame(),1,1)
def validate(s,name,raws,expected=1,error=0,calls=None,reused=None,signatures=None,cancel=None):
 s.start_action(name,cancel);t=time.monotonic_ns()
 input_frame(s,8,struct.pack("<2Q",2,len(raws))+b"".join(struct.pack("<Q",len(r))+r for r in raws))
 result=pool_result(s.frame(),2,expected,error)
 result.update(name=name,input_hex=[r.hex() for r in raws],progress=s.progress[s.progress_start:],elapsed_ns=time.monotonic_ns()-t)
 h=result["mempool"]["header"]
 if calls is not None:need(h[5]==calls,"Actual main validation count "+repr((h,calls)))
 if reused is not None:need(h[7]==reused,"Cached exact-wire count "+repr((h,reused)))
 if signatures is not None:need(h[6]==signatures,"Actual strict signature count "+repr((h,signatures)))
 controls.append(result)
 print(json.dumps({"case":name,"status":"PASS","outcome":expected,"error":error,"main_validations":h[5],"strict_signatures":h[6],"reused":h[7],"progress":len(result["progress"]),"elapsed_ns":result["elapsed_ns"]}),flush=True)
 return result

def opened_session(name,timestamp=None,workers=1,cap=8,reserve=0,max_bytes=524288):
 owned=OUT/(name+"-owned");owned.mkdir(mode=0o700)
 ss=PoolSession(name,owned,0,timestamp,workers)
 first=ready(ss.frame());ctx=first[160:]
 ss.command(1);initial=state(ss.frame());initial_disk=snapshot(owned)
 ss.start_action(name+"-open")
 input_frame(ss,8,struct.pack("<7Q",1,cap,max_bytes,reserve,min(cap,16),4096,0)+public(0))
 opened=pool_result(ss.frame(),1,1)
 controls.append({"name":name+"-held-open","status":"PASS","timestamp":timestamp,"workers":workers,"pool_open":opened,"context_hex":ctx.hex()})
 return ss,ctx,initial,initial_disk
def finish_session(ss,initial,disk,active=True):
 if active:
  ss.start_action("drop")
  input_frame(ss,8,struct.pack("<Q",3));pool_result(ss.frame(),3,1)
 ss.command(1);need(state(ss.frame())==initial,"Canonical base was mutated")
 ss.command(2);need(ss.frame()==b"NBCLOSE1"+bytes(8),"Node close failed")
 receipt=ss.finish(0);need(snapshot(ss.owned)==disk,"Persistent namespace changed")
 controls.append({"name":ss.directory.name+"-exact-base-disk-close","status":"PASS","process":receipt,"progress":ss.progress})
def signed(ctx,nonce=1,index=0,fee=10000000,expiry=(1<<64)-1,network=None,amount=7,tag=1,payload=None):
 if network is None:network=ctx[24:56]
 if payload is None:payload=public(1)+struct.pack("<Q",amount)
 return wire(tag,payload,index=index,nonce=nonce,fee=fee,expiry=expiry,network=network)

def main(argv=None):
 global OUT,build_path,build,elf_path,elf,sessions,controls,failure,cleanup_errors,after_errors,start
 safe.need(__debug__,"Optimized Python is not admitted")
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--build",required=True,type=Path)
 parser.add_argument("--output",required=True,type=Path)
 args=parser.parse_args(argv)
 OUT=safe.new_output(args.output,R)
 build_path=args.build.absolute()/"build.json";build=validate_build(build_path.parent,R)
 elf_path=build_path.parent/"owner.elf";elf=safe.read(build_path.parent,"owner.elf")
 sessions=[];controls=[];failure=None;cleanup_errors=[];after_errors=[];start=time.monotonic_ns()
 roster=safe.read_json(HERE,"case_roster.json")["boundaries"]
 try:
  sources();need(build["status"]=="PASS" and build["source_after"]["status"]=="MATCH","Invalid native build")
  ss,ctx,before,disk=opened_session("error-priority")
  good=signed(ctx);second=signed(ctx,nonce=2)
  cases=[
  ("empty-body",b"",1,0,0),
  ("oversize-body",b"x"*2049,1,0,0),
  ("short-encoding",b"PN",2,0,0),
  ("nonce-zero-encoding",signed(ctx,nonce=0),2,0,0),
  ("fee-over-max-encoding",signed(ctx,fee=10000001),2,0,0),
  ("zero-signer-before-signature",good[:36]+bytes(32)+good[68:],3,0,0),
  ("network-before-signature",signed(ctx,network=bytes([ctx[24]^1])+ctx[25:56]),113,1,0),
  ("expiry-before-signature",signed(ctx,expiry=0),113,1,0),
  ("wrong-nonce-after-signature",second,115,1,1),
  ("fee-after-signature",signed(ctx,fee=0),117,1,1),
  ("signature-before-nonce",second[:-1]+bytes([second[-1]^1]),113,1,1),
  ("critical-profile-before-signature",signed(ctx,tag=17,payload=bytes(128)),113,1,0),
  ]
  for name,raw,code,calls,sigs in cases:
   validate(ss,name,[raw],expected=2,error=code,calls=calls,reused=0,signatures=sigs)
  # M05 success does not imply M06 funds/semantic success or cache publication.
  unfunded=signed(ctx,index=99)
  a=validate(ss,"actual-funds-error-after-ready",[unfunded],expected=2,error=0,calls=1,reused=0,signatures=1)
  need(a["mempool"]["header"][4]==1 and "prefix" in a,"Failed execution did not follow actual Ready")
  validate(ss,"funds-failure-is-not-signature-cache",[unfunded],expected=2,error=0,calls=1,reused=0,signatures=1)
  validate(ss,"valid-after-all-refusals",[good],calls=1,reused=0,signatures=1)
  finish_session(ss,before,disk)

  ss,ctx,before,disk=opened_session("callback")
  good=signed(ctx);second=signed(ctx,nonce=2)
  cancel=lambda magic,kind,classification=1:{"magic":magic,"kind":kind,"class":classification,"token":42}
  validate(ss,"cancel-before-pnx",[good],expected=3,error=0,calls=0,reused=0,signatures=0,cancel=cancel("M05PROG1",1))
  validate(ss,"panic-before-pnx",[good],expected=4,error=0,calls=0,reused=0,signatures=0,cancel=cancel("M05PROG1",1,2))
  validate(ss,"cancel-after-admit-before-ready",[good],expected=3,error=0,calls=1,reused=0,signatures=1,cancel=cancel("M05PROG1",2))
  validate(ss,"cancel-before-commitment",[good],expected=3,error=0,calls=1,reused=0,signatures=1,cancel=cancel("PXPROG01",15))
  validate(ss,"cancel-does-not-mint-signature-cache",[good],calls=1,reused=0,signatures=1)
  validate(ss,"cancel-after-commitment",[good,second],expected=3,error=0,calls=1,reused=1,signatures=1,cancel=cancel("PXPROG01",16))
  validate(ss,"cancel-before-output",[good,second],expected=3,error=0,calls=1,reused=1,signatures=1,cancel=cancel("PXPROG01",17))
  validate(ss,"panic-before-output",[good,second],expected=4,error=0,calls=1,reused=1,signatures=1,cancel=cancel("PXPROG01",17,2))
  validate(ss,"retry-after-late-cancel-and-panic",[good,second],calls=1,reused=1,signatures=1)
  validate(ss,"repeat-after-late-success",[good,second],calls=0,reused=2,signatures=0)
  finish_session(ss,before,disk)

  ss,ctx,before,disk=opened_session("capacity-one",cap=1)
  a=signed(ctx);b=signed(ctx,nonce=2)
  validate(ss,"duplicate-before-record-limit",[a,a],expected=2,error=7,calls=1,reused=0,signatures=1)
  validate(ss,"record-limit-before-second-signature",[a,b[:-1]+bytes([b[-1]^1])],expected=2,error=8,calls=1,reused=0,signatures=1)
  validate(ss,"decode-before-record-limit",[a,b"PN"],expected=2,error=2,calls=1,reused=0,signatures=1)
  validate(ss,"capacity-one-exact",[a],calls=1,reused=0,signatures=1)
  finish_session(ss,before,disk)

  ss,ctx,before,disk=opened_session("reserved-lane",cap=2,reserve=1)
  a=signed(ctx);b=signed(ctx,nonce=2);critical=signed(ctx,tag=17,payload=bytes(128))
  validate(ss,"normal-borrows-empty-reserve",[a,b],calls=2,reused=0,signatures=2)
  validate(ss,"critical-reserve-reaches-real-profile-check",[a,critical],expected=2,error=113,calls=2,reused=0,signatures=1)
  validate(ss,"normal-reserve-borrow-recovery",[a,b],calls=0,reused=2,signatures=0)
  finish_session(ss,before,disk)


  ss,ctx,before,disk=opened_session("reserve-final-slot",cap=3,reserve=2)
  a=signed(ctx);b=signed(ctx,nonce=2);third=signed(ctx,nonce=3);critical=signed(ctx,tag=17,payload=bytes(128))
  validate(ss,"final-reserve-before-third-signature",[a,b,third],expected=2,error=11,calls=2,reused=0,signatures=2)
  validate(ss,"final-reserve-accepts-critical-profile-check",[a,b,critical],expected=2,error=113,calls=3,reused=0,signatures=2)
  got=validate(ss,"borrowed-ready-does-not-reorder-m06",[a,b],calls=2,reused=0,signatures=2)
  need([int.from_bytes(bytes.fromhex(r["metadata_hex"])[32:40],"little") for r in got["mempool"]["ready"]]==[1,0],"Actual reserved lane Ready pop order")
  finish_session(ss,before,disk)
  for timestamp,workers in [(1,2),(1800000000,4),(9223372036854775807,8)]:
   name="actual-context-"+str(timestamp)
   ss,ctx,before,disk=opened_session(name,timestamp,workers,max_bytes=1)
   a=signed(ctx)
   validate(ss,name+"-valid-despite-non-permit-max-bytes",[a],calls=1,reused=0,signatures=1)
   validate(ss,name+"-repeat",[a],calls=0,reused=1,signatures=0)
   finish_session(ss,before,disk)

  # Invalid policy refuses before creating a live View; all original fields use one
  # original POOL_LIMITS category, while private diagnostics retain field location.
  owned=OUT/"policy-owned";owned.mkdir(mode=0o700)
  ss=PoolSession("policy",owned,0,None);ready(ss.frame());ss.command(1);before=state(ss.frame());disk=snapshot(owned)
  fields=[8,524288,0,8,4096,0]
  for name,slot,value,code in [("records-zero",0,0,31),("records-high",0,257,31),("bytes-zero",1,0,32),("bytes-high",1,524289,32),
  ("group-zero",3,0,33),("group-high",3,17,33),("reserve-full",2,8,34),("removals-zero",4,0,35),("removals-high",4,4097,35)]:
   values=fields.copy();values[slot]=value
   ss.start_action("policy-"+name);input_frame(ss,8,struct.pack("<7Q",1,*values)+public(0))
   got=pool_result(ss.frame(),1,2,code);need(got["header"][6]==0,"Invalid policy minted View")
   controls.append({"name":"policy-"+name,"status":"PASS","result":got})
  ss.start_action("policy-miner-zero");input_frame(ss,8,struct.pack("<7Q",1,*fields)+bytes(32))
  got=pool_result(ss.frame(),1,2,36);need(got["header"][6]==0,"Zero miner minted View")
  controls.append({"name":"policy-miner-zero","status":"PASS","result":got})
  finish_session(ss,before,disk,active=False)
  need([c["name"] for c in controls]==roster["controls"],"Complete fixed control names/order")
  need(len(sessions)==roster["processes"],"Complete fixed process count")
 except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
 finally:
  for session in sessions:
   try:session.abort()
   except BaseException as e:cleanup_errors.append({"name":session.directory.name,"error":repr(e)})
  try:sources()
  except BaseException as e:after_errors.append(repr(e))
  report={"schema":"trnm.production-m05-runtime-boundaries.v1","status":"PASS" if failure is None and not cleanup_errors and not after_errors else "FAIL",
   "build":identity(build_path.read_bytes()),"executable":identity(elf),"controls":controls,"controls_total":len(controls),"real_processes":len(sessions),
   "failure":failure,"cleanup_errors":cleanup_errors,"source_after":{"status":"MATCH" if not after_errors else "FAIL","errors":after_errors},
   "elapsed_ns":time.monotonic_ns()-start,"script":identity(Path(__file__).read_bytes()),
   "scope":{"held_disk_owned_state":True,"actual_pnx_sha_ed25519":True,"private_ready_consumed":True,"actual_prefix":True,
   "caller_state_or_verified":False,"production_permit":False,"complete_checked_parent":False,"local_pool_durable":False,"node_commit":False}}
  (OUT/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:report[k] for k in ["status","controls_total","real_processes","failure","cleanup_errors","source_after","elapsed_ns"]}),flush=True)
  if report["status"]!="PASS":raise SystemExit(1)

if __name__=="__main__":main()
