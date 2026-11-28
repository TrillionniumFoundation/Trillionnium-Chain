"""Actual capacity qualification; fixed original case set, 240-second child and 3-second cleanup."""
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
  self.argv=["/proc/self/fd/"+str(fd)]
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
   observed=time.monotonic_ns();stat_raw=Path("/proc/"+str(self.p.pid)+"/stat").read_bytes()
   stat_fields=stat_raw[stat_raw.rfind(b")")+2:].split()
   sample={"action":self.action,"observed_hex":raw.hex(),"ack_hex":ack.hex(),"kind":q[4],"index":q[5],"height":q[6],"classification":classification,"observed_monotonic_ns":observed,"actual_proc_stat_hex":stat_raw.hex(),"user_ticks":int(stat_fields[11]),"system_ticks":int(stat_fields[12]),"clock_ticks_per_second":os.sysconf("SC_CLK_TCK")}
   self.progress.append(sample);self.write(ack);sample["ack_written_monotonic_ns"]=time.monotonic_ns()
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

import resource

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
 roster=safe.read_json(HERE,"case_roster.json")["capacity"]
 try:
  sources();need(build["status"]=="PASS" and build["source_after"]["status"]=="MATCH","Invalid actual build")
  # Fixture signing is complete before starting the timed child; it supplies only
  # signed wire input. The live owner independently creates and checks its Config.
  prior=json.loads((HERE/"capacity_context.json").read_bytes())
  first=bytes.fromhex(prior["frames_hex"][0]);ready(first);network=first[184:216]
  fixture_source=HERE/"capacity_fixture.json";fixture_raw=fixture_source.read_bytes();fixture=json.loads(fixture_raw)
  need(fixture["timestamp"] is None and fixture["workers"]==8 and fixture["network_hex"]==network.hex(),"Retained exact input context")
  raws=[bytes.fromhex(r) for r in fixture["transactions_hex"]];need(len(raws)==257,"Retained original full-capacity roster")
  (OUT/"fixture-source.json").write_text(json.dumps({"path":str(fixture_source),"identity":identity(fixture_raw)},sort_keys=True,indent=2)+"\n")
  (OUT/"fixture.json").write_text(json.dumps(fixture,sort_keys=True,indent=2)+"\n")
  owned=OUT/"owned";owned.mkdir(mode=0o700);usage_before=resource.getrusage(resource.RUSAGE_CHILDREN)
  s=PoolSession("capacity",owned,0,None,8);observed=ready(s.frame());need(observed==first,"Actual independently constructed Config changed")
  s.command(1);before=state(s.frame());disk_before=snapshot(owned)
  s.start_action("capacity-open");pool_open(s,public(0),cap=256,reserve=0)
  got=validate(s,"full-original-256-record-capacity",raws[:256],calls=256,reused=0,signatures=256)
  need(got["mempool"]["header"][4]==256 and len(got["mempool"]["ready"])==256,"Complete actual Ready queue")
  need(got["prefix"]["header"][8]==256,"Actual M06 did not accept full input")
  validate(s,"record-257-before-signature",raws,expected=2,error=8,calls=0,reused=256,signatures=0)
  validate(s,"duplicate-257-before-record-limit",raws[:256]+[raws[0]],expected=2,error=7,calls=0,reused=256,signatures=0)
  validate(s,"encoding-257-before-record-limit",raws[:256]+[b"PN"],expected=2,error=2,calls=0,reused=256,signatures=0)
  s.start_action("drop");input_frame(s,8,struct.pack("<Q",3));pool_result(s.frame(),3,1)
  s.command(1);need(state(s.frame())==before,"Full capacity changed canonical base")
  s.command(2);need(s.frame()==b"NBCLOSE1"+bytes(8),"Full-capacity close failed")
  receipt=s.finish(0);usage_after=resource.getrusage(resource.RUSAGE_CHILDREN)
  need(snapshot(owned)==disk_before,"Full capacity changed persistent namespace")
  controls.append({"name":"full-capacity-owner-release","status":"PASS","process":receipt,"progress":s.progress,
   "measured_child_user_seconds":usage_after.ru_utime-usage_before.ru_utime,"measured_child_system_seconds":usage_after.ru_stime-usage_before.ru_stime,
   "maxrss_kib":usage_after.ru_maxrss,"physical_trace":"NOT_RUN_IN_THIS_CAPACITY_PROCESS"})
  need([c["name"] for c in controls]==roster["controls"],"Complete fixed control names/order")
  need(len(sessions)==roster["processes"],"Complete fixed process count")
 except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
 finally:
  for session in sessions:
   try:session.abort()
   except BaseException as e:cleanup_errors.append({"name":session.directory.name,"error":repr(e)})
  try:sources()
  except BaseException as e:after_errors.append(repr(e))
  for session in sessions:
   (session.directory/"progress-observations.json").write_text(json.dumps(session.progress,sort_keys=True,indent=2)+"\n")
  report={"schema":"trnm.production-m05-runtime-capacity.v2","status":"PASS" if failure is None and not cleanup_errors and not after_errors else "FAIL",
   "build":identity(build_path.read_bytes()),"executable":identity(elf),"controls":controls,"controls_total":len(controls),"real_processes":len(sessions),
   "failure":failure,"cleanup_errors":cleanup_errors,"source_after":{"status":"MATCH" if not after_errors else "FAIL","errors":after_errors},
   "elapsed_ns":time.monotonic_ns()-start,"script":identity(Path(__file__).read_bytes()),
   "scope":{"held_disk_owned_state":True,"actual_pnx_sha_ed25519":True,"private_ready_consumed":True,"actual_prefix":True,
   "caller_state_or_verified":False,"production_permit":False,"complete_checked_parent":False,"local_pool_durable":False,"node_commit":False}}
  (OUT/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:report[k] for k in ["status","controls_total","real_processes","failure","cleanup_errors","source_after","elapsed_ns"]}),flush=True)
  if report["status"]!="PASS":raise SystemExit(1)

if __name__=="__main__":main()
