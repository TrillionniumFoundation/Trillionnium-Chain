"""Qualify the actual Work relation in this hosted job's existing fixed parent.

This controller never provisions/adopts a parent. It supplies a sealed untrusted
proof, observes actual native tasks, and retains complete bytes. The native
image owns every Host/resource/clock/W1 transition. A production-positive frame
does not qualify Node/Paid embedding, a full service, or an unexecuted trace.
"""
from __future__ import annotations
import argparse,fcntl,hashlib,json,os,re,select,signal,stat,struct,subprocess,sys,time
from pathlib import Path
if not __debug__:raise RuntimeError("Work production qualification refuses optimized Python")
if __package__ in (None,""):sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from hia.platform import build as platform_build
from hia.platform.work_owner import build,cases,native_io,bundle
from hia.platform.work_owner.primitive_evidence import same
from hia.platform.host_checkpoint import qualify_production as host
from hia.platform.host_resource import qualify_production as resource_host
ROOT=build.ROOT
MODULE="hia/platform/work_owner/qualify_production.py"
TEST="hia/platform/work_owner/test_production.py"
SCOPE="LIVE_FIXED_PARENT_WORK_RELATION_ONLY"
PARENT=Path("/sys/fs/cgroup/trnmponpublic.slice")
FIXED={"cpu_quota":25000,"cpu_period":100000,"memory_limit":2147483648,"pids_limit":256}
NAMESPACES=("mnt","pid","user","cgroup")
require=build.need
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return build.read_json(path)
def write(path,value):
 with Path(path).open("x",encoding="utf-8") as stream:json.dump(value,stream,sort_keys=True,indent=2,allow_nan=False);stream.write("\n")
def source_inputs():
 require(Path(__file__).resolve()==ROOT/MODULE,"HOSTED_MODULE_AT_FINAL_SOURCE_REQUIRED")
 require(host.ROOT==resource_host.ROOT==ROOT,"SHARED_HOST_MODULE_FROM_DIFFERENT_CHECKOUT")
 for module,path in ((build,"hia/platform/work_owner/build.py"),(cases,"hia/platform/work_owner/cases.py"),(native_io,"hia/platform/work_owner/native_io.py"),(bundle,"hia/platform/work_owner/bundle.py"),(platform_build,"hia/platform/build.py"),(host,"hia/platform/host_checkpoint/qualify_production.py"),(resource_host,"hia/platform/host_resource/qualify_production.py")):
  require(Path(module.__file__).resolve()==ROOT/path,"IMPORTED_MODULE_FROM_DIFFERENT_CHECKOUT")
 rows=build.source_manifest()
 for name in (MODULE,TEST):
  value=build.identity(ROOT/name)
  require(name not in rows or same(rows[name],value),"SOURCE_COLLISION")
  rows[name]=value
 return dict(sorted(rows.items()))
def validate_build(directory):
 directory=directory.absolute()
 require(directory.name=="build" and directory.is_dir() and directory.resolve(strict=True)==directory and not directory.is_symlink(),"CANONICAL_COMPLETE_BUILD_DIRECTORY_REQUIRED")
 raw=(directory/"build.json").read_bytes();report=build.read_json(directory/"build.json")
 require(report.get("status")=="PASS" and same(report.get("source_inputs"),build.source_manifest()),"COMPLETE_CURRENT_NATIVE_SOURCE_REQUIRED")
 # The public build reader binds complete input, compiler stdout, flat images,
 # emitter lengths, prefix and final ELF. This is not a suffix/hash-only gate.
 bundle.validate_build(directory.parent,{"build":report,"source_inputs":report["source_inputs"]})
 image=(directory/"owner.elf").read_bytes();abi=build.read_json(ROOT/"hia/platform/work_owner/abi.json")
 require(same(build.identity(directory/"owner.elf"),abi["images"]["owner"]["executable"]),"ACTUAL_PRODUCTION_IMAGE_REQUIRED")
 require(digest(image)!=report["images"]["fixture"]["sha256"],"FIXTURE_CANNOT_REPLACE_PRODUCTION_IMAGE")
 build.inspect_owner(image)
 return image,report,digest(raw)
def validate_service(name):
 require(type(name) is str and re.fullmatch(r"trnm-hia-work-[0-9]+-[0-9]+-[A-Za-z0-9_-]{1,80}-[0-9]+\.service",name),"EXPLICIT_OWNED_WORK_SERVICE_REQUIRED")
def service_name(environment=None,pid=None):
 e=os.environ if environment is None else environment
 s="trnm-hia-work-{}-{}-{}-{}.service".format(e.get("GITHUB_RUN_ID",""),e.get("GITHUB_RUN_ATTEMPT",""),e.get("GITHUB_JOB",""),os.getpid() if pid is None else pid)
 validate_service(s);return s
def service_argv(service,directory,lease_root,resource_root,output,uid,gid,environment):
 validate_service(service)
 require(type(uid) is int and uid>0 and type(gid) is int and gid>=0,"ACTUAL_UNPRIVILEGED_OWNER_REQUIRED")
 return ["sudo","-n","systemd-run","--unit="+service,"--wait","--pipe","--collect","--service-type=exec","--expand-environment=no","--slice=trnmponpublic.slice","--uid="+str(uid),"--gid="+str(gid),"--working-directory="+str(ROOT),"--property=KillMode=control-group","--property=TimeoutStopSec=20s","--property=Delegate=no","--property=NoNewPrivileges=yes","--property=CapabilityBoundingSet=",*["--setenv="+key+"="+environment[key] for key in host.FORWARDED_ENV if key in environment],sys.executable,"-B",str(ROOT/MODULE),"--inside","--build",str(directory),"--lease-receipts",str(lease_root),"--resource-receipts",str(resource_root),"--output",str(output),"--service",service]
def directories(lease_root,resource_root,output,*,inside):
 lease_root,output=resource_host.lease_directory(lease_root,output,inside=inside)
 resource_root=resource_root.absolute()
 require(resource_root.is_dir() and resource_root.resolve(strict=True)==resource_root and not resource_root.is_symlink() and resource_root.is_relative_to(lease_root) and resource_root!=lease_root,"EXACT_PREVIOUS_RESOURCE_CHILD_REQUIRED")
 require(not output.is_relative_to(resource_root) and not resource_root.is_relative_to(output),"WORK_AND_RESOURCE_RECEIPTS_MUST_BE_DISTINCT")
 return lease_root,resource_root,output
def prior_resource(lease_root,resource_root,source,prior_host):
 report=read(resource_root/"report.json");native=read(resource_root/"child/native.json");inside=read(resource_root/"child/inside-report.json")
 require(report.get("schema")=="trnm.hia.production-resource-controller.v1" and report.get("status")=="PASS" and report.get("cleanup_errors")==[],"PREVIOUS_ACTUAL_RESOURCE_PASS_REQUIRED")
 require(same(report.get("native"),native) and inside.get("status")=="PASS" and inside.get("cleanup_errors")==[],"PREVIOUS_RESOURCE_RAW_REPORT_CHAIN_REQUIRED")
 require(native.get("status")=="PASS" and type(native.get("actual_fixed_parent_resource_samples")) is int and native["actual_fixed_parent_resource_samples"]==3 and native.get("standalone_native_same_tid") is True and native.get("cleanup_errors")==[] and native.get("trace",{}).get("status")=="PASS" and same(native.get("source_inputs"),resource_host.required_sources()),"PREVIOUS_RESOURCE_SOURCE_TRACE_REQUIRED")
 require(same(read(resource_root/"source.json"),source) and same(read(resource_root/"source-after.json"),source),"PREVIOUS_RESOURCE_SOURCE_CHANGED")
 before=report.get("parent_lease");after=report.get("final_parent_lease")
 resource_host.validate_service(report.get("service"))
 h=resource_host.stable_prior_binding(prior_host)
 require(same(prior_host["parent_lease"],prior_host["final_parent_lease"]),"PRIOR_HOST_LEASE_TYPE_OR_VALUE_CHANGED")
 require(same(before,after) and same(before,{**h,"current_service":report["service"]}),"PREVIOUS_RESOURCE_NOT_BOUND_TO_SAME_HOST_SEAL")
 return {"service":report["service"],"report":build.identity(resource_root/"report.json"),"native_report":build.identity(resource_root/"child/native.json"),"parent_lease":before,"final_parent_lease":after,"execution_authority_from_prior_receipt":False}
def bind_prior(prior_host,prior_resource,current,service):
 require(same(prior_host.get("parent_lease"),prior_host.get("final_parent_lease")),"PRIOR_HOST_FINAL_LEASE_TYPE_OR_VALUE_CHANGED")
 resource_host.require_prior_lease_binding(prior_host,current,service)
 require(same(current,{**prior_host["parent_lease"],"current_service":service}),"PRIOR_HOST_LEASE_TYPE_OR_VALUE_CHANGED")
 require(same(current,{**prior_resource["parent_lease"],"current_service":service}) and same(prior_resource["parent_lease"],prior_resource["final_parent_lease"]),"RESOURCE_PASS_NOT_BOUND_TO_CURRENT_SEAL")
def namespace_identity(pid):
 return {key:os.readlink(Path("/proc")/str(pid)/"ns"/key) for key in NAMESPACES}
def observe_tasks(process,image_hash,service,namespace,observations):
 expected="0::/trnmponpublic.slice/"+service
 try:
  base=Path("/proc")/str(process.pid)
  actual_image=digest((base/"exe").read_bytes())
  if actual_image!=image_hash:return
  ns=namespace_identity(process.pid)
  require(ns==namespace,"NATIVE_CHANGED_AUTHORITY_NAMESPACE")
  for task in (base/"task").iterdir():
   if not task.name.isdecimal():raise ValueError("NONNUMERIC_ACTUAL_THREAD")
   tid=int(task.name)
   try:
    membership=(task/"cgroup").read_text().strip();task_ns=namespace_identity(tid)
    status=(task/"status").read_text()
   except FileNotFoundError:continue
   require(membership==expected or membership.startswith(expected+"/"),"ACTUAL_NATIVE_THREAD_OUTSIDE_OWNED_SERVICE")
   require(task_ns==namespace,"WORKER_CHANGED_AUTHORITY_NAMESPACE")
   ids=re.search(r"(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$",status)
   require(ids is not None and all(int(x)==os.getuid() for x in ids.groups()),"ACTUAL_NATIVE_THREAD_UID_DIFFERS")
   row={"tid":tid,"tgid":process.pid,"membership":membership,"namespaces":task_ns,"executable_sha256":actual_image,"uid":os.getuid()}
   if tid in observations:require(same(observations[tid],row),"ACTUAL_THREAD_OBSERVATION_CHANGED")
   observations[tid]=row
 except FileNotFoundError:
  # Exit racing this pure observation is not a positive observation. Both main
  # and worker must have been observed alive, or the final admission fails.
  return
def validate_native(raw,case,process_pid,observations,parent,expected_service,*,namespace,image_hash,uid):
 validate_service(expected_service)
 require(type(process_pid) is int and process_pid>0 and type(uid) is int and uid>0 and type(parent) is tuple and len(parent)==3 and all(type(x) is int and x>=0 for x in parent),"ACTUAL_OBSERVER_IDENTITY_TYPES_REQUIRED")
 require(type(observations) is dict and type(namespace) is dict and set(namespace)==set(NAMESPACES) and all(type(namespace[k]) is str and re.fullmatch(re.escape(k)+r":\[[0-9]+\]",namespace[k]) for k in NAMESPACES) and type(image_hash) is str and re.fullmatch(r"[0-9a-f]{64}",image_hash),"ACTUAL_NAMESPACE_IMAGE_IDENTITY_REQUIRED")
 decoded=native_io.decode(raw);h=decoded["header"]
 require(h["fixture"]==h["host_fixture"]==0,"FIXTURE_CANNOT_CLAIM_PRODUCTION")
 require(h["boot_bytes"]==36,"ACTUAL_COMPLETE_BOOT_ID_EXTENT_REQUIRED")
 require(h["domain"]==h["code"]==h["work_code"]==h["post_sample_error"]==0,"ACTUAL_NATIVE_WORK_RELATION_REFUSED")
 require(h["main_tid"]==h["acquirer_tid"]==process_pid and h["worker_tid"]!=process_pid and h["worker_tid"]>0 and h["generation"]==h["joins"]==1,"ACTUAL_WORKER_LIFETIME_REQUIRED")
 require(set(observations)=={process_pid,h["worker_tid"]},"BOTH_ACTUAL_NATIVE_THREADS_MUST_BE_OBSERVED")
 require((h["parent_dev"],h["parent_ino"],h["parent_uid"])==parent and parent[2]==0,"NATIVE_PARENT_IDENTITY_DIFFERS")
 require(all(h[key]==value for key,value in FIXED.items()),"ORIGINAL_RESOURCE_LIMITS_CHANGED")
 require(h["progress_count"]==1099 and h["worker_host_calls"]==1101 and h["pre_checks"]==3 and h["post_checks"]==5 and h["aggregate_samples"]==2 and h["alive_clocks"]==2200 and h["gates"]==0,"MISSING_ACTUAL_FRESH_BOUNDARY")
 require(same(decoded["progress"],case["progress"]),"COMPLETE_ORIGINAL_PROGRESS_ORDER_CHANGED")
 product=bytes.fromhex(case["product_hex"])
 require(len(product)==decoded["product_bytes"]==16384 and raw[-16384:]==product,"ACTUAL_COMPLETE_PRODUCT_DIFFERS")
 request=bytes.fromhex(case["request_hex"])
 require(len(request)==49284 and request[96:100]==b"PNW1","NATIVE_PROOF_REQUEST_FORMAT_CHANGED")
 # The third request word is the target; the output carries the independently
 # derived ticket bound to the complete request's challenge and transcript.
 ticket=cases.tagged(b"ticket",request[:32],request[-32:])
 require(decoded["challenge_hex"]==request[:32].hex() and decoded["task_hex"]==request[32:64].hex()
         and decoded["ticket_hex"]==ticket.hex(),"NATIVE_PROOF_IDENTITY_CHANGED")
 require(ticket<=request[64:96],"NATIVE_PROOF_TARGET_REFUSED")
 before,after,worker=(decoded[n] for n in ("host_before","host_after","host_worker_final"))
 require(before[2:8]==[0,1,3,1,1,1] and after[2:8]==[0,2,5,2,2,1] and worker[2:8]==[0,1102,1104,1,0,0],"NATIVE_RESOURCE_AND_WORKER_RECEIPT_ORDER_CHANGED")
 require(before[23]==after[23]==process_pid and worker[23]==h["worker_tid"],"HOST_RECEIPT_THREAD_DIFFERS")
 require(before[14:18]==[0]*4 and worker[8:18]==before[8:18] and all(after[8+i]>=before[8+i] and after[14+i]==after[8+i]-before[8+i] for i in range(4)),"ACTUAL_RESOURCE_DELTA_DIFFERS")
 require(before[28:31]==after[28:31]==[3,0,1] and worker[28:31]==[0,0,1] and all(r[22]==0 and r[25:27]==[0,0] for r in (before,after,worker)),"NATIVE_CLOSE_OR_EXTRA_OBSERVER_DIFFERED")

 paid=decoded["paid"];account=paid["owner"];checkpoints=h["progress_count"]+1
 require(paid["epoch"][0]==int.from_bytes(b"PCPU0001","little")
         and paid["epoch"][9:12]==[1,2000000000,0],
         "ACTUAL_TRUSTED_LOCAL_STANDALONE_EPOCH_REQUIRED")
 require(paid["global_poison"]==paid["request_poison"]==0 and paid["epoch"][1]==0
         and paid["epoch"][6:9]==[0,0,0],"ACTUAL_FINITE_PAID_ACCOUNT_NOT_RETIRED")
 require(account[0]==int.from_bytes(b"PCOWN001","little") and account[1:4]==[0,0,0]
         and account[20:22]==[h["worker_tid"],2] and account[22:]==[0]*42,
         "ACTUAL_FINITE_PAID_OWNER_IDENTITY_REQUIRED")
 require(all(account[i]==1 for i in (4,6,8,10,12)) and account[7]==0
         and account[14:20]==[0]*6 and account[5]==account[9]
         and account[9]==account[11]+account[13],
         "ACTUAL_FINITE_PAID_KNOWN_UNIQUE_SETTLEMENT_REQUIRED")
 require(paid["checkpoint_calls"]==checkpoints
         and paid["binding"]==[0,3,checkpoints+2,2,checkpoints,0,0,0,1,0]
         and paid["meta"]==[0,0,checkpoints+2,3,0,0,0,0],
         "ACTUAL_FINITE_PAID_CHECKPOINT_AND_RETIREMENT_REQUIRED")

 for tid,row in observations.items():
  membership="0::/trnmponpublic.slice/"+expected_service
  require(type(tid) is int and type(row) is dict and type(row.get("tid")) is int and row["tid"]==tid and type(row.get("tgid")) is int and row["tgid"]==process_pid and type(row.get("uid")) is int and row["uid"]==uid,"THREAD_RECORD_DIFFERS")
  require(type(row.get("membership")) is str and (row["membership"]==membership or row["membership"].startswith(membership+"/")),"THREAD_MEMBERSHIP_DIFFERS")
  require(type(namespace) is dict and set(namespace)==set(NAMESPACES) and same(row.get("namespaces"),namespace) and row.get("executable_sha256")==image_hash,"THREAD_NAMESPACE_OR_EXECUTABLE_DIFFERS")
 return decoded

NATIVE_CAPTURE_FIELDS=frozenset((
 "schema","status","qualified_scope","source_inputs","native_build_source_inputs",
 "executable_sha256","build_report_sha256","fixture","independent_complete_syscall_trace",
 "normal_production_CLOCK_fault_qualified","Node_or_Paid_embedding_qualified",
 "original_4s_16_service_qualified","original_1800s_history_qualified","retirement_accepted",
 "native_deadline_seconds","observed_actual_tasks","controller_namespaces","actual_process_pid",
 "actual_fixed_parent_positive","decoded","parent_identity","source_after","cleanup_errors",
 "exit_code","elapsed_wall_ns","stdin","stdout","stderr",
))
def capture_bytes(path,limit):
 path=Path(path)
 for item in (path,*path.parents):
  require(not item.is_symlink(),"LINKED_NATIVE_CAPTURE")
 descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(descriptor,"rb") as stream:
  before=os.fstat(stream.fileno())
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit,
          "BOUNDED_SINGLE_REGULAR_NATIVE_CAPTURE_REQUIRED")
  raw=stream.read(limit+1);after=os.fstat(stream.fileno())
 fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_nlink","st_mode")
 stamp=tuple(getattr(before,key) for key in fields)
 require(len(raw)==before.st_size and len(raw)<=limit and stamp==tuple(getattr(after,key) for key in fields),
         "NATIVE_CAPTURE_CHANGED_DURING_READ")
 return raw,stamp
def capture_json(raw):
 def pairs(items):
  value={}
  for key,item in items:
   require(key not in value,"DUPLICATE_NATIVE_CAPTURE_FIELD")
   value[key]=item
  return value
 def noninteger(value):raise ValueError("NONINTEGER_NATIVE_CAPTURE_NUMBER:"+value)
 return json.loads(raw,object_pairs_hook=pairs,parse_float=noninteger,parse_constant=noninteger)
def read_native_capture(directory,image,built,built_hash,sources,service,parent,uid):
 """Reread complete child bytes; a cached PASS/decoded summary is insufficient."""
 directory=Path(directory).absolute()
 require(directory.is_dir() and directory.resolve(strict=True)==directory,
         "CANONICAL_NATIVE_CAPTURE_DIRECTORY_REQUIRED")
 raw={};stamps={}
 for name,limit in (("native.json",4<<20),("stdin.raw",65536),("stdout.raw",65536),("stderr.raw",65536)):
  raw[name],stamps[name]=capture_bytes(directory/name,limit)
 native=capture_json(raw["native.json"])
 require(type(native) is dict and set(native)==NATIVE_CAPTURE_FIELDS,
         "EXACT_NATIVE_CAPTURE_FIELDS_REQUIRED")
 expected={
  "schema":"trnm.hia.production-work-native-positive.v1","status":"PASS",
  "qualified_scope":SCOPE,"source_inputs":sources,"native_build_source_inputs":built["source_inputs"],
  "executable_sha256":digest(image),"build_report_sha256":built_hash,"fixture":False,
  "independent_complete_syscall_trace":"NOT_RUN","normal_production_CLOCK_fault_qualified":False,
  "Node_or_Paid_embedding_qualified":False,"original_4s_16_service_qualified":False,
  "original_1800s_history_qualified":False,"retirement_accepted":False,
  "native_deadline_seconds":4,"actual_fixed_parent_positive":True,
  "parent_identity":{"dev":parent[0],"ino":parent[1],"uid":parent[2]},
  "source_after":"MATCH","cleanup_errors":[],"exit_code":0,
 }
 require(same({key:native[key] for key in expected},expected),
         "NATIVE_CAPTURE_SCOPE_SOURCE_OR_OUTCOME_DIFFERS")
 require(type(native["elapsed_wall_ns"]) is int and native["elapsed_wall_ns"]>0,
         "ACTUAL_ELAPSED_OBSERVATION_REQUIRED")
 for name in ("stdin","stdout","stderr"):
  value=raw[name+".raw"]
  require(same(native[name],{"bytes":len(value),"sha256":digest(value)}),
          "COMPLETE_NATIVE_CAPTURE_IDENTITY_DIFFERS")
 proof=cases.corpus()[0]
 require(proof["name"]=="dense-positive" and proof["options"]=={},
         "PINNED_FULL_CAPTURE_PROOF_REQUIRED")
 require(raw["stdin.raw"]==bytes.fromhex(proof["request_hex"]) and not raw["stderr.raw"],
         "ACTUAL_CAPTURE_INPUT_OR_STDERR_DIFFERS")
 observations=native["observed_actual_tasks"]
 require(type(observations) is list and len(observations)==2 and all(type(row) is dict and type(row.get("tid")) is int for row in observations),
         "COMPLETE_ACTUAL_CAPTURE_TASK_ROSTER_REQUIRED")
 observed={row["tid"]:row for row in observations}
 require(len(observed)==2,"DUPLICATE_ACTUAL_CAPTURE_TASK")
 decoded=validate_native(raw["stdout.raw"],proof,native["actual_process_pid"],observed,parent,service,
                         namespace=native["controller_namespaces"],image_hash=digest(image),uid=uid)
 require(same(native["decoded"],decoded),"CACHED_NATIVE_DECODE_DIFFERS_FROM_ACTUAL_BYTES")
 for name,limit in (("native.json",4<<20),("stdin.raw",65536),("stdout.raw",65536),("stderr.raw",65536)):
  after,stamp=capture_bytes(directory/name,limit)
  require(after==raw[name] and stamp==stamps[name],"NATIVE_CAPTURE_CHANGED_DURING_VALIDATION")
 return native

def native_positive(directory,output,service):
 validate_service(service);image,built,built_hash=validate_build(directory);before_sources=source_inputs()
 proof=cases.corpus()[0];require(proof["name"]=="dense-positive" and proof["options"]=={},"PINNED_FULL_PROOF_REQUIRED")
 request=bytes.fromhex(proof["request_hex"]);require(len(request)==49284,"SEALED_REQUEST_EXTENT")
 descriptors=set();process=None;stdout=bytearray();stderr=bytearray();observed={};finished=False;failure=None;started=time.monotonic_ns()
 report={"schema":"trnm.hia.production-work-native-positive.v1","status":"FAIL","qualified_scope":SCOPE,"source_inputs":before_sources,"native_build_source_inputs":built["source_inputs"],"executable_sha256":digest(image),"build_report_sha256":built_hash,"fixture":False,"independent_complete_syscall_trace":"NOT_RUN","normal_production_CLOCK_fault_qualified":False,"Node_or_Paid_embedding_qualified":False,"original_4s_16_service_qualified":False,"original_1800s_history_qualified":False,"retirement_accepted":False,"native_deadline_seconds":4,"observed_actual_tasks":[]}
 try:
  initial=PARENT.lstat();parent=(initial.st_dev,initial.st_ino,initial.st_uid);require(stat.S_ISDIR(initial.st_mode) and initial.st_uid==0 and not initial.st_mode&0o022,"ACTUAL_FIXED_PARENT_REQUIRED")
  namespace=namespace_identity("self");report["controller_namespaces"]=namespace
  inp=os.memfd_create("hia-production-work-input",os.MFD_ALLOW_SEALING);descriptors.add(inp)
  offset=0
  while offset<len(request):
   n=os.write(inp,request[offset:]);require(n>0,"SHORT_INPUT_CAPTURE");offset+=n
  fcntl.fcntl(inp,fcntl.F_ADD_SEALS,15);require(fcntl.fcntl(inp,fcntl.F_GET_SEALS)==15,"ACTUAL_INPUT_SEALS_REQUIRED")
  require(os.lseek(inp,0,os.SEEK_SET)==0,"SEALED_INPUT_POSITION")
  fd=platform_build.sealed_executable(image,"hia-production-work-owner");descriptors.add(fd)
  executable=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,20);descriptors.add(executable)
  process=subprocess.Popen(["/proc/self/fd/"+str(executable)],cwd=ROOT,env={"PATH":""},stdin=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(executable,),start_new_session=True)
  report["actual_process_pid"]=process.pid
  for n in list(descriptors):os.close(n);descriptors.remove(n)
  streams={process.stdout.fileno():(process.stdout,stdout),process.stderr.fileno():(process.stderr,stderr)}
  for n in streams:os.set_blocking(n,False)
  end=time.monotonic()+20
  while streams or process.poll() is None:
   require(time.monotonic()<end,"OWNED_NATIVE_MONITOR_TIMEOUT")
   observe_tasks(process,digest(image),service,namespace,observed)
   ready,_,_=select.select(list(streams),[],[],0.01)
   for n in ready:
    part=os.read(n,65536)
    if part:
     streams[n][1].extend(part);require(len(stdout)<=65536 and len(stderr)<=65536,"NATIVE_STREAM_EXCEEDS_FIXED_PROFILE")
    else:
     streams[n][0].close();del streams[n]
  process.wait(timeout=3);finished=True
  require(process.returncode==0 and not stderr,"ACTUAL_NATIVE_PROCESS_REFUSED")
  final=PARENT.lstat();require(stat.S_ISDIR(final.st_mode) and not final.st_mode&0o022 and (final.st_dev,final.st_ino,final.st_uid)==parent,"PARENT_REPLACED_DURING_NATIVE")
  decoded=validate_native(bytes(stdout),proof,process.pid,observed,parent,service,namespace=namespace,image_hash=digest(image),uid=os.getuid())
  report.update(status="PASS",actual_fixed_parent_positive=True,decoded=decoded,observed_actual_tasks=[observed[k] for k in sorted(observed)],parent_identity={"dev":parent[0],"ino":parent[1],"uid":parent[2]})
 except BaseException as error:
  failure=error;report["failure"]=type(error).__name__+": "+str(error)
  raise
 finally:
  errors=[]
  for fd in descriptors:
   try:os.close(fd)
   except BaseException as e:errors.append("CAP_CLOSE:"+repr(e))
  if process is not None and not finished:
   if process.poll() is None:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
   try:
    remaining={s.fileno():(s,t) for s,t in ((process.stdout,stdout),(process.stderr,stderr)) if s is not None and not s.closed}
    for n in remaining:os.set_blocking(n,False)
    until=time.monotonic()+5
    while remaining:
     require(time.monotonic()<until,"NATIVE_FAILURE_DRAIN_TIMEOUT")
     ready,_,_=select.select(list(remaining),[],[],0.02)
     for n in ready:
      part=os.read(n,65536)
      if part:remaining[n][1].extend(part);require(len(stdout)<=65536 and len(stderr)<=65536,"NATIVE_FAILURE_STREAM_EXCEEDS_PROFILE")
      else:remaining[n][0].close();del remaining[n]
    process.wait(timeout=5)
   except BaseException as e:errors.append("NATIVE_DRAIN:"+repr(e))
  try:
   final_image,final_build,final_hash=validate_build(directory)
   require(final_image==image and same(final_build,built) and final_hash==built_hash and same(source_inputs(),before_sources),"WORK_SOURCE_OR_BUILD_CHANGED")
   report["source_after"]="MATCH"
  except BaseException as e:errors.append("SOURCE_BUILD_AFTER:"+repr(e))
  report.update(cleanup_errors=errors,exit_code=None if process is None else process.returncode,elapsed_wall_ns=time.monotonic_ns()-started,observed_actual_tasks=[observed[k] for k in sorted(observed)])
  if errors:report["status"]="FAIL"
  for name,raw in (("stdin.raw",request),("stdout.raw",stdout),("stderr.raw",stderr)):
   (output/name).write_bytes(raw);report[name.removesuffix(".raw")]=build.identity(output/name)
  write(output/"native.json",report)
  if errors and failure is None:raise ValueError("NATIVE_FINAL_EVIDENCE_FAILED")
 return report
def inside(directory,lease_root,resource_root,output,service):
 host.hosted_context();validate_service(service);source_inputs()
 require(Path.cwd().resolve()==ROOT,"ORIGINAL_WORK_CWD_REQUIRED")
 lease_root,resource_root,output=directories(lease_root,resource_root,output,inside=True)
 observation,lease,verify=resource_host.ci_modules()
 before=observation.capture("hia-work-inside-before",service)
 require(not observation.validate(before,inside=True,uid=os.getuid(),gid=os.getgid(),cwd=str(ROOT)),"ACTUAL_UNPRIVILEGED_WORK_SERVICE_REQUIRED")
 source=verify("head",os.environ["TRNM_EXPECTED_SOURCE_SHA"],root=ROOT);require(same(source,read(lease_root/"source.json")),"EXACT_LEASE_SOURCE_CHANGED")
 write(output/"inside-before.json",before);write(output/"inside-source-before.json",source)
 result={"schema":"trnm.hia.production-work-inside.v1","status":"FAIL","cleanup_errors":[]};failure=None
 try:
  native_positive(directory,output,service);result["status"]="PASS"
 except BaseException as e:failure=e;result["failure"]=repr(e);raise
 finally:
  try:
   after=observation.capture("hia-work-inside-after",service);write(output/"inside-after.json",after)
   require(not observation.validate(after,inside=True,uid=os.getuid(),gid=os.getgid(),cwd=str(ROOT),reference=before),"WORK_HOST_CHANGED")
  except BaseException as e:result["cleanup_errors"].append("HOST_AFTER:"+repr(e))
  try:
   after=verify("head",os.environ["TRNM_EXPECTED_SOURCE_SHA"],root=ROOT);write(output/"inside-source-after.json",after);require(same(source,after),"SOURCE_CHANGED_INSIDE")
  except BaseException as e:result["cleanup_errors"].append("SOURCE_AFTER:"+repr(e))
  if result["cleanup_errors"]:result["status"]="FAIL"
  write(output/"inside-report.json",result)
  if result["cleanup_errors"] and failure is None:raise ValueError("INSIDE_FINAL_EVIDENCE_FAILED")
 return 0
def outer(directory,lease_root,resource_root,output):
 host.hosted_context();sources=source_inputs();require(Path.cwd().resolve()==ROOT,"ORIGINAL_WORK_CWD_REQUIRED")
 lease_root,resource_root,output=directories(lease_root,resource_root,output,inside=False)
 image,built,built_hash=validate_build(directory);observation,lease,verify=resource_host.ci_modules()
 source=verify("head",os.environ["TRNM_EXPECTED_SOURCE_SHA"],root=ROOT)
 prior_host=resource_host.previous_host(lease_root,source);prior=prior_resource(lease_root,resource_root,source,prior_host);lock=resource_host.lock_identity();service=service_name()
 output.mkdir(mode=0o700);controller=output/"controller";child=output/"child";controller.mkdir();child.mkdir();write(output/"source.json",source)
 result={"schema":"trnm.hia.production-work-controller.v1","status":"FAIL","qualified_scope":SCOPE,"service":service,"previous_host":prior_host,"previous_resource":prior,"cleanup_errors":[],"parent_provisioned_or_adopted":False,"local_workstation_provisioned":False,"Node_or_Paid_embedding_qualified":False,"original_4s_16_service_qualified":False,"original_1800s_history_qualified":False,"independent_complete_syscall_trace":"NOT_RUN","retirement_accepted":False}
 owned=False;baseline=None;failure=None
 def command(argv,label,required=True):
  with (controller/(label+".log")).open("xb") as stream:done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=30)
  require(not required or done.returncode==0,label+"_FAILED");return done.returncode
 try:
  with lease.parent_lock():
   try:
    require(same(resource_host.lock_identity(),lock),"JOB_PARENT_LOCK_REPLACED")
    baseline=observation.capture("hia-work-before-owned-child",service);write(controller/"before-owned-child.json",baseline)
    command(["systemctl","show",observation.UNIT,"--property="+",".join(lease.SYSTEMD_PROPERTIES)],"parent-properties-before")
    parent=lease.validate_for_reuse(baseline,controller/"parent-properties-before.log");bind_prior(prior_host,prior,parent,service);result["parent_lease"]=parent
    command(["systemctl","show","--property=LoadState","--value",service],"child-load-state",False)
    require((controller/"child-load-state.log").read_text().strip()=="not-found","WORK_CHILD_ALREADY_EXISTS")
    argv=service_argv(service,directory,lease_root,resource_root,child,os.getuid(),os.getgid(),os.environ);result["owned_service_argv"]=argv;owned=True
    with (controller/"systemd-run.log").open("xb") as stream:done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=180)
    result["systemd_run_exit"]=done.returncode;require(done.returncode==0,"ACTUAL_WORK_SERVICE_FAILED")
    parent_stat=PARENT.lstat()
    require(stat.S_ISDIR(parent_stat.st_mode) and parent_stat.st_uid==0 and not parent_stat.st_mode&0o022,
            "ACTUAL_FINAL_FIXED_PARENT_REQUIRED")
    native=read_native_capture(child,image,built,built_hash,sources,service,
                               (parent_stat.st_dev,parent_stat.st_ino,parent_stat.st_uid),os.getuid())
    inside_report=read(child/"inside-report.json")
    require(native.get("status")=="PASS" and native.get("qualified_scope")==SCOPE and native.get("actual_fixed_parent_positive") is True and native.get("cleanup_errors")==[] and native.get("executable_sha256")==digest(image) and native.get("build_report_sha256")==built_hash and same(native.get("source_inputs"),sources) and native.get("source_after")=="MATCH" and inside_report.get("status")=="PASS" and inside_report.get("cleanup_errors")==[],"ACTUAL_WORK_NATIVE_EVIDENCE_REQUIRED")
    result.update(status="PASS",native=native,actual_fixed_parent_positive=True)
   finally:
    if owned:
     try:
      command(["systemctl","show","--property=LoadState","--value",service],"owned-child-final-state",False)
      if (controller/"owned-child-final-state.log").read_text().strip()!="not-found":command(["sudo","-n","systemctl","stop",service],"stop-owned-child")
     except BaseException as e:result["cleanup_errors"].append("OWNED_CHILD_STOP:"+repr(e))
    if baseline is not None:
     try:
      after=observation.capture("hia-work-after-owned-child",service);write(controller/"after-owned-child.json",after)
      require(not observation.validate(after,inside=False,uid=os.getuid(),gid=os.getgid(),cwd=str(ROOT),reference=baseline),"WORK_PARENT_CHANGED")
      command(["systemctl","show",observation.UNIT,"--property="+",".join(lease.SYSTEMD_PROPERTIES)],"parent-properties-after")
      final=lease.validate_for_reuse(after,controller/"parent-properties-after.log");result["final_parent_lease"]=final
      require("parent_lease" in result and same(final,result["parent_lease"]) and same(resource_host.lock_identity(),lock),"WORK_JOB_LEASE_CHANGED")
     except BaseException as e:result["cleanup_errors"].append("PARENT_AFTER:"+repr(e))
    if result["cleanup_errors"]:result["status"]="FAIL"
 except BaseException as e:failure=e;result["status"]="FAIL";result["failure"]=repr(e);raise
 finally:
  try:
   final=verify("head",os.environ["TRNM_EXPECTED_SOURCE_SHA"],root=ROOT);write(output/"source-after.json",final);require(same(source,final),"SOURCE_CHANGED_OUTSIDE")
  except BaseException as e:result["cleanup_errors"].append("SOURCE_AFTER:"+repr(e))
  try:
   final_image,final_build,final_hash=validate_build(directory);require(final_image==image and same(final_build,built) and final_hash==built_hash and same(source_inputs(),sources),"WORK_SOURCE_BUILD_CHANGED_OUTSIDE")
  except BaseException as e:result["cleanup_errors"].append("BUILD_AFTER:"+repr(e))
  if result["cleanup_errors"]:result["status"]="FAIL"
  write(output/"report.json",result)
  if result["status"]!="PASS":host.emit_failure_evidence(output)
  if result["cleanup_errors"] and failure is None:raise ValueError("OUTER_FINAL_EVIDENCE_FAILED")
 return 0
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--build",required=True,type=Path);parser.add_argument("--lease-receipts",required=True,type=Path);parser.add_argument("--resource-receipts",required=True,type=Path);parser.add_argument("--output",required=True,type=Path);parser.add_argument("--inside",action="store_true");parser.add_argument("--service")
 args=parser.parse_args();require(args.inside==(args.service is not None),"OWNED_INSIDE_SERVICE_ARGUMENT_REQUIRED")
 if args.inside:return inside(args.build,args.lease_receipts,args.resource_receipts,args.output,args.service)
 return outer(args.build,args.lease_receipts,args.resource_receipts,args.output)
if __name__=="__main__":raise SystemExit(main())
