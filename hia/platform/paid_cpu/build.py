"""Compile the finite account directly from checked HIA sources."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
from hia.platform.build import Build as PlatformBuild, inspect_executable, new_output
from hia.platform.thread_cpu.rust_oracle import complete_source_manifest as thread_source_manifest

OWNED=(
 "__init__.py","README.md","abi.json","private_layout.json","build.py","cases.py",
 "native_io.py","trace_audit.py","fault_audit.py","owned_ptrace.py","qualify.py",
 "rust_reference.rs","rust_oracle.py","dependency.py","fault_oracle.py","test_integrity.py",
 "owner.hepta","linux_owner_emitter.hepta","arithmetic_fixture.hepta","linux_arithmetic_emitter.hepta",
)
ORIGINAL=(
 "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs",
 "trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs",
)
def need(ok,message):
 if not ok:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):
 path=Path(path)
 need(path.is_file() and not path.is_symlink() and path.resolve()==path,"Missing/noncanonical source or evidence: "+str(path))
 h=hashlib.sha256();size=0
 with path.open("rb") as stream:
  for data in iter(lambda:stream.read(1<<20),b""):size+=len(data);h.update(data)
 return {"bytes":size,"sha256":h.hexdigest()}
def unique(pairs):
 value={}
 for key,item in pairs:
  need(key not in value,"Duplicate JSON key: "+key);value[key]=item
 return value
def read_json(path):return json.loads(Path(path).read_bytes(),object_pairs_hook=unique)
def write_json(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def source_manifest():
 need(__debug__,"PaidCPU qualification refuses optimized Python")
 result=thread_source_manifest()
 for name in OWNED:
  relative="hia/platform/paid_cpu/"+name;result[relative]=identity(ROOT/relative)
 for relative in ORIGINAL:result[relative]=identity(ROOT/relative)
 return dict(sorted(result.items()))
def validate_source_bindings(native):
 current=source_manifest()
 need(type(native) is dict and type(native.get("build")) is dict,"Missing complete native build binding")
 need(native.get("source_inputs")==native["build"].get("source_inputs")==current,
      "Top-level/build/current complete source sets differ")
 return current
def validate_layout(value):
 need(type(value) is dict and type(value.get("fields")) is list and type(value.get("regions")) is list,"Incomplete private layout")
 rows=sorted(value["fields"]+value["regions"],key=lambda row:row["offset"])
 need(len({row["name"] for row in rows})==len(rows),"Duplicate private field/region")
 for index,row in enumerate(rows):
  need(type(row["offset"]) is int and type(row["bytes"]) is int and row["offset"]>=0 and row["bytes"]>0
       and row["offset"]+row["bytes"]<=73728,"Private continuation extent escaped its allocation")
  if index:need(rows[index-1]["offset"]+rows[index-1]["bytes"]<=row["offset"],"Private continuation fields overlap")
 return rows
class Build(PlatformBuild):
 def __init__(self,output):
  need(__debug__,"PaidCPU builder refuses optimized Python")
  super().__init__(output)
  self.source_inputs=source_manifest()
  self.account_sources={name:(HERE/name).read_bytes() for name in
   ("owner.hepta","linux_owner_emitter.hepta","arithmetic_fixture.hepta","linux_arithmetic_emitter.hepta")}
  for name,raw in self.account_sources.items():
   need({"bytes":len(raw),"sha256":digest(raw)}==self.source_inputs["hia/platform/paid_cpu/"+name],
        "HIA source changed during capture")
  self.abi=read_json(HERE/"abi.json")
  self.layout=validate_layout(read_json(HERE/"private_layout.json"))
 def check_pin(self):
  super().check_pin()
  if hasattr(self,"source_inputs"):need(source_manifest()==self.source_inputs,"PaidCPU complete source closure changed")
 def shared_core(self):
  sys.path.insert(0,str(self.toolchain))
  from hepta.hia_agent_assembly import assemble_program
  programs={name:assemble_program(raw).as_dict() for name,raw in self.account_sources.items()}
  a={f["name"]:f for f in programs["owner.hepta"]["functions"]}
  b={f["name"]:f for f in programs["arithmetic_fixture.hepta"]["functions"]}
  names=sorted((a.keys()&b.keys())-{"f0"})
  need(names==self.abi["shared_budget_functions"],"Production/private arithmetic helper roster differs")
  values={}
  for name in names:
   need(a[name]==b[name],"Private arithmetic helper differs from actual production HIA: "+name)
   values[name]=digest(json.dumps(a[name],sort_keys=True,separators=(",",":")).encode())
  return values
 def build(self):
  shared=self.shared_core()
  images={};flats={}
  for label,policy_name,emitter_name in (
   ("owner","owner.hepta","linux_owner_emitter.hepta"),
   ("arithmetic","arithmetic_fixture.hepta","linux_arithmetic_emitter.hepta")):
   flat=self.stage(self.compiler,self.account_sources[policy_name],"compile-"+label)
   emitter=self.stage(self.compiler,self.account_sources[emitter_name],"compile-"+label+"-emitter")
   inspect_executable(emitter)
   image=self.stage(emitter,flat,"emit-"+label)
   elf=inspect_executable(image)
   need(image.endswith(flat) and 0<len(flat)<=1048576,"Emitted image does not contain the exact native HIA policy")
   prefix=len(image)-len(flat);adapter=image[176:prefix]
   contract=self.abi["images"][label]
   need(len(adapter)==contract["adapter_bytes"] and digest(adapter)==contract["adapter_sha256"],
        "Native adapter differs from the explicitly reviewed HIA emitter")
   need({"bytes":len(image),"sha256":digest(image)}==contract["executable"],
        "Pinned native compilation differs from the reviewed runtime image")
   for name,raw in ((label+".flat.bin",flat),(label+"-emitter.elf",emitter),(label+".elf",image)):
    (self.output/name).write_bytes(raw)
   images[label]={"path":label+".elf","bytes":len(image),"sha256":digest(image),**elf}
   flats[label]={"bytes":len(flat),"sha256":digest(flat)}
  self.check_pin()
  result={"schema":"trnm.hia.paid-cpu-build.v1","status":"PASS","source_inputs":self.source_inputs,
   "toolchain":self.lock,"compiler_sha256":digest(self.compiler),"compiler_qualification_binding":self.binding,
   "images":images,"native_policies":flats,"shared_budget_core":shared,"stages":self.stages,
   "runtime_host_language_or_dynamic_loader":False,"hosted_build_and_test_driver":True,
   "production_accepts_caller_clock_or_cpu":False,"whole_paid_account_or_node_closed":False}
  write_json(self.output/"build.json",result)
  return result
def main():
 need(__debug__,"PaidCPU builder refuses optimized Python")
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True)
 args=parser.parse_args();out=new_output(args.output);result=Build(out/"build").build()
 print(json.dumps({"status":result["status"],"images":result["images"],"report":str(out/"build/build.json")},sort_keys=True))
if __name__=="__main__":main()
