"""Compile the checked HIA owner and its literal-ISA Linux boundary."""
from __future__ import annotations
import argparse,os,struct,sys,traceback
from pathlib import Path
from hia.platform.build import Build as PinnedBuild,inspect_executable
from .contract import (ROOT,OWNED,COMPILER_SHA,TOOLCHAIN_REVISION,need,identity,file_bytes,
    source_manifest,original_manifest,manifest_sha,write_json,fresh_output,preflight)

class Build:
    def __init__(self,output,repository=ROOT):
        self.repository=Path(repository).resolve(strict=True)
        need(self.repository==ROOT.resolve(),"Builder belongs to a different repository")
        self.output=Path(output);self.output.mkdir(mode=0o700)
        self.manifest=source_manifest(self.repository);self.original=original_manifest(self.repository)
        self.inputs={name:file_bytes(self.repository/name) for name in self.manifest}
        self.pinned=PinnedBuild(self.output/"pinned-native")
        need(identity(self.pinned.compiler)["sha256"]==COMPILER_SHA,"Compiler mismatch")
        need(self.pinned.lock["revision"]==TOOLCHAIN_REVISION,"Toolchain mismatch")
        self.core={}
        sys.path.insert(0,str(self.pinned.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        for label,name in (("owner","typed_fixture.hepta"),("emitter","linux_emitter.hepta")):
            raw=self.inputs[OWNED+"/"+name]
            document=assemble_program(raw).as_dict()
            counts={"functions":len(document["functions"]),
                    "blocks":sum(len(f["blocks"]) for f in document["functions"]),
                    "ops":sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])}
            need(document["functions"][0]["name"]=="f0","Entry function differs")
            need(counts["functions"]<=128 and counts["blocks"]<=1536 and counts["ops"]<=8192,
                 "Pinned native compiler profile exceeded")
            self.core[label]=counts
        snapshot=self.output/"source-snapshot"
        for name,raw in self.inputs.items():
            target=snapshot/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        self.check_sources()

    def check_sources(self):
        self.pinned.check_pin()
        need(source_manifest(self.repository)==self.manifest,"Complete native source closure changed")
        need(original_manifest(self.repository)==self.original,"Original mempool source closure changed")
        for name,raw in self.inputs.items():need(file_bytes(self.repository/name)==raw,"Captured source changed")

    def build(self):
        report={"schema":"trnm.hia.mempool-typed-build.v1","status":"FAIL",
            "source_inputs":self.manifest,"original_sources":self.original,
            "source_set_sha256":manifest_sha(self.manifest),"core":self.core,
            "compiler_sha256":COMPILER_SHA,"toolchain":self.pinned.lock,
            "compiler_qualification_binding":self.pinned.binding,
            "native_test_trait_adapter_only":True,"node_or_persistent_pool_authority":False,
            "runtime_host_proxy":False,"rust_or_interpreter_fallback":False,
            "literal_isa_is_a_separate_trusted_boundary":True}
        try:
            self.check_sources()
            owner=self.pinned.stage(self.pinned.compiler,self.inputs[OWNED+"/typed_fixture.hepta"],"compile-typed")
            need(0<len(owner)<=1048576 and not owner.startswith(b"\x7fELF"),"Unexpected flat native image")
            emitter=self.pinned.stage(self.pinned.compiler,self.inputs[OWNED+"/linux_emitter.hepta"],"compile-emitter")
            inspect_executable(emitter)
            executable=self.pinned.stage(emitter,struct.pack("<Q",len(owner))+owner,"emit-owner")
            profile=inspect_executable(executable)
            need(executable.endswith(owner) and len(executable)-len(owner)==1992,"Wrong native owner extent")
            for name,raw in (("owner.flat",owner),("emitter.elf",emitter),("typed-owner.elf",executable)):
                path=self.output/name;path.write_bytes(raw)
                if name.endswith(".elf"):path.chmod(0o500)
            self.check_sources()
            report.update(status="PASS",image=identity(owner),emitter=identity(emitter),
                executable=identity(executable)|profile,native_runtime_executed=False)
            return executable,report
        except BaseException as error:
            report["failure"]={"error":repr(error),"traceback":traceback.format_exc()};raise
        finally:
            failure=None
            report["stages"]=self.pinned.stages
            try:self.check_sources();report["source_after"]="MATCH"
            except BaseException as error:report["source_after"]="FAIL";report["status"]="FAIL";report["source_failure"]=repr(error);failure=error
            write_json(self.output/"build.json",report)
            if failure is not None:raise failure

def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--audit",action="store_true",help="Use the existing read-only project audit boundary for a detached CI checkout")
    args=parser.parse_args();out=fresh_output(args.output);preflight(ROOT,out,audit=args.audit)
    _,report=Build(out/"build").build()
    print(__import__("json").dumps({k:report[k] for k in ("status","source_set_sha256","core","executable")}))

if __name__=="__main__":main()
