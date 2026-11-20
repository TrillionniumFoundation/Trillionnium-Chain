"""Build the HIA default-genesis persistent owner without hosted runtime code."""
from __future__ import annotations
import argparse,hashlib,json,os,re,struct,sys
from pathlib import Path
from hia.platform.build import Build as PinnedBuild,inspect_executable,sha256,INPUTS as PINNED_INPUTS
from hia.tools.toolchain import compose_source
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
HIA=ROOT/"hia"
SKIP={"target",".git","__pycache__",".pytest_cache"}
def need(condition,message):
    if not condition:raise ValueError(message)
def identity(raw):
    return {"bytes":len(raw),"sha256":sha256(raw)}
def file_identity(path):
    digest=hashlib.sha256();size=0
    need(not path.is_symlink() and path.is_file(),"Nonregular source "+str(path))
    with path.open("rb") as stream:
        while block:=stream.read(1<<20):size+=len(block);digest.update(block)
    return {"bytes":size,"sha256":digest.hexdigest()}
def original_manifest(repository):
    result={}
    for directory in ("trillionnium","config","formal"):
        for path in sorted((repository/directory).rglob("*")):
            relative=path.relative_to(repository)
            if any(p in SKIP for p in relative.parts):continue
            need(not path.is_symlink(),"Original symlink "+str(relative))
            if path.is_file():result[relative.as_posix()]=file_identity(path)
    need("trillionnium/Cargo.lock" in result,"Original Cargo graph absent")
    return result
def unique_keys(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,"Duplicate JSON key")
        result[key]=value
    return result
def source_manifest(repository):
    result={}
    def capture(path):
        relative=path.relative_to(repository)
        for parent in (path,*path.parents):
            if parent==repository.parent:break
            need(not parent.is_symlink(),"Source ancestor symlink "+str(parent))
        need(path.is_file(),"Source absent "+str(relative))
        raw=path.read_bytes();entry=identity(raw)
        need(relative.as_posix() not in result or result[relative.as_posix()]==entry,"Source changed")
        result[relative.as_posix()]=entry
        return raw
    owned=repository/"hia/platform/genesis_store"
    for path in sorted(owned.iterdir()):
        need(not path.is_symlink(),"Owned symlink")
        if path.is_file() and path.suffix in {".py",".rs",".json",".hepta",".md"}:capture(path)
    for name in ("hia/platform/build.py","hia/tools/toolchain.py","hia/components.json",
                 "hia/tests/native_support.py","hia/toolchain.lock.json",
                 "hia/qualification/compiler-binding.json"):
        capture(repository/name)
    for name in PINNED_INPUTS:capture(repository/"hia"/name)
    configuration=json.loads((owned/"source-inputs.json").read_bytes(),object_pairs_hook=unique_keys)
    need(configuration["schema"]=="trnm.hia.genesis-default-inputs.v1","Configuration schema")
    for name in configuration["files"]:
        need(isinstance(name,str) and name.startswith("config/pon/") and ".." not in Path(name).parts,
             "Configuration escapes original")
        capture(repository/name)
    component=json.loads((repository/"hia/components.json").read_bytes(),object_pairs_hook=unique_keys)
    need(set(component)=={"schema","includes"} and component["schema"]=="trnm.hia.component-includes.v1"
        and isinstance(component["includes"],dict),"Canonical component manifest schema")
    def canonical(name):
        need(isinstance(name,str) and name.startswith(("src/","platform/","storage/"))
            and Path(name).as_posix()==name and not Path(name).is_absolute()
            and ".." not in Path(name).parts and name.endswith(".hepta"),"Noncanonical component path")
        path=repository/"hia"/name
        for parent in (path,*path.parents):
            if parent==repository:break
            need(not parent.is_symlink(),"Symlinked canonical dependency")
        need(path.is_file(),"Missing canonical dependency")
        return path
    for name in component["includes"]:canonical(name)
    available={}
    def visit(name,ancestry):
        need(name not in ancestry,"Cyclic component dependency")
        if name in available:return available[name]
        raw=capture(canonical(name))
        declarations=re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(",raw)
        bodies=re.findall(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)",raw)
        need(len(declarations)==len(set(declarations)) and set(declarations)==set(bodies)
            and len(bodies)==len(declarations),"Ambiguous component functions")
        own={n.decode() for n in declarations};all_names=set(own)
        rows=component["includes"].get(name,[])
        need(isinstance(rows,list),"Malformed include list")
        for row in rows:
            need(isinstance(row,dict) and set(row)=={"source","functions"}
                and isinstance(row["functions"],list) and bool(row["functions"]),"Malformed include row")
            dependency=visit(row["source"],(*ancestry,name))
            for selected in row["functions"]:
                need(isinstance(selected,str) and selected in dependency and selected not in all_names,
                    "Missing or duplicate canonical function")
                all_names.add(selected)
        available[name]=own
        return own
    for name in ("src/node/settings_development.hepta","src/protocol/state_root_compact.hepta"):visit(name,())
    return dict(sorted(result.items()))
class Build:
    def __init__(self,output:Path,repository:Path=ROOT):
        self.repository=repository.resolve(strict=True)
        need(self.repository==ROOT.resolve(),"Builder is from another repository")
        self.output=output;output.mkdir(mode=0o700)
        self.pinned=PinnedBuild(output/"pinned-native")
        self.manifest=source_manifest(self.repository)
        self.inputs={name:(self.repository/name).read_bytes() for name in self.manifest}
        self.original=original_manifest(self.repository)
        sys.path.insert(0,str(self.pinned.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        self.assemble=assemble_program
        self.sources={"policy":self.inputs["hia/platform/genesis_store/owner_policy.hepta"]}
        for name,relative in (("settings","src/node/settings_development.hepta"),("root","src/protocol/state_root_compact.hepta")):
            self.sources[name],_=compose_source(HIA/relative)
        self.sources["emitter"]=self.inputs["hia/platform/genesis_store/linux_emitter.hepta"]
        self.core={}
        for name,raw in self.sources.items():
            document=self.assemble(raw).as_dict()
            self.core[name]={"functions":len(document["functions"]),
              "blocks":sum(len(f["blocks"]) for f in document["functions"]),
              "ops":sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])}
            need(self.core[name]["functions"]<=128 and self.core[name]["ops"]<=8192,"Pinned native profile exceeded")
        snapshot=output/"source-snapshot"
        for name,raw in self.inputs.items():
            path=snapshot/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        self.check_sources()
    def check_sources(self):
        self.pinned.check_pin()
        need(source_manifest(self.repository)==self.manifest,"Complete source closure changed")
        for name,raw in self.inputs.items():
            need((self.repository/name).read_bytes()==raw,"Captured source changed: "+name)
        need(original_manifest(self.repository)==self.original,"Original source changed")
    def build(self):
        self.check_sources();images={}
        for name in ("policy","settings","root"):
            images[name]=self.pinned.stage(self.pinned.compiler,self.sources[name],"compile-"+name)
            need(0<len(images[name])<=1048576,"Native image exceeds unchanged compiler profile")
            (self.output/(name+".flat")).write_bytes(images[name])
            (self.output/(name+"-composed.hepta")).write_bytes(self.sources[name])
        writer=self.pinned.stage(self.pinned.compiler,self.sources["emitter"],"compile-emitter")
        inspect_executable(writer)
        prefix=self.pinned.stage(writer,struct.pack("<3Q",*(len(x) for x in images.values())),"emit-prefix")
        need(176<=len(prefix)<=4096,"Native ELF prefix has unexpected extent")
        executable=prefix+b"".join(images.values());profile=inspect_executable(executable)
        for name,raw in (("emitter.elf",writer),("elf-prefix.raw",prefix),("genesis-owner.elf",executable)):
            (self.output/name).write_bytes(raw)
        self.check_sources()
        report={"schema":"trnm.hia.default-genesis-store-build.v1","status":"PASS",
          "source_inputs":self.manifest,"original_sources":self.original,
          "source_set_sha256":sha256(json.dumps(self.manifest,sort_keys=True,separators=(",",":")).encode()),
          "core":self.core,"images":{k:identity(v) for k,v in images.items()},
          "emitter":identity(writer),"elf_prefix":identity(prefix),"executable":identity(executable)|profile,
          "compiler_sha256":sha256(self.pinned.compiler),"toolchain":self.pinned.lock,
          "compiler_qualification_binding":self.pinned.binding,"stages":self.pinned.stages,
          "source_inputs_stable":True,"runtime_host_proxy":False,"rust_or_interpreter_fallback":False,
          "hosted_link_action":"concatenate the native-emitted prefix and three exact native-compiled images",
          "literal_isa_is_a_separate_trusted_boundary":True,"complete_node":False,
          "successor_block_admission":False}
        (self.output/"build.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        return executable,report
def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise RuntimeError("Optimized Python is not admitted")
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    builder=Build(args.output);_,report=builder.build()
    print(json.dumps({"status":"PASS","source_set_sha256":report["source_set_sha256"],
      "core":report["core"],"executable":report["executable"]}))
if __name__=="__main__":main()
