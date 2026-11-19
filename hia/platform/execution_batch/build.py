"""Compile each complete native M06 profile with the unchanged pinned compiler."""
from __future__ import annotations
import argparse,json,os,struct,sys,time,traceback
from pathlib import Path
from hia.platform.build import Build as PinnedBuild,inspect_executable
from .source_graph import REPOSITORY,PROFILES,IMAGE_ORDER,complete_sources,original_manifest,check_sources,identity,digest,need
class Build:
    def __init__(self,output,profile,repository=REPOSITORY):
        self.repository=Path(repository).absolute()
        need(self.repository==REPOSITORY and self.repository.resolve()==self.repository,'Import this exact source repository')
        need(profile in PROFILES,'Unknown complete execution profile');self.profile=profile
        self.output=Path(output).absolute()
        need(self.output.resolve()==self.output and not self.output.exists() and self.repository not in self.output.parents,'Fresh output outside the repository required')
        self.output.mkdir(mode=0o700)
        self.inputs,self.profiles=complete_sources(self.repository);self.sources=self.profiles[profile]
        self.original=original_manifest(self.repository);self.images={};self.pinned=None;self.report=None;self.executable=None
        for name,row in self.inputs.items():
            raw=(self.repository/name).read_bytes();need(identity(raw)==row,'Captured source changed')
            path=self.output/'source-snapshot'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    def build(self):
        failure=None;errors=[];start=time.monotonic_ns();core={};prefix=None
        try:
            self.pinned=PinnedBuild(self.output/'pinned-native');sys.path.insert(0,str(self.pinned.toolchain))
            from hepta.hia_agent_assembly import assemble_program
            for name in (*IMAGE_ORDER,'emitter'):
                raw=self.sources[name];checked=assemble_program(raw).as_dict()
                core[name]={'functions':len(checked['functions']),'blocks':sum(len(f['blocks']) for f in checked['functions']),'ops':sum(len(b['ops']) for f in checked['functions'] for b in f['blocks'])}
                (self.output/(name+'-composed.hepta')).write_bytes(raw)
                image=self.pinned.stage(self.pinned.compiler,raw,'compile-'+name);self.images[name]=image
                (self.output/(name+('.elf' if name=='emitter' else '.flat'))).write_bytes(image)
            prefix=self.pinned.stage(self.images['emitter'],struct.pack('<19Q',*(len(self.images[n]) for n in IMAGE_ORDER)),'emit-prefix')
            need(176<=len(prefix)<=8192,'Unexpected native prefix extent')
            self.executable=prefix+b''.join(self.images[n] for n in IMAGE_ORDER);inspect_executable(self.executable)
            (self.output/'elf-prefix.raw').write_bytes(prefix);(self.output/'owner.elf').write_bytes(self.executable)
        except BaseException as error:failure={'error':repr(error),'traceback':traceback.format_exc()}
        finally:
            for name,call in [('complete_sources',lambda:check_sources(self.inputs,self.original,self.repository)),('compiler',lambda:self.pinned.check_pin() if self.pinned is not None else None)]:
                try:call()
                except BaseException as error:errors.append({'stage':name,'error':repr(error)})
            self.report={'schema':'trnm.execution-batch-build.v1','status':'PASS' if failure is None and not errors else 'FAIL','profile':self.profile,
             'source_inputs':self.inputs,'source_set_sha256':digest(self.inputs),'original_sources':self.original,'original_source_set_sha256':digest(self.original),
             'composed_sources':{n:identity(raw) for n,raw in self.sources.items()},'core':core,'images':{n:identity(raw) for n,raw in self.images.items()},
             'elf_prefix':None if prefix is None else identity(prefix),'executable':None if self.executable is None else identity(self.executable),
             'compiler_sha256':None if self.pinned is None else identity(self.pinned.compiler)['sha256'],'toolchain':None if self.pinned is None else self.pinned.lock,
             'compiler_qualification_binding':None if self.pinned is None else self.pinned.binding,'stages':[] if self.pinned is None else self.pinned.stages,
             'failure':failure,'source_after':{'status':'PASS' if not errors else 'FAIL','errors':errors},'elapsed_ns':time.monotonic_ns()-start,
             'runtime_host_proxy':False,'original_rust_executed':False,'complete_node':False,'admission_persistence':False,
             'literal_isa_is_a_separate_trusted_boundary':True}
            (self.output/'build.json').write_text(json.dumps(self.report,sort_keys=True,indent=2)+'\n')
        need(self.report['status']=='PASS','Actual native build failed; complete raw stages retained')
        return self.report
def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',choices=PROFILES,required=True);a=p.parse_args()
    b=Build(a.output,a.profile);r=b.build();print(json.dumps({k:r[k] for k in ('status','profile','source_set_sha256','executable')}));return 0
if __name__=='__main__':raise SystemExit(main())
