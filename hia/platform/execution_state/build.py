"""Source-bound native State/View/Patch builder. Runtime is three HIA images."""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, struct, sys
from pathlib import Path
from hia.platform.build import Build as PinnedBuild, inspect_executable, INPUTS as PINNED_INPUTS

HERE=Path(__file__).resolve().parent
HIA=HERE.parents[1]
REPOSITORY=HIA.parent
PREFIX='hia/platform/execution_state/'
EXPLICIT=('hia/platform/build.py','hia/tools/toolchain.py','hia/components.json','hia/toolchain.lock.json',
 'hia/qualification/compiler-binding.json','hia/qualification/compiler-cold.json','hia/qualification/compiler-cold-full.json.xz')
ROOT_SOURCE='src/protocol/state_root_compact.hepta'


def identity(raw:bytes)->dict:
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def digest(rows:dict)->str:
    return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError('Duplicate JSON key: '+key)
        out[key]=value
    return out


def regular(repository:Path,name:str)->Path:
    if not isinstance(name,str) or '\\' in name or '\x00' in name:raise ValueError('Noncanonical source path')
    rel=Path(name)
    if rel.is_absolute() or rel.as_posix()!=name or any(x in ('','.','..') for x in rel.parts):raise ValueError('Noncanonical source path')
    path=repository
    for part in rel.parts:
        path=path/part
        if path.is_symlink():raise ValueError('Symlinked source: '+name)
    if not stat.S_ISREG(path.stat().st_mode):raise ValueError('Nonregular source: '+name)
    return path


def owned_paths(repository:Path=REPOSITORY)->list[str]:
    root=regular(repository,PREFIX+'build.py').parent
    out=[]
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise ValueError('Symlinked owned source')
        if path.is_dir():
            if path.name=='__pycache__':raise ValueError('Bytecode cache is not admitted')
            continue
        if path.suffix not in {'.py','.rs','.hepta','.json','.md'}:raise ValueError('Unexpected owned artifact: '+str(path))
        name=path.relative_to(repository).as_posix();regular(repository,name);out.append(name)
    return out


def declarations(raw:bytes)->dict[str,bytes]:
    names=re.findall(rb'(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(',raw)
    blocks=list(re.finditer(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)',raw))
    out={m.group(1).decode():m.group(0) for m in blocks}
    if len(names)!=len(set(names)) or len(blocks)!=len(out) or set(out)!={n.decode() for n in names}:raise ValueError('Ambiguous HIA declarations')
    return out


def compose(repository:Path=REPOSITORY)->tuple[dict[str,bytes],dict[str,dict]]:
    from hepta.hia_agent_assembly import assemble_program
    from hia.tools.toolchain import compose_source
    if repository.resolve()!=REPOSITORY.resolve():raise ValueError('Builder must import from its exact repository')
    captured={}
    def capture(name):
        raw=regular(repository,name).read_bytes();row=identity(raw)
        if name in captured and captured[name]!=row:raise ValueError('Source changed while composing')
        captured[name]=row;return raw
    for name in owned_paths(repository)+list(EXPLICIT)+["hia/"+name for name in PINNED_INPUTS]:capture(name)
    includes=json.loads(capture(PREFIX+'includes.json'),object_pairs_hook=unique)
    if set(includes)!={'schema','includes'} or includes['schema']!='trnm.hia.execution-state-includes.v1':raise ValueError('Unsupported include declaration')
    expected={p[4:] for p in owned_paths(repository) if p.endswith('.hepta')}
    if set(includes['includes'])!=expected:raise ValueError('Owned HIA include inventory differs')
    admitted={}
    def component(name,parents=()):
        if name in parents:raise ValueError('Cyclic includes')
        if name in admitted:return admitted[name]
        if not name.startswith(('src/','platform/','storage/')) or not name.endswith('.hepta'):raise ValueError('Noncanonical HIA include')
        raw=capture('hia/'+name);own=declarations(raw)
        if name not in includes['includes']:
            combined,inputs=compose_source(regular(repository,'hia/'+name))
            for path,data in inputs:
                relative=path.relative_to(repository).as_posix()
                if capture(relative)!=data:raise ValueError('Canonical source changed')
            assemble_program(combined)
        else:
            rows=includes['includes'][name]
            if not isinstance(rows,list):raise ValueError('Include rows must be a list')
            names=set(own);pieces=[raw.rstrip()+b'\n']
            for row in rows:
                if not isinstance(row,dict) or set(row)!={'source','functions'} or not isinstance(row['functions'],list) or not row['functions']:raise ValueError('Malformed include')
                dep,available=component(row['source'],(*parents,name))
                for function in row['functions']:
                    if not isinstance(function,str) or function not in available or function in names:raise ValueError('Unknown or duplicate HIA function')
                    names.add(function);pieces.append(available[function].rstrip()+b'\n')
            combined=b''.join(pieces);assemble_program(combined)
        admitted[name]=(combined,own);return admitted[name]
    sources={name:component('platform/execution_state/'+name+'.hepta')[0] for name in ('owner','linux_emitter')}
    sources['root']=component(ROOT_SOURCE)[0]
    return sources,dict(sorted(captured.items()))


def original_manifest(repository:Path=REPOSITORY)->dict:
    from .rust_oracle import original_manifest as capture_original
    return capture_original(repository)


def check_sources(source_inputs:dict,original_sources:dict)->None:
    _,current=compose()
    if current!=source_inputs or original_manifest()!=original_sources:raise ValueError('Source fence changed')


class Build:
    def __init__(self,output:Path):
        self.output=output.absolute()
        if self.output.resolve()==REPOSITORY or REPOSITORY in self.output.resolve().parents:raise ValueError('Build output must be outside repository')
        self.output.mkdir(mode=0o700)
        sys.path.insert(0,os.environ['HIA_TOOLCHAIN_ROOT'])
        self.sources,self.inputs=compose();self.original=original_manifest();self.pinned=PinnedBuild(self.output/'pinned-native');self.images={}
    def build(self)->dict:
        failure=None
        try:
            for name in ('owner','root','linux_emitter'):
                source=self.sources[name];(self.output/(name+'.hepta')).write_bytes(source)
                self.images[name]=self.pinned.stage(self.pinned.compiler,source,'compile-'+name)
                (self.output/(name+('.elf' if name=='linux_emitter' else '.flat'))).write_bytes(self.images[name])
            joined=struct.pack('<QQ',len(self.images['owner']),len(self.images['root']))+self.images['owner']+self.images['root']
            self.executable=self.pinned.stage(self.images['linux_emitter'],joined,'emit-owner')
            profile=inspect_executable(self.executable)
            if not self.executable.endswith(self.images['owner']+self.images['root']):raise ValueError('Final ELF does not bind both exact images')
            (self.output/'owner.elf').write_bytes(self.executable)
        except BaseException as error:
            failure=repr(error)
            raise
        finally:
            source_errors=[]
            for label,check in (('compiler',self.pinned.check_pin),('sources',lambda:check_sources(self.inputs,self.original))):
                try:check()
                except BaseException as error:source_errors.append({'stage':label,'error':repr(error)})
            self.report={'schema':'trnm.execution-state-build.v1','status':'PASS' if failure is None and not source_errors else 'FAIL','source_inputs':self.inputs,'source_set_sha256':digest(self.inputs),'original_sources':self.original,'original_source_set_sha256':digest(self.original),'toolchain':self.pinned.lock,'compiler_sha256':hashlib.sha256(self.pinned.compiler).hexdigest(),'compiler_qualification_binding':self.pinned.binding,'stages':self.pinned.stages,'images':{n:identity(raw) for n,raw in self.images.items()},'executable':None if not hasattr(self,'executable') else identity(self.executable),'failure':failure,'source_after':{'status':'PASS' if not source_errors else 'FAIL','errors':source_errors},'runtime_host_proxy':False,'original_rust_executed':False}
            (self.output/'build.json').write_text(json.dumps(self.report,sort_keys=True,indent=2)+'\n')
        if self.report['status']!='PASS':raise RuntimeError('Native build source fence failed; report preserved')
        return self.report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();b=Build(args.output);report=b.build();print(json.dumps({key:report[key] for key in ('status','source_set_sha256','executable')},sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
