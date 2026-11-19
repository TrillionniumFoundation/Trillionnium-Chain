"""Qualify actual private SQLite continuations; not a complete Task store."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.build import Build as PinnedBuild,INPUTS as PINNED_INPUTS
from hia.platform.task_kernel.build_boundary import SourceBuild
from hia.platform.task_kernel.build_provider import identity,need
HERE=Path(__file__).resolve().parent
DEPENDENCIES=[ROOT/p for p in [
    'hia/src/task_kernel/store_owner_common.hepta','hia/src/task_kernel/store_common.hepta',
    'hia/src/task_kernel/store_files.hepta','hia/src/task_kernel/store_path.hepta',
    'hia/src/task_kernel/typed_values.hepta','hia/src/task_kernel/codec.hepta',
    'hia/src/control_plane/core.hepta','hia/src/crypto/sha256_stream.hepta',
    'hia/src/codec/json_primitives.hepta']]

class StoreIoBuild(SourceBuild):
    def __init__(self,output,provider):
        super().__init__(output);self.provider=provider.resolve(strict=True)

    def run(self):
        self.report.update(schema='trnm.hia.task-kernel.store-io-build.v1',scope=__doc__)
        self.write()
        try:
            need(__debug__,'Optimized builder refused')
            self.stage('preflight',['bash','scripts/project-preflight.sh','--audit'])
            self.pinned=PinnedBuild(self.output/'pinned-native')
            sys.path.insert(0,str(self.pinned.toolchain))
            from hepta.hia_agent_assembly import assemble_program
            self.assemble=assemble_program
            for path in PINNED_INPUTS:self.capture(ROOT/'hia'/path)
            for path in [Path(__file__),HERE/'build_boundary.py',HERE/'build_provider.py',HERE/'provider_abi.json',HERE/'provider.c',
                         HERE/'store_open_includes.json',HERE/'qualification/store_io_hook.rs',
                         HERE/'qualification/store_io_original.rs',HERE/'qualification/store_io_observer.py',
                         HERE/'qualification/emit_observer.py',ROOT/'scripts/project-preflight.sh',
                         ROOT/'scripts/ci/project_boundary.py',ROOT/'hia/tools/toolchain.py']:
                self.capture(path)
            for name in ['store.rs','types.rs','codec.rs','error.rs']:self.capture(ROOT/'trillionnium/crates/trnm-task-kernel/src'/name)
            self.capture(self.provider/'build.json')
            provider=json.loads((self.provider/'build.json').read_text())
            need(provider['status']=='PASS' and provider['finalized'] and provider['source_before']==provider['source_after'],'Unqualified provider')
            need(provider['fence']==json.loads((HERE/'provider_abi.json').read_text())['build_fence'],'Provider ABI changed')
            for p,expected in provider['source_before'].items():
                self.capture(Path(p));need(identity(p)==expected,'Provider source changed')
            for name,expected in provider['artifacts'].items():
                self.capture(self.provider/name);need(identity(self.provider/name)==expected,'Provider artifact changed')
            self.capture(Path(provider['compiler']['path']));self.capture(self.pinned.compiler_path)
            self.report['function_sources']={}
            images=[('root',HERE/'qualification/store_io_fixture.hepta',0),
                    ('query',ROOT/'hia/src/task_kernel/store_query.hepta',1),
                    ('files',ROOT/'hia/src/task_kernel/store_files.hepta',2),
                    ('open',ROOT/'hia/src/task_kernel/store_open.hepta',3),
                    ('driver-emitter',HERE/'native_driver.hepta',None),
                    ('dispatch-emitter',HERE/'store_dispatch.hepta',None)]
            for name,source,index in images:
                deps=[] if index is None else [p for p in DEPENDENCIES if p!=source]
                raw,closure=self.compose(source,deps)
                if name=='open':
                    declaration=json.loads((HERE/'store_open_includes.json').read_text())
                    actual={n:str(Path(r['source']).relative_to(ROOT)) for n,r in closure.items() if Path(r['source'])!=source}
                    need(actual==declaration['functions'],'Open include closure changed')
                self.report['function_sources'][name]=closure
                (self.output/(name+'.hepta')).write_bytes(raw)
                native=self.pinned.stage(self.pinned.compiler,raw,'compile-'+name)
                need(native.startswith(b'\x7fELF\x02\x01'),'Expected actual ELF64LE')
                (self.output/(name+'.o')).write_bytes(native)
                if index is None:
                    self.stage('link-'+name,['ld','-shared','-z','defs','-z','noexecstack','--build-id=none',self.output/(name+'.o'),'-lc','-o',self.output/(name+'.so')])
                else:
                    self.stage('rename-'+name,['objcopy','--redefine-sym','f0=trnm_task_step_'+str(index),self.output/(name+'.o'),self.output/(name+'-named.o')])
                self.fence()
            for name,tag in [('driver','TKDRV001'),('dispatch','TKDSP001')]:
                self.stage('emit-'+name,[sys.executable,HERE/'qualification/emit_observer.py',self.output,name,tag])
                self.stage('inspect-'+name,['objdump','-dr',self.output/(name+'.o')])
            shutil.copyfile(self.provider/'provider.so',self.output/'provider.so')
            self.stage('link-native',[provider['compiler']['path'],'-shared','-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections',
                       self.output/'driver.o',self.output/'dispatch.o',*[self.output/(name+'-named.o') for name in ['root','query','files','open']],
                       '-L'+str(self.output),'-Wl,-rpath,$ORIGIN','-l:provider.so','-lm','-ldl','-lpthread','-o',self.output/'store-io-native.so'])
            (self.output/'native-compiler').write_bytes(self.pinned.compiler)
            self.fence()
            self.report.update(status='PASS',finalized=True,source_before=self.sources,
                               source_after={p:identity(p) for p in self.sources},native_stages=self.pinned.stages,
                               artifacts={p.name:identity(p) for p in self.output.iterdir() if p.is_file() and (p.suffix in {'.o','.so','.hepta'} or p.name=='native-compiler')},
                               provider_build=str(self.provider/'build.json'),full_task_kernel_owner_qualified=False)
            self.write();return self.report
        except BaseException as e:
            self.report.update(status='FAIL',finalized=False,failure=repr(e),source_before=self.sources)
            if hasattr(self,'pinned'):self.report['native_stages']=self.pinned.stages
            self.write();raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--provider',type=Path,required=True)
    args=parser.parse_args();result=StoreIoBuild(args.output,args.provider).run()
    print(json.dumps({'status':result['status'],'images':len(result['function_sources']),'report':str(args.output/'build.json')}))
