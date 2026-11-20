"""Qualify actual private store roots and schema/metadata audits; not a complete Task store."""
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
    'hia/src/codec/json_primitives.hepta','hia/src/task_kernel/kernel_policy.hepta',
    'hia/src/task_kernel/agent_transaction_wire.hepta','hia/src/crypto/ed25519_group.hepta',
    'hia/src/crypto/ed25519_verify_joint.hepta','hia/src/crypto/sha512_arena.hepta']]

class StoreAuditBuild(SourceBuild):
    scope=__doc__
    builder_name='build_store_audit.py'
    qualification_prefix='store_audit'
    dispatch_name='audit_dispatch.hepta'
    library_name='store-audit-native.so'
    additional_units=()
    image_dependencies={}
    root_source=None
    extra_emitters=()
    extra_sources=()
    export_map=None
    export_inventory=None
    def __init__(self,output,provider):
        super().__init__(output);self.provider=provider.resolve(strict=True)

    def run(self):
        self.report.update(schema='trnm.hia.task-kernel.store-audit-build.v1',scope=self.scope)
        self.write()
        try:
            need(__debug__,'Optimized builder refused')
            self.stage('preflight',['bash','scripts/project-preflight.sh','--audit'])
            self.pinned=PinnedBuild(self.output/'pinned-native')
            sys.path.insert(0,str(self.pinned.toolchain))
            from hepta.hia_agent_assembly import assemble_program
            self.assemble=assemble_program
            for path in PINNED_INPUTS:self.capture(ROOT/'hia'/path)
            for path in [Path(__file__),HERE/self.builder_name,HERE/'build_boundary.py',HERE/'build_provider.py',HERE/'provider_abi.json',HERE/'provider_native.hepta',
                         HERE/'build_witness.py',HERE/'witness_emitter.hepta',HERE/'readback_provider.py',
                         HERE/'qualification/borsh_fixture.py',HERE/'qualification/type_layout.json',HERE/('qualification/'+self.qualification_prefix+'_hook.rs'),
                         HERE/('qualification/'+self.qualification_prefix+'_original.rs'),HERE/('qualification/'+self.qualification_prefix+'_observer.py'),
                         HERE/'qualification/emit_observer.py',ROOT/'scripts/project-preflight.sh',
                         ROOT/'scripts/ci/project_boundary.py',ROOT/'hia/tools/toolchain.py']:
                self.capture(path)
            for name in ['store.rs','types.rs','codec.rs','error.rs']:self.capture(ROOT/'trillionnium/crates/trnm-task-kernel/src'/name)
            for path in self.extra_sources:self.capture(path)
            if self.export_map is not None:self.capture(self.export_map)
            if self.export_inventory is not None:self.capture(self.export_inventory)
            self.capture(self.provider/'build.json')
            provider=json.loads((self.provider/'build.json').read_text())
            need(provider['status']=='PASS' and provider['finalized'] and provider['source_before']==provider['source_after'],'Unqualified provider')
            need(provider['fence']==json.loads((HERE/'provider_abi.json').read_text())['build_fence'],'Provider ABI changed')
            for p,expected in provider['source_before'].items():
                self.capture(Path(p));need(identity(p)==expected,'Provider source changed')
            for name,expected in provider['artifacts'].items():
                self.capture(self.provider/name);need(identity(self.provider/name)==expected,'Provider artifact changed')
            self.verify_provider(self.provider)
            self.capture(Path(provider['compiler']['path']));self.capture(self.pinned.compiler_path)
            self.report['function_sources']={}
            images=[('root',self.root_source or HERE/('qualification/'+self.qualification_prefix+'_fixture.hepta'),0),
                    ('query',ROOT/'hia/src/task_kernel/store_query.hepta',1),
                    ('files',ROOT/'hia/src/task_kernel/store_files.hepta',2),
                    ('open',ROOT/'hia/src/task_kernel/store_open.hepta',3),
                    ('roots',ROOT/'hia/src/task_kernel/store_roots.hepta',4),
                    ('schema',ROOT/'hia/src/task_kernel/store_schema.hepta',5),
                    ('objects',ROOT/'hia/src/task_kernel/store_objects.hepta',6),
                    ('operations',ROOT/'hia/src/task_kernel/store_operations.hepta',7),
                    ('markers',ROOT/'hia/src/task_kernel/store_markers.hepta',8),
                    ('blocks',ROOT/'hia/src/task_kernel/store_blocks.hepta',9),
                    *[(name,ROOT/('hia/src/task_kernel/store_'+name+'.hepta'),index) for name,index in self.additional_units],
                    ('driver-emitter',HERE/'native_driver.hepta',None),
                    ('dispatch-emitter',HERE/self.dispatch_name,None),
                    *[(name+'-emitter',source,None) for name,source,tag in self.extra_emitters]]
            for name,source,index in images:
                deps=[] if index is None else [p for p in [*DEPENDENCIES,*self.image_dependencies.get(name,())] if p!=source]
                raw,closure=self.compose(source,deps)
                if index is not None and index>=3:
                    declaration_path=HERE/('store_'+name+'_includes.json');self.capture(declaration_path)
                    declaration=json.loads(declaration_path.read_text())
                    actual={n:str(Path(r['source']).relative_to(ROOT)) for n,r in closure.items() if Path(r['source'])!=source}
                    need(actual==declaration['functions'],'Open include closure changed')
                if index==0 and self.root_source is not None:
                    declaration_path=HERE/'store_public_includes.json';self.capture(declaration_path)
                    declaration=json.loads(declaration_path.read_text())
                    actual={n:str(Path(r['source']).relative_to(ROOT)) for n,r in closure.items() if Path(r['source'])!=source}
                    need(actual==declaration['functions'],'Public include closure changed')
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
            for name,tag in [('driver','TKDRV001'),('dispatch','TKDSP001'),*[(name,tag) for name,source,tag in self.extra_emitters]]:
                self.stage('emit-'+name,[sys.executable,HERE/'qualification/emit_observer.py',self.output,name,tag])
                self.stage('inspect-'+name,['objdump','-dr',self.output/(name+'.o')])
            shutil.copyfile(self.provider/'provider.so',self.output/'provider.so')
            self.stage('link-native',[provider['compiler']['path'],'-shared','-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections',
                       self.output/'driver.o',self.output/'dispatch.o',*[self.output/(name+'-named.o') for name,_,index in images if index is not None],
                       *[self.output/(name+'.o') for name,source,tag in self.extra_emitters],
                       *([] if self.export_map is None else ['-Wl,--version-script='+str(self.export_map)]),
                       '-L'+str(self.output),'-Wl,-rpath,$ORIGIN','-l:provider.so','-lm','-ldl','-lpthread','-o',self.output/self.library_name])
            if self.export_inventory is not None:
                symbols=self.stage('inspect-public-symbols',['nm','-D','--defined-only',self.output/self.library_name]).decode().splitlines()
                actual={row.split()[-1] for row in symbols if row.strip()}
                expected=set(json.loads(self.export_inventory.read_text())['exports'])
                need(actual==expected,'Public symbol inventory differs or private mint/invoke escaped')
                self.report['public_symbols']=sorted(actual)
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
    args=parser.parse_args();result=StoreAuditBuild(args.output,args.provider).run()
    print(json.dumps({'status':result['status'],'images':len(result['function_sources']),'report':str(args.output/'build.json')}))
