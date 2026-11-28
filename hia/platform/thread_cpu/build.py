"""Build the finite native ThreadCpuStamp and actual thread-lifetime owner."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.build import Build as PinnedBuild
from hia.platform.build import inspect_executable,new_output,sha256,write_json

HERE=Path(__file__).resolve().parent
PREFIX='hia/platform/thread_cpu/'
OWNED=('README.md','abi.json','owner_policy.hepta','fixture_entry.hepta',
       'linux_emitter.hepta','build.py','native_io.py','trace_audit.py','cases.py',
       'qualify.py','rust_reference.rs','rust_oracle.py','test_integrity.py')
ORIGINAL_PREFIX='trillionnium/crates/trnm-pon-node/src/ingress/'
INPUTS=tuple(PREFIX+name for name in OWNED)+(
    'hia/platform/transport_request/rust_oracle.py','hia/tools/toolchain.py',
    ORIGINAL_PREFIX+'public_v3/request_observation.rs',
    ORIGINAL_PREFIX+'public_v3/scalar_cpu.rs',
    ORIGINAL_PREFIX+'public_v3.rs',
    ORIGINAL_PREFIX+'public_v3/scalar_cpu_tests.rs',
    ORIGINAL_PREFIX+'public_v3/scalar_cpu_completion_tests.rs',
    ORIGINAL_PREFIX+'public_v3/scalar_cpu_flow_tests.rs',
    ORIGINAL_PREFIX+'public_v3/scalar_cpu_history_handoff_tests.rs',
    ORIGINAL_PREFIX+'public_v3/scalar_cpu_native_completion_tests.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs',
    'trillionnium/Cargo.toml','trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-pon-node/Cargo.toml',
)
ORIGINAL_SOURCE=ORIGINAL_PREFIX+'public_v3/request_observation.rs'
ORIGINAL_SHA256='9d4f8c71a87e2e1214789e0e096ded2c3497f93fb61e3239099e8753a639015b'
ADAPTER_BYTES=1900
ADAPTER_SHA256='c7dcfa89e31f0570f032f6683b3eb6c13de02e67cc5718c0572273bb34800878'


def source_manifest() -> dict:
    if not __debug__:
        raise RuntimeError('Thread CPU source binding refuses optimized Python')
    if len(INPUTS)!=len(set(INPUTS)):
        raise ValueError('Duplicate Thread CPU source binding')
    result={}
    for relative in INPUTS:
        path=ROOT/relative
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True)!=path:
            raise ValueError('Noncanonical or missing Thread CPU source: '+relative)
        raw=path.read_bytes()
        result[relative]={'bytes':len(raw),'sha256':sha256(raw)}
    if result[ORIGINAL_SOURCE]['sha256']!=ORIGINAL_SHA256:
        raise ValueError('Complete original ThreadCpuStamp source differs')
    return result


def compose(production:bytes,fixture_entry:bytes) -> tuple[bytes,dict]:
    matches=list(re.finditer(rb'^fn ([A-Za-z_][A-Za-z_0-9]*)\(',production,re.MULTILINE))
    entries=list(re.finditer(rb'^fn ([A-Za-z_][A-Za-z_0-9]*)\(',fixture_entry,re.MULTILINE))
    if (len(matches)!=15 or matches[0].group(1)!=b'f0'
            or matches[1].group(1)!=b'cpu_entry'
            or any(not m.group(1).startswith(b'cpu_') for m in matches[1:])
            or len(entries)!=1 or entries[0].group(1)!=b'f0'
            or not production.endswith(b'\n') or not fixture_entry.endswith(b'\n')):
        raise ValueError('Thread CPU owned-function composition differs')
    helpers=production[matches[1].start():]
    fixture=fixture_entry+helpers
    return fixture,{'production_source_sha256':sha256(production),
            'fixture_source_sha256':sha256(fixture),'helpers_sha256':sha256(helpers),
            'helpers_bytes':len(helpers),'fixture_reuses_all_production_helpers':True,
            'fixture_changes_only_literal_entry_flag':True}


class Build(PinnedBuild):
    def __init__(self,output:Path):
        if not __debug__:
            raise RuntimeError('Thread CPU build refuses optimized Python')
        super().__init__(output)
        self.thread_manifest=source_manifest()
        self.check_pin()

    @property
    def source_inputs(self):
        return {**{'hia/'+k:v for k,v in self.manifest.items()},**self.thread_manifest}

    def check_pin(self):
        super().check_pin()
        if hasattr(self,'thread_manifest') and source_manifest()!=self.thread_manifest:
            raise ValueError('Thread CPU native or complete comparison source changed')

    def core_check(self,raw):
        sys.path.insert(0,str(self.toolchain))
        from hepta import hia_agent_assembly
        if self.toolchain not in Path(hia_agent_assembly.__file__).resolve().parents:
            raise ValueError('Thread CPU Core must be the pinned toolchain')
        checked=hia_agent_assembly.assemble_program(raw)
        return {'status':'CORE_ACCEPTED','sha256':sha256(raw),
                'functions':len(checked.as_dict()['functions']),
                'literal_isa_effects_proven':False}

    def pack(self,policy,label):
        if not 0<len(policy)<=524288:
            raise ValueError('Thread CPU native policy exceeds the finite profile')
        image=self.stage(self.emitter,policy,label)
        profile=inspect_executable(image)
        if (not image.endswith(policy) or len(image)-len(policy)!=176+ADAPTER_BYTES
                or sha256(image[176:176+ADAPTER_BYTES])!=ADAPTER_SHA256):
            raise ValueError('Native thread adapter differs from the reviewed instruction bytes')
        return image,{'bytes':len(image),'sha256':sha256(image),
                'adapter_prefix_bytes':176+ADAPTER_BYTES,**profile}

    def build(self):
        self.check_pin()
        production=(HERE/'owner_policy.hepta').read_bytes()
        entry=(HERE/'fixture_entry.hepta').read_bytes()
        emitter=(HERE/'linux_emitter.hepta').read_bytes()
        fixture,composition=compose(production,entry)
        core={'production':self.core_check(production),'fixture':self.core_check(fixture),
              'emitter':self.core_check(emitter)}
        policy=self.stage(self.compiler,production,'compile-thread-cpu-owner')
        private_policy=self.stage(self.compiler,fixture,'compile-thread-cpu-fixture')
        self.emitter=self.stage(self.compiler,emitter,'compile-thread-cpu-emitter')
        emitter_profile=inspect_executable(self.emitter)
        self.executable,executable_profile=self.pack(policy,'emit-thread-cpu-owner')
        self.fixture_executable,fixture_profile=self.pack(private_policy,'emit-thread-cpu-fixture')
        if self.executable==self.fixture_executable:
            raise ValueError('Fixture and production native entries must be distinct')
        for name,data in [('owner.elf',self.executable),('fixture.elf',self.fixture_executable),
                ('emitter.elf',self.emitter),('policy.flat.bin',policy),
                ('fixture-policy.flat.bin',private_policy),('fixture-composed.hepta',fixture)]:
            (self.output/name).write_bytes(data)
        self.check_pin()
        result={'schema':'trnm.hia.thread-cpu-build.v1','status':'PASS',
            'source_inputs':self.source_inputs,'toolchain':self.lock,
            'compiler_sha256':sha256(self.compiler),
            'compiler_qualification_binding':self.binding,'core_checks':core,
            'stages':self.stages,'composition':composition,
            'executable':executable_profile,'fixture_executable':fixture_profile,
            'emitter':{'sha256':sha256(self.emitter),**emitter_profile},
            'flat_policy':{'bytes':len(policy),'sha256':sha256(policy)},
            'flat_fixture_policy':{'bytes':len(private_policy),'sha256':sha256(private_policy)},
            'adapter':{'bytes':ADAPTER_BYTES,'sha256':ADAPTER_SHA256},
            'runtime_host_language_or_dynamic_loader':False,
            'runtime_host_supplied_clock_identity_or_verdict':False,
            'real_thread_lifecycle_qualified_by_build_only':False,
            'paid_cpu_account_or_scoped_executor_implemented':False,
            'node_worker_embedding_or_original_service_budget_qualified':False}
        write_json(self.output/'build.json',result)
        return result


def main():
    if not __debug__:
        raise RuntimeError('Thread CPU build refuses optimized Python')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    output=new_output(args.output)
    result=Build(output/'build').build()
    print(json.dumps({'status':result['status'],'executable':result['executable'],
                      'report':str(output/'build/build.json')},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
