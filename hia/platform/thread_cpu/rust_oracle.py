"""Execute the complete original Rust stamp methods against actual HIA histories.

No original production source is edited in the repository. A private cfg(test)
child is appended only to an isolated original source copy. Controlled ptrace
timespec/error fixtures are distinct from mandatory real Linux-clock positives.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tomllib

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.build import source_manifest as platform_source_manifest
from hia.platform.transport_request.rust_oracle import command
from .build import source_manifest,ADAPTER_BYTES,ADAPTER_SHA256
from .cases import corpus
from .native_io import frame,FIELDS,need
from .qualify import qualify,corpus_bytes,comparison_from_receipts
from .trace_audit import audit_trace,clock_value,validate_injections

HERE=Path(__file__).resolve().parent
ORIGINAL='trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs'
ORIGINAL_SHA256='9d4f8c71a87e2e1214789e0e096ded2c3497f93fb61e3239099e8753a639015b'
HOOK='hia_thread_cpu_oracle.rs'
DECLARATION=(b'\n#[cfg(test)]\nmod hia_thread_cpu_oracle {\n'
             b'    include!("hia_thread_cpu_oracle.rs");\n}\n')
TEST='ingress::public_v3::request_observation::hia_thread_cpu_oracle::evaluate'
AVAILABLE='ingress::public_v3::request_observation::hia_thread_cpu_oracle::linux_clock_is_mandatory'
REQUIRED='ingress::public_v3::request_observation::tests::cpu_clock_intervals_stay_on_the_execution_thread_and_are_nested'
MARKER='HIA_THREAD_CPU_ORACLE:'
SKIP={'target','__pycache__','.pytest_cache'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: '+key)
        result[key]=value
    return result


def parse_json(raw):
    return json.loads(raw,object_pairs_hook=unique_object)


def write_json(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def identity(path):
    need(path.is_file() and not path.is_symlink() and path.resolve(strict=True)==path,
         'Missing or noncanonical source/evidence: '+str(path))
    hasher=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while data:=stream.read(1<<20):
            size+=len(data);hasher.update(data)
    return {'bytes':size,'sha256':hasher.hexdigest()}


def complete_source_manifest():
    need(__debug__,'Thread CPU source validation refuses optimized Python')
    return {**{'hia/'+key:value for key,value in platform_source_manifest().items()},
            **source_manifest()}


def validate_source_bindings(native):
    need(type(native) is dict and type(native.get('build')) is dict,'Missing complete native build binding')
    current=complete_source_manifest()
    top=native.get('source_inputs');built=native['build'].get('source_inputs')
    need(type(top) is dict and type(built) is dict and top==built==current,
         'Native top-level/build/current complete source sets differ')
    return current


def locked_clock_dependency(isolated,events):
    """Verify the actual compiled rustix source before/after original execution."""
    contract=parse_json((HERE/'abi.json').read_bytes())['clock_backend_compatibility']
    need(contract['original_package']=='rustix' and contract['target_backend']=='linux_raw'
         and contract['target_width_bits']==64 and contract['required_feature']=='time',
         'Unsupported original clock dependency target profile')
    lock=isolated/'trillionnium/Cargo.lock'
    packages=tomllib.loads(lock.read_text())['package']
    selected=[row for row in packages if row['name']=='rustix' and row['version']==contract['version']]
    need(len(selected)==1 and selected[0].get('source')=='registry+https://github.com/rust-lang/crates.io-index'
         and selected[0].get('checksum')==contract['locked_crate_sha256'],
         'Original locked rustix package or checksum differs')
    package='registry+https://github.com/rust-lang/crates.io-index#rustix@'+contract['version']
    artifacts=[event for event in events if event.get('reason')=='compiler-artifact'
               and event.get('package_id')==package and event.get('target',{}).get('name')=='rustix'
               and event['target'].get('kind')==['lib']]
    scripts=[event for event in events if event.get('reason')=='build-script-executed'
             and event.get('package_id')==package]
    need(len(artifacts)==1 and len(scripts)==1,'Actual Cargo rustix dependency metadata is not unique')
    artifact=artifacts[0];script=scripts[0]
    need('time' in artifact['features'] and 'linux_raw' in script['cfgs']
         and 'libc' not in script['cfgs'],'Actual rustix compilation selected another clock backend')
    manifest=Path(artifact['manifest_path'])
    identity(manifest)
    registry=manifest.parent
    need(registry.name=='rustix-'+contract['version'] and registry.parent.parent.name=='src'
         and Path(artifact['target']['src_path'])==registry/'src/lib.rs',
         'Actual compiled rustix source is outside its locked registry package')
    crate=registry.parent.parent.parent/'cache'/registry.parent.name/(registry.name+'.crate')
    crate_identity=identity(crate)
    need(crate_identity['sha256']==selected[0]['checksum'],'Actual cached rustix crate checksum differs')
    sources={}
    with tarfile.open(crate,'r:gz') as archive:
        for member in archive:
            name=PurePosixPath(member.name)
            need(not name.is_absolute() and '..' not in name.parts
                 and bool(name.parts) and name.parts[0]==registry.name,
                 'Noncanonical path in the locked dependency crate')
            if member.isdir():
                continue
            need(member.isfile() and len(name.parts)>1,'Unsupported nonregular dependency archive member')
            relative=PurePosixPath(*name.parts[1:]).as_posix()
            need(relative not in sources,'Duplicate dependency archive member')
            stream=archive.extractfile(member)
            need(stream is not None,'Missing complete dependency member bytes')
            raw=stream.read()
            expected={'bytes':len(raw),'sha256':digest(raw)}
            need(identity(registry/relative)==expected,'Compiled rustix source differs from locked crate: '+relative)
            sources[relative]=expected
    observed=set()
    for path in registry.rglob('*'):
        need(not path.is_symlink(),'Symlinked compiled dependency source')
        if path.is_file():
            observed.add(path.relative_to(registry).as_posix())
    need(observed-set(sources)<= {'.cargo-ok','.cargo-checksum.json'}
         and set(sources)<=observed,'Actual compiled dependency file set differs from locked crate')
    wrapper=contract['original_wrapper_path']
    need(wrapper in sources and sources[wrapper]['sha256']==contract['original_wrapper_sha256'],
         'Original rustix dynamic-clock wrapper source differs')
    binaries={}
    for filename in artifact['filenames']:
        path=Path(filename)
        need(path.suffix in ('.rlib','.rmeta') and str(path) not in binaries,
             'Unexpected compiled rustix library artifact')
        binaries[str(path)]=identity(path)
    need(bool(binaries),'Missing actual compiled rustix library')
    return {'schema':'trnm.hia.thread-cpu-locked-clock-dependency.v1','status':'PASS',
        'scope':'source and actual Cargo metadata checked before and after original test execution',
        'name':'rustix','version':contract['version'],'lock':identity(lock),
        'crate':{'path':str(crate),**crate_identity},'registry':str(registry),
        'complete_registry_source_files':sources,'regular_files':len(sources),
        'compiled_library_artifacts':binaries,'actual_compiler_artifact':artifact,
        'actual_build_script':script,'clock_wrapper':sources[wrapper],
        'package_checksum_matches_lock':True,'all_crate_regular_files_match_compiled_registry':True}


def original_manifest(repository):
    need(__debug__,'Original comparison refuses optimized Python')
    result={}
    for directory in ('trillionnium','config','formal'):
        for path in sorted((repository/directory).rglob('*')):
            relative=path.relative_to(repository)
            if any(part in SKIP for part in relative.parts):
                continue
            need(not path.is_symlink(),'Symlinked original input')
            if path.is_file():
                result[relative.as_posix()]=identity(path)
    listed=subprocess.run(['git','-C',str(repository),'ls-tree','-r','--name-only','-z',
        'HEAD','--','trillionnium','config','formal'],check=True,capture_output=True,timeout=20).stdout
    tracked={name.decode() for name in listed.split(b'\0') if name}
    need(tracked and tracked<=set(result),'Original source copy omits tracked retained inputs')
    need(ORIGINAL in result and result[ORIGINAL]['sha256']==ORIGINAL_SHA256,
         'Complete original ThreadCpuStamp production source differs')
    need(all(name in result for name in ('trillionnium/Cargo.toml','trillionnium/Cargo.lock')),
         'Original Cargo graph is incomplete')
    return result


def input_from_receipts(case,rows):
    stamps={};raw=bytearray()
    for definition,row in zip(case['commands'],rows[1:],strict=True):
        selected=stamps.get(definition['stamp']) if definition['stamp'] is not None else None
        need(definition['stamp'] is None or selected is not None,'Missing captured original handle input')
        raw.extend(frame(definition['op'],definition['target'],selected,definition['argument']))
        if definition['op'] in (1,2) and row['some']:
            stamps[definition['save']]=(row['handle'],row['cap0'],row['cap1'])
    return bytes(raw)


def native_comparison(repository,output):
    original=original_manifest(repository)
    physical=qualify(output/'physical')
    sources=physical['build']['source_inputs']
    need(sources==complete_source_manifest(),'Incomplete native source manifest')
    raw=corpus_bytes()
    need((output/'physical/cases.jsonl').read_bytes()==raw,'Native corpus changed')
    (output/'corpus.jsonl').write_bytes(raw)
    for name in ('owner.elf','fixture.elf'):
        shutil.copyfile(output/'physical/build'/name,output/name)
    observations=[]
    for row in physical['semantic']:
        copied=copy_native_row(row,output)
        observations.append(copied)
    need(original_manifest(repository)==original,'Original source changed during native qualification')
    need(all(identity(repository/key)==value for key,value in sources.items()),'Bound source differs after native qualification')
    result={'schema':'trnm.hia.thread-cpu-native-input.v1','status':'NATIVE_PASS_ORIGINAL_NOT_RUN',
        'build':physical['build'],'source_inputs':sources,'original_sources':original,
        'original_source_set_sha256':digest(json.dumps(original,sort_keys=True,separators=(',',':')).encode()),
        'corpus':identity(output/'corpus.jsonl'),'cases':observations,
        'native_protocol_controls':physical['controls'],
        'native_trace_negative_controls':physical['trace_negative_controls'],
        'actual_original_execution':'NOT_RUN','whole_node_or_paid_account_qualified':False}
    write_json(output/'native-comparison.json',result)
    return result


def copy_native_row(row,output):
    result=dict(row);source=Path(row['physical']).parent
    destination=output/'raw'/row['name'];destination.mkdir(parents=True,mode=0o700)
    result['raw_inputs']={}
    for name in ('stdin.raw','stdout.raw','syscalls.raw'):
        shutil.copyfile(source/name,destination/name)
        result['raw_inputs'][name]=identity(destination/name)
    result.pop('physical',None)
    return result


def validate_native_case(case,row,bundle,build):
    need(row['name']==case['name'] and row['status']=='PASS','Native physical case missing or failed')
    image=build['fixture_executable'] if case['fixture'] else build['executable']
    need(row['native_image_sha256']==image['sha256'],'Native case used another executable')
    receipts=row['receipts']
    need(comparison_from_receipts(case,receipts)==row['comparison'],'Native reduced result differs from complete receipts')
    rawroot=bundle/'raw'/case['name']
    expected_keys={'stdin.raw','stdout.raw','syscalls.raw'}
    need(set(row['raw_inputs'])==expected_keys,'Native raw evidence closure incomplete')
    need({name:identity(rawroot/name) for name in expected_keys}==row['raw_inputs'],'Native raw evidence changed')
    input_raw=(rawroot/'stdin.raw').read_bytes();output_raw=(rawroot/'stdout.raw').read_bytes()
    need(input_raw==input_from_receipts(case,receipts),'Native case input does not match actual published capabilities')
    output_expected=b''.join(struct.pack('<28Q',*(receipt[key] for key in FIELDS)) for receipt in receipts)
    need(output_raw==output_expected,'Native receipt bytes differ from captured stdout')
    checked=audit_trace((rawroot/'syscalls.raw').read_text(),input_raw,output_raw,
             fixture=case['fixture'],injection=case['injection'])
    need(checked==row['trace'],'Native trace qualification differs')


def original_clock_trace(path,case):
    text=path.read_text()
    pending={};calls=[]
    for number,line in enumerate(text.splitlines(),1):
        match=re.match(r'^(?:\[pid\s+)?(\d+)(?:\])?\s+(.*)$',line)
        if match is None:
            continue
        tid=int(match[1]);body=match[2]
        if body.startswith('clock_gettime('):
            if body.endswith(' <unfinished ...>'):
                need(tid not in pending,'Ambiguous original clock trace')
                pending[tid]=body[:-len(' <unfinished ...>')]
                continue
        elif body.startswith('<... clock_gettime resumed>'):
            need(tid in pending,'Original clock resume without entry')
            body=pending.pop(tid)+body[len('<... clock_gettime resumed>'):]
        else:
            continue
        parsed=re.fullmatch(r'clock_gettime\((.*)\)\s+=\s+(-?\d+)(.*)',body)
        need(parsed is not None,'Incomplete original clock result')
        calls.append({'tid':tid,'name':'clock_gettime','args':parsed[1],
                      'value':int(parsed[2]),'result':parsed[2]+parsed[3],'line':number})
    need(not pending,'Original clock trace ended unfinished')
    injected=validate_injections(calls,case['injection'])
    need(injected and all(call['args'].startswith('CLOCK_THREAD_CPUTIME_ID, ') for call in injected),
         'Original fault was injected into another clock')
    if case['controlled_timespec'] is not None:
        need(len(injected)==1 and clock_value(injected[0])==case['controlled_timespec']['expected'],
             'Actual original controlled timespec bytes differ')
    else:
        expected=case['injection'].split('error=',1)[1].split(':',1)[0]
        need(all(call['value']==-1 and (' '+expected+' ') in call['result'] for call in injected),
             'Actual original errno injection differs')
    return {'status':'PASS','trace':identity(path),'actual_clock_calls':len(calls),
            'injected_clock':injected[0],'injected_clocks':injected,
            'actual_injected_clock_calls':len(injected),'controlled_syscall_fixture':True}


def original_comparison(repository,bundle,output,target):
    stages=[];report={'schema':'trnm.hia.thread-cpu-original-differential.v1',
        'status':'FAIL','stages':stages,'runtime_rust_dependency':False,
        'whole_node_or_paid_account_qualified':False,
        'original_scoped_executor_or_shared_account_executed':False}
    source_fence=None;dependency=None;events=None
    try:
        comparison_raw=(bundle/'native-comparison.json').read_bytes()
        native=parse_json(comparison_raw)
        need(native.get('schema')=='trnm.hia.thread-cpu-native-input.v1'
             and native.get('status')=='NATIVE_PASS_ORIGINAL_NOT_RUN'
             and native.get('build',{}).get('status')=='PASS','Native qualification missing')
        sources=validate_source_bindings(native)
        original=original_manifest(repository)
        report.update(source_inputs=sources,original_sources=original)
        need(original==native['original_sources'],'Original source differs from native binding')
        need(all(identity(repository/key)==value for key,value in sources.items()),'Native-bound source differs')
        corpus_raw=(bundle/'corpus.jsonl').read_bytes()
        need(corpus_raw==corpus_bytes() and identity(bundle/'corpus.jsonl')==native['corpus'],
             'Exact original/native corpus differs')
        definitions=corpus()
        need([row['name'] for row in native['cases']]==[case['name'] for case in definitions],
             'Native cases missing, extra or reordered')
        for name,key in [('owner.elf','executable'),('fixture.elf','fixture_executable')]:
            need(identity(bundle/name)=={k:native['build'][key][k] for k in ('bytes','sha256')},
                 'Captured native executable differs')
            image=(bundle/name).read_bytes()
            need(digest(image[176:176+ADAPTER_BYTES])==ADAPTER_SHA256,'Native instruction adapter differs')
        for case,row in zip(definitions,native['cases'],strict=True):
            validate_native_case(case,row,bundle,native['build'])
        missing=[name for name in ('cargo','rustc','strace') if shutil.which(name) is None]
        if missing:
            report.update(status='NOT_RUN',missing_tools=missing)
            write_json(output/'report.json',report)
            return report
        isolated=output/'isolated-source';isolated.mkdir(mode=0o700)
        for relative,value in original.items():
            need(identity(repository/relative)==value,'Original input changed before isolated copy')
            destination=isolated/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(repository/relative,destination)
        include=isolated/ORIGINAL;prefix=include.read_bytes()
        need(digest(prefix)==ORIGINAL_SHA256 and b'mod hia_thread_cpu_oracle' not in prefix,
             'Original already modified or hooked')
        hook=(HERE/'rust_reference.rs').read_bytes()
        hookpath=include.parent/HOOK;need(not hookpath.exists(),'Private original hook collision')
        hookpath.write_bytes(hook);include.write_bytes(prefix+DECLARATION)
        exact_corpus=output/'corpus.jsonl';exact_corpus.write_bytes(corpus_raw)
        def check_sources(binary=None,expected_binary=None):
            need((bundle/'native-comparison.json').read_bytes()==comparison_raw
                 and (bundle/'corpus.jsonl').read_bytes()==corpus_raw,'Native bundle changed')
            need(validate_source_bindings(native)==sources,'Complete current source set changed')
            need(original_manifest(repository)==original,'Original repository changed')
            for relative,value in original.items():
                if relative==ORIGINAL:
                    need((isolated/relative).read_bytes()==prefix+DECLARATION,
                         'Isolated original production prefix changed')
                else:
                    need(identity(isolated/relative)==value,'Isolated original input changed: '+relative)
            need(hookpath.read_bytes()==hook==(HERE/'rust_reference.rs').read_bytes(),'Private original hook changed')
            need(exact_corpus.read_bytes()==corpus_raw,'Executed corpus changed')
            if binary is not None:
                need(identity(binary)==expected_binary,'Actual original executable changed')
            if dependency is not None:
                need(locked_clock_dependency(isolated,events)==dependency,
                     'Actual compiled clock dependency changed during original execution')
                report['clock_dependency_after']='MATCH'
        source_fence=check_sources
        check_sources()
        version,row=command(['rustc','-Vv'],isolated,output,'rustc-version',timeout=10);stages.append(row)
        target=target.resolve() if target else output/'cargo-target'
        need(target!=repository and repository not in target.parents
             and target!=isolated and isolated not in target.parents,'Cargo target overlaps original source')
        argv=['cargo','test','--locked','--manifest-path',str(isolated/'trillionnium/Cargo.toml'),
              '-p','trnm-pon-node','--lib','--no-run','--message-format=json','--target-dir',str(target)]
        raw,row=command(argv,isolated,output,'cargo-original-test-build',timeout=900);stages.append(row)
        events=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
        artifacts=[event for event in events if event.get('reason')=='compiler-artifact'
            and event['target']['name']=='trnm_pon_node' and event.get('executable')
            and event['profile'].get('test')]
        need(len(artifacts)==1,'No unique actual original Node test executable')
        compiled=Path(artifacts[0]['executable']);binary_identity=identity(compiled)
        binary=output/'original-test-binary';shutil.copyfile(compiled,binary);binary.chmod(0o500)
        need(identity(binary)==binary_identity,'Retained independent original binary differs')
        report.update(executable={'path':str(binary),**binary_identity},
                      compiled_executable={'path':str(compiled),**binary_identity})
        source_fence=lambda:check_sources(binary,binary_identity)
        with binary.open('rb') as stream:
            elf=stream.read(20)
        need(len(elf)==20 and elf[:7]==b'\x7fELF\x02\x01\x01' and elf[18:20]==b'\x3e\x00',
             'Actual original binary is not Linux x86-64 ELF64')
        dependency=locked_clock_dependency(isolated,events)
        report['locked_clock_dependency']=dependency
        crate_source=Path(dependency['crate']['path'])
        crate_copy=output/('locked-rustix-'+dependency['version']+'.crate')
        shutil.copyfile(crate_source,crate_copy)
        need(identity(crate_copy)=={key:dependency['crate'][key] for key in ('bytes','sha256')},
             'Retained exact original clock dependency crate differs')
        report['retained_clock_dependency_crate']={'path':str(crate_copy),**identity(crate_copy)}
        check_sources(binary,binary_identity)
        listed,row=command([str(binary),'--list'],isolated,output,'list-original-tests',timeout=30);stages.append(row)
        tests={line.removesuffix(': test') for line in listed.decode().splitlines() if line.endswith(': test')}
        need({TEST,AVAILABLE,REQUIRED}<=tests,'Required original Linux stamp tests were not linked')
        runtime_env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),
                     'TRNM_HIA_THREAD_CPU_CORPUS':str(exact_corpus)}
        retained,row=command([str(binary),'ingress::public_v3::request_observation::',
            '--skip','hia_thread_cpu_oracle','--nocapture','--test-threads=1'],
            isolated,output,'retained-original-observation-tests',env=runtime_env,timeout=240);stages.append(row)
        need('test '+REQUIRED+' ... ok' in retained.decode(),'Original nested/wrong-thread stamp test did not run')
        available,row=command([str(binary),'--exact',AVAILABLE,'--nocapture','--test-threads=1'],
            isolated,output,'mandatory-original-linux-clock',env=runtime_env,timeout=30);stages.append(row)
        need('HIA_THREAD_CPU_LINUX_AVAILABLE:' in available.decode()
             and 'test result: ok. 1 passed' in available.decode(),'Original clock availability control did not execute')
        observed={}
        report['observed_original_history_names']=[]
        def collect(raw):
            rows=[json.loads(line.split(MARKER,1)[1]) for line in raw.decode().splitlines() if MARKER in line]
            for value in rows:
                need(value['name'] not in observed,'Duplicate actual original result')
                observed[value['name']]=value
                report['observed_original_history_names'].append(value['name'])
            return rows
        raw,row=command([str(binary),'--exact',TEST,'--nocapture','--test-threads=1'],
            isolated,output,'actual-original-real-clock-histories',env=runtime_env,timeout=240);stages.append(row)
        real=collect(raw)
        need([value['name'] for value in real]==[case['name'] for case in definitions if case['injection'] is None],
             'Original real-clock histories missing or reordered')
        faults=[]
        report['controlled_original_syscalls']=faults
        for case in definitions:
            if case['injection'] is None:
                continue
            tracepath=output/('original-'+case['name']+'.trace')
            env=dict(runtime_env,TRNM_HIA_THREAD_CPU_CASE=case['name'])
            args=['/usr/bin/strace','-f','-qq','-v','-s','4096','-o',str(tracepath),
                  '-e','inject='+case['injection'],'--',str(binary),'--exact',TEST,'--nocapture','--test-threads=1']
            raw,row=command(args,isolated,output,'actual-original-'+case['name'],env=env,timeout=60);stages.append(row)
            values=collect(raw)
            need(len(values)==1 and values[0]['name']==case['name'],'Wrong original controlled case executed')
            faults.append({'name':case['name'],**original_clock_trace(tracepath,case)})
        check_sources(binary,binary_identity)
        need(set(observed)=={case['name'] for case in definitions},'Actual original history set incomplete')
        comparisons=[]
        for expected in native['cases']:
            actual=observed[expected['name']]
            same=actual['comparison']==expected['comparison']
            comparisons.append({'name':expected['name'],'status':'PASS' if same else 'FAIL',
                'native':expected['comparison'],'original':actual})
        write_json(output/'comparison.json',{'controls':comparisons})
        need(all(row['status']=='PASS' for row in comparisons),'Actual original ThreadCpuStamp differential failed')
        report.update(status='PASS',histories=len(comparisons),
            operations=sum(len(row['original']['comparison']) for row in comparisons),
            original_calls=sum(row['original']['original_calls'] for row in comparisons),
            controlled_original_syscalls=faults,compiler=version.decode(),
            executable={'path':str(binary),**binary_identity},
            compiled_executable={'path':str(compiled),**binary_identity},
            original_sources=original,source_inputs=sources,source_inputs_stable=True,
            exact_corpus=native['corpus'],native_comparison_sha256=digest(comparison_raw),
            original_production_prefix=original[ORIGINAL],
            original_repository_modified=False,appended_private_cfg_test_child_hex=DECLARATION.hex(),
            private_reference_sha256=digest(hook),mandatory_original_clock_available=True,
            retained_original_summary=[line for line in retained.decode().splitlines() if line.startswith('test result:')],
            original_primitive_methods=['ThreadCpuStamp::start','Clone::clone',
                'ThreadCpuStamp::checkpoint','ThreadCpuStamp::finish','ThreadCpuStamp value drop'],
            actual_original_kernel_clock_vs_controlled_syscall_fixtures_separated=True)
        return report
    except BaseException as error:
        report['failure']=repr(error)
        raise
    finally:
        if source_fence is not None:
            try:
                source_fence()
                report['source_after']='MATCH'
            except BaseException as error:
                report['source_after']='FAIL';report['source_after_failure']=repr(error);report['status']='FAIL'
        write_json(output/'report.json',report)


def main():
    if not __debug__:
        raise RuntimeError('Original Thread CPU validation refuses optimized Python')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',type=Path,default=ROOT)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--target-dir',type=Path)
    parser.add_argument('--native-only',action='store_true')
    args=parser.parse_args()
    need(not (args.native_only and args.bundle),'native-only cannot consume a bundle')
    output=args.output.resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    repository=args.repository.resolve(strict=True)
    if args.bundle is None:
        native_comparison(repository,output)
        if args.native_only:
            print(json.dumps({'status':'NATIVE_PASS_ORIGINAL_NOT_RUN','bundle':str(output)},sort_keys=True))
            return 0
        bundle=output
    else:
        bundle=args.bundle.resolve(strict=True)
    original_output=output/'original';original_output.mkdir(mode=0o700)
    result=original_comparison(repository,bundle,original_output,args.target_dir)
    need(result['status']=='PASS','Actual original Thread CPU comparison did not pass')
    print(json.dumps({key:result[key] for key in ('status','histories','operations','original_calls')},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
