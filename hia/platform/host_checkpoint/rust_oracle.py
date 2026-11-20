"""Execute source-bound native HIA and complete original private Host primitives.

The original production file is never edited, including in the isolated copy.
A test-only child is appended to the already test-only relative fixture include.
Both sides operate on real private files; fixture acceptance is not Host authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

HERE=Path(__file__).resolve().parent
REPOSITORY=HERE.parents[2]
sys.path.insert(0,str(REPOSITORY))

from hia.platform.host_checkpoint.build import Build
from hia.platform.host_checkpoint import original_cases
from hia.platform.host_checkpoint.qualify import Corpus
from hia.platform.transport_request.rust_oracle import command

HOST='trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs'
RELATIVE='trillionnium/crates/trnm-pon-node/src/host_kernel_parent_relative_tests.rs'
HOOK='hia_host_checkpoint_oracle.rs'
DECLARATION=(b'\n#[cfg(test)]\nmod hia_host_checkpoint_oracle {\n'
             b'    include!("hia_host_checkpoint_oracle.rs");\n}\n')
TEST='host_kernel_parent::kernel_parent::relative_tests::hia_host_checkpoint_oracle::evaluate'
MARKER='HIA_HOST_CHECKPOINT_ORACLE:'
SKIP={'target','__pycache__','.pytest_cache'}
EXTRA_INPUTS=(
    'hia/platform/host_checkpoint/original_cases.py',
    'hia/platform/host_checkpoint/rust_reference.rs',
    'hia/platform/host_checkpoint/rust_oracle.py',
    'hia/platform/transport_request/rust_oracle.py',
    RELATIVE,
)
REQUIRED_ORIGINAL_TESTS=(
    'host_kernel_parent::kernel_parent::tests::context_reader_keeps_complete_text_and_unbounded_original_long_input',
    'host_kernel_parent::kernel_parent::tests::context_reader_validates_all_utf8_after_real_eof_on_both_paths',
    'host_kernel_parent::kernel_parent::tests::context_reader_retains_late_io_error_before_utf8_or_prefix_acceptance',
    'host_kernel_parent::kernel_parent::tests::limit_reader_waits_for_real_eof_after_short_reads_and_interruptions',
    'host_kernel_parent::kernel_parent::tests::read_kernel_membership_from_current_os_thread_not_process_leader',
    'host_kernel_parent::kernel_parent::relative_tests::relative_limits_preserve_eof_size_utf8_and_late_io_error_precedence',
    'host_kernel_parent::kernel_parent::relative_tests::relative_limits_refuse_nonregular_children_in_bounded_native_processes',
    'host_kernel_parent::kernel_parent::relative_tests::held_parent_production_final_fence_observes_change_after_actual_fifth_open',
    'host_kernel_parent::kernel_parent::relative_tests::held_parent_final_fence_does_not_replace_an_earlier_limit_parse_error',
)


def require(condition, message):
    if not condition:raise ValueError(message)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def identity(path: Path):
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True)==path,
            'Missing, symlinked or noncanonical source: '+str(path))
    result=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while block:=stream.read(1<<20):result.update(block);size+=len(block)
    return {'bytes':size,'sha256':result.hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def original_manifest(repository: Path):
    require(__debug__,'Original Host validation refuses optimized Python')
    rows={}
    for directory in ('trillionnium','config','formal'):
        for path in sorted((repository/directory).rglob('*')):
            relative=path.relative_to(repository)
            if any(part in SKIP for part in relative.parts):continue
            require(not path.is_symlink(),'Symlinked original Cargo input: '+str(relative))
            if path.is_file():rows[relative.as_posix()]=identity(path)
    require(all(path in rows for path in (HOST,RELATIVE,'trillionnium/Cargo.toml','trillionnium/Cargo.lock')),
            'Incomplete original Host/Cargo sources')
    return rows


def native_comparison(repository: Path, output: Path):
    build=Build(output/'build')
    sources={**build.source_inputs,**{path:identity(repository/path) for path in EXTRA_INPUTS}}
    original=original_manifest(repository)
    original_snapshot=digest(json.dumps(original,sort_keys=True,separators=(',',':')).encode())
    built=build.build()
    definitions=original_cases.cases()
    corpus_bytes=b''.join((json.dumps(case,sort_keys=True,separators=(',',':'))+'\n').encode()
                          for case in definitions)
    (output/'corpus.jsonl').write_bytes(corpus_bytes)
    corpus=Corpus(build.fixture_executable,output/'physical')
    controls=[]
    report={'schema':'trnm.hia.host-native-original-input.v1','status':'FAIL',
            'build':built,'source_inputs':sources,'original_sources':original,
            'original_source_set_sha256':original_snapshot,
            'corpus':identity(output/'corpus.jsonl'),'cases':controls,
            'native_physical_observations':corpus.rows,
            'production_parent_authority':False,'original_execution':'NOT_RUN'}
    try:
        for definition in definitions:
            def actions(key, captured=definition):
                return lambda root,parent:original_cases.apply(root,captured[key])
            row=corpus.case(definition['name'],before=actions('before'),after=actions('after'),
                gate=definition['gate'],mutation=actions('mutate'),
                initial_error=definition['expected_initial'],expected=definition['expected_final'],
                second_error=definition['second_error'],chunk=definition['chunk'],count=definition['count'])
            controls.append({'name':definition['name'],'codes':[r['error'] for r in row['receipts']],
                'full_checks':row['receipts'][-1]['full_checks'],
                'gate_observed':bool(definition['gate']),
                'image_sha256':digest(build.fixture_executable),'physical_status':row['status']})
        build.check_pin()
        require(original_manifest(repository)==original,'Original source changed during native execution')
        for path,expected in sources.items():require(identity(repository/path)==expected,'Source changed: '+path)
        require(identity(output/'corpus.jsonl')==report['corpus'],'Native corpus changed')
        report['status']='NATIVE_PASS_ORIGINAL_NOT_RUN'
    except BaseException as error:
        report['failure']=repr(error)
        write_json(output/'native-comparison.json',report)
        raise
    write_json(output/'native-comparison.json',report)
    return report


def original_comparison(repository: Path, bundle: Path, output: Path, target: Path | None):
    stages=[]
    report={'schema':'trnm.hia.host-original-differential.v1','status':'FAIL','stages':stages,
            'production_parent_authority':False,'production_fixed_parent_positive':False,
            'whole_node_qualified':False,'original_4s_16_service_budget_qualified':False,
            'runtime_rust_dependency':False,
            'scope':'actual original private primitives and private-file acquisition/check sequences'}
    try:
        missing=[tool for tool in ('cargo','rustc') if shutil.which(tool) is None]
        if missing:
            report.update(status='NOT_RUN',missing_tools=missing)
            write_json(output/'report.json',report)
            return report
        comparison_raw=(bundle/'native-comparison.json').read_bytes()
        native=json.loads(comparison_raw)
        require(native['status']=='NATIVE_PASS_ORIGINAL_NOT_RUN','Native corpus did not complete successfully')
        require(native['build']['status']=='PASS' and native['cases'],'Missing actual native owner observations')
        source_inputs=native['source_inputs']
        original=original_manifest(repository)
        require(original==native['original_sources'],'Original Cargo source set differs from actual native binding')
        for path,expected in source_inputs.items():
            require(identity(repository/path)==expected,'Native-bound source differs: '+path)
        exact_corpus=(bundle/'corpus.jsonl').read_bytes()
        corpus=output/'corpus.jsonl';corpus.write_bytes(exact_corpus)
        require(identity(corpus)==native['corpus'],'Exact native corpus bytes differ')
        definitions=[json.loads(line) for line in exact_corpus.splitlines()]
        require([row['name'] for row in definitions]==[row['name'] for row in native['cases']],
                'Native corpus observation order differs')
        require(len(native['native_physical_observations'])==len(definitions),'Native physical cases missing')
        for semantic,physical in zip(native['cases'],native['native_physical_observations'],strict=True):
            require(physical['status']=='PASS' and semantic['physical_status']=='PASS'
                    and semantic['name']==physical['name'],'Native physical observation did not pass')
            require(semantic['codes']==[row['error'] for row in physical['receipts']]
                    and semantic['full_checks']==physical['receipts'][-1]['full_checks'],
                    'Native semantic record differs from actual receipts')
            require(semantic['image_sha256']==native['build']['fixture_executable']['sha256'],
                    'Native cases used a different image')
        isolated=output/'isolated-source';isolated.mkdir(mode=0o700)
        for relative,expected in original.items():
            source=repository/relative
            require(identity(source)==expected,'Original source changed before copy: '+relative)
            destination=isolated/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,destination)
        relative_path=isolated/RELATIVE
        original_relative=relative_path.read_bytes()
        require(b'mod hia_host_checkpoint_oracle' not in original_relative,'Original already declares this oracle')
        hook=(HERE/'rust_reference.rs').read_bytes()
        hook_path=relative_path.parent/HOOK
        require(not hook_path.exists(),'Original hook path already exists')
        hook_path.write_bytes(hook)
        relative_path.write_bytes(original_relative+DECLARATION)
        def check_sources(binary=None,binary_identity=None):
            require((bundle/'native-comparison.json').read_bytes()==comparison_raw,'Native evidence changed')
            require((bundle/'corpus.jsonl').read_bytes()==exact_corpus,'Native exact corpus changed')
            require(original_manifest(repository)==original,'Original repository changed during differential')
            for relative,expected in original.items():
                path=isolated/relative
                if relative==RELATIVE:
                    require(path.read_bytes()==original_relative+DECLARATION,'Original test include was edited')
                else:require(identity(path)==expected,'Original isolated bytes changed: '+relative)
            require(identity(isolated/HOST)==original[HOST],'Production Host source was edited')
            for path,expected in source_inputs.items():
                require(identity(repository/path)==expected,'Bound source changed: '+path)
            require(hook_path.read_bytes()==hook and (HERE/'rust_reference.rs').read_bytes()==hook,
                    'Original private adapter changed')
            require(identity(corpus)==native['corpus'],'Original exact corpus changed')
            if binary is not None:require(identity(binary)==binary_identity,'Original executable changed')
        check_sources()
        version,row=command(['rustc','-Vv'],isolated,output,'rustc-version',timeout=10);stages.append(row)
        target=target.resolve() if target else output/'cargo-target'
        require(target!=repository and repository not in target.parents and target!=isolated
                and isolated not in target.parents,'Cargo target must be outside original source')
        argv=['cargo','test','--locked','--manifest-path',str(isolated/'trillionnium/Cargo.toml'),
              '-p','trnm-pon-node','--lib','--no-run','--message-format=json','--target-dir',str(target)]
        raw,row=command(argv,isolated,output,'cargo-original-test-build',timeout=900);stages.append(row)
        events=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
        binaries=[item for item in events if item.get('reason')=='compiler-artifact'
                  and item['target']['name']=='trnm_pon_node' and item.get('executable')
                  and item['profile'].get('test')]
        require(len(binaries)==1,'Expected one actual original Node test executable')
        binary=Path(binaries[0]['executable']);binary_identity=identity(binary)
        check_sources(binary,binary_identity)
        listed,row=command([str(binary),'--list'],isolated,output,'list-original-tests',timeout=20);stages.append(row)
        tests={line.removesuffix(': test') for line in listed.decode().splitlines() if line.endswith(': test')}
        require(set((TEST,)+REQUIRED_ORIGINAL_TESTS)<=tests,'Required original Host tests were not linked')
        retained,row=command([str(binary),'host_kernel_parent::','--skip','hia_host_checkpoint_oracle',
                               '--nocapture','--test-threads=1'],
                              isolated,output,'retained-original-host-tests',timeout=240);stages.append(row)
        for name in REQUIRED_ORIGINAL_TESTS:
            require(('test '+name+' ... ok') in retained.decode(),'Required original test did not execute: '+name)
        environment=dict(os.environ,TRNM_HIA_HOST_CHECKPOINT_CORPUS=str(corpus))
        raw,row=command([str(binary),'--exact',TEST,'--nocapture','--test-threads=1'],isolated,output,
                        'actual-original-private-corpus',env=environment,timeout=240);stages.append(row)
        check_sources(binary,binary_identity)
        observed=[json.loads(line.split(MARKER,1)[1]) for line in raw.decode().splitlines() if MARKER in line]
        require([row['name'] for row in observed]==[row['name'] for row in native['cases']],
                'Actual original rows missing, reordered or extra')
        controls=[]
        for expected,actual in zip(native['cases'],observed,strict=True):
            same=all(expected[key]==actual[key] for key in ('name','codes','full_checks','gate_observed'))
            controls.append({'name':expected['name'],'status':'PASS' if same else 'FAIL',
                             'native':expected,'original':actual})
        write_json(output/'comparison.json',{'controls':controls})
        require(all(row['status']=='PASS' for row in controls),'Actual original Host differential failed')
        summary=[line for line in retained.decode().splitlines() if line.startswith('test result:')]
        report.update(status='PASS',controls=len(controls),failed=0,compiler=version.decode(),
            executable=binary_identity,original_sources=original,
            native_image=native['build']['fixture_executable'],
            native_comparison_sha256=digest(comparison_raw),exact_corpus=native['corpus'],
            source_inputs=source_inputs,source_inputs_stable=True,
            original_production_file_unchanged=original[HOST],
            original_test_file_prefix_unchanged=original[RELATIVE],
            appended_test_child_hex=DECLARATION.hex(),private_adapter_sha256=digest(hook),
            required_original_tests=list(REQUIRED_ORIGINAL_TESTS),retained_original_summary=summary,
            actual_original_primitives=['read_context','read_limit_text','cgroup_within_parent',
                'validate_limits','open_current_parent','ScopedParentDirectory::from_file',
                'ScopedParentDirectory::read_limits','ScopedParentDirectory::verify_limits',
                'ScopedParentDirectory::verify_path'],
            fixed_production_KernelBudget_open_and_checked_parent_executed=False)
        write_json(output/'report.json',report)
        return report
    except BaseException as error:
        report['failure']=repr(error);write_json(output/'report.json',report)
        raise


def main():
    if not __debug__:raise RuntimeError('Original Host qualification refuses optimized Python')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',type=Path,default=REPOSITORY)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--native-only',action='store_true')
    parser.add_argument('--target-dir',type=Path)
    args=parser.parse_args()
    repository=args.repository.resolve(strict=True)
    require(repository==REPOSITORY,'Run the exact oracle from the selected repository')
    require(not(args.native_only and args.bundle),'Native-only cannot reuse a previous bundle')
    output=args.output.absolute()
    require(not output.exists() and not output.is_symlink(),'Use a fresh original Host output directory')
    output.mkdir(mode=0o700,parents=True)
    if args.bundle:
        bundle=args.bundle.resolve(strict=True)
    else:
        bundle=output/'native';bundle.mkdir(mode=0o700)
        native=native_comparison(repository,bundle)
        if args.native_only:
            print(json.dumps({'status':native['status'],'cases':len(native['cases']),
                              'report':str(bundle/'native-comparison.json')}))
            return 0
    original=output/'original';original.mkdir(mode=0o700)
    report=original_comparison(repository,bundle,original,args.target_dir)
    print(json.dumps({'status':report['status'],'cases':report.get('controls',0),
                      'report':str(original/'report.json')}))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
