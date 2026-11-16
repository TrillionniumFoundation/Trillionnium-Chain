"""Admit complete native evidence, then compile and run unchanged original M06.

This hosted verifier has no production authority.  It compares actual native
pipe observations with actual original prepare/application/View/Patch methods.
"""
from __future__ import annotations
import argparse,hashlib,json,os,shutil,stat,struct,sys,time,traceback
from pathlib import Path
from hia.platform.execution_state import rust_oracle as utility
from .source_graph import REPOSITORY,OWNED,IMAGE_ORDER,complete_sources,original_manifest,bound_corpus
from .native_io import ReplaySession
from .qualify import Observer,BATCH_SIZE,NATIVE_SECONDS

need=utility.need;identity=utility.identity;file_identity=utility.file_identity
canonical=utility.canonical_json;digest=utility.digest;load_json=utility.load_json
write_json=utility.write_json;canonical_path=utility.canonical_path
STORE=utility.STORE
HOOK='hia_execution_application_oracle.rs'
DECL=b'\n#[cfg(test)]\n#[path = "hia_execution_application_oracle.rs"]\nmod hia_execution_application_oracle;\n'
TEST='pon_executor::hia_execution_application_oracle::evaluate'
TESTS=(*utility.ORIGINAL_TESTS,
 'pon_executor::legacy_preparation_tests::canonical_wire_hashes_match_original_all_tags_and_variable_payload_boundaries',
 'pon_executor::legacy_preparation_tests::malformed_wire_never_reaches_borrowed_hashes',
 'pon_executor::legacy_preparation_tests::actual_preparation_keeps_strict_signatures_error_order_and_attempt_counts')


def validate_source_bindings(repository,comparison):
    need(isinstance(comparison,dict) and comparison.get('schema')=='trnm.execution-application-comparison.v1' and comparison.get('status')=='PASS','Native application comparison did not pass')
    build=comparison.get('build');need(isinstance(build,dict) and build.get('schema')=='trnm.execution-application-build.v1' and build.get('status')=='PASS','Native build did not pass')
    supplied=build.get('source_inputs');need(isinstance(supplied,dict) and supplied,'Missing bound source map')
    for name,row in supplied.items():canonical_path(repository,name);need(utility.valid_identity(row),'Invalid source identity')
    actual,composed=complete_sources(repository)
    need(supplied==actual and build.get('source_set_sha256')==digest(canonical(actual)),'Incomplete, changed, extra source closure or source digest')
    need(build.get('composed_sources')=={name:identity(raw) for name,raw in composed.items()},'Actual composed native sources differ')
    need(build.get('source_after')=={'status':'PASS','errors':[]} and build.get('failure') is None and build.get('runtime_host_proxy') is False and build.get('original_rust_executed') is False and build.get('complete_node') is False,'Incomplete build fence or invalid runtime scope')
    pin=load_json(canonical_path(repository,'hia/qualification/compiler-binding.json').read_bytes());lock=load_json(canonical_path(repository,'hia/toolchain.lock.json').read_bytes())
    need(build.get('compiler_qualification_binding')==pin and build.get('compiler_sha256')==pin['compiler_sha256'] and build.get('toolchain')==lock,'Actual compiler/source pin differs')
    return actual,composed


def validate_bundle(repository,bundle):
    repository=utility.canonical_root(repository);bundle=utility.canonical_root(bundle)
    comparison=load_json(canonical_path(bundle,'native-comparison.json').read_bytes())
    need(set(comparison)=={'schema','status','build','corpus','cases','processes'},'Unexpected comparison fields')
    sources,composed=validate_source_bindings(repository,comparison);build=comparison['build']
    original=original_manifest(repository)
    need(build.get('original_sources')==original and build.get('original_source_set_sha256')==digest(canonical(original)),'Original complete source graph differs')
    corpus,inputs,configuration=bound_corpus(repository);declared=comparison['corpus']
    need(isinstance(declared,dict) and set(declared)=={'path','raw','compressed'} and declared['path']=='corpus.jsonl.xz' and declared['raw']==identity(corpus) and utility.valid_identity(declared['compressed']),'Canonical corpus declaration differs')
    need(canonical_path(bundle,'corpus.jsonl').read_bytes()==corpus,'Canonical raw corpus differs')
    archived=canonical_path(bundle,'corpus.jsonl.xz');need(file_identity(archived)==declared['compressed'],'Compressed corpus identity differs');utility.bounded_xz(archived,corpus)
    report=load_json(canonical_path(bundle,'native-report.json').read_bytes())
    need(report.get('schema')=='trnm.execution-application-qualification.v1' and report.get('status')=='PASS' and report.get('build')==build and report.get('corpus')==declared,'Native report/source binding differs')
    need(report.get('comparison')==file_identity(canonical_path(bundle,'native-comparison.json')),'Native comparison byte identity differs')
    need(report.get('verification')=={'primary_error':None,'cleanup_errors':[],'source_after':{'status':'PASS','errors':[]}},'Native source/lifetime verification did not close')
    need(report.get('scope')=={'actual_private_prepared':True,'actual_private_state_view_patch':True,'runtime_host_proxy':False,'default_commands':list(range(1,13)),'complete_node':False,'admission_persistence':False,'original_rust':'NOT_RUN'},'Native scope differs')
    files={'native-comparison.json','native-report.json','corpus.jsonl','corpus.jsonl.xz'}
    images={}
    for name in (*IMAGE_ORDER,'linux_emitter'):
        path='native-build/'+name+('.elf' if name=='linux_emitter' else '.flat');files.add(path);images[name]=canonical_path(bundle,path).read_bytes()
    prefix_path='native-build/elf-prefix.raw';elf_path='native-build/owner.elf';files.update((prefix_path,elf_path))
    prefix=canonical_path(bundle,prefix_path).read_bytes();elf=canonical_path(bundle,elf_path).read_bytes()
    need(build.get('images')=={name:identity(raw) for name,raw in images.items()} and build.get('elf_prefix')==identity(prefix) and build.get('executable')==identity(elf),'Actual compiled images/prefix/ELF differ')
    need(elf.startswith(b'\x7fELF') and elf==prefix+b''.join(images[name] for name in IMAGE_ORDER),'Actual ELF omits or reorders a native image')
    stages=build.get('stages');need(isinstance(stages,list) and len(stages)==16,'Missing actual native compiler/emitter stage')
    for stage,name in zip(stages,(*IMAGE_ORDER,'linux_emitter','prefix'),strict=True):
        payload=struct.pack('<14Q',*(len(images[n]) for n in IMAGE_ORDER)) if name=='prefix' else composed[name]
        emitted=prefix if name=='prefix' else images[name]
        executable=identity(images['linux_emitter'])['sha256'] if name=='prefix' else build['compiler_sha256']
        need(stage.get('stage')==('emit-prefix' if name=='prefix' else 'compile-'+name) and stage.get('exit_code')==0 and stage.get('timed_out') is False and stage.get('stderr_hex')=='' and stage.get('cleanup') is None,'Native build stage did not succeed')
        need({'bytes':stage.get('input_bytes'),'sha256':stage.get('input_sha256')}==identity(payload) and {'bytes':stage.get('output_bytes'),'sha256':stage.get('output_sha256')}==identity(emitted) and stage.get('executable_sha256')==executable,'Actual native stage input/output/executable binding differs')
    processes=comparison['processes'];cases=comparison['cases'];controls=report.get('controls')
    expected_processes=(len(inputs)+BATCH_SIZE-1)//BATCH_SIZE
    need(isinstance(processes,list) and len(processes)==expected_processes and isinstance(cases,list) and len(cases)==len(inputs) and isinstance(controls,list) and len(controls)==len(inputs),'Missing native histories/processes/controls')
    observed=[];state_commands=0;contexts=[]
    for index,process in enumerate(processes):
        directory='processes/%03d'%index;subset=inputs[index*BATCH_SIZE:(index+1)*BATCH_SIZE]
        need(set(process)=={'directory','histories','state_commands','context','receipt'} and process['directory']==directory and process['histories']==[r['name'] for r in subset],'Native history process assignment differs')
        names={name:directory+'/'+name for name in ('stdin.raw','stdout.raw','stderr.raw','receipt.json','observed-frames.json')};files.update(names.values())
        raw={name:canonical_path(bundle,path).read_bytes() for name,path in names.items()};receipt=load_json(raw['receipt.json'])
        need(receipt==process['receipt'] and receipt.get('schema')=='trnm.execution-state-native-process.v1' and receipt.get('executable')==build['executable'],'Native process/binary receipt differs')
        need(receipt.get('exit_code')==0 and receipt.get('clean_close') is True and receipt.get('failure') is None and receipt.get('cleanup') is None and receipt.get('unconsumed_stdout_hex')=='' and receipt.get('runtime_host_proxy') is False,'Actual native process did not close cleanly')
        need(receipt.get('wall_limit_seconds')==NATIVE_SECONDS and receipt.get('cleanup_limit_seconds')==3 and type(receipt.get('elapsed_ns')) is int and receipt['elapsed_ns']>0 and receipt.get('instrumentation')=={'trace':False,'mremap_errno_injected':False},'Unexpected actual native execution budget or instrumentation')
        need(raw['stderr.raw']==b'' and receipt.get('stderr_bytes')==0 and receipt.get('files')=={name:identity(raw[name]) for name in ('stdin.raw','stdout.raw','stderr.raw')},'Actual native stream identities differ')
        replay=ReplaySession(raw['stdin.raw'],raw['stdout.raw']);observer=Observer(replay)
        need(replay.context_fields==process['context'],'Native context observation differs')
        for name in ('network','parameters','family','plan'):need(replay.context_fields[name]==configuration[name].hex(),'Native Config hash differs from bound fixture')
        need(replay.context_fields['params']==configuration['params'],'Native Config params differ')
        for row in subset:observed.append(observer.history(row))
        observer.state(26);replay.finish();contexts.append(replay.context_fields)
        need(observer.state_commands==process['state_commands'],'Native State command accounting differs')
        state_commands+=observer.state_commands
        frames=load_json(raw['observed-frames.json']);need(isinstance(frames,list) and len(frames)==len(replay.frames),'Native frame journal is incomplete')
        for recorded,actual in zip(frames,replay.frames,strict=True):
            need(set(recorded)=={'sent_hex','received_hex','elapsed_ns'} and type(recorded['elapsed_ns']) is int and recorded['elapsed_ns']>=0,'Invalid native frame observation')
            need({k:recorded[k] for k in ('sent_hex','received_hex')}==actual,'Frame journal differs from full actual pipes')
        need(receipt.get('stdin_attempted_bytes')==len(raw['stdin.raw'])==receipt.get('stdin_actual_write_bytes') and receipt.get('stdout_bytes')==len(raw['stdout.raw']) and receipt.get('commands')==len(replay.commands),'Native process command/pipe counts differ')
    need(utility.same_json(observed,cases),'Normalized native observations differ from actual source-driven pipes')
    need(controls==[{'name':row['name'],'status':'PASS','transactions':len(row['transactions'])} for row in inputs],'Native control summary differs')
    need(report.get('histories_total')==len(inputs) and report.get('transactions')==sum(len(r['transactions']) for r in inputs) and report.get('state_commands')==state_commands and report.get('actual_processes')==expected_processes and report.get('batch_size')==BATCH_SIZE,'Native aggregate counts differ')
    found=set()
    for path in bundle.rglob('*'):
        need(not path.is_symlink(),'Symbolic native evidence')
        if path.is_dir():continue
        name=path.relative_to(bundle).as_posix();canonical_path(bundle,name);found.add(name)
    need(found==files,'Missing or extra native evidence artifact')
    need(all(c==contexts[0] for c in contexts),'Native context varies across identical default construction')
    return {'comparison':comparison,'report':report,'source_inputs':sources,'original_sources':original,'corpus_raw':corpus,'inputs':inputs,'configuration':configuration,'context':contexts[0],'bundle_artifacts':{n:file_identity(canonical_path(bundle,n)) for n in sorted(files)}}


def run_original(args):
    repository=utility.canonical_root(args.repository);bundle=utility.canonical_root(args.bundle)
    need(canonical_path(repository,OWNED+'/rust_oracle.py')==Path(__file__).absolute(),'Run the oracle from the exact selected repository')
    output=args.output.absolute();need(output==output.resolve() and not output.exists(),'Fresh nonsymbolic output required')
    for source in (repository,bundle):need(output!=source and source not in output.parents,'Output overlaps a bound input')
    output.mkdir(mode=0o700);isolated=output/'isolated-source';start=time.monotonic_ns()
    stages=[];fences=[];retained=[];controls=[];actual=[];admitted=None;binary=None;binary_identity=None
    tool_paths=None;serde=None;serde_capture=None;serde_library=None;isolated_expected=None
    failure=None;final_errors=[];missing=[];original_map=None;actual_context=None
    environment=None
    def fence(label):
        checks={};errors=[]
        def test(name,fn):
            try:checks[name]=fn()
            except BaseException as error:errors.append({'name':name,'error':repr(error)})
        if admitted is not None:
            def sources():
                observed,_=validate_source_bindings(repository,admitted['comparison']);need(observed==admitted['source_inputs'],'Native source changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(canonical(observed))}
            def originals():
                observed=original_manifest(repository);need(observed==original_map,'Original source drift')
                return {'status':'MATCH','files':len(observed),'sha256':digest(canonical(observed))}
            def artifacts():
                found={}
                for path in bundle.rglob('*'):
                    need(not path.is_symlink(),'Symbolic native evidence')
                    if path.is_dir():continue
                    name=path.relative_to(bundle).as_posix();found[name]=file_identity(canonical_path(bundle,name))
                need(found==admitted['bundle_artifacts'],'Native artifact set or bytes changed')
                raw,_,_=bound_corpus(repository);need(raw==admitted['corpus_raw'],'Bound corpus changed')
                return {'status':'MATCH','files':len(found),'sha256':digest(canonical(found))}
            test('complete_native_source',sources);test('actual_original_source',originals);test('complete_native_artifacts_and_corpus',artifacts)
        if isolated_expected is not None:
            def copied():
                observed=original_manifest(isolated);need(observed==isolated_expected,'Isolated original/hook drift')
                need(file_identity(output/'corpus.jsonl')==admitted['comparison']['corpus']['raw'],'Actual original input changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(canonical(observed))}
            test('isolated_original_and_exact_hook',copied)
        if binary is not None:
            def binary_check():
                observed=file_identity(binary);need(observed==binary_identity,'Independent original binary drift')
                return {'status':'MATCH',**observed}
            test('actual_original_binary',binary_check)
        if serde_capture is not None:
            def serde_check():
                observed=serde_capture();need(observed==serde['crate_sources'],'Locked actual serde sources changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(canonical(observed))}
            test('actual_serde_source',serde_check)
        if serde_library is not None:
            def library_check():
                need(file_identity(output/'actual-serde-library.rlib')==serde_library['identity'],'Actual retained serde library changed')
                return {'status':'MATCH',**serde_library}
            test('actual_serde_library',library_check)
        if tool_paths is not None:
            def compiler_check():
                for name,row in tool_paths.items():need(file_identity(Path(row['path']))=={k:row[k] for k in ('bytes','sha256')},'Bound compiler/Cargo changed')
                return {'status':'MATCH','tools':tool_paths}
            test('actual_compilers',compiler_check)
        receipt={'label':label,'status':('PASS' if admitted is not None else 'NOT_REACHED') if not errors else 'FAIL','checks':checks,'errors':errors};fences.append(receipt);write_json(output/(label+'.json'),receipt);need(not errors,'Source/artifact fence failed')
    def run(argv,label,timeout=240,env=None):
        return utility.run_command(argv,isolated,output,label,stages,timeout=timeout,environment=environment if env is None else env)[0]
    try:
        environment=utility.clean_build_environment()
        target=utility.safe_target(args.target_dir,output,repository,bundle,isolated)
        admitted=validate_bundle(repository,bundle);original_map=admitted['original_sources']
        write_json(output/'admission.json',{'status':'ADMITTED_NOT_ORIGINAL_EXECUTED','source_inputs':admitted['source_inputs'],'original_sources':original_map,'bundle_artifacts':admitted['bundle_artifacts'],'corpus':admitted['comparison']['corpus']['raw']})
        fence('source-before');missing=[name for name in ('rustc','cargo') if not shutil.which(name)]
        need(not missing,'Required actual Rust tools unavailable: '+repr(missing))
        isolated.mkdir(mode=0o700)
        for name,row in original_map.items():
            destination=isolated/name;destination.parent.mkdir(parents=True,exist_ok=True)
            with canonical_path(repository,name).open('rb') as source,destination.open('xb') as out:shutil.copyfileobj(source,out,1<<20)
            need(file_identity(destination)==row,'Original copy changed')
        original_store=(isolated/STORE).read_bytes();hook=canonical_path(repository,OWNED+'/rust_reference.rs').read_bytes()
        need(b'mod hia_execution_application_oracle' not in original_store,'Original already hooked')
        hook_path=(isolated/STORE).parent/HOOK
        with hook_path.open('xb') as out:out.write(hook)
        with (isolated/STORE).open('ab') as stream:stream.write(DECL)
        isolated_expected={**original_map,STORE:identity(original_store+DECL),hook_path.relative_to(isolated).as_posix():identity(hook)}
        corpus_path=output/'corpus.jsonl';corpus_path.write_bytes(admitted['corpus_raw']);fence('isolated-source-before')
        version=run(['rustc','-Vv'],'rustc-version',15);need(b'host: x86_64-unknown-linux-gnu\n' in version,'Wrong Rust host')
        sysroot=Path(run(['rustc','--print','sysroot'],'rustc-sysroot',15).decode().strip()).resolve(strict=True);tool_paths={}
        for name in ('rustc','cargo','rustdoc'):
            path=(sysroot/'bin'/name).resolve(strict=True);tool_paths[name]={'path':str(path),**file_identity(path)}
        need(run([tool_paths['rustc']['path'],'-Vv'],'rustc-selected-version',15)==version,'Selected real Rust differs')
        environment.update(RUSTC=tool_paths['rustc']['path'],RUSTDOC=tool_paths['rustdoc']['path'],CARGO=tool_paths['cargo']['path'],RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='')
        metadata=run([tool_paths['cargo']['path'],'metadata','--locked','--format-version=1','--filter-platform','x86_64-unknown-linux-gnu','--manifest-path',str(isolated/'trillionnium/Cargo.toml')],'cargo-original-metadata',120)
        serde,serde_capture=utility.capture_serde_graph(load_json(metadata),isolated,output)
        built=run([tool_paths['cargo']['path'],'test','--locked','--manifest-path',str(isolated/'trillionnium/Cargo.toml'),'-p','trnm-mvcc-fee','--lib','--no-run','--message-format=json','--target-dir',str(target)],'cargo-original-test-build',900)
        artifacts=[load_json(line) for line in built.splitlines() if line.startswith(b'{')]
        serde_rows,binaries=utility.original_artifacts([row for row in artifacts if row.get('reason')=='compiler-artifact'])
        need(len(serde_rows)==1 and len(binaries)==1,'Expected exactly one actual serde library and one M06 test binary')
        need(serde_rows[0]['package_id']==serde['package']['id'] and set(serde_rows[0]['features'])=={'default','std'},'Actual serde graph/artifact differs')
        libraries=[Path(name).absolute() for name in serde_rows[0]['filenames'] if name.endswith('.rlib')]
        need(len(libraries)==1 and libraries[0]==libraries[0].resolve(strict=True) and target.resolve() in libraries[0].parents,'Actual serde library escaped target')
        lib=libraries[0];lib_id=file_identity(lib)
        with lib.open('rb') as source,(output/'actual-serde-library.rlib').open('xb') as destination:shutil.copyfileobj(source,destination,1<<20)
        (output/'actual-serde-library.rlib').chmod(0o400);need(file_identity(output/'actual-serde-library.rlib')==lib_id==file_identity(lib),'Serde library copy differs')
        serde_library={'artifact':serde_rows[0],'source_path':str(lib),'retained_path':str(output/'actual-serde-library.rlib'),'identity':lib_id};write_json(output/'actual-serde-library-before.json',serde_library)
        compiled=Path(binaries[0]['executable']).absolute();need(compiled==compiled.resolve(strict=True) and target.resolve() in compiled.parents,'Actual Rust binary escaped target')
        binary_identity=file_identity(compiled);binary=output/'original-test-binary'
        with compiled.open('rb') as source,binary.open('xb') as destination:shutil.copyfileobj(source,destination,1<<20)
        binary.chmod(0o500);need(file_identity(binary)==binary_identity==file_identity(compiled),'Independent binary copy differs')
        write_json(output/'original-binary-before.json',{'retained':str(binary),'source':str(compiled),'artifact':binaries[0],**binary_identity});fence('compiled-source-and-binary-before')
        listed=run([str(binary),'--list'],'list-original-tests',30);tests={line.removesuffix(': test') for line in listed.decode().splitlines() if line.endswith(': test')}
        need({TEST,*TESTS}<=tests,'Actual original test missing: '+repr({TEST,*TESTS}-tests))
        for index,name in enumerate(TESTS):
            observed=run([str(binary),'--exact',name,'--nocapture','--test-threads=1'],'retained-original-'+str(index));utility.assert_test_executed(observed,name);retained.append(name)
        observed=run([str(binary),'--exact',TEST,'--nocapture','--test-threads=1'],'actual-execution-application-corpus',600,dict(environment,TRNM_HIA_EXECUTION_APPLICATION_CORPUS=str(corpus_path)));utility.assert_test_executed(observed,TEST)
        contexts=[load_json(line.split(b'APCONTEXT:',1)[1]) for line in observed.splitlines() if b'APCONTEXT:' in line]
        actual=[load_json(line.split(b'AP_ORIGINAL:',1)[1]) for line in observed.splitlines() if b'AP_ORIGINAL:' in line]
        need(len(contexts)==1,'Actual original Config context missing');actual_context=contexts[0]
        for name in ('network','parameters','family','plan','params','fees','evaluators'):need(utility.same_json(actual_context[name],admitted['context'][name]),'Actual original/native Config differs: '+name)
        need(len(actual)==len(admitted['inputs']) and [row['name'] for row in actual]==[row['name'] for row in admitted['inputs']],'Original rows incomplete or reordered')
        for expected,row in zip(admitted['comparison']['cases'],actual,strict=True):
            differences=[key for key in ('name','before_hex','observations') if not utility.same_json(expected[key],row[key])]
            need(row.get('actual_private_preparation') is True and row.get('actual_original_application') is True and row.get('native_runtime_host_proxy') is False,'Actual original method provenance missing')
            controls.append({'name':expected['name'],'status':'FAIL' if differences else 'PASS','differences':differences,'native':expected,'original':row})
        write_json(output/'comparison.json',{'schema':'trnm.execution-application-original-controls.v1','controls':controls})
        need(all(row['status']=='PASS' for row in controls),'Actual original application differential failed')
    except BaseException as error:failure={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        try:fence('source-and-binary-after')
        except BaseException as error:final_errors.append({'fence':repr(error)})
        raw_path=output/'actual-execution-application-corpus/stdout.raw'
        if raw_path.is_file() and not actual:
            try:actual=[load_json(line.split(b'AP_ORIGINAL:',1)[1]) for line in raw_path.read_bytes().splitlines() if b'AP_ORIGINAL:' in line]
            except BaseException as error:final_errors.append({'partial_rows':repr(error)})
        for stage in stages:
            if file_identity(output/stage['stage']/'stdout.raw')!=stage['stdout'] or file_identity(output/stage['stage']/'stderr.raw')!=stage['stderr']:final_errors.append({'stage_log_changed':stage['stage']})
        status='NOT_RUN' if missing else 'PASS' if failure is None and not final_errors else 'FAIL'
        report={'schema':'trnm.execution-application-original.v1','status':status,'failure':failure,'final_errors':final_errors,'missing_actual_tools':missing,
          'stages':stages,'source_fences':fences,'actual_rust_tools':tool_paths,'serde_json_source':serde,'actual_serde_library':serde_library,
          'source_inputs':None if admitted is None else admitted['source_inputs'],'original_sources':original_map,'bundle_artifacts':None if admitted is None else admitted['bundle_artifacts'],
          'original_tests':retained,'required_original_tests':list(TESTS),'original_case_rows_observed':len(actual),'controls':len(controls),'passed':sum(row['status']=='PASS' for row in controls),'failed':sum(row['status']!='PASS' for row in controls),
          'original_test_binary':None if binary is None else {'path':str(binary),**binary_identity},'actual_original_context':actual_context,'elapsed_ns':time.monotonic_ns()-start,
          'complete_node':False,'production_runtime_dependency':False,'original_production_function_bytes_preserved':True,'runtime_host_proxy':False}
        write_json(output/'report.json',report)
        if actual:write_json(output/'original-observations.json',{'cases':actual,'complete_differential_pass':status=='PASS'})
        print(json.dumps({key:report[key] for key in ('status','failure','original_case_rows_observed','controls','passed','failed','elapsed_ns')}),flush=True)
    return report


def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,default=REPOSITORY);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--target-dir',type=Path);a=p.parse_args();return int(run_original(a)['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
