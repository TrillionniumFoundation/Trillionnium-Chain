"""Strict complete native admission followed by actual original M06 methods."""
from __future__ import annotations
import argparse,json,os,shutil,time,traceback
from pathlib import Path
from hia.platform.execution_state import rust_oracle as utility
from . import safe_io as safe
from .source_graph import REPOSITORY,OWNED,complete_sources,original_manifest,bound_corpus,check_sources,identity,digest,need
from .bundle import admit_complete,identities
from .batch_observations import compare as compare_batch
from .prefix_observations import compare as compare_prefix
STORE=utility.STORE
BATCH_TESTS=(
 'pon_executor::repeated_sender_tests::repeated_sender_complete_signed_batches_keep_state_receipts_root_and_every_signature',
 'pon_executor::repeated_sender_tests::repeated_sender_complete_failures_preserve_canonical_first_error_and_parent',
 'pon_executor::repeated_sender_tests::repeated_sender_tag11_and_cross_sender_funding_keep_complete_canonical_relation',
 'pon_executor::repeated_sender_tests::repeated_sender_cancel_and_partial_worker_start_join_all_actual_workers',
 'pon_executor::account_conflict_tests::account_conflict_common_recipient_elides_real_predictions_without_skipping_signatures',
 'pon_executor::account_conflict_tests::account_conflict_funding_chain_and_prior_sender_recipient_keep_canonical_results',
 'pon_executor::account_conflict_tests::account_conflict_disjoint_and_self_transfers_retain_parallel_work',
 'pon_executor::account_conflict_tests::account_conflict_unpredicted_task_payment_still_replays_once_against_exact_reads',
 'pon_executor::account_conflict_tests::account_conflict_untrusted_hints_preserve_full_validation_and_first_error')
PREFIX_TESTS=(
 'pon_commitment::full_root_arithmetic_tests::arithmetic_prefix_keeps_two_signed_appends_and_cancelled_successor_rollback',
 'pon_executor::prefix_scan_tests::prefix_rows_preserve_original_filter_order_values_and_all_string_boundaries',
 'pon_executor::prefix_scan_tests::prefix_scan_overlays_writes_and_retains_the_original_snapshot',
 'pon_executor::prefix_scan_tests::prefix_scan_revalidation_keeps_insert_delete_and_value_conflicts',
 'pon_executor::prefix_scan_tests::prefix_scan_does_not_replace_point_read_or_write_conflict_checks',
 'pon_executor::prefix_scan_tests::empty_and_nested_prefix_snapshots_revalidate_the_complete_observed_sets')
PROFILES={
 'batch':{'module':'hia_execution_batch_oracle','source':'rust_batch_reference.rs','tests':BATCH_TESTS,
          'environment':'TRNM_HIA_EXECUTION_BATCH_CORPUS','context':b'BPCONTEXT:','result':b'BP_ORIGINAL:','stage':'actual-execution-batch-corpus','compare':compare_batch},
 'prefix':{'module':'hia_transaction_prefix_oracle','source':'rust_prefix_reference.rs','tests':PREFIX_TESTS,
           'environment':'TRNM_HIA_TRANSACTION_PREFIX_CORPUS','context':b'PXCONTEXT:','result':b'PX_ORIGINAL:','stage':'actual-transaction-prefix-corpus','compare':compare_prefix}}
def bound_target(value,output,repository,bundles,isolated):
    """Apply the real target admission to every bound source partition."""
    need(isinstance(bundles,(list,tuple)) and bundles,'At least one bound native bundle is required')
    target=None
    for bundle in bundles:
        observed=utility.safe_target(value,output,repository,bundle,isolated)
        need(target is None or observed==target,'Cargo target changed between native partitions')
        target=observed
    return target
def run_original(args):
    repository=utility.canonical_root(args.repository);bundles=[utility.canonical_root(path) for path in args.bundle]
    need(utility.canonical_path(repository,OWNED+'/rust_oracle.py')==Path(__file__).absolute(),'Run the oracle from the selected complete repository')
    need(args.profile in PROFILES,'Known exact original profile');profile=PROFILES[args.profile]
    output=args.output.absolute();need(output.resolve()==output and not output.exists(),'Fresh nonsymbolic output required')
    for path in (repository,*bundles):need(output!=path and path not in output.parents,'Output overlaps original inputs')
    output.mkdir(mode=0o700);isolated=output/'isolated-source';started=time.monotonic_ns()
    stages=[];fences=[];retained=[];controls=[];actual=[];admitted=None;original=None
    tools=None;serde=None;serde_capture=None;serde_library=None;isolated_expected=None;binary=None;binary_id=None
    environment=None;failure=None;final_errors=[];actual_context=None;target=None
    def fence(label):
        checks={};errors=[]
        def check(name,fn):
            try:checks[name]=fn()
            except BaseException as error:errors.append({'name':name,'error':repr(error)})
        if admitted is not None:
            def sources():
                observed,_=complete_sources(repository);need(safe.same(observed,admitted['source_inputs']),'Complete native source changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(observed)}
            def originals():
                observed=original_manifest(repository);need(safe.same(observed,original),'Complete original source changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(observed)}
            def artifacts():
                maps=[]
                for path,part in zip(bundles,admitted['parts_by_argument'],strict=True):
                    observed=identities(path);need(safe.same(observed,part['bundle_artifacts']),'Complete native partition artifact changed');maps.append(observed)
                raw,_=bound_corpus(repository,args.profile);need(raw==admitted['corpus_raw'],'Full source-defined corpus changed')
                return {'status':'MATCH','partitions':len(maps),'files':sum(len(row) for row in maps),'sha256':digest(maps)}
            check('complete_native_source',sources);check('actual_original_source',originals);check('complete_native_artifacts_and_corpus',artifacts)
        if isolated_expected is not None:
            def copied():
                observed=original_manifest(isolated);need(safe.same(observed,isolated_expected),'Sole appended hook/original copy changed')
                need(identity(safe.read(output,'corpus.jsonl'))==identity(admitted['corpus_raw']),'Actual original input changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(observed)}
            check('isolated_original_and_exact_hook',copied)
        if binary is not None:
            def executable():
                observed=utility.file_identity(binary);need(safe.same(observed,binary_id),'Actual independent original binary changed')
                return {'status':'MATCH',**observed}
            check('actual_original_binary',executable)
        if serde_capture is not None:
            def serde_source():
                observed=serde_capture();need(safe.same(observed,serde['crate_sources']),'Actual locked serde source changed')
                return {'status':'MATCH','files':len(observed),'sha256':digest(observed)}
            check('actual_serde_source',serde_source)
        if serde_library is not None:
            def library():
                need(safe.same(utility.file_identity(output/'actual-serde-library.rlib'),serde_library['identity']),'Retained actual serde library changed')
                return {'status':'MATCH',**serde_library}
            check('actual_serde_library',library)
        if tools is not None:
            def tool_bytes():
                for name,row in tools.items():need(safe.same(utility.file_identity(Path(row['path'])),{key:row[key] for key in ('bytes','sha256')}),'Actual tool changed: '+name)
                return {'status':'MATCH','tools':tools}
            check('actual_compilers',tool_bytes)
        receipt={'label':label,'status':('PASS' if admitted is not None else 'NOT_REACHED') if not errors else 'FAIL','checks':checks,'errors':errors}
        fences.append(receipt);safe.write_json(output/(label+'.json'),receipt);need(not errors,'Final source/artifact fence failed')
    def run(argv,label,timeout=240,env=None):
        return utility.run_command(argv,isolated,output,label,stages,timeout=timeout,environment=environment if env is None else env)[0]
    try:
        # Refuse environment substitutions before source copying or any compiler invocation.
        environment=utility.clean_build_environment()
        need(args.target_dir is not None,'Actual original execution requires an isolated Cargo target')
        target=bound_target(args.target_dir,output,repository,bundles,isolated)
        admitted=admit_complete(repository,bundles,args.profile);original=admitted['original_sources']
        part_index={row['comparison']['partition']['index']:row for row in admitted['parts']}
        admitted['parts_by_argument']=[part_index[safe.load(path,'native-comparison.json')['partition']['index']] for path in bundles]
        safe.write_json(output/'admission.json',{'status':'ADMITTED_NOT_ORIGINAL_EXECUTED','profile':args.profile,'source_inputs':admitted['source_inputs'],'original_sources':original,
         'native_executable':admitted['executable'],'corpus':identity(admitted['corpus_raw']),'partitions':[{'path':str(path),'index':part['comparison']['partition']['index'],'artifacts':part['bundle_artifacts']} for path,part in zip(bundles,admitted['parts_by_argument'],strict=True)]})
        fence('source-before');need(shutil.which('rustc') and shutil.which('cargo'),'Actual Rust tools unavailable')
        isolated.mkdir(mode=0o700)
        for name,row in original.items():
            raw=safe.read(repository,name);need(identity(raw)==row,'Original source changed during actual copy')
            destination=isolated/name;destination.parent.mkdir(parents=True,exist_ok=True)
            with destination.open('xb') as out:out.write(raw)
            need(utility.file_identity(destination)==row,'Actual original copy differs')
        original_store=safe.read(isolated,STORE);module=profile['module'];hook=module+'.rs'
        declaration=('\n#[cfg(test)]\n#[path = "'+hook+'"]\nmod '+module+';\n').encode()
        need(('mod '+module).encode() not in original_store,'Original production source was already hooked')
        hook_raw=safe.read(repository,OWNED+'/'+profile['source']);hook_path=(isolated/STORE).parent/hook
        with hook_path.open('xb') as out:out.write(hook_raw)
        with (isolated/STORE).open('ab') as out:out.write(declaration)
        isolated_expected={**original,STORE:identity(original_store+declaration),hook_path.relative_to(isolated).as_posix():identity(hook_raw)}
        corpus_path=output/'corpus.jsonl';corpus_path.write_bytes(admitted['corpus_raw']);fence('isolated-source-before')
        version=run(['rustc','-Vv'],'rustc-version',15);need(b'host: x86_64-unknown-linux-gnu\n' in version,'Wrong actual Rust host')
        sysroot=Path(run(['rustc','--print','sysroot'],'rustc-sysroot',15).decode().strip()).resolve(strict=True);tools={}
        for name in ('rustc','cargo','rustdoc'):
            path=(sysroot/'bin'/name).resolve(strict=True);tools[name]={'path':str(path),**utility.file_identity(path)}
        need(run([tools['rustc']['path'],'-Vv'],'rustc-selected-version',15)==version,'Actual selected Rust version differs')
        environment.update(RUSTC=tools['rustc']['path'],RUSTDOC=tools['rustdoc']['path'],CARGO=tools['cargo']['path'],RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='')
        metadata=run([tools['cargo']['path'],'metadata','--locked','--format-version=1','--filter-platform','x86_64-unknown-linux-gnu','--manifest-path',str(isolated/'trillionnium/Cargo.toml')],'cargo-original-metadata',120)
        serde,serde_capture=utility.capture_serde_graph(safe.json_load(metadata),isolated,output)
        built=run([tools['cargo']['path'],'test','--locked','--manifest-path',str(isolated/'trillionnium/Cargo.toml'),'-p','trnm-mvcc-fee','--lib','--no-run','--message-format=json','--target-dir',str(target)],'cargo-original-test-build',900)
        artifacts=[safe.json_load(line) for line in built.splitlines() if line.startswith(b'{')]
        serde_rows,binaries=utility.original_artifacts([row for row in artifacts if row.get('reason')=='compiler-artifact'])
        need(len(serde_rows)==len(binaries)==1,'One actual serde library and one original test binary')
        library_row=serde_rows[0];need(library_row['package_id']==serde['package']['id'] and set(library_row['features'])=={'default','std'},'Actual locked serde metadata/library features differ')
        libraries=[Path(name).absolute() for name in library_row['filenames'] if name.endswith('.rlib')]
        need(len(libraries)==1 and libraries[0]==libraries[0].resolve(strict=True) and target.resolve() in libraries[0].parents,'Actual serde library escaped isolated target')
        library=libraries[0];library_id=utility.file_identity(library)
        with library.open('rb') as source,(output/'actual-serde-library.rlib').open('xb') as out:shutil.copyfileobj(source,out,1<<20)
        (output/'actual-serde-library.rlib').chmod(0o400)
        need(utility.file_identity(output/'actual-serde-library.rlib')==library_id==utility.file_identity(library),'Independent serde library copy changed')
        serde_library={'artifact':library_row,'source_path':str(library),'retained_path':str(output/'actual-serde-library.rlib'),'identity':library_id}
        safe.write_json(output/'actual-serde-library-before.json',serde_library)
        compiled=Path(binaries[0]['executable']).absolute()
        need(compiled==compiled.resolve(strict=True) and target.resolve() in compiled.parents,'Original test binary escaped isolated target')
        binary_id=utility.file_identity(compiled);binary=output/'original-test-binary'
        with compiled.open('rb') as source,binary.open('xb') as out:shutil.copyfileobj(source,out,1<<20)
        binary.chmod(0o500);need(utility.file_identity(binary)==binary_id==utility.file_identity(compiled),'Independent original binary differs')
        safe.write_json(output/'original-binary-before.json',{'retained':str(binary),'source':str(compiled),'artifact':binaries[0],**binary_id})
        fence('compiled-source-and-binary-before')
        listed=run([str(binary),'--list'],'list-original-tests',30);tests={line.removesuffix(': test') for line in listed.decode().splitlines() if line.endswith(': test')}
        test='pon_executor::'+module+'::evaluate';required=profile['tests'];need({test,*required}<=tests,'Missing actual original test: '+repr({test,*required}-tests))
        for index,name in enumerate(required):
            observed=run([str(binary),'--exact',name,'--nocapture','--test-threads=1'],'retained-original-'+str(index))
            utility.assert_test_executed(observed,name);retained.append(name)
        observed=run([str(binary),'--exact',test,'--nocapture','--test-threads=1'],profile['stage'],600,dict(environment,**{profile['environment']:str(corpus_path)}))
        utility.assert_test_executed(observed,test)
        contexts=[safe.json_load(line.split(profile['context'],1)[1]) for line in observed.splitlines() if profile['context'] in line]
        actual=[safe.json_load(line.split(profile['result'],1)[1]) for line in observed.splitlines() if profile['result'] in line]
        need(len(contexts)==1,'Actual complete original Config context missing');actual_context=contexts[0]
        need(len(actual)==len(admitted['inputs']) and [row['name'] for row in actual]==[row['name'] for row in admitted['inputs']],'Actual original histories incomplete/reordered')
        for native,row,case in zip(admitted['cases'],actual,admitted['inputs'],strict=True):controls.append(profile['compare'](native,row,case,actual_context))
        safe.write_json(output/'comparison.json',{'schema':'trnm.execution-batch-original-controls.v1','profile':args.profile,'controls':controls})
        need(all(row['status']=='PASS' for row in controls),'Actual original M06 differential failed')
    except BaseException as error:failure={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        try:fence('source-and-binary-after')
        except BaseException as error:final_errors.append({'fence':repr(error)})
        raw_path=output/profile['stage']/'stdout.raw'
        if raw_path.is_file() and not actual:
            try:actual=[safe.json_load(line.split(profile['result'],1)[1]) for line in raw_path.read_bytes().splitlines() if profile['result'] in line]
            except BaseException as error:final_errors.append({'partial_rows':repr(error)})
        for stage in stages:
            try:
                for stream in ('stdout','stderr'):need(utility.file_identity(output/stage['stage']/(stream+'.raw'))==stage[stream],'Actual command raw log changed')
            except BaseException as error:final_errors.append({'stage':stage['stage'],'error':repr(error)})
        report={'schema':'trnm.execution-batch-original-qualification.v1','status':'PASS' if failure is None and not final_errors else 'FAIL','profile':args.profile,
         'failure':failure,'final_errors':final_errors,'stages':stages,'source_fences':fences,'actual_rust_tools':tools,'serde_json_source':serde,'actual_serde_library':serde_library,
         'source_inputs':None if admitted is None else admitted['source_inputs'],'original_sources':original,'native_executable':None if admitted is None else admitted['executable'],
         'native_partitions':None if admitted is None else [{'index':part['comparison']['partition']['index'],'build':part['comparison']['build'],'artifacts':part['bundle_artifacts']} for part in admitted['parts']],
         'corpus':None if admitted is None else identity(admitted['corpus_raw']),'original_tests':retained,'required_original_tests':list(profile['tests']),'actual_original_context':actual_context,
         'original_case_rows_observed':len(actual),'controls':len(controls),'passed':sum(row['status']=='PASS' for row in controls),'failed':sum(row['status']!='PASS' for row in controls),
         'original_test_binary':None if binary is None else {'path':str(binary),**binary_id},'elapsed_ns':time.monotonic_ns()-started,'complete_node':False,'admission_persistence':False}
        safe.write_json(output/'report.json',report)
        safe.write_json(output/'original-observations.json',{'cases':actual,'complete_differential_pass':report['status']=='PASS'})
    need(report['status']=='PASS','Actual original qualification failed; all partial output and source fences retained')
    return report
def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    parser=argparse.ArgumentParser();parser.add_argument('--repository',type=Path,default=REPOSITORY);parser.add_argument('--bundle',type=Path,action='append',required=True)
    parser.add_argument('--profile',choices=('batch','prefix'),required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--target-dir',type=Path);parser.add_argument('--validate-only',action='store_true')
    args=parser.parse_args()
    need(utility.canonical_path(utility.canonical_root(args.repository),OWNED+'/rust_oracle.py')==Path(__file__).absolute(),'Run admission from the selected exact source')
    if args.validate_only:
        utility.clean_build_environment();need(args.target_dir is None,'Validation does not use a Cargo target')
        try:
            admitted=admit_complete(args.repository,args.bundle,args.profile)
            report={'schema':'trnm.execution-batch-public-admission.v1','status':'PASS','profile':args.profile,'histories':len(admitted['inputs']),'source_set_sha256':digest(admitted['source_inputs']),'native_executable':admitted['executable'],'actual_original_executed':False}
        except BaseException as error:report={'schema':'trnm.execution-batch-public-admission.v1','status':'FAIL','profile':args.profile,'error':repr(error),'traceback':traceback.format_exc(),'actual_original_executed':False}
        output=args.output.absolute();need(output.resolve()==output and not output.exists(),'Fresh validation output');output.mkdir(mode=0o700);safe.write_json(output/'report.json',report)
        print(json.dumps({key:value for key,value in report.items() if key!='traceback'},sort_keys=True));return 0 if report['status']=='PASS' else 1
    result=run_original(args);print(json.dumps({key:result[key] for key in ('status','profile','original_case_rows_observed','passed','failed','elapsed_ns')},sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
