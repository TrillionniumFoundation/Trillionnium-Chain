"""Source/corpus and actual-bundle rejection controls without a Rust prerequisite.

The source-only fixture below is expressly not a native execution report. A
supplied real bundle adds public CLI and coherent-observation negative controls.
All rejected CLI invocations must stop before source copying or Cargo.
"""
from __future__ import annotations
import argparse,copy,json,lzma,os,shutil,struct,subprocess,sys,time,traceback
from pathlib import Path
from .source_graph import REPOSITORY,OWNED,REQUIRED,EXPLICIT,complete_sources,bound_corpus,identity,need
from .rust_oracle import validate_source_bindings,validate_bundle,utility


def write_json(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def source_fixture(repository):
    source,composed=complete_sources(repository)
    pin=utility.load_json((repository/'hia/qualification/compiler-binding.json').read_bytes())
    build={'schema':'trnm.execution-application-build.v1','status':'PASS','source_inputs':source,
           'source_set_sha256':utility.digest(utility.canonical_json(source)),
           'composed_sources':{name:identity(raw) for name,raw in composed.items()},
           'source_after':{'status':'PASS','errors':[]},'failure':None,'runtime_host_proxy':False,
           'original_rust_executed':False,'complete_node':False,'compiler_qualification_binding':pin,
           'compiler_sha256':pin['compiler_sha256'],'toolchain':utility.load_json((repository/'hia/toolchain.lock.json').read_bytes())}
    return {'schema':'trnm.execution-application-comparison.v1','status':'PASS','build':build}


def qualify(output,bundle=None):
    output=output.absolute();need(output.resolve()==output and not output.exists() and REPOSITORY not in output.parents,'Fresh integrity output outside repository required')
    output.mkdir(mode=0o700);started=time.monotonic_ns();controls=[];primary=None;groups=set();source=None;original=None
    def passed(group,name,**details):groups.add(group);controls.append({'group':group,'name':name,'status':'PASS',**details})
    def reject(group,name,call):
        try:call()
        except (RuntimeError,ValueError,FileNotFoundError,NotADirectoryError,KeyError,AssertionError) as error:
            passed(group,name,actual_rejection=repr(error));return
        raise AssertionError('Invalid input accepted: '+name)
    def changed(path,raw,call):
        before=path.read_bytes()
        try:path.write_bytes(raw);return call()
        finally:path.write_bytes(before)
    def absent(path,call):
        before=path.read_bytes()
        try:path.unlink();return call()
        finally:path.write_bytes(before)
    def cli(name,selected_bundle,*,environment=None,target=None,optimized=False):
        directory=output/('cli-'+name);directory.mkdir();result=directory/'output'
        env=dict(os.environ);env.pop('PYTHONOPTIMIZE',None);env['PYTHONDONTWRITEBYTECODE']='1'
        for key in list(env):
            if utility.forbidden_override(key):env.pop(key)
        env.update(environment or {})
        argv=[sys.executable,'-B']+(['-O'] if optimized else [])+['-m','hia.platform.execution_application.rust_oracle','--repository',str(REPOSITORY),'--bundle',str(selected_bundle),'--output',str(result)]
        if target is not None:argv+=['--target-dir',str(target)]
        begin=time.monotonic_ns();process=subprocess.run(argv,cwd=REPOSITORY,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        (directory/'stdout.raw').write_bytes(process.stdout);(directory/'stderr.raw').write_bytes(process.stderr)
        need(process.returncode!=0 and not (result/'isolated-source').exists(),'Invalid public input reached source copy or returned success')
        report=utility.load_json((result/'report.json').read_bytes()) if (result/'report.json').is_file() else None
        if report is not None:need(report['status']=='FAIL' and report['stages']==[] and report['original_test_binary'] is None,'Invalid public input reached Rust/Cargo')
        receipt={'argv':argv,'exit_code':process.returncode,'elapsed_ns':time.monotonic_ns()-begin,'stdout':identity(process.stdout),'stderr':identity(process.stderr),'report_written':report is not None,'source_copy_created':False,'original_rust_executed':False}
        write_json(directory/'receipt.json',receipt);passed('public-cli',name,receipt=receipt)
    try:
        source,_=complete_sources(REPOSITORY);original=utility.original_manifest(REPOSITORY)
        temporary=output/'source-fixture';temporary.mkdir()
        for name,row in source.items():
            path=temporary/name;path.parent.mkdir(parents=True,exist_ok=True);raw=(REPOSITORY/name).read_bytes();need(identity(raw)==row,'Source changed during fixture copy');path.write_bytes(raw)
        fixture=source_fixture(temporary);actual,_=validate_source_bindings(temporary,fixture)
        need(actual==source,'Source-only fixture closure differs');passed('source-closure','actual-complete-dynamic-source-fixture',native_execution_claim=False,source_files=len(source))
        for name in source:
            mutant=copy.deepcopy(fixture);del mutant['build']['source_inputs'][name]
            mutant['build']['source_set_sha256']=utility.digest(utility.canonical_json(mutant['build']['source_inputs']))
            reject('every-source-omission','omitted-'+name,lambda m=mutant:validate_source_bindings(temporary,m))
        for name in sorted(REQUIRED):
            reject('physical-source-omission','missing-owned-'+name,lambda n=name:absent(temporary/OWNED/n,lambda:complete_sources(temporary)))
        for name in ('hia/platform/build.py','hia/components.json','hia/src/crypto/ed25519_verify.hepta','config/pon/devnet-v1.json'):
            reject('physical-source-omission','missing-shared-'+name,lambda n=name:absent(temporary/n,lambda:complete_sources(temporary)))
        for field,value in [('source_set_sha256','0'*64),('compiler_sha256','0'*64),('runtime_host_proxy',True),('original_rust_executed',True),('complete_node',True),('source_after',{'status':'PASS','errors':['changed']})]:
            mutant=copy.deepcopy(fixture);mutant['build'][field]=value
            reject('forged-binding','forged-'+field,lambda m=mutant:validate_source_bindings(temporary,m))
        for name in ('../escaped.py','hia/../escaped.py','/absolute.py','hia\\escaped.py'):
            mutant=copy.deepcopy(fixture);mutant['build']['source_inputs'][name]=identity(b'')
            reject('path-and-inventory','escaping-'+repr(name),lambda m=mutant:validate_source_bindings(temporary,m))
        future=temporary/OWNED/'future_dependency.py';future.write_bytes(b'"""Future source fixture; never executed."""\n')
        try:
            enlarged,_=complete_sources(temporary);need(OWNED+'/future_dependency.py' in enlarged,'Future owned source not dynamically captured')
            reject('path-and-inventory','new-owned-source-cannot-be-omitted',lambda:validate_source_bindings(temporary,fixture))
        finally:future.unlink()
        link=temporary/OWNED/'borrowed.py';link.symlink_to(temporary/OWNED/'cases.py')
        try:reject('path-and-inventory','symbolic-owned-source',lambda:complete_sources(temporary))
        finally:link.unlink()
        cache=temporary/OWNED/'__pycache__';cache.mkdir();(cache/'cases.pyc').write_bytes(b'not source')
        try:reject('path-and-inventory','stale-bytecode-directory',lambda:complete_sources(temporary))
        finally:shutil.rmtree(cache)
        includes=temporary/OWNED/'includes.json';decoded=utility.load_json(includes.read_bytes());core='platform/execution_application/core.hepta'
        for name,row in [('cycle',{'source':core,'functions':['f0']}),('missing-function',{'source':'src/crypto/sha256.hepta','functions':['not_a_native_function']}),('escaping-include',{'source':'../../outside.hepta','functions':['f0']})]:
            mutant=copy.deepcopy(decoded);mutant['includes'][core].append(row)
            reject('native-dependency-closure',name,lambda m=mutant:changed(includes,(json.dumps(m)+'\n').encode(),lambda:complete_sources(temporary)))
        reject('native-dependency-closure','duplicate-json-key',lambda:changed(includes,b'{"schema":"a","schema":"b","includes":{}}',lambda:complete_sources(temporary)))
        raw,rows,_=bound_corpus(REPOSITORY);copy_raw,copy_rows,_=bound_corpus(temporary)
        need(raw==copy_raw and utility.same_json(rows,copy_rows),'Direct source-derived corpus differs');passed('canonical-corpus','source-derived-328-histories',corpus=identity(raw),histories=len(rows),transactions=sum(len(row['transactions']) for row in rows))
        archive=output/'xz-fixture.xz';encoded=lzma.compress(raw);archive.write_bytes(encoded)
        utility.bounded_xz(archive,raw);passed('canonical-corpus','single-bounded-xz-stream')
        for label,invalid in [('truncated',encoded[:-1]),('trailing',encoded+b'x'),('concatenated',encoded+lzma.compress(b'')),('different',lzma.compress(raw+b'\n'))]:
            reject('canonical-corpus','xz-'+label,lambda data=invalid:changed(archive,data,lambda:utility.bounded_xz(archive,raw)))
        empty=output/'unexecuted-empty-bundle';empty.mkdir()
        for key in ('RUSTC','CARGO_BUILD_RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOC','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER'):
            cli('override-'+key.lower(),empty,environment={key:'/not-an-admitted-compiler-or-option'})
        cli('optimized-python',empty,optimized=True)
        if bundle is not None:
            bundle=utility.canonical_root(bundle);admitted=validate_bundle(REPOSITORY,bundle)
            passed('actual-bundle','actual-complete-native-bundle',histories=len(admitted['inputs']),artifacts=len(admitted['bundle_artifacts']))
            candidate=output/'mutant-bundle';shutil.copytree(bundle,candidate,symlinks=False)
            saved={name:(candidate/name).read_bytes() for name in ('native-comparison.json','native-report.json')}
            def restore():
                for name,raw_bytes in saved.items():(candidate/name).write_bytes(raw_bytes)
            def coherent(comparison=None,report=None):
                comparison=copy.deepcopy(admitted['comparison']) if comparison is None else comparison
                report=copy.deepcopy(admitted['report']) if report is None else report
                comparison_raw=(json.dumps(comparison,sort_keys=True,indent=2)+'\n').encode();(candidate/'native-comparison.json').write_bytes(comparison_raw)
                report['comparison']=identity(comparison_raw);write_json(candidate/'native-report.json',report)
            for label,mutator in [('source-omission',lambda c:c['build']['source_inputs'].pop(OWNED+'/quota.hepta')),
                                  ('semantic-observation',lambda c:c['cases'][0]['observations'][0].__setitem__('fee',c['cases'][0]['observations'][0]['fee']+1)),
                                  ('history-omission',lambda c:c['cases'].pop()),
                                  ('process-omission',lambda c:c['processes'].pop())]:
                mutant=copy.deepcopy(admitted['comparison']);mutator(mutant);coherent(mutant)
                try:
                    reject('actual-bundle','coherent-'+label,lambda:validate_bundle(REPOSITORY,candidate))
                    cli('valid-bundle-'+label,candidate)
                finally:restore()
            native_stdin=candidate/'processes/000/stdin.raw';original_bytes=native_stdin.read_bytes();changed_bytes=bytearray(original_bytes);changed_bytes[16]^=1
            receipt_path=candidate/'processes/000/receipt.json';original_receipt=receipt_path.read_bytes()
            try:
                native_stdin.write_bytes(changed_bytes);receipt=utility.load_json(original_receipt);receipt['files']['stdin.raw']=identity(changed_bytes);write_json(receipt_path,receipt)
                mutant=copy.deepcopy(admitted['comparison']);mutant['processes'][0]['receipt']=receipt;coherent(mutant)
                reject('actual-bundle','coherent-actual-stdin-semantic-tamper',lambda:validate_bundle(REPOSITORY,candidate))
                cli('valid-bundle-actual-stdin-tamper',candidate)
            finally:native_stdin.write_bytes(original_bytes);receipt_path.write_bytes(original_receipt);restore()
            for name in ('native-build/quota.flat','processes/008/observed-frames.json'):
                reject('actual-bundle','missing-'+name,lambda n=name:absent(candidate/n,lambda:validate_bundle(REPOSITORY,candidate)))
            extra=candidate/'unbound-result.json';extra.write_bytes(b'{}')
            try:reject('actual-bundle','extra-artifact',lambda:validate_bundle(REPOSITORY,candidate))
            finally:extra.unlink()
            xz_path=candidate/'corpus.jsonl.xz';xz_before=xz_path.read_bytes()
            try:
                xz_path.write_bytes(xz_before+lzma.compress(b''));mutant=copy.deepcopy(admitted['comparison']);mutant['corpus']['compressed']=identity(xz_path.read_bytes())
                report=copy.deepcopy(admitted['report']);report['corpus']=mutant['corpus'];coherent(mutant,report)
                reject('actual-bundle','coherent-concatenated-corpus-stream',lambda:validate_bundle(REPOSITORY,candidate))
            finally:xz_path.write_bytes(xz_before);restore()
            validate_bundle(REPOSITORY,candidate);passed('actual-bundle','all-mutants-restored-to-exact-valid-bundle')
            cli('target-inside-repository',bundle,target=REPOSITORY/'tria-invalid-application-target')
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        after=[]
        if source is not None:
            try:need(complete_sources(REPOSITORY)[0]==source and utility.original_manifest(REPOSITORY)==original,'Integrity tests changed their bound sources')
            except BaseException as error:after.append(repr(error))
        report={'schema':'trnm.execution-application-integrity.v1','status':'PASS' if primary is None and not after else 'FAIL',
            'groups':len(groups),'controls':controls,'controls_total':len(controls),'public_cli_controls':sum(c['group']=='public-cli' for c in controls),
            'actual_bundle_checked':bundle is not None,'primary_error':primary,'source_after':{'status':'PASS' if not after else 'FAIL','errors':after},
            'source_inputs':source,'source_set_sha256':None if source is None else utility.digest(utility.canonical_json(source)),
            'source_fixture_is_native_execution_claim':False,'original_rust_executed':False,'elapsed_ns':time.monotonic_ns()-started}
        write_json(output/'report.json',report);print(json.dumps({k:report[k] for k in ('status','groups','controls_total','public_cli_controls','actual_bundle_checked','primary_error','source_after','elapsed_ns')}),flush=True)
    return report


def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--bundle',type=Path);a=p.parse_args()
    return int(qualify(a.output,a.bundle)['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
