"""Adversarial source, fixture, file and public evidence-entry controls."""
from __future__ import annotations
import argparse,copy,hashlib,json,lzma,os,shutil,socket,stat,struct,subprocess,sys,tempfile,time,traceback
from pathlib import Path
from . import source_graph as graph
from . import safe_io as safe
from . import cases
from . import build_evidence
from . import bundle as admission
from .lifecycle import plans
ROOT=graph.REPOSITORY
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True);parser.add_argument('--bundle',type=Path);parser.add_argument('--profile',choices=('batch','prefix'))
    args=parser.parse_args();graph.need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    graph.need((args.bundle is None)==(args.profile is None),'A bound bundle and profile are supplied together')
    report_path=args.report.absolute();graph.need(not report_path.exists(),'Fresh integrity report')
    report_path.parent.mkdir(parents=True,exist_ok=True)
    observations=report_path.parent/(report_path.stem+'-observations');observations.mkdir(mode=0o700)
    controls=[];groups=[];primary=None;cleanup=[];started=time.monotonic_ns();source_before=None;original_before=None
    def okay(name,condition):
        graph.need(condition,name);controls.append({'name':name,'status':'PASS'})
    def refuses(name,call):
        caught=None
        try:call()
        except (ValueError,RuntimeError,OSError,KeyError,TypeError,AssertionError,lzma.LZMAError) as error:caught=repr(error)
        graph.need(caught is not None,'Invalid input accepted: '+name);controls.append({'name':name,'status':'PASS','refusal':caught})
    def cli(name,module,arguments,*,expected=0,contains=None,env=None,optimized=False):
        directory=observations/name;directory.mkdir(mode=0o700)
        argv=[sys.executable,'-B',*(['-O'] if optimized else []),'-m','hia.platform.execution_batch.'+module,*map(str,arguments)]
        environment=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
        if env:environment.update(env)
        begin=time.monotonic_ns();failure=None;child=None;stdout=b'';stderr=b'';exit_code=None
        try:
            child=subprocess.Popen(argv,cwd=ROOT,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:stdout,stderr=child.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,9);stdout,stderr=child.communicate(timeout=3);raise ValueError('Public admission control timed out')
            exit_code=child.returncode
            graph.need(exit_code==0 if expected==0 else exit_code!=0,'Actual public CLI exit '+name)
            if contains is not None:graph.need(contains.encode() in stdout+stderr,'Actual refusal is attributed to the intended gate: '+name)
        except BaseException as error:failure={'error':repr(error),'traceback':traceback.format_exc()}
        finally:
            if child is not None and child.poll() is None:
                os.killpg(child.pid,9);child.wait(timeout=3)
            (directory/'stdout.raw').write_bytes(stdout);(directory/'stderr.raw').write_bytes(stderr)
            row={'name':name,'status':'PASS' if failure is None else 'FAIL','argv':argv,'cwd':str(ROOT),'pid':None if child is None else child.pid,
              'exit_code':exit_code,'elapsed_ns':time.monotonic_ns()-begin,'timeout_seconds':60,'cleanup_seconds':3,'environment_overrides':env or {},'failure':failure,
              'stdout':safe.identity(stdout),'stderr':safe.identity(stderr)}
            safe.write_json(directory/'receipt.json',row);controls.append(row)
        graph.need(failure is None,'Public CLI control failed: '+name)
    def group(name,call):
        begin=len(controls);call();groups.append({'name':name,'status':'PASS','controls':len(controls)-begin})
    try:
        source_before,profiles=graph.complete_sources();original_before=graph.original_manifest()
        def closure():
            okay('three complete native profiles',set(profiles)==set(graph.PROFILES))
            okay('nineteen ordered native images',len(graph.IMAGE_ORDER)==19 and all(set(v)==set(graph.IMAGE_ORDER)|{'emitter'} for v in profiles.values()))
            own=[name for name in source_before if name.startswith(graph.OWNED+'/')]
            okay('all sixteen canonical HIA files',sum(name.endswith('.hepta') for name in own)==16)
            okay('source includes every hosted controller',all(graph.OWNED+'/'+name in source_before for name in graph.REQUIRED))
            for name in ('tests/vectors/pon/native-growth-reference-v2.json','tests/fixtures/cpq1-content-v1/vectors.json'):
                okay('actual original compile-time fixture '+name,name in original_before)
            okay('complete original source and fixtures',len(original_before)==4363)
            for profile,images in profiles.items():
                for name,raw in images.items():
                    counts=build_evidence.core_counts(raw)
                    okay('bounded actual Core source '+profile+'/'+name,0<counts['functions']<=128 and 0<counts['blocks']<=1536 and 0<counts['ops']<=8192)
        group('complete-source-and-function-closure',closure)
        corpus={}
        def fixtures():
            expected={'batch':(102,268876,'451d6435a09c25c862ab67f882ad831d88013f39041b5e2cd272962ed8992a3a'),
             'prefix':(186,2968271,'53e5dd524ac12911f9ecb06c2926c8ebe9628c8323cc69851536a045a53f5b63')}
            for profile,(count,size,digest) in expected.items():
                raw,rows=graph.bound_corpus(ROOT,profile);corpus[profile]=(raw,rows)
                okay('exact retained input corpus '+profile,len(rows)==count and len(raw)==size and hashlib.sha256(raw).hexdigest()==digest)
                indices=[index for part in range(1 if profile=='batch' else cases.PREFIX_PARTS) for index in cases.selection(profile,part)]
                okay('complete disjoint partition '+profile,len(indices)==len(set(indices))==count and sorted(indices)==list(range(count)))
            scoped=plans(ROOT)
            okay('complete six private lifetime histories',len(scoped)==6)
            okay('all original private methods retained',sum(len(row['steps']) for row in scoped)==69)
            for profile,part in [('prefix',False),('prefix',-1),('prefix',4),('batch',1)]:
                refuses('invalid partition '+repr((profile,part)),lambda p=profile,q=part:cases.selection(p,q))
        group('exact-full-corpus-and-partitions',fixtures)
        def fixture_types():
            rows=corpus['prefix'][1]
            for name,key,value in [('timestamp-string','timestamp','1'),('timestamp-bool','timestamp',False),('height-float','height',10.0),('height-negative','height',-1),('timestamp-too-large','timestamp',1<<64)]:
                bad=copy.deepcopy(rows);bad[0]['commands'][0][key]=value;refuses(name,lambda b=bad:cases.validate(b,'prefix'))
            for value in (0,1,'true',None):
                bad=copy.deepcopy(rows);bad[0]['commands'][1]['requires_ready']=value;refuses('ready-type-'+repr(value),lambda b=bad:cases.validate(b,'prefix'))
            bad=copy.deepcopy(rows);bad[0]['commands'][0]['actions']=[{'sequence':1,'class':1,'token':1},{'sequence':1,'class':2,'token':2}]
            refuses('duplicate original callback action',lambda:cases.validate(bad,'prefix'))
            for value in (False,1.0,3,-1):
                bad=copy.deepcopy(rows);bad[0]['commands'][0]['actions']=[{'sequence':1,'class':value,'token':1}]
                refuses('callback class '+repr(value),lambda b=bad:cases.validate(b,'prefix'))
        group('typed-fixtures-and-callbacks',fixture_types)
        def types():
            for left,right in [(0,False),(1,True),(0,0.0),(1,1.0),({'x':[0]}, {'x':[False]})]:
                okay('distinct JSON representations '+repr((left,right)),not safe.same(left,right))
            refuses('duplicate JSON object key',lambda:safe.json_load(b'{"a":1,"a":2}'))
            for row in [{'bytes':False,'sha256':'0'*64},{'bytes':0.0,'sha256':'0'*64},{'bytes':-1,'sha256':'0'*64},{'bytes':0,'sha256':'G'*64},{'bytes':0,'sha256':'0'*64,'extra':0}]:
                refuses('invalid byte identity '+repr(row),lambda r=row:build_evidence.check_identity(r))
            for name in ('../x','/x','a//b','./a','a/../b','a\\b','a\0b'):
                refuses('evidence path '+repr(name),lambda n=name:safe.read(observations,n))
        group('strict-json-and-byte-identities',types)
        def files():
            with tempfile.TemporaryDirectory(prefix='regular-evidence-',dir=observations) as temporary:
                root=Path(temporary);(root/'data').write_bytes(b'actual bytes')
                okay('descriptor-bound regular positive',safe.read(root,'data')==b'actual bytes')
                os.mkfifo(root/'fifo');refuses('FIFO metadata rejection without payload read',lambda:safe.read(root,'fifo'))
                sock=socket.socket(socket.AF_UNIX);directory_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                try:sock.bind('/proc/self/fd/'+str(directory_fd)+'/socket');refuses('socket metadata rejection',lambda:safe.read(root,'socket'))
                finally:sock.close();os.close(directory_fd)
                (root/'sym').symlink_to('data');refuses('symlink leaf rejection',lambda:safe.read(root,'sym'))
                (root/'dirsym').symlink_to(root,target_is_directory=True);refuses('symlink ancestor rejection',lambda:safe.read(root,'dirsym/data'))
                os.link(root/'data',root/'linked');refuses('hard-linked regular leaf',lambda:safe.read(root,'data'))
                refuses('special evidence inventory',lambda:safe.roster(root))
                (root/'linked').unlink();refuses('regular extent bound',lambda:safe.read(root,'data',3))
        group('actual-file-capability-controls',files)
        def sources():
            with tempfile.TemporaryDirectory(prefix='source-copy-',dir=observations) as temporary:
                replica=Path(temporary)/'repo';replica.mkdir()
                for name in sorted(set(source_before)|set(original_before)):
                    path=replica/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(safe.read(ROOT,name))
                manifest,_=graph.complete_sources(replica);okay('complete private source copy',safe.same(manifest,source_before) and safe.same(graph.original_manifest(replica),original_before))
                path=replica/graph.OWNED/'README.md';saved=path.read_bytes();path.unlink()
                refuses('required source missing',lambda:graph.complete_sources(replica));path.write_bytes(saved)
                extra=replica/graph.OWNED/'unknown.bin';extra.write_bytes(b'x')
                refuses('unbound owned binary',lambda:graph.complete_sources(replica));extra.unlink()
                extra=replica/graph.OWNED/'extra.json';extra.write_bytes(b'{}')
                refuses('new accepted source changes complete binding',lambda:graph.check_sources(source_before,original_before,replica));extra.unlink()
                graph_path=replica/graph.OWNED/'images.json';saved=graph_path.read_bytes();g=safe.json_load(saved)
                next(iter(g['fragments'].values()))['functions'][0]['function']='absent_function'
                graph_path.write_bytes(graph.canonical(g))
                refuses('missing selected native function',lambda:graph.complete_sources(replica));graph_path.write_bytes(saved)
                fixture=replica/'tests/vectors/pon/native-growth-reference-v2.json';saved=fixture.read_bytes();fixture.unlink()
                refuses('required original include fixture missing',lambda:graph.original_manifest(replica));fixture.write_bytes(saved)
                path=replica/'trillionnium/Cargo.lock';saved=path.read_bytes();path.write_bytes(saved+b'\n')
                refuses('changed actual original graph',lambda:graph.check_sources(source_before,original_before,replica));path.write_bytes(saved)
                okay('private source controls restored',safe.same(graph.complete_sources(replica)[0],source_before) and safe.same(graph.original_manifest(replica),original_before))
        group('dynamic-native-and-original-source-gates',sources)
        def compression():
            raw=b'complete source corpus\n';packed=lzma.compress(raw,preset=3);admission.bounded_xz(packed,raw);okay('bounded exact XZ positive',True)
            for name,changed in [('truncated',packed[:-1]),('trailing',packed+b'x'),('second-stream',packed+packed),('too-long',lzma.compress(raw+b'x',preset=3)),('too-short',lzma.compress(raw[:-1],preset=3))]:
                refuses('compressed corpus '+name,lambda p=changed:admission.bounded_xz(p,raw))
        group('bounded-source-corpus-compression',compression)
        def entrypoints():
            for module in ('qualification','physical','lifecycle','rust_oracle','bundle','build_evidence'):
                cli('help-'+module,module,['--help'])
            cli('optimized-reader','bundle',['--profile','batch','--bundle',observations/'absent'],expected=1,contains='Optimized Python',optimized=True)
            for name in ('RUSTC','RUSTDOC','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTFLAGS','LD_PRELOAD','LD_LIBRARY_PATH'):
                cli('override-'+name,'rust_oracle',['--validate-only','--profile','batch','--bundle',observations/'absent','--output',observations/('must-not-run-'+name)],expected=1,contains=name,env={name:'/unadmitted'})
        group('actual-public-cli-and-environment-refusal',entrypoints)

        def directory_races():
            with tempfile.TemporaryDirectory(prefix='directory-capability-',dir=observations) as temporary:
                here=Path(temporary)
                current=here/'current';saved=here/'held-original';alternate=here/'alternate'
                (current/'root').mkdir(parents=True);(alternate/'root').mkdir(parents=True)
                (current/'root'/'data').write_bytes(b'original')
                (alternate/'root'/'data').write_bytes(b'substituted')
                okay('ancestor control regular baseline',safe.read(current/'root','data')==b'original')
                actual_open=safe.os.open;triggered=[];fds_before=len(os.listdir('/proc/self/fd'))
                def substitute(path,*positional,**keywords):
                    if not triggered and (str(path)=='current' or Path(path)==current/'root'):
                        current.rename(saved);current.symlink_to(alternate,target_is_directory=True)
                        triggered.append({'operation':'rename-parent-then-symlink','path':str(current),'dir_fd':keywords.get('dir_fd')})
                    return actual_open(path,*positional,**keywords)
                try:
                    safe.os.open=substitute
                    refuses('actual ancestor switch before directory open',lambda:safe.read(current/'root','data'))
                finally:
                    safe.os.open=actual_open
                    if triggered:
                        current.unlink();saved.rename(current)
                okay('actual ancestor transition executed',len(triggered)==1 and type(triggered[0]['dir_fd']) is int)
                okay('failed ancestor read closes all private descriptors',len(os.listdir('/proc/self/fd'))==fds_before)
                okay('ancestor refusal leaves both regular objects intact',safe.read(current/'root','data')==b'original' and safe.read(alternate/'root','data')==b'substituted')
                safe.write_json(observations/'ancestor-transition.json',triggered)
        group('actual-root-ancestor-descriptor-transition',directory_races)
        def multiple_targets():
            from . import rust_oracle as oracle
            with tempfile.TemporaryDirectory(prefix='multi-native-target-',dir=observations) as temporary:
                here=Path(temporary);output=here/'output';isolated=output/'isolated-source'
                bundles=[]
                for index in range(4):
                    path=here/('bundle-'+str(index));path.mkdir();bundles.append(path)
                target=here/'target';target.mkdir()
                okay('four actual bundle target admission',oracle.bound_target(target,output,ROOT,bundles,isolated)==target)
                okay('one actual bundle target admission',oracle.bound_target(target,output,ROOT,bundles[:1],isolated)==target)
                for index,bound in enumerate(bundles):
                    for label,bad in [('same',bound),('nested',bound/'cargo-target')]:
                        refuses('target overlaps partition-'+str(index)+'-'+label,lambda p=bad:oracle.bound_target(p,output,ROOT,bundles,isolated))
                for label,bad in [('all-input-parent',here),('repository',ROOT),('isolated',isolated),('output',output),('output-child',output/'unadmitted-target')]:
                    refuses('target boundary '+label,lambda p=bad:oracle.bound_target(p,output,ROOT,bundles,isolated))
                link=here/'target-link';link.symlink_to(target,target_is_directory=True)
                refuses('symbolic multiple-bundle target',lambda:oracle.bound_target(link,output,ROOT,bundles,isolated))
                regular=here/'regular-target';regular.write_bytes(b'not a directory')
                refuses('regular multiple-bundle target',lambda:oracle.bound_target(regular,output,ROOT,bundles,isolated))
                refuses('missing bound target inventory',lambda:oracle.bound_target(target,output,ROOT,[],isolated))
                # This real public entry gets through all four target checks.
                # Deliberately empty evidence is then refused before any compiler.
                stopped=here/'public-output'
                arguments=['--profile','prefix','--output',stopped,'--target-dir',target]
                for bundle in bundles:arguments+=['--bundle',bundle]
                cli('four-bundle-original-precompiler-admission','rust_oracle',arguments,expected=1)
                observed=safe.load(stopped,'report.json')
                okay('public four-bundle failure is missing evidence, not argument arity',
                     isinstance(observed['failure'],dict) and observed['failure']['error'].startswith('FileNotFoundError(')
                     and observed['stages']==[] and observed['original_case_rows_observed']==0
                     and observed['original_tests']==[] and observed['final_errors']==[])
        group('multiple-native-partition-target-admission',multiple_targets)
        if args.bundle is not None:
            def evidence():
                admitted=admission.validate_bundle(ROOT,args.bundle,args.profile);before=admitted['bundle_artifacts']
                work=observations/'mutable-bundle';admission.copy_files(args.bundle,work,set(before))
                def public(name,module,arguments,contains=None):
                    cli(name,module,arguments,expected=1,contains=contains)
                baseline={name:safe.read(work,name) for name in before}
                changed=set()
                def put(name,raw):
                    graph.need(name in baseline,'Mutation only changes existing proof files');(work/name).write_bytes(raw);changed.add(name)
                def mutate(name,call,module,arguments,contains=None):
                    try:call();public(name,module,arguments,contains)
                    finally:
                        for key in changed:(work/key).write_bytes(baseline[key])
                        changed.clear()
                    okay('raw evidence restored '+name,admission.identities(work)==before)
                def json_put(name,value):put(name,graph.canonical(value)+b'\n')
                build_path='native-build/build.json';original_build=safe.json_load(baseline[build_path])
                def empty_original():
                    row=copy.deepcopy(original_build);row['original_sources']={};row['original_source_set_sha256']=graph.digest({});json_put(build_path,row)
                mutate('empty-original-map-coherent',empty_original,'build_evidence',['--profile',args.profile,'--build',work/'native-build'],contains='original_sources')
                def image_drop():
                    row=copy.deepcopy(original_build);name='master';flat=baseline['native-build/master.flat'][1:]
                    put('native-build/master.flat',flat);row['images'][name]=safe.identity(flat)
                    stage=row['stages'][0];stage['output_bytes']=len(flat);stage['output_sha256']=safe.identity(flat)['sha256']
                    put('native-build/pinned-native/compile-master/stdout.raw',flat)
                    json_put('native-build/pinned-native/compile-master/receipt.json',stage);json_put(build_path,row)
                mutate('coherent-flat-with-unchanged-elf',image_drop,'build_evidence',['--profile',args.profile,'--build',work/'native-build'],contains='Full ordered image')
                def stage_bool():
                    row=copy.deepcopy(original_build);row['stages'][0]['exit_code']=False
                    json_put('native-build/pinned-native/compile-master/receipt.json',row['stages'][0]);json_put(build_path,row)
                mutate('boolean-compiler-exit',stage_bool,'build_evidence',['--profile',args.profile,'--build',work/'native-build'],contains='Actual successful stage')
                def input_change():
                    raw=baseline['native-build/pinned-native/compile-master/stdin.raw']+b'\n';put('native-build/pinned-native/compile-master/stdin.raw',raw)
                    row=copy.deepcopy(original_build);row['stages'][0]['input_bytes']=len(raw);row['stages'][0]['input_sha256']=safe.identity(raw)['sha256']
                    json_put('native-build/pinned-native/compile-master/receipt.json',row['stages'][0]);json_put(build_path,row)
                mutate('coherent-compiler-input-change',input_change,'build_evidence',['--profile',args.profile,'--build',work/'native-build'],contains='Actual full compiler input')
                def original_boolean():
                    row=copy.deepcopy(original_build);key=next(iter(row['original_sources']));row['original_sources'][key]['bytes']=float(row['original_sources'][key]['bytes']);row['original_source_set_sha256']=graph.digest(row['original_sources']);json_put(build_path,row)
                mutate('float-original-byte-count',original_boolean,'build_evidence',['--profile',args.profile,'--build',work/'native-build'],contains='original_sources')
                if args.profile=='prefix':
                    index=admitted['comparison']['partition']['indices'][0];directory='cases/%04d/'%index
                    def range_bool():
                        old=baseline[directory+'report.json'];r=safe.json_load(old);r['commands'][0]['stream_ranges']['stdin'][0]=False
                        json_put(directory+'command-0001.json',r['commands'][0]);json_put(directory+'report.json',r)
                        old_id=safe.identity(old);new_id=safe.identity(safe.read(work,directory+'report.json'))
                        def replace(v):
                            if isinstance(v,dict):
                                if safe.same(v,old_id):return new_id
                                return {k:replace(x) for k,x in v.items()}
                            return [replace(x) for x in v] if isinstance(v,list) else v
                        comparison=replace(safe.json_load(baseline['native-comparison.json']));json_put('native-comparison.json',comparison)
                        report=replace(safe.json_load(baseline['native-report.json']));report['comparison']=safe.identity(safe.read(work,'native-comparison.json'));json_put('native-report.json',report)
                    mutate('boolean-stream-range-coherent',range_bool,'bundle',['--profile',args.profile,'--bundle',work],contains='Typed complete contiguous stream ranges')
                    def missing_events():
                        r=safe.json_load(baseline[directory+'report.json']);target=next((i for i,x in enumerate(r['commands']) if x['events']),None);graph.need(target is not None,'Actual case has callback bytes')
                        r['commands'][target]['events']=[];json_put(directory+'command-%04d.json'%(target+1),r['commands'][target]);json_put(directory+'report.json',r)
                    mutate('missing-actual-callback-roster',missing_events,'bundle',['--profile',args.profile,'--bundle',work],contains='Typed complete contiguous stream ranges')
                def missing_controls():
                    r=safe.json_load(baseline['native-report.json']);r['controls']=r['controls'][1:];json_put('native-report.json',r)
                mutate('missing-history-control',missing_controls,'bundle',['--profile',args.profile,'--bundle',work],contains='Complete actual selected history roster')
                cli('restored-complete-evidence','bundle',['--profile',args.profile,'--bundle',work])
                okay('original complete artifact unchanged',admission.identities(args.bundle)==before)
            group('actual-valid-bundle-public-cli-mutations',evidence)
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        if source_before is not None and original_before is not None:
            try:graph.check_sources(source_before,original_before)
            except BaseException as error:cleanup.append({'source_after':repr(error)})
        report={'schema':'trnm.execution-batch-admission-controls.v1','status':'PASS' if primary is None and not cleanup else 'FAIL',
          'groups':groups,'controls':controls,'groups_passed':len(groups),'controls_passed':sum(row['status']=='PASS' for row in controls),
          'actual_cli_calls':sum('argv' in row for row in controls),'primary_error':primary,'cleanup_errors':cleanup,
          'source_inputs':source_before,'original_sources':original_before,'elapsed_ns':time.monotonic_ns()-started,
          'native_semantics_executed':False,'actual_original_executed':False,'valid_bundle_controls':'NOT_RUN' if args.bundle is None else 'PASS' if primary is None else 'FAIL'}
        safe.write_json(report_path,report)
    print(json.dumps({key:report[key] for key in ('status','groups_passed','controls_passed','actual_cli_calls','primary_error','cleanup_errors','valid_bundle_controls')}),flush=True)
    raise SystemExit(0 if report['status']=='PASS' else 1)
if __name__=='__main__':main()
