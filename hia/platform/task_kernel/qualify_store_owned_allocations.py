"""Relink exact HIA owner objects with a qualification-only libc allocation observer."""
from pathlib import Path
import argparse,json,os,shutil,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.task_kernel.build_provider import identity,need
HERE=Path(__file__).resolve().parent

def qualify(build,records,output):
    build=build.resolve(strict=True);records=records.resolve(strict=True);output=output.absolute()
    need(not output.exists() and ROOT not in output.parents,'Fresh external qualification output required')
    output.mkdir(mode=0o700);sources={};report_path=output/'build.json';report={'schema':'trnm.hia.task-kernel.allocator-observed-build.v1','status':'FAIL','finalized':False,'stages':[],'scope':__doc__}
    def capture(path):
        path=Path(path).absolute();value=identity(path)
        if str(path) in sources:need(value==sources[str(path)],'Source changed before recapture');return
        sources[str(path)]=value
        import hashlib
        p=output/'source-snapshots'/hashlib.sha256(str(path).encode()).hexdigest()/path.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(path.read_bytes());need(identity(p)==value,'Source changed while capturing')
    def save():report_path.write_text(json.dumps(report,indent=2)+'\n')
    def stage(name,args,timeout=60):
        args=list(map(str,args));row={'name':name,'argv':args,'cwd':str(ROOT),'timeout_seconds':timeout,'completed':False};report['stages'].append(row);save();(output/(name+'.stdin.raw')).write_bytes(b'');started=time.monotonic_ns()
        try:result=subprocess.run(args,input=b'',capture_output=True,cwd=ROOT,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (output/(name+'.stdout.raw')).write_bytes(error.stdout or b'');(output/(name+'.stderr.raw')).write_bytes(error.stderr or b'');row.update(error=repr(error),elapsed_ns=time.monotonic_ns()-started);save();raise
        (output/(name+'.stdout.raw')).write_bytes(result.stdout);(output/(name+'.stderr.raw')).write_bytes(result.stderr);row.update(completed=True,exit_code=result.returncode,elapsed_ns=time.monotonic_ns()-started);save();result.check_returncode();return result.stdout
    try:
        need(__debug__,'Optimized qualifier refused');capture(build/'build.json');source=json.loads((build/'build.json').read_text())
        need(source['status']=='PASS' and source['finalized'] and source['source_before']==source['source_after'],'Unqualified public build')
        for p,expected in source['source_before'].items():capture(p);need(identity(p)==expected,'Public source graph changed')
        for name,expected in source['artifacts'].items():capture(build/name);need(identity(build/name)==expected,'Public executable object changed')
        capture(source['provider_build']);provider=json.loads(Path(source['provider_build']).read_text());cc=provider['compiler']['path'];capture(cc)
        for p in [Path(__file__),HERE/'qualification/store_owned_allocator_observer.c',HERE/'qualification/store_owned_allocator_observer.py',HERE/'qualification/store_public_native.py',HERE/'store_owned_exports.json']:capture(p)
        report['source_before']=sources;save()
        stage('preflight',['bash','scripts/project-preflight.sh','--audit'])
        stage('compile-allocation-observer',[cc,'-std=c11','-O2','-fPIC','-Wall','-Wextra','-Werror','-c',HERE/'qualification/store_owned_allocator_observer.c','-o',output/'allocation-observer.o'])
        diagnostic=['trnm_task_test_alloc_'+x for x in ['calls','frees','live','bytes','failures','bad_frees','fail_after']]
        exports=json.loads((HERE/'store_owned_exports.json').read_text())['exports']+diagnostic
        (output/'observer.map').write_text('{\n global:\n'+''.join('  '+n+';\n' for n in exports)+' local: *;\n};\n')
        objects=[build/'driver.o',build/'dispatch.o',build/'owned.o']+[build/(name+'-named.o') for name in source['function_sources'] if not name.endswith('-emitter')]
        need(all(p.exists() for p in objects),'Missing actual compiled HIA object')
        report['exact_original_hia_objects']={str(p):identity(p) for p in objects}
        shutil.copyfile(build/'provider.so',output/'provider.so');need(identity(output/'provider.so')==identity(build/'provider.so'),'Shared provider differs')
        stage('link-allocation-observed',[cc,'-shared','-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections,--wrap=calloc,--wrap=free',*objects,output/'allocation-observer.o','-Wl,--version-script='+str(output/'observer.map'),'-L'+str(output),'-Wl,-rpath,$ORIGIN','-l:provider.so','-lm','-ldl','-lpthread','-o',output/'task-store-allocator-observed.so'])
        actual={r.split()[-1] for r in stage('inspect-symbols',['nm','-D','--defined-only',output/'task-store-allocator-observed.so']).decode().splitlines() if r.strip()};need(actual==set(exports),'Observed public symbols differ')
        need({p:identity(p) for p in sources}==sources,'Qualification source changed')
        report.update(status='PASS',finalized=True,source_before=sources,source_after={p:identity(p) for p in sources},artifacts={p.name:identity(p) for p in output.iterdir() if p.is_file() and p.suffix in {'.o','.so','.map'}});save()
        # Build PASS is separate from the following actual allocation qualification.
        # Keep the input build receipt immutable while and after the observer reads it.
        report_path=output/'run.json'
        report={**report,'schema':'trnm.hia.task-kernel.allocator-observed-run.v1','status':'FAIL','finalized':False,'stages':[],
                'build_manifest':identity(output/'build.json')}
        save()
        stage('allocation-lifetime-qualification',[sys.executable,HERE/'qualification/store_owned_allocator_observer.py',output,records,output/'qualification'],180)
        report['qualification']=identity(output/'qualification/report.json');need({p:identity(p) for p in sources}==sources,'Source changed during allocator qualification')
        report.update(status='PASS',finalized=True);save()
        return report
    except BaseException as error:
        report.update(status='FAIL',finalized=False,failure=repr(error),source_before=sources);save();raise

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--records',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=qualify(a.build,a.records,a.output);print(json.dumps({'status':r['status'],'report':str(a.output/'build.json'),'qualification':r['qualification']}))
