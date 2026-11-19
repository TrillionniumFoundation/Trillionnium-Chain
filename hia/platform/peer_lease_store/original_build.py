"""Build and retain the actual original modules and unfiltered original tests."""
from __future__ import annotations
import hashlib,json,os,shutil,subprocess,time,tarfile
from pathlib import Path
from .build import ROOT,identity,need

class Original:
    def __init__(self, output:Path, source_snapshot:Path):
        self.output=output;output.mkdir(mode=0o700)
        self.stages=[];self.retained=None;self.dependencies={};self.source_snapshot=source_snapshot;self.dependency_directories=[]
        self.environment=dict(os.environ)
        self.removed_build_overrides={}
        for name in ('RUSTFLAGS','RUSTDOCFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER'):
            if name in self.environment:self.removed_build_overrides[name]=self.environment.pop(name)
    def stage(self,name,argv,*,required=True,timeout=300,env=None):
        start=time.monotonic_ns();timed=False
        try:
            result=subprocess.run(argv,cwd=ROOT,env=self.environment if env is None else env,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
            rc=result.returncode;out=result.stdout;err=result.stderr
        except subprocess.TimeoutExpired as failure:
            timed=True;rc=None;out=failure.stdout or b'';err=failure.stderr or b''
        (self.output/(name+'.stdout.raw')).write_bytes(out)
        (self.output/(name+'.stderr.raw')).write_bytes(err)
        row={'name':name,'argv':argv,'cwd':str(ROOT),'returncode':rc,'timed_out':timed,
             'timeout_seconds':timeout,'elapsed_ns':time.monotonic_ns()-start,'stdout':identity(out),'stderr':identity(err)}
        self.stages.append(row);self.save()
        if required:need(not timed and rc==0,'Original stage failed; raw preserved: '+name)
        return out,err,row
    def save(self):
        (self.output/'build.json').write_text(json.dumps({'schema':'trnm.peer-store.original-build.v1',
            'stages':self.stages,'retained':self.retained,'dependencies':self.dependencies,
            'dependency_search_directories':self.dependency_directories,
            'removed_process_build_overrides':sorted(self.removed_build_overrides)},indent=2,sort_keys=True)+'\n')
    def physical_baseline(self, target, provenance, binaries):
        checked = {}
        source_inputs = None
        for kind, variable, key in (("execution", "HIA_PEER_STORE_ORIGINAL_ARCHIVE", "retained_bundle"),
                                    ("source", "HIA_PEER_STORE_SOURCE_ARCHIVE", "source_package")):
            name = os.environ.get(variable)
            need(name, "Complete preserved original archive required: " + variable)
            archive = Path(name).resolve(strict=True)
            raw = archive.read_bytes()
            expected = provenance[key]
            need(identity(raw) == {k: expected[k] for k in ("bytes", "sha256")}, "Original archive envelope changed")
            retained = target / (kind + ".tar.xz")
            retained.write_bytes(raw)
            files = {}; documents = {}; manifest = None
            with tarfile.open(retained, "r|xz") as stream:
                for member in stream:
                    if member.isdir():
                        continue
                    need(member.isfile(), "Original archive nonregular member")
                    relative = member.name
                    if kind == "execution":
                        need(relative.startswith("evidence/"), "Original evidence archive root")
                        relative = relative[len("evidence/"):]
                    need(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                         "Original archive escapes")
                    need(relative not in files, "Original archive duplicate member")
                    data = stream.extractfile(member).read()
                    need(len(data) == member.size, "Original member truncated")
                    files[relative] = identity(data)
                    if relative in {"MANIFEST.json", "complete-source-before.json", "complete-source-after.json"}:
                        documents[relative] = json.loads(data)
                    if relative == "MANIFEST.json":
                        manifest = documents[relative]
                    elif kind == "source":
                        current = ROOT / relative
                        need(current.is_file() and identity(current.read_bytes()) == files[relative],
                             "Complete original source differs: " + relative)
            need(manifest is not None, "Original complete manifest missing")
            members = dict(files); members.pop("MANIFEST.json")
            if kind == "execution":
                need(members == manifest["files"], "Complete original evidence member identity changed")
                for row in binaries:
                    need(members.get(row["path"]) == {k: row[k] for k in ("bytes", "sha256")},
                         "Actual original binary bytes differ")
                before = documents["complete-source-before.json"]
                after = documents["complete-source-after.json"]
                need(before == after, "Complete original executed source changed")
                source_inputs = before
            else:
                declared = {row["path"]: {k: row[k] for k in ("bytes", "sha256")} for row in manifest["files"]}
                need(members == declared and declared == source_inputs, "Original executed/source-package graph differs")
            checked[kind] = {"archive": identity(raw), "regular_members": len(files),
                             "complete_members_read": True, "files": files}
        (target / "physical-readback.json").write_text(json.dumps(checked, indent=2, sort_keys=True) + "\n")
        return checked
    def baseline(self):
        name=os.environ.get('HIA_PEER_STORE_ORIGINAL_BASELINE')
        if not name:return False
        directory=Path(name).resolve(strict=True);target=self.output/'retained-baseline';target.mkdir()
        provenance=json.loads((directory/'provenance.json').read_bytes())
        required={'execution.json','stdout.raw','stderr.raw','source-before.json','source-after.json',
                  'retained-report.json','retained-manifest.json','original-binaries.json','terminal-job-status.json','process-request.json'}
        need(provenance.get('schema')=='trnm.peer-lease.retained-execution-provenance.v1' and
             required<=set(provenance.get('files',{})), 'Complete retained provenance absent')
        for file,wanted in provenance['files'].items():
            need(Path(file).name==file,'Baseline filename escapes')
            raw=(directory/file).read_bytes();need(identity(raw)==wanted,'Baseline raw identity changed: '+file)
            (target/file).write_bytes(raw)
        (target/'provenance.json').write_bytes((directory/'provenance.json').read_bytes())
        execution=json.loads((target/'execution.json').read_bytes())
        before=json.loads((target/'source-before.json').read_bytes());after=json.loads((target/'source-after.json').read_bytes())
        files=sorted((ROOT/'trillionnium/crates/trnm-peer-lease').rglob('*.rs')) + [ROOT/'trillionnium/crates/trnm-peer-lease/Cargo.toml',ROOT/'trillionnium/Cargo.toml',ROOT/'trillionnium/Cargo.lock']
        current={p.relative_to(ROOT).as_posix():identity(p.read_bytes()) for p in files}
        need(current==before==after and len(current)==28,'Complete original package source graph changed')
        argv=execution.get('argv',[])
        need(len(argv)==15 and Path(argv[0]).name=='cargo' and Path(argv[0]).is_absolute(),'Retained command shape')
        expected=[argv[0],'test','--offline','--locked','--no-fail-fast','--manifest-path',argv[6],'-p','trnm-peer-lease','--all-features','--target-dir',argv[11],'--message-format=json','--','--test-threads=1']
        need(argv==expected and Path(argv[6]).is_absolute() and Path(argv[11]).is_absolute(),'Retained command filtering')
        for stream in ('stdout','stderr'):need(execution[stream]==identity((target/(stream+'.raw')).read_bytes()),'Retained actual streams changed')
        need(execution.get('timed_out') is False and execution.get('returncode')==0
             and execution.get('source_unchanged') is True and execution.get('retained_original_tests_not_filtered') is True,'Original suite did not truly pass unchanged')
        report=json.loads((target/'retained-report.json').read_bytes())
        binaries=json.loads((target/'original-binaries.json').read_bytes())
        terminal=json.loads((target/'terminal-job-status.json').read_bytes())
        request=json.loads((target/'process-request.json').read_bytes())
        need(report['original_execution']==execution and report['original_binaries']==binaries and binaries
             and report.get('source_unchanged') is True and report.get('complete_source_unchanged') is True
             and report.get('complete_unfiltered_original_passed') is True and provenance.get('complete_unfiltered_original_passed') is True
             and terminal.get('job_id')==provenance.get('job_id') and terminal.get('terminal_publication_confirmed') is True
             and terminal.get('output_complete') is True and terminal.get('timed_out') is False and terminal.get('exit_code')==0
             and request['host']==provenance['host'],'Complete original execution host/provenance mismatch')
        physical=self.physical_baseline(target,provenance,binaries)
        self.retained={'status':'PASS','execution':execution,'source_inputs':before,'provenance':provenance,
                       'observation_host_is_current_test_host':False,'reused_exact_observation':True, 'physical_archive_readback':{k:{p:v for p,v in value.items() if p!='files'} for k,value in physical.items()}}
        self.save();return True
    def build(self):
        rustc=shutil.which('rustc');cargo=shutil.which('cargo')
        need(rustc and cargo,'Actual rustc/cargo required')
        raw,_,_=self.stage('rustc-sysroot',[rustc,'--print','sysroot'])
        compiler=(Path(raw.decode().strip())/'bin/rustc').resolve(strict=True)
        shim,_,_=self.stage('rustc-shim-version',[rustc,'-Vv'])
        actual,_,_=self.stage('rustc-actual-version',[str(compiler),'-Vv'])
        need(shim==actual,'Rust shim and actual compiler identity differ')
        (self.output/'compiler.json').write_text(json.dumps({'path':str(compiler),**identity(compiler.read_bytes())},indent=2)+'\n')
        self.stage('cargo-version',[cargo,'--version'])
        external=self.baseline()
        target=Path(os.environ.get('HIA_PEER_STORE_CARGO_TARGET',str(self.output/'cargo-target'))).absolute()
        argv=[cargo,'test','--offline','--locked']
        if external:argv+=['--no-run']
        else:argv+=['--no-fail-fast']
        argv+=['--manifest-path',str(ROOT/'trillionnium/Cargo.toml'),'-p','trnm-peer-lease','--all-features','--target-dir',str(target),'--message-format=json']
        if not external:argv+=['--','--test-threads=1']
        out,err,execution=self.stage('complete-original-crate',argv,required=external,timeout=600)
        if not external:
            self.retained={'status':'PASS' if execution['returncode']==0 and not execution['timed_out'] else 'FAIL',
                           'execution':execution,'observation_host_is_current_test_host':True,'reused_exact_observation':False}
        messages=[]
        for line in out.splitlines():
            if line.startswith(b'{'):
                row=json.loads(line)
                if row.get('reason')=='compiler-artifact':messages.append(row)
        selected={}
        versions={'fs2':'0.4.3','sha2':'0.10.9','rustix':'1.1.6','libc':'0.2.184','tempfile':'3.27.0'}
        for key,version in versions.items():
            candidates=[Path(f) for row in messages if row['target']['name']==key and row['package_id'].endswith('#'+key+'@'+version)
                        for f in row['filenames'] if f.endswith('.rlib')]
            need(len(candidates)==1,'Exact original dependency artifact not unique: '+key)
            selected[key]=candidates[0]
        dest=self.output/'actual-artifacts';dest.mkdir()
        all_artifacts=sorted({f for row in messages for f in row['filenames'] if f.endswith(('.rlib','.rmeta'))}
                             | {row['executable'] for row in messages if row.get('executable')})
        for source in all_artifacts:
            path=Path(source);data=path.read_bytes();info=identity(data)
            name=path.name+'-'+info['sha256'][:16];(dest/name).write_bytes(data)
            self.dependencies[source]={'retained_path':'actual-artifacts/'+name,**info}
        # Cargo's admitted artifact graph may put each dependency in its own
        # build/<crate>/<hash>/out directory. Do not assume one deps directory.
        self.dependency_directories=sorted({str(Path(p).parent) for p in all_artifacts if p.endswith(('.rlib','.rmeta'))})
        need(self.dependency_directories,'Actual Cargo dependency directories absent')
        args=[str(compiler),'--edition=2021','-O',str(self.source_snapshot/'hia/platform/peer_lease_store/original.rs')]
        for directory in self.dependency_directories:args+=['-L','dependency='+directory]
        for key in ('fs2','sha2','rustix','libc'):args+=['--extern',key+'='+str(selected[key])]
        env=dict(self.environment);env['ORIGINAL_PEER_SOURCE']=str(self.source_snapshot/'trillionnium/crates/trnm-peer-lease')
        self.observer=self.output/'observer.elf'
        self.stage('observer-build',args+['-o',str(self.observer)],env=env)
        unit=self.output/'original-store-protocol-tests.elf'
        self.stage('unchanged-unit-tests-build',args+['--test','--extern','tempfile='+str(selected['tempfile']),'-o',str(unit)],env=env)
        _,_,tests=self.stage('unchanged-unit-tests',[str(unit),'--test-threads=1'],required=False)
        self.unit_tests=tests
        for path in (self.observer,unit):self.dependencies[str(path)]={'retained_path':path.name,**identity(path.read_bytes())}
        self.save()
        return self.observer.read_bytes()
