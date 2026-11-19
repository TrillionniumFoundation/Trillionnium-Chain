"""Qualification-only read overlays test rejection without editing recorded evidence."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,time

def identity(path):
    raw=Path(path).read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['reader','evidence','repo','roster','output']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();E=args.evidence.resolve();R=args.repo.resolve();OUT=args.output.absolute();assert __debug__ and not OUT.exists();OUT.mkdir(mode=0o700)
    spec=importlib.util.spec_from_file_location('task_reader_negative',args.reader);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    original=json.loads((E/'report.json').read_text());before=identity(E/'report.json');cases=[]
    def stage(name,stage_name,mutation):
        changed=copy.deepcopy(original);row=next(x for x in changed['stages'] if x['name']==stage_name);mutation(row);cases.append((name,changed))
    def argv_value(name,stage_name,option,value):stage(name,stage_name,lambda row:row['argv'].__setitem__(row['argv'].index(option)+1,value))
    for name in ['original-retained-tests','original-clippy']:
        stage(name+'-executable',name,lambda row:row['argv'].__setitem__(0,'/usr/bin/false'))
        argv_value(name+'-manifest',name,'--manifest-path','/tmp/unrelated-project/Cargo.toml')
        argv_value(name+'-package',name,'-p','unrelated-crate')
    stage('cargo-positional-test-filter','original-retained-tests',lambda row:row['argv'].append('one_test_only'))
    stage('cargo-missing-locked','original-retained-tests',lambda row:row['argv'].remove('--locked'))
    argv_value('cargo-different-target','original-retained-tests','--target-dir','/tmp/unrelated-target')
    stage('cargo-different-cwd','original-retained-tests',lambda row:row.__setitem__('cwd','/tmp/unrelated-checkout'))
    stage('cargo-relaxed-timeout','original-retained-tests',lambda row:row.__setitem__('timeout_seconds',1200))
    stage('clippy-missing-all-targets','original-clippy',lambda row:row['argv'].remove('--all-targets'))
    stage('clippy-missing-all-features','original-clippy',lambda row:row['argv'].remove('--all-features'))
    stage('clippy-allow-warnings','original-clippy',lambda row:row['argv'].__setitem__(-2,'-A'))
    argv_value('fmt-different-manifest','original-format','--manifest-path','/tmp/unrelated-project/Cargo.toml')
    argv_value('fmt-different-package','original-format','-p','unrelated-crate')
    stage('fmt-different-cwd','original-format',lambda row:row.__setitem__('cwd','/tmp/unrelated-checkout'))
    for name,value in [('CARGO_NET_OFFLINE','false'),('RUSTUP_TOOLCHAIN','1.100.0'),('GIT_NO_LAZY_FETCH','0'),('PATH','/tmp/unrelated/bin'),('RUSTC_WORKSPACE_WRAPPER','/usr/bin/false')]:
        changed=copy.deepcopy(original);changed['environment'][name]=value;cases.append(('environment-'+name,changed))
    stage('native-observer-executable','records-native-original',lambda row:row['argv'].__setitem__(0,'/usr/bin/false'))
    argv_value('native-build-different-provider','records-native-build','--provider','/tmp/unrelated-provider')
    changed=copy.deepcopy(original);changed['original_git_objects'].pop(next(iter(changed['original_git_objects'])));cases.append(('original-git-source-omitted',changed))
    changed=copy.deepcopy(original);changed['original_artifacts'].pop(next(iter(changed['original_artifacts'])));cases.append(('actual-cargo-artifact-omitted',changed))
    changed=copy.deepcopy(original);changed['original_direct_package_ids']['sha2']='sha2@0.11.1';cases.append(('wrong-original-sha2-package',changed))
    assert len(cases)==27
    cases=[{'name':name,'final':changed} for name,changed in cases]
    for name,relative in [('source-reader-omitted','hia/platform/task_kernel/readback_task_store.py'),('source-roster-omitted','hia/platform/task_kernel/qualification/task_store_roster.json'),('source-document-omitted','hia/platform/task_kernel/QUALIFICATION.md')]:
        changed=copy.deepcopy(original)
        for fence in ['source_before','source_after']:changed[fence].pop(str(R/relative))
        cases.append({'name':name,'final':changed,'expected_failure':'Qualification omitted or added a current Task source input'})
    foreign=OUT/'foreign-inputs';foreign.mkdir()
    foreign_reader=foreign/'readback_task_store.py';foreign_reader.write_bytes(args.reader.read_bytes())
    foreign_roster=foreign/'task_store_roster.json';foreign_roster.write_bytes(args.roster.read_bytes())
    cases.append({'name':'external-identical-reader','reader':foreign_reader,'expected_failure':'Reader and fixed case roster must be the canonical files'})
    cases.append({'name':'external-identical-roster','roster':foreign_roster,'expected_failure':'Reader and fixed case roster must be the canonical files'})
    changed=copy.deepcopy(original)
    for fence in ['source_before','source_after']:changed[fence][str(foreign_roster)]=identity(foreign_roster)
    cases.append({'name':'source-foreign-extra','final':changed,'expected_failure':'Qualification omitted or added a current Task source input'})
    build_path=E/'records-native/build.json';build=json.loads(build_path.read_text());build_before=identity(build_path)
    image='root';function='cp_read';owner=Path(build['function_sources'][image][function]['source'])
    assert owner==R/'hia/src/control_plane/core.hepta'
    foreign_source=foreign/'copied-core.hepta';foreign_source.write_bytes(owner.read_bytes())
    for name,kind in [('function-owner-not-fenced','omit'),('function-foreign-unfenced','foreign'),('function-foreign-fenced','foreign-fenced'),('include-owner-not-fenced','include')]:
        changed=copy.deepcopy(build);overlays={}
        if kind in ['omit','include']:
            omitted=str(owner if kind=='omit' else R/'hia/platform/task_kernel/store_open_includes.json')
            for fence in ['source_before','source_after']:changed[fence].pop(omitted)
        else:
            changed['function_sources'][image][function]['source']=str(foreign_source)
            if kind=='foreign-fenced':
                for fence in ['source_before','source_after']:changed[fence][str(foreign_source)]=identity(foreign_source)
                snapshot=E/'records-native/source-snapshots/external'/hashlib.sha256(str(foreign_source).encode()).hexdigest()/foreign_source.name
                overlays[str(snapshot)]=foreign_source
        failure='Canonical include declaration is not fenced' if kind=='include' else 'Compiled function is not bound to its canonical fenced owner'
        cases.append({'name':name,'build':changed,'overlays':overlays,'expected_failure':failure})
    baseline=module.Readback(E,R,args.roster,OUT/'positive').run();assert baseline['status']=='PASS'
    rows=[];report={'schema':'trnm.hia.task-store.reader-negative-controls.v2','status':'FAIL','finalized':False,'scope':'Read-time qualification metadata and foreign-path overlays; original recorded evidence is unchanged and no native result is manufactured','reader':identity(args.reader),'harness':identity(__file__),'evidence':before,'positive_readback':identity(OUT/'positive/report.json'),'original_command_controls':27,'source_binding_controls':len(cases)-27,'controls':rows}
    def save():(OUT/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    save()
    for case in cases:
        name=case['name'];directory=OUT/name;directory.mkdir();changed=copy.deepcopy(case.get('final',original));overlays=dict(case.get('overlays',{}))
        if 'build' in case:
            altered_build=directory/'altered-build.json';altered_build.write_text(json.dumps(case['build'],indent=2,sort_keys=True)+'\n');overlays[str(build_path)]=altered_build
            changed['qualifications']['records-native/build.json']=identity(altered_build)
        shadow=directory/'altered-report.json';shadow.write_text(json.dumps(changed,indent=2,sort_keys=True)+'\n');overlays[str(E/'report.json')]=shadow
        candidate=module
        if 'reader' in case:
            spec=importlib.util.spec_from_file_location('task_reader_foreign',case['reader']);candidate=importlib.util.module_from_spec(spec);spec.loader.exec_module(candidate)
        class Overlay(candidate.Readback):
            def read(self,path,expected=None):return super().read(overlays.get(str(Path(path).absolute()),path),expected)
        accepted=False;failure=None;start=time.monotonic_ns()
        try:accepted=Overlay(E,R,case.get('roster',args.roster),directory/'readback').run()['status']=='PASS'
        except ValueError as error:failure=str(error)
        rows.append({'name':name,'rejected':not accepted,'failure':failure,'expected_failure':case.get('expected_failure'),'elapsed_ns':time.monotonic_ns()-start,'altered_report':identity(shadow),'read_overlays':{path:{'replacement':str(replacement),**identity(replacement)} for path,replacement in overlays.items()},'readback':identity(directory/'readback/report.json')});save()
        assert not accepted and failure,name
        if 'expected_failure' in case:assert case['expected_failure'] in failure,(name,failure)
    assert identity(E/'report.json')==before
    assert identity(build_path)==build_before
    report.update(status='PASS',finalized=True,negative_controls=len(rows),source_evidence_unchanged=True);save();print(json.dumps({'status':'PASS','negative_controls':len(rows),'report':str(OUT/'report.json'),'identity':identity(OUT/'report.json')}),flush=True)

if __name__=='__main__':main()
