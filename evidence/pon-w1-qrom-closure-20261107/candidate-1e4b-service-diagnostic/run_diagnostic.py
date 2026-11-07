#!/usr/bin/env python3
"""One independent exact diagnostic; preserves failed module run and frozen A."""
from pathlib import Path
import gzip,hashlib,io,json,os,re,stat,subprocess,sys,tarfile,types
P=Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence')
ORIGINAL=P/'native-1e4bffc371bc'
OUT=P/'native-1e4bffc371bc-failure-diagnostic'
HEAD='1e4bffc371bcdc53aabc621b6b6cb2485ab36f53'
TEST='release_owner::service_tests::admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch'
RUNNER_SHA='0de72bb06ab637ffb834a3f7d22a024f8f031dbadfd79bf53373f82823f764c7'
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(n,v):
    with (OUT/n).open('x') as f: json.dump(v,f,indent=2,sort_keys=True);f.write('\n')
assert json.loads((ORIGINAL/'native-summary.json').read_text())['narrow_candidate_gate_pass'] is False
assert sha(ORIGINAL/'observations.tar.gz')=='787ecdea6f3dfb11f03b61dd20f2484b763453f390b3d9802ca37e0cc5ec89c0'
data=(ORIGINAL/'run_candidate.py').read_bytes()
assert hashlib.sha256(data).hexdigest()==RUNNER_SHA
m=types.ModuleType('pinned_native_observer')
m.__file__=str(ORIGINAL/'run_candidate.py')
exec(compile(data,m.__file__,'exec'),m.__dict__)
m.frozen()
OUT.mkdir(exist_ok=False)
(OUT/'run_diagnostic.py').write_bytes(Path(__file__).read_bytes())
(OUT/'pinned_candidate_runner.py').write_bytes(data)
(OUT/'base_helper.py').write_bytes((ORIGINAL/'base_helper.py').read_bytes())
m.OUT=OUT
base=m.helper('base_helper.py')
base.REPO,base.OUT,base.HEAD=m.ROOT,OUT,HEAD
identities=json.loads((ORIGINAL/'binary-identities.json').read_text())
row=next(r for r in identities['files'] if r['role']=='compiled node lib test binary before module execution')
binary=Path(row['path'])
assert row['unchanged'] and sha(binary)==row['sha256']
before=None
try:
    assert m.observe('preflight-audit',['bash','scripts/project-preflight.sh','--audit'])
    before=m.source_snapshot('selected-source-before',base)
    assert before['selected_bytes_and_modes_match_head']
    prefix='trillionnium/crates/trnm-pon-node/src/release_owner/'
    sources=[]
    for name in ['service_tests.rs','service_test_fixture.rs','clock_contract.rs','service_clock.rs','service_store.rs','frontier_service.rs']:
        path=m.ROOT/prefix/name
        dest=OUT/('source-'+name)
        dest.write_bytes(path.read_bytes())
        sources.append({'path':prefix+name,'sha256':sha(dest),'bytes':dest.stat().st_size})
    write('source-identities.json',{'head':HEAD,'files':sources})
    m.observe('service-exact-test',[str(binary),TEST,'--exact','--nocapture','--test-threads=1'],timeout=90)
finally:
    after=m.source_snapshot('selected-source-after',base)
    final_binary_sha=sha(binary)
    record=next((r for r in m.RECORDS if r['name']=='service-exact-test'),None)
    text=(OUT/'service-exact-test.stdout.log').read_text() if record else ''
    result={'schema':'TRNM-W1-A-ISOLATED-FAILURE-DIAGNOSTIC1','head':HEAD,
        'test_name':TEST,'records':m.RECORDS,'binary_before':row,
        'binary_after_sha256':final_binary_sha,'binary_unchanged':final_binary_sha==row['sha256'],
        'selected_count':after['selected_count'],
        'selected_source_before_after_match_head':before is not None and before['files']==after['files'] and after['selected_bytes_and_modes_match_head'],
        'selected_before_sha256':sha(OUT/'selected-source-before.json') if before else None,
        'selected_after_sha256':sha(OUT/'selected-source-after.json'),
        'isolated_diagnostic_pass':record is not None and record['expectation_met'] and
            re.search(r'^test '+re.escape(TEST)+r' \.\.\. ok$',text,re.M) is not None and
            re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;',text,re.M) is not None,
        'original_module_failure_preserved':True,'original_module_narrow_gate_pass':False,
        'original_archive_sha256':sha(ORIGINAL/'observations.tar.gz'),
        'test_window_or_source_modified':False,'run_count':1,
        'failure_cause_established':False,'post_quantum_soundness_qualified':False}
    write('diagnostic-summary.json',result)
    files=[p for p in sorted(OUT.iterdir()) if p.is_file()]
    manifest={'head':HEAD,'files':[{'path':p.name,'bytes':p.stat().st_size,'sha256':sha(p)}for p in files]}
    write('manifest.json',manifest)
    with (OUT/'observations.tar.gz').open('xb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as z:
            with tarfile.open(mode='w',fileobj=z) as archive:
                for p in files+[OUT/'manifest.json']:
                    data=p.read_bytes();info=tarfile.TarInfo(p.name);info.size=len(data);info.mode=0o600;info.mtime=0
                    archive.addfile(info,io.BytesIO(data))
    package={'path':str(OUT/'observations.tar.gz'),'bytes':(OUT/'observations.tar.gz').stat().st_size,
        'sha256':sha(OUT/'observations.tar.gz'),'summary_sha256':sha(OUT/'diagnostic-summary.json'),
        'isolated_diagnostic_pass':result['isolated_diagnostic_pass'],
        'original_narrow_gate_remains_failed':True}
    write('package-result.json',package)
    print(json.dumps(package,sort_keys=True),flush=True)
