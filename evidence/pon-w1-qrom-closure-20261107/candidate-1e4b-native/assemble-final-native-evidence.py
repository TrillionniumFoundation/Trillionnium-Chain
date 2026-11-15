#!/usr/bin/env python3
"""Create-only publication copy set; original native evidence remains untouched."""
from pathlib import Path
import hashlib,json,os,subprocess
P=Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence')
ROOT=Path('/home/qian-qi/work/chain-qrom-local-20261107-7150')
RAW=P/'native-1e4bffc371bc'
REVIEW=P/'native-1e4bffc371bc-review'
DIAG=P/'native-1e4bffc371bc-failure-diagnostic'
FINAL=P/'final-native-evidence'
HEAD='1e4bffc371bcdc53aabc621b6b6cb2485ab36f53'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,x):
    with p.open('x') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==HEAD
assert sha(RAW/'observations.tar.gz')=='787ecdea6f3dfb11f03b61dd20f2484b763453f390b3d9802ca37e0cc5ec89c0'
assert sha(DIAG/'observations.tar.gz')=='413a6c7bf5a589b876cf05dd72855379b1643b9da2cbe19d64bacc3a5d5a9d09'
assert sha(REVIEW/'summary.json')=='90ee6d281e5b4d4e71ef3ca8c27eb49b66cf3260bf58840278ef0b3041e66d00'
review=json.loads((REVIEW/'summary.json').read_text())
assert review['narrow_candidate_gate_pass'] is False
assert review['key_fifteen']['all_fifteen_actual_pass'] is True
assert review['evidence_integrity_checks_completed'] is True
FINAL.mkdir(exist_ok=False)
plans={
'candidate-1e4b-native':[
(RAW/'observations.tar.gz','observations.tar.gz'),
(RAW/'native-summary.json','native-summary.json'),
(RAW/'manifest.json','manifest.json'),
(RAW/'package-result.json','package-result.json'),
(RAW/'run_candidate.py','run_candidate.py'),
(RAW/'release-owner-tests.stdout.log','release-owner-tests.stdout.log'),
(RAW/'release-owner-tests.stderr.log','release-owner-tests.stderr.log'),
(RAW/'release-owner-tests.json','release-owner-tests.json'),
(RAW/'release-owner-compiled-roster.json','release-owner-compiled-roster.json'),
(RAW/'selected-source-comparison.json','selected-source-comparison.json'),
(REVIEW/'summary.json','independent-summary.json'),
(REVIEW/'observations.tar.gz','independent-review.tar.gz'),
(REVIEW/'manifest.json','independent-review-manifest.json'),
(REVIEW/'package-result.json','independent-review-package-result.json'),
(REVIEW/'review.py','independent-review.py'),
(REVIEW/'archive-integrity.json','independent-archive-integrity.json'),
(REVIEW/'key-fifteen-completion.json','key-fifteen-completion.json'),
(REVIEW/'selected-source-third-check.json','selected-source-third-check.json'),
(REVIEW/'sealed-production-comment-only.json','sealed-production-comment-only.json'),
(REVIEW/'controller-terminal.json','controller-terminal.json'),
(REVIEW/'review-process-semantics.json','review-process-semantics.json'),
(Path(__file__),'assemble-final-native-evidence.py')],
'candidate-1e4b-service-diagnostic':[
(DIAG/'observations.tar.gz','observations.tar.gz'),
(DIAG/'diagnostic-summary.json','diagnostic-summary.json'),
(DIAG/'manifest.json','manifest.json'),
(DIAG/'package-result.json','package-result.json'),
(DIAG/'run_diagnostic.py','run_diagnostic.py'),
(DIAG/'service-exact-test.json','service-exact-test.json'),
(DIAG/'service-exact-test.stdout.log','service-exact-test.stdout.log'),
(DIAG/'service-exact-test.stderr.log','service-exact-test.stderr.log'),
(DIAG/'source-identities.json','source-identities.json')]+[(DIAG/('source-'+n),'source-'+n)for n in
['service_tests.rs','service_test_fixture.rs','clock_contract.rs','service_clock.rs','service_store.rs','frontier_service.rs']]
}
all_rows=[]
directory_rows=[]
for dirname,items in plans.items():
    target=FINAL/dirname;target.mkdir()
    rows=[]
    for source,name in items:
        data=source.read_bytes()
        dest=target/name
        with dest.open('xb')as f:f.write(data);f.flush();os.fsync(f.fileno())
        assert sha(dest)==sha(source)
        os.chmod(dest,0o644)
        row={'path':name,'bytes':len(data),'sha256':sha(dest),'copied_from':str(source)}
        rows.append(row);all_rows.append(dict(row,path=dirname+'/'+name))
    write(target/'copy-manifest.json',{'schema':'TRNM-W1-A-NATIVE-COPY-DIRECTORY1','head':HEAD,'directory':dirname,
        'files':rows,'narrow_candidate_gate_pass':False,'cloud_copy_completed':False,
        'copy_is_evidence_only_not_a_new_native_test_run':True})
    p=target/'copy-manifest.json'
    os.chmod(p,0o644)
    all_rows.append({'path':dirname+'/copy-manifest.json','bytes':p.stat().st_size,'sha256':sha(p),
        'copied_from':None})
    directory_rows.append({'directory':dirname,'files':len(rows)+1,'copy_manifest_sha256':sha(p)})
write(FINAL/'manifest.json',{'schema':'TRNM-W1-A-FINAL-NATIVE-COPY-SET1','head':HEAD,'files':all_rows,
    'file_count':len(all_rows),'native_gate_pass':False,'cloud_copy_completed':False,
    'original_native_archive_preserved':True,'original_diagnostic_archive_preserved':True})
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==HEAD
result={'path':str(FINAL),'head':HEAD,'file_count':len(all_rows),
'manifest_sha256':sha(FINAL/'manifest.json'),'directories':directory_rows,
'narrow_candidate_gate_pass':False,'key_fifteen_pass':True,'cloud_copy_completed':False,
'source_clone_remains_frozen_at_A':True,'ready_for_publication_evidence_copy':True}
write(FINAL/'package-result.json',result)
print(json.dumps(result,sort_keys=True),flush=True)
