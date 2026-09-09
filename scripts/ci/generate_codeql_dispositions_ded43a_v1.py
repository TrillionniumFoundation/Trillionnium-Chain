#!/usr/bin/env python3
"""Generate a complete candidate disposition packet for the exact ded43a Rust SARIF.

This tool is fail-closed and review-only. It never dismisses alerts or grants
production, testnet, release, audit, or activation authority.
"""
from __future__ import annotations
import argparse, copy, csv, hashlib, json, pathlib, sys, tempfile
from collections import Counter
from typing import Any

SUBJECT_SHA='ded43a0704b455cd4bef724cb3ca40fb6db9465d'
SUBJECT_TREE='c0791ffb57e05fde43f87bfed1a3b4656c09efc0'
CODEQL_RUN='34311122905'
TRIAGE_RUN='34312572616'
SARIF_SHA='d21b98a0e1b78dc3a45091cf7d2f2a9d24f8811ef08861bc5268d2fb19517f83'
EXPECTED_RULES={'rust/cleartext-logging':90,'rust/hard-coded-cryptographic-value':613}
EXPECTED_CLASSES={'test_fixture_bounded_nonproduction':667,'query_dataflow_false_positive':32,'public_deterministic_protocol_value':3,'public_deterministic_policy_limit':1}
COLLECTION=('.push_back(','.push_front(','.insert(','.remove(','.pop_front(','.pop_back(','.entry(','.extend(','.retain(','.append(')

# Exact-result overrides missed by the conservative v2 lexical test classifier.
# Each value binds the final source context; any source movement fails closed.
SCOPE_OVERRIDES={
    '9146c212d0cd1fc99e62efdccdd80263b0684bbc1dbcb4860035b81cbe4c2004': {'kind': 'file_cfg_test', 'source_context_sha256': 'ecde4d916cb923be80274ba0f6cafd2a8f4ab67f7997085ea7fa58335063dd61'},
    'b90b71dee3e6776cc056444d174ec99255cf937a6249b8403baa6aab3f9a25de': {'kind': 'file_test_support_feature', 'source_context_sha256': 'dfaddadd734c5b6fd680ebdab99e7550cbcfa0cfc27be9d061b2e81d59b91f15'},
    'af2ca6a723357eeaf447b523f7a37e2ecb396ffa13b6924df2b15fb0016a4dc5': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '52ab21c8a5796b3f9210fbe2de3deb66ba4ff05e66825449fff1bc91b5ce5ad3'},
    'd73b1af138d83146ddbffdbb3e262dd2cf6061ffcd6f455b1ac2e8a3bd363cce': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '61b9588d250fb828050faa8e4d5a3c954c7c10cef7bdb5af462b27f9cf523981'},
    'cddc5b281122844894b38b59772234dbb485b2aa2f3f4075894c90923810fb3a': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '1c19bcfe990f925e069b8e8fd1fbbb85431f01f7d139555d23ecb9e8279ee41c'},
    '2382498c4ac7a34322b4e07d087f8198b7e4fe8055d5b501b306519c5b8df1a0': {'kind': 'cfg_test_item', 'source_context_sha256': '4b02bbb1e28a2712a0a5dae5e12f0a3e4faa46f0866b474840d95ab69e35ed1c'},
    '09c9a1953abad4066fe0ad33a5e03af760925b63950422e72034e455005be581': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '9719dbed793bb13ce954c55880aa9db07b3ca02fae8c4b3fb8d9401edd1573d2'},
    'e7632a9994c2b56a889434e7b0abd0d44dbb465f8e9e589f202f0313f17f3892': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '1a60c80c95da8cebc51ea21de35de72217420dd0c5c698afeba598b3fc01da9c'},
    'f0f8ddec583e82c1b7afa1b3455fe82aef05dc2b188ea82cb314d94cca5099ee': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '1044beed6ca797f33e426e7e17a49603f1a93ac41b944a9c843e3dd95af08d2a'},
    'da211cfdd4a57c014f53e93da4c2e0437acc7836a6ffbfb60ceac6b448cc1fbf': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '7945c5b2be8c5aec99716f89b4233c3aad2052029f0ffddf52eac9b110fbbc59'},
    'fd304daa43c6c6f0cbb20dc20b85425342c1e1edeeb858bdc7b24ab1c292dbe2': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '82a1d6f7be72f1f0f19530aa3d997037df4c7f82a6ee4b5b464ea13f0c7fc503'},
    'c59e2993b4d72b5b287f15d4bba4f11d464859b23bebb9ad49240a7dbae65055': {'kind': 'imported_under_cfg_test', 'source_context_sha256': 'd6d4a84e987f618d9817ae845d032b3a8c7663055f136528e9c90c25c5a77956'},
    'bec4fe40efc723a1738936d0f15b7962c2658ed183e33bed3416bf3cd2c11046': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '0079f4e91afa97a1745f21f1aff727c5eb924c3d045ed59f14fb615f8b604297'},
    '160e59c4e266e3dcf0b232308faaf2ee8789a902590a99683af1658bbe2c7605': {'kind': 'imported_under_cfg_test', 'source_context_sha256': 'ce54bcf3a47b2ff07a7fc12e9af4472996ef2641e6fa5dc4eae90a957a25038d'},
    '537ad38e2a69f632267ea9ee22c2d58f6018d5f881dd01e05282597016c02f6a': {'kind': 'imported_under_cfg_test', 'source_context_sha256': 'a5eeca1841959948198b8b6788ff055ef8d692935f0387487c6fd2a3220fc260'},
    '40163cbc2c7e3fa7571aa5c3a96b017c568d4a9530de2d021370b07e77533e6c': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '1686197ab0a078c70f4d35bb68c497745f8db0905728d69af4cf1287ba9d44b9'},
    'a0a3aee48e9b38a8e74368ac2bee4502fd09ac738022c6a015be74c2d45f9c56': {'kind': 'imported_under_cfg_test', 'source_context_sha256': 'cedcb619157a0ece06a9c7733b46a4c2137e5e89189bccd8cb359b1bac075dd3'},
    'd56f05288170089f185bf808e35602ce89f78aa56619e5e5ee2cbde56e50590f': {'kind': 'imported_under_cfg_test', 'source_context_sha256': 'd41116dd3101f9194f3fb8d9d73e05d07caaf2faf47cac2ad6cab97719b65fe2'},
    '801d9332b7df1629ace5f5760b09aa28e47f71290500cce92754211d413fbe4f': {'kind': 'imported_under_cfg_test', 'source_context_sha256': 'e4b8638c0c03df0b6b4a1a64e3ac62474278ab6c753bc13dd66b616b2b2344a7'},
    'a2e8d36c4c22fb1a59b97ac90e61808f275147e948e8351abf65c241c0c3423b': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '835ec7d66bb0d268cf51ab7c0f0e57c460041bc25d3f70fb81d93a78607b9b10'},
    'fd8df0f7b4e651284e147a94d5d6c6c0852c07846c914c7141cb549c2f3ff22c': {'kind': 'imported_under_cfg_test', 'source_context_sha256': '6487788a7878d9e46fc5df2dd06d3ccf98d3069bb82a24de6439ac0baad08adc'},
    'eced4d3a186329575bbe116ce329e09916da218836c906b7e7f9a1ab47b16fbf': {'kind': 'test_function', 'source_context_sha256': 'a106001c66d221007bc081552e450e6ce51a628b865606e3435afbb4334040a1'},
    'f76e602378fb8e91e88302a316d8bd2fbd56cd4df10fad52a9be244d447ddf6a': {'kind': 'test_function', 'source_context_sha256': '40dfa277785321d5cc0712740c49f694e69517f0b739a84601f02f1aa49125de'},
}

class Error(RuntimeError): pass
def fail(msg:str)->None: raise Error(msg)
def h(raw:bytes)->str: return hashlib.sha256(raw).hexdigest()
def cjson(v:Any)->bytes: return json.dumps(v,sort_keys=True,separators=(',',':')).encode()

def norm(uri:str|None)->str|None:
    if not uri:return None
    v=uri.replace('\\','/').removeprefix('file://')
    for m in ('/Trillionnium-Chain/','/trillionnium-chain/'):
        if m in v:v=v.split(m,1)[1]
    v=v.lstrip('/')
    for p in ('trillionnium/','contracts/','scripts/','formal/','tools/','web4-frontend/','proto/','docs/','config/'):
        i=v.find(p)
        if i>=0:return v[i:]
    return v

def key_from_result(r:dict[str,Any])->tuple[Any,...]:
    p=(r.get('locations') or [{}])[0].get('physicalLocation') or {}
    a=p.get('artifactLocation') or {}; g=p.get('region') or {}; f=r.get('partialFingerprints') or {}
    return (r.get('ruleId'),norm(a.get('uri')),g.get('startLine'),g.get('startColumn'),f.get('primaryLocationLineHash'),f.get('primaryLocationStartColumnFingerprint'))

def key_from_triage(r:dict[str,Any])->tuple[Any,...]:
    l=(r.get('locations') or [{}])[0]; f=r.get('partial_fingerprints') or {}
    return (r.get('rule_id'),l.get('normalized_path') or norm(l.get('uri')),l.get('start_line'),l.get('start_column'),f.get('primaryLocationLineHash'),f.get('primaryLocationStartColumnFingerprint'))

def sid(k:tuple[Any,...])->str:return h('|'.join(str(x) for x in k).encode())

def context(root:pathlib.Path,path:str,line:int)->tuple[str,str,str]:
    p=root/path
    if not p.is_file():fail(f'missing source {path}')
    lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
    if line<1 or line>len(lines):fail(f'bad source line {path}:{line}')
    exact=lines[line-1]
    start=max(1,line-3); end=min(len(lines),line+3)
    excerpt='\n'.join(f'{i}: {lines[i-1]}' for i in range(start,end+1))
    return exact,excerpt,h(excerpt.encode())

def load_manual(path:pathlib.Path)->dict[str,dict[str,Any]]:
    d=json.loads(path.read_text())
    if d.get('schema')!='trnm-rust-codeql-manual-semantic-review-v1' or d.get('subject')!={'commit':SUBJECT_SHA,'tree':SUBJECT_TREE}:fail('manual contract mismatch')
    if d.get('review_status')!='candidate_pending_independent_specialist':fail('manual review status drift')
    out={r['stable_id']:r for r in d.get('records',[])}
    if len(out)!=len(d.get('records',[])):fail('duplicate manual stable id')
    return out

def classify(root:pathlib.Path,sarif_path:pathlib.Path,triage_path:pathlib.Path,manual_path:pathlib.Path,overrides:dict[str,Any]|None=None)->dict[str,Any]:
    if h(sarif_path.read_bytes())!=SARIF_SHA:fail('canonical SARIF digest mismatch')
    sarif=json.loads(sarif_path.read_text())
    results=[r for run in sarif.get('runs',[]) for r in run.get('results',[])]
    if len(results)!=703:fail(f'SARIF count drift {len(results)}')
    by_key={key_from_result(r):r for r in results}
    if len(by_key)!=len(results):fail('duplicate SARIF primary identity')
    triage=json.loads(triage_path.read_text())
    if triage.get('source_sha')!=SUBJECT_SHA or triage.get('source_tree')!=SUBJECT_TREE or str(triage.get('source_workflow_run'))!=CODEQL_RUN:fail('triage source mismatch')
    findings=triage.get('findings') or []
    if len(findings)!=703:fail('triage count drift')
    manual=load_manual(manual_path); used=set(); records=[]
    scope=SCOPE_OVERRIDES if overrides is None else overrides
    seen=set()
    for t in findings:
        k=key_from_triage(t); ident=sid(k)
        if ident in seen:fail(f'duplicate triage identity {ident}')
        seen.add(ident)
        r=by_key.get(k)
        if r is None:fail(f'triage/SARIF mismatch {k}')
        rule,path,line,col,lfp,cfp=k
        if not path or not isinstance(line,int):fail(f'unresolved primary location {ident}')
        exact,excerpt,ctx_hash=context(root,path,line)
        result_hash=h(cjson(r)); op='collection_mutation' if any(x in excerpt for x in COLLECTION) else 'other'
        cat=t.get('triage_category')
        scope_record=None
        if cat=='test-only':scope_record={'kind':'triage_v2_exact_test_scope','source_run':TRIAGE_RUN}
        elif ident in scope:
            scope_record=scope[ident]
            if scope_record.get('source_context_sha256')!=ctx_hash:fail(f'scope override source drift {ident}')
        elif cat!='production-review-required':fail(f'unexpected triage category {ident}: {cat}')
        if scope_record is not None:
            if rule=='rust/cleartext-logging' and op=='collection_mutation':
                cls='query_dataflow_false_positive'; resolution='false positive'; rationale='The reported sink is a collection mutation inside a test/test-support surface, not process-visible logging.'
            else:
                cls='test_fixture_bounded_nonproduction'; resolution='used in tests'; rationale='Exact source-scope evidence bounds this result to a test, fixture, simulator, vector, or explicit test-support surface absent from production authority.'
        else:
            m=manual.get(ident)
            if m is None:fail(f'non-test result lacks manual semantic record {path}:{line}')
            for field,value in {'rule_id':rule,'path':path,'line':line,'source_context_sha256':ctx_hash,'sarif_result_sha256':result_hash}.items():
                if m.get(field)!=value:fail(f'manual binding mismatch {ident}:{field}')
            cls=m.get('disposition_class'); rationale=m.get('rationale'); used.add(ident)
            if cls not in ('query_dataflow_false_positive','public_deterministic_protocol_value','public_deterministic_policy_limit'):fail(f'unsupported manual class {ident}')
            if cls=='query_dataflow_false_positive':
                if op!='collection_mutation' and path!='trillionnium/crates/trnm-consensus-core/src/core.rs':fail(f'unbounded false-positive rationale {ident}')
                resolution='false positive'
            elif path=='trillionnium/crates/trnm-consensus-sim/src/simulator.rs':
                resolution='used in tests'
            else:
                resolution='false positive'
        records.append({'stable_id':ident,'rule_id':rule,'path':path,'line':line,'column':col,'partial_fingerprints':{'primaryLocationLineHash':lfp,'primaryLocationStartColumnFingerprint':cfp},'sarif_result_sha256':result_hash,'source_line_sha256':h(exact.encode()),'source_context_sha256':ctx_hash,'triage_category':cat,'scope_proof':scope_record,'operation_class':op,'disposition_class':cls,'recommended_github_resolution':resolution,'rationale':rationale,'review_status':'candidate_pending_independent_specialist','source_change_required':False})
    if used!=set(manual):fail(f'unconsumed manual records: {sorted(set(manual)-used)}')
    rules=Counter(x['rule_id'] for x in records); classes=Counter(x['disposition_class'] for x in records); resolutions=Counter(x['recommended_github_resolution'] for x in records)
    if dict(rules)!=EXPECTED_RULES:fail(f'rule count drift {dict(rules)}')
    if dict(classes)!=EXPECTED_CLASSES:fail(f'class count drift {dict(classes)}')
    if dict(resolutions)!={'false positive':35,'used in tests':668}:fail(f'resolution count drift {dict(resolutions)}')
    return {'schema':'trnm-rust-codeql-disposition-candidate-v1','repository':'TrillionniumFoundation/Trillionnium-Chain','subject':{'commit':SUBJECT_SHA,'tree':SUBJECT_TREE},'analyzer':{'codeql_workflow_run':CODEQL_RUN,'triage_workflow_run':TRIAGE_RUN,'canonical_sarif_sha256':SARIF_SHA,'language':'rust','build_mode':'none','query_suite':'security-extended'},'counts':{'total':703,'by_rule':dict(sorted(rules.items())),'by_disposition':dict(sorted(classes.items())),'recommended_github_resolution':dict(sorted(resolutions.items())),'unreviewed':0,'actionable_production_findings':0},'authority':{'automatic_dismissal_performed':False,'alert_dismissal_authorized':False,'independent_specialist_acceptance':False,'administration_readback_complete':False,'official_codeql_gate_success':False,'all_gaps_closed':False,'production_candidate':False,'public_testnet_ready':False,'release_ready':False},'findings':records}

def write(d:dict[str,Any],out:pathlib.Path)->None:
    out.mkdir(parents=True,exist_ok=True)
    (out/'dispositions-v1.json').write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
    fields=('stable_id','rule_id','path','line','column','disposition_class','recommended_github_resolution','triage_category','operation_class','source_line_sha256','source_context_sha256','sarif_result_sha256','rationale')
    with (out/'dispositions-v1.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows({k:r.get(k) for k in fields} for r in d['findings'])
    report={k:d[k] for k in ('schema','repository','subject','analyzer','counts','authority')}
    (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    c=d['counts']; lines=['<!-- trnm-codeql-disposition-candidate-ded43a-v1 -->','## Complete exact-source Rust CodeQL disposition candidate','',f"- source: `{SUBJECT_SHA}`",f"- tree: `{SUBJECT_TREE}`",f"- complete results: **{c['total']}**",f"- test/fixture bounded non-production: **{c['by_disposition']['test_fixture_bounded_nonproduction']}**",f"- query/dataflow false positive: **{c['by_disposition']['query_dataflow_false_positive']}**",f"- public deterministic protocol values: **{c['by_disposition']['public_deterministic_protocol_value']}**",f"- public deterministic policy limits: **{c['by_disposition']['public_deterministic_policy_limit']}**",f"- unreviewed: **{c['unreviewed']}**",f"- candidate actionable production findings: **{c['actionable_production_findings']}**",'', 'Every result is bound to an exact primary fingerprint, SARIF-result digest, and source-line/context digest.','', 'This packet is pending non-author specialist review. It performs no alert dismissal and grants no release or activation authority.']
    (out/'summary.md').write_text('\n'.join(lines)+'\n')
    (out/'SHA256SUMS').write_text('\n'.join(f'{h(p.read_bytes())}  {p.name}' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS')+'\n')

def selftest(root:pathlib.Path,sarif:pathlib.Path,triage:pathlib.Path,manual:pathlib.Path)->None:
    classify(root,sarif,triage,manual)
    d=json.loads(manual.read_text()); d['records'].pop()
    with tempfile.TemporaryDirectory() as td:
        p=pathlib.Path(td)/'manual.json';p.write_text(json.dumps(d))
        try:classify(root,sarif,triage,p)
        except Error:pass
        else:fail('missing-manual mutant escaped')
        bad=copy.deepcopy(SCOPE_OVERRIDES); first=next(iter(bad));bad[first]=dict(bad[first]);bad[first]['source_context_sha256']='0'*64
        try:classify(root,sarif,triage,manual,bad)
        except Error:pass
        else:fail('forged-scope mutant escaped')
        t=json.loads(triage.read_text());t['findings'].pop();q=pathlib.Path(td)/'triage.json';q.write_text(json.dumps(t))
        try:classify(root,sarif,q,manual)
        except Error:pass
        else:fail('missing-finding mutant escaped')

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=pathlib.Path,required=True);ap.add_argument('--sarif',type=pathlib.Path,required=True);ap.add_argument('--triage',type=pathlib.Path,required=True);ap.add_argument('--manual',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--self-test',action='store_true');a=ap.parse_args()
    try:
        d=classify(a.source_root.resolve(),a.sarif.resolve(),a.triage.resolve(),a.manual.resolve())
        if a.self_test:selftest(a.source_root.resolve(),a.sarif.resolve(),a.triage.resolve(),a.manual.resolve())
        write(d,a.output.resolve());print(json.dumps(d['counts'],indent=2,sort_keys=True));return 0
    except Error as e:print(f'FAIL: {e}',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
