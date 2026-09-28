#!/usr/bin/env python3
"""Typed procedure/source/schema completeness, not a natural-language correctness proof.
Executable conformance and independent acceptance remain separate mandatory evidence.
"""
from pathlib import Path
import ast,json,re

def fail(condition,message):
    if not condition:raise ValueError(message)
def normalized(text):return re.sub(r'\s+',' ',text).strip()
def validate(root):
    root=Path(root)
    def load(p):return json.loads((root/p).read_text())
    def file(p):
        path=(root/p).resolve();fail(path.is_relative_to(root.resolve())and path.is_file(),'missing/escaping contract dependency '+p);return path
    registry=load('config/pon/module-contracts-v1.json');rows=registry['modules']
    maturity=load('config/pon/module-maturity-v1.json');states={r['id']:r for r in maturity['modules']}
    fail(len(rows)==18 and {r['id']for r in rows}=={f'M{i:02d}'for i in range(18)},'18 unique procedures owners required')
    fail(len(states)==18,'maturity coverage')
    known_tests=set()
    for p in (root/'formal/pon-nakamoto-v1').glob('test_*.py'):
        known_tests.update(n.name for n in ast.walk(ast.parse(p.read_text()))if isinstance(n,ast.ClassDef))
    for row in rows:
        fail(set(row)=={'id','specification','shared_contract','operations','source_refs','test_classes','native_packages','implementation_scope','native_product_integrated','independent_accepted'},'module registry fields')
        text=file(row['specification']).read_text();file(row['shared_contract'])
        match=re.search(r'(?ms)^## PoN State machine\s*\n(.*?)(?=^## |\Z)',text)
        fail(match is not None,'algorithm section absent '+row['id']);body=match.group(1)
        fail(not re.search(r'^\s*(?:TBD|TODO|FIXME|待定|待补)[.!:]?\s*$',body,re.I|re.M),'placeholder algorithm '+row['id'])
        fail(len(row['operations'])>=2,'missing concrete operations')
        for op in row['operations']:
            fail(set(op)=={'id','inputs','output','algorithm','commit','errors','limits'},'procedure fields')
            fail(op['id'].startswith(row['id']+'.')and op['id']in body,'missing procedure binding')
            for k,v in op.items():
                fail(isinstance(v,str)and len(v.strip())>=3,'empty procedure '+k)
                fail(not re.fullmatch(r'(?:TBD|TODO|none)',v,re.I),'undefined procedure '+k)
            fail(len(op['algorithm'])>=60 and len(op['commit'])>=20,'non-executable procedure detail')
        for p in row['source_refs']:file(p)
        fail(bool(row['test_classes'])and set(row['test_classes'])<=known_tests,'missing executable tests')
        s=states[row['id']]
        fail(s['documented'] is True and s['has_executable_contract'] is True,'maturity must describe supplied contract')
        fail(s['has_native_component']==bool(row['native_packages']),'native/reference distinction drift')
        fail(s['native_product_integrated'] is False and s['independent_accepted'] is False,'unearned integration or acceptance')
        fail(row['native_product_integrated'] is False and row['independent_accepted'] is False,'unearned source authority')
    w=load('config/pon/work-profile-v1.json');p=load('config/pon/devnet-v1.json');wire=load('config/pon/ledger-v1.json');family=load('config/pon/model-family-v1.json')
    fail(w['id']==p['work_profile'] and w['n']==64 and w['rank']==8 and w['field_modulus']==4294967291 and w['proof_bytes']==49188,'work relation parameter mismatch')
    fail(w['production_eligible'] is False and w['external_hardness_acceptance'] is False,'unqualified work activated')
    fail(p['not_mainnet'] is True and p['production_activation'] is False,'experiment is not a mainnet genesis')
    fail([r['tag']for r in wire['commands']]==list(range(1,13)),'closed command set drift')
    fail(len({r['name']for r in wire['commands']})==12,'duplicate command')
    widths={'hash32':32,'u64':8,'sig64':64}
    for row in wire['commands']:
        fields=row['payload'];fail(len({f['name']for f in fields})==len(fields),'duplicate payload field')
        if all(f['type']in widths for f in fields):fail(row['fixed_payload_bytes']==sum(widths[f['type']]for f in fields),'payload byte width mismatch')
        else:fail(row['fixed_payload_bytes']is None,'variable payload incorrectly fixed')
    fail(family['dimensions']==257 and family['experts']==3 and family['weight_scale']==1024,'model family mismatch')
    vectors=load('formal/pon-nakamoto-v1/vectors/expected.json')
    fail({r['tag']for r in vectors['transactions']}==set(range(1,13)),'vector command coverage')
    for r in vectors['transactions']+vectors['negative']:file('formal/pon-nakamoto-v1/vectors/'+r['file'])
    fail(file('formal/pon-nakamoto-v1/vectors/work.bin').stat().st_size==w['proof_bytes'],'work vector size')
    fail(file('formal/pon-nakamoto-v1/vectors/header.bin').stat().st_size==318,'header vector size')
    plan=file('docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md').read_text()
    fail('existing evidence-contract symlink'not in plan,'removed symlink requirement')
    m00=normalized(file(rows[0]['specification']).read_text())
    fail(not re.search(r'Preserve historical CEV0/CEV1 decoders|decoders in explicit legacy dispatch',m00,re.I),'retired decoder requirement')
    boundary=load('PROJECT_BOUNDARY.json')['repository']
    fail(boundary['required_pull_request_reviews']==0 and boundary['require_code_owner_review']is False and boundary['require_last_push_approval']is False,'review policy contradicts owner-approved remote settings')
    fail(file('README.md').read_bytes()==b'\n','owner-cleared root README changed')
    return {'modules':18,'typed_operations':sum(len(r['operations'])for r in rows),'wire_tags':12,'native_product_accepted':False,'independent_accepted':False}
if __name__=='__main__':
    root=Path(__file__).resolve().parents[2]
    print(json.dumps(validate(root),sort_keys=True))
