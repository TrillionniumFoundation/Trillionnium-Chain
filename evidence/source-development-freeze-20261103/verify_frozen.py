"""Verify frozen AST identities, source ranges, feature vectors and isolation edges."""
import collections,hashlib,json,importlib.util,gzip
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('collector',HERE/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
rows=json.loads(gzip.decompress((HERE/'rows.json.gz').read_bytes()));groups=json.loads((HERE/'groups.json').read_text());summary=json.loads((HERE/'summary.json').read_text())
assert summary['collection_plan_sha256']==hashlib.sha256((HERE/'COLLECTION_PLAN.json').read_bytes()).hexdigest()
assert len(rows)==len({r['id'] for r in rows})==419
byid={r['id']:r for r in rows};groupof={i:g for g in groups for i in g['token_ids']}
assert set(byid)==set(groupof)
proofs=0
for r in rows:
 funcs,status=c.extract(r['source'].encode());assert not status['file_parse_errors'] and len(funcs)==1
 f=funcs[0];assert f['token_id']==r['id'];assert c.features(' '.join(f['tokens']))==r['x']
 g=groupof[r['id']];assert r['family']==g['component'] and r['split']==g['split']
 assert ['M00','M04','M10'][r['label']]==r['module']
 for proof in r['provenance']:
  raw=c.content(proof['blob']);span=raw[proof['start_byte']:proof['end_byte']]
  assert hashlib.sha256(span).hexdigest()==proof['source_sha256']
  ff,st=c.extract(span);assert not st['file_parse_errors'] and len(ff)==1 and ff[0]['token_id']==r['id'];proofs+=1
for g in groups:
 assert hashlib.sha256('\n'.join(sorted(g['token_ids'])).encode()).hexdigest()==g['component']
 assert len(g['modules'])==1
 expected='dev_probe'if int(g['component'],16)%5==0 else 'dev_fit';assert g['split']==expected
for edge in json.loads((HERE/'family-edges.json').read_text()):
 if edge['a']in byid and edge['b']in byid:assert byid[edge['a']]['family']==byid[edge['b']]['family']
for a,b in json.loads((HERE/'near-edges.json').read_text()):
 if a in byid and b in byid:assert byid[a]['family']==byid[b]['family']
# A parent source file and split descendants may not cross groups.
path_groups=collections.defaultdict(set)
for r in rows:
 for p in r['paths']:path_groups[p].add(r['family'])
assert all(len(v)==1 for v in path_groups.values())
for p,families in path_groups.items():
 for child,other in path_groups.items():
  if child.startswith(p.removesuffix('.rs')+'/'):assert families==other
# Fixed parser stress cases: comments and string braces do not define boundaries;
# nested functions are not emitted as overlapping observations.
fixture=b'#[test]\nfn outside() { let message = r###"} // fake fn x() {"###; /* } */ fn inner() {} let padding = "012345678901234567890123456789"; }'
fs,st=c.extract(fixture);assert not st['file_parse_errors']and len(fs)==1 and fs[0]['name']=='outside'and fs[0]['direct_test']
fs,st=c.extract(b'fn broken() { let value = "unterminated');assert st['file_parse_errors']
assert summary['collection_split_viable']is False
assert not any(r['module']=='M04'and r['split']=='dev_probe'for r in rows)
report={'result':'PASS','functions':len(rows),'source_range_proofs':proofs,'families':len(groups),'parser_stress_cases':2,'family_and_near_edges_no_cross_split':True,'M04_families':sum(g['modules']==['M04']for g in groups),'M04_probe_functions':0,'split_gate_failed_as_expected':True,'training_not_run':True}
print(json.dumps(report,indent=2))
