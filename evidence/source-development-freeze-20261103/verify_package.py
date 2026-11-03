"""Standard-library integrity check; does not replace AST/source-range verification."""
import gzip,hashlib,json
from pathlib import Path
p=Path(__file__).resolve().parent
for line in (p/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split('  ',1);assert hashlib.sha256((p/name).read_bytes()).hexdigest()==digest,name
for name,digest in json.loads((p/'decoded-hashes.json').read_text()).items():
 assert hashlib.sha256(gzip.decompress((p/(name+'.gz')).read_bytes())).hexdigest()==digest,name
rows=json.loads(gzip.decompress((p/'rows.json.gz').read_bytes()));groups=json.loads((p/'groups.json').read_text());summary=json.loads((p/'summary.json').read_text())
assert len(rows)==len({r['id']for r in rows})==419
members={i:g for g in groups for i in g['token_ids']};assert set(members)=={r['id']for r in rows}
for r in rows:assert r['family']==members[r['id']]['component']and r['split']==members[r['id']]['split']
assert len(groups)==29 and summary['collection_split_viable']is False
assert not any(r['module']=='M04'and r['split']=='dev_probe'for r in rows)
print('PASS: package and decoded hashes, 419 identities, 29 frozen groups, failed M04 probe gate. Full AST/source-range validation is separate.')
