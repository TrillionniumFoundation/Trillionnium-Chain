"""Validate all retained out-of-fold predictions against train-only identities."""
import hashlib,json
from pathlib import Path
p=Path(__file__).resolve().parent;root=p.parents[1]
plan=json.loads((p/'PLAN.json').read_text());r=json.loads((p/'report.json').read_text())
raw=(root/plan['input']).read_bytes();rows=json.loads(raw)
assert hashlib.sha256(raw).hexdigest()==r['input_sha256']==plan['input_sha256']
assert hashlib.sha256((p/'PLAN.json').read_bytes()).hexdigest()==r['plan_sha256']
assert len(r['out_of_fold'])==len(rows)==1005
assert len({x['id'] for x in r['out_of_fold']})==len(rows)
f={};mat=[[0]*3 for _ in range(3)]
for row,out in zip(rows,r['out_of_fold']):
    assert row['split']=='train' and row['id']==out['id'] and row['label']==out['true']
    f.setdefault(row['file'],out['fold']);assert f[row['file']]==out['fold']
    assert out['float']==out['integer'];mat[out['true']][out['integer']]+=1
assert len(f)==150 and set(f.values())==set(range(5))
assert mat==r['summary']['integer']['confusion_true_rows_predicted_columns']
assert sum(mat[i][i] for i in range(3))==647
assert all(x['disagreements']==x['quantized_clipped_weights']==0 for x in r['folds'])
assert sum(x['test_rows'] for x in r['folds'])==1005
print('PASS: input and plan hashes; 1005 unique OOF identities; 150 whole-file groups; five folds; exact confusion and prediction parity.')
