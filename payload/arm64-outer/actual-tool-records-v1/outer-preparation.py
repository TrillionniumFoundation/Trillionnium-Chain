import os,sys,pathlib,hashlib,json,ast,difflib,stat
R=pathlib.Path('/private/tmp/chain-H5DF-arm64-cross-cost-original-evidence-20261114-v1')
old=pathlib.Path('/private/tmp/chain-prci-H5DF-cross-arch-cost-x64-original-log-20261114-v1/producer.py')
b=old.read_bytes()
if len(b)!=9427 or hashlib.sha256(b).hexdigest()!='54a584717bb86071cfa2afe7a03ca5ad9aa6de4cd7ac968d636f1b228cd9b0b2':raise ValueError('old producer pin')
new=sys.argv[1].encode()
ast.parse(new);compile(new,str(R/'producer.py'),'exec')
a=ast.parse(b);z=ast.parse(new)
for name in ['capture','one','utc','need','fp','pin','write','unique_pairs','read_json']:
 f=next(x for x in a.body if isinstance(x,ast.FunctionDef) and x.name==name);g=next(x for x in z.body if isinstance(x,ast.FunctionDef) and x.name==name)
 if ast.dump(f,include_attributes=False)!=ast.dump(g,include_attributes=False):raise ValueError('capture helper changed '+name)
R.mkdir()
def w(n,b):
 p=R/n
 with p.open('xb') as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('readback')
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
p=w('producer.py',new)
d=w('x64-to-arm64-outer.patch',''.join(difflib.unified_diff(b.decode().splitlines(True),new.decode().splitlines(True),fromfile=str(old),tofile=str(R/'producer.py'))).encode())
r=w('preparation.json',(json.dumps({'schema':'H5DF-arm64-outer-capture-preparation-v1','status':'PREPARED_NOT_EXECUTED','producer':p,'diff':d,'syntax_AST_only':True,'capture_helpers_AST_unchanged':True,'planned_GETs':3,'overall_seconds':300,'job_id':132528769087,'artifact_id':14124468052,'artifact_bytes':9909858,'artifact_downloaded':False,'native_build_test_probe':False,'source_refs_stage_changed':False},indent=2)+'\n').encode())
print(json.dumps({'producer':p,'diff':d,'preparation':r}))
