import ast,difflib,hashlib,json,os,stat,sys
from pathlib import Path
old,new=json.loads(sys.argv[1])
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
base.mkdir(mode=0o700)
def pin(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def put(name,b):
 p=base/name
 with p.open('xb') as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('READBACK')
 return pin(p)
prior=Path('/private/tmp/chain-prci-H5DF-cross-cost-selected-artifact-20261114-v1/directory-producer.py')
r=prior.read_bytes()
if len(r)!=21134 or hashlib.sha256(r).hexdigest()!='b5378e5bab78f3c41ecd0379107d7bf9effaeac3de60577ef4bae6a30335e256' or r!=old.encode():raise ValueError('PRIOR_PIN')
compile(new,str(base/'directory-producer.py'),'exec',dont_inherit=True,optimize=0)
a=ast.parse(old);b=ast.parse(new)
af={n.name:ast.dump(n,include_attributes=False) for n in a.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
bf={n.name:ast.dump(n,include_attributes=False) for n in b.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
if set(af)!=set(bf) or any(af[k]!=bf[k] for k in af if k!='main'):raise ValueError('HELPER_AST_DRIFT')
source_pin=put('directory-producer.py',new.encode())
patch_pin=put('x64-to-arm64-directory.patch',''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='reviewed-x64/directory-producer.py',tofile='arm64/directory-producer.py')).encode())
plan={'schema':'trnm-H5DF-arm-directory-acquisition-plan-v1','status':'PREPARED_NOT_EXECUTED','artifact_id':14124468052,'artifact_bytes':9909858,'artifact_declared_sha256':'3b093c989b92fb7d657195826ae6faed9e641840dbe8f48c7721aebcf7804d7d','run_id':43621754143,'job_id':132528769087,'head':'5df7ae6f482157c5f7fdcbcd52222117a965053f','tree':'6be4940d38cc88782657f2684cbefe48866f8b9f','execution_requires_root_confirmation':True,'requests':[{'method':'GET','endpoint':'repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/14124468052','body_cap':65536},{'method':'GET','endpoint':'repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/14124468052/zip','range':'bytes=9844301-9909857','body_cap':65557,'required_status':206,'required_content_range':'bytes 9844301-9909857/9909858'}],'actual_directory_count':'UNKNOWN_UNTIL_DIRECTORY_READ','whole_zip_download':False,'automatic_retry':False,'per_get_max_seconds':180,'existing_combined_deadline_seconds':900,'combined_deadline_will_not_be_reset_implicitly':True,'member_requests_currently_authorized':False,'selected_records_require_actual_directory_and_explicit_plan':'pending','refuse_200_or_incomplete_directory':True,'save_signed_url_headers_auth_cookies':False,'executed_target_or_helpers':False,'static_compile_only':True,'unchanged_helper_names':[k for k in af if k!='main'],'source':source_pin,'diff':patch_pin,'reference':pin(prior)}
plan_pin=put('directory-plan.json',(json.dumps(plan,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'status':'PREPARED_NOT_EXECUTED','producer':source_pin,'diff':patch_pin,'plan':plan_pin,'unchanged_helper_count':len(af)-1},sort_keys=True))
