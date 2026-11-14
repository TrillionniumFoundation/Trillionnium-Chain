"""Dispatch exactly the reviewed one-shot operation after the parent's explicit go."""
import hashlib,json,os,stat
from pathlib import Path
ROOT=Path('/home/qq/work/chain-bt-4a0b-frozen02')
BASE=Path(str(ROOT)+'-validation');CONTROL=Path(str(ROOT)+'-control')
CONFIG=CONTROL/'model-config.env2.json'
CONFIG_SHA='f0e314ac93b175ada1a56969cfef58fe4e0236ed8c3e6b1cb0c2764f8b230150'
OPERATION='bf34a669dc4b3617d97bee356f1cadf3504f3c5993999c5136ce1d6b0cd6f9c2'
SOURCE_SHA='3d4b4bbd30f1c37dc9986a5e512d13ae4d93a330a00fde904bd9b3fcf381083e'
AUDIT_SHA='2a5db7a61d5340511895cdc6b2e2675b2cc87aaa2a38b2a8815c8bc4059edd47'
WRAPPER_SHA='46329982d1de9e3e7dac3bcbc9cb7fcf1455ab3ceb514637097cbad8e0b9d313'
BINARY_SHA='ef4d33be1574c27852187546f4393f301eb175b8246f647ce3d15a5d21fd2155'
os.umask(0o077)

def raw(path,maximum=64*1024**2):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  before=os.fstat(stream.fileno());assert stat.S_ISREG(before.st_mode) and 0<=before.st_size<=maximum
  value=stream.read(before.st_size+1);after=os.fstat(stream.fileno())
 fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
 assert len(value)==before.st_size and tuple(getattr(before,k) for k in fields)==tuple(getattr(after,k) for k in fields)
 return value

def pinned(path,checksum,size=None):
 value=raw(path);assert hashlib.sha256(value).hexdigest()==checksum
 if size is not None:assert len(value)==size
 return value

assert len(CONFIG_SHA)==64 and all(c in '0123456789abcdef' for c in CONFIG_SHA),'unbound draft cannot dispatch'
assert Path.cwd()==ROOT and ROOT.resolve(strict=True)==ROOT
config=json.loads(pinned(CONFIG,CONFIG_SHA))
assert config['head']=='031d442dd0acb693afcfaf42f9cc4db446ba52cb' and config['tree']=='a897ba4c74897a05ceb364f098b1bfe32c850213'
assert config['operation']==OPERATION and config['requires_root_explicit_model_go'] is True
assert (config['required_native_seconds'],config['required_memory_max_bytes'],config['required_whole_job_cpu_quota_percent'])==(300,8589934592,400)
assert (config['torch_intraop_threads'],config['torch_interop_threads'],config['payload_files'],config['payload_bytes'],config['chunks'])==(4,1,30,279627268,95)
assert config['model_generation']==1 and config['environment_generation']==2
for key in ('model_loaded','model_executed','native_operation_started','original_hepta_owner_used','hepta_final_use','independent_domains_qualified','production_activation'):
 assert config[key] is False
source=BASE/'inputs-env2-01/source-inputs.native-v2-env2.json'
audit=BASE/'inputs-env2-01/source-inputs.native-v2-env2.verification.json'
assert config['source']==str(source) and config['source_sha256']==SOURCE_SHA
assert config['audit']==str(audit) and config['audit_sha256']==AUDIT_SHA
spec=json.loads(pinned(source,SOURCE_SHA,9984));pinned(audit,AUDIT_SHA,13842)
assert spec['operation']==OPERATION and spec['environment_generation']==2 and spec['parent']['generation']==1
output=BASE/('real-native-env2-'+OPERATION[:16]+'-attempt01')
assert spec['output']==str(output)
assert not os.path.lexists(output) and not os.path.lexists(str(output)+'-wrapper'),'original operation is one-shot only'
wrapper=CONTROL/'run_model.py';pinned(wrapper,WRAPPER_SHA,13622)
assert config['wrapper_sha256']==WRAPPER_SHA
binary=Path(str(ROOT)+'-target/release/examples/cell_native_shard_research_next_use_v2')
assert config['binary']==str(binary) and config['binary_sha256']==BINARY_SHA
assert pinned(binary,BINARY_SHA,19752832)[:4]==b'\x7fELF'
receipt=json.loads(raw(BASE/'model-preparation-01/preparation-success.json'))
assert receipt['completed'] is True and receipt['passed'] is True
assert receipt['config']['path']==str(CONFIG) and receipt['config']['sha256']==CONFIG_SHA
assert receipt['operation']==OPERATION and receipt['dependency_only_runtime_import_passed'] is True
assert receipt['native_operation_started'] is False and receipt['model_loaded'] is False and receipt['model_executed'] is False
print(json.dumps({'dispatch':'original_one_shot_wrapper','operation':OPERATION,'config_sha256':CONFIG_SHA,'wrapper_sha256':WRAPPER_SHA,'binary_sha256':BINARY_SHA,'native_operation_started':False},sort_keys=True),flush=True)
os.execv('/usr/bin/python3',['/usr/bin/python3','-B',str(wrapper),str(CONFIG),'--execute'])
