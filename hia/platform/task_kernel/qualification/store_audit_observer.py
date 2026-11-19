"""Compare native private audits with the unchanged original Rust methods."""
from pathlib import Path
import ctypes,hashlib,json,os,shutil,sqlite3,struct,subprocess,sys,time
from borsh_fixture import Fixtures
ROOT=Path(__file__).resolve().parents[4]
BUILD,ORIGINAL,POLICY,WORK=map(lambda s:Path(s).absolute(),sys.argv[1:])
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700);(WORK/'blobs').mkdir();CASES=WORK/'cases';CASES.mkdir();DB=CASES/'audit.sqlite'
report={'schema':'trnm.hia.task-kernel.store-audit-qualification.v1','status':'FAIL','finalized':False,'scope':'state/journal roots, four metadata reads, schema/metadata/object/operation/committed-block audits, marker loader, freshly audited block root and complete private audit_store; not full store owner','native_calls':0,'original_calls':0,'fixture_preparations':0,'stages':[]}
def identity(path):
 b=Path(path).read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def blob(raw):
 sha=hashlib.sha256(raw).hexdigest();p=WORK/'blobs'/sha
 if not p.exists():p.write_bytes(raw)
 assert p.read_bytes()==raw
 return {'bytes':len(raw),'sha256':sha,'path':'blobs/'+sha}
def save():(WORK/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def stage(label,executable,data):
 (WORK/(label+'.stdin.raw')).write_bytes(data);start=time.monotonic_ns()
 p=subprocess.run([str(executable)],input=data,capture_output=True,cwd=CASES,timeout=30)
 (WORK/(label+'.stdout.raw')).write_bytes(p.stdout);(WORK/(label+'.stderr.raw')).write_bytes(p.stderr)
 report['stages'].append({'name':label,'argv':[str(executable)],'cwd':str(CASES),'timeout_seconds':30,'elapsed_ns':time.monotonic_ns()-start,'exit_code':p.returncode});save();assert p.returncode==0 and not p.stderr
 return p.stdout
def original(label,raw,prefix=b''):
 out=stage(label,ORIGINAL,prefix+raw.hex().encode()+b'\n').strip();code,out=out.split(b'|',1);return int(code),bytes.fromhex(out.decode())
def frame(method,bundle,maximum=(1<<64)-1):
 path=os.fsencode(DB);return b'TKSA0001'+struct.pack('<QQQQ',method,maximum,len(path),len(bundle))+bytes([9])*32+path+bundle
def successful(code,out):return code==0 and len(out)>=32 and struct.unpack_from('<Q',out)[0]==0

def inventory():
 rows=[]
 for p in sorted(CASES.iterdir()):
  assert p.is_file() and not p.is_symlink();rows.append({'name':p.name,'mode':p.stat().st_mode & 0o777,'bytes':blob(p.read_bytes())})
 return rows

try:
 build=json.loads((BUILD/'build.json').read_text());assert build['status']=='PASS' and build['finalized'] and build['source_before']==build['source_after']
 inputs=dict(build['source_before'])
 for name,expected in build['artifacts'].items():assert identity(BUILD/name)==expected;inputs[str(BUILD/name)]=expected
 for p in [Path(__file__),Path(__file__).with_name('borsh_fixture.py'),Path(__file__).with_name('type_layout.json'),BUILD/'build.json',ORIGINAL,POLICY]:inputs[str(p)]=identity(p)
 assert {p:identity(p) for p in inputs}==inputs
 report['source_before']=inputs;report['fixture_sqlite_version']=sqlite3.sqlite_version;save()
 fixture=Fixtures(71291);raw_bundle=fixture.value(27,0)
 bundle=bytes.fromhex(stage('fixture-original-trust',POLICY,b'trust:'+raw_bundle.hex().encode()+b'\n').strip().decode());report['fixture_preparations']+=1
 code,out=original('fixture-create-store',frame(0,bundle),b'create:');assert successful(code,out);report['fixture_preparations']+=1
 baseline=DB.read_bytes();report['baseline_database']=blob(baseline);report['trust_bundle']=blob(bundle)
 library=ctypes.CDLL(str(BUILD/'store-audit-native.so'))
 new=library.trnm_task_owner_new;new.argtypes=[];new.restype=ctypes.c_void_p
 invoke=library.trnm_task_owner_invoke;invoke.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint64)];invoke.restype=ctypes.c_uint64
 free=library.trnm_task_owner_free;free.argtypes=[ctypes.c_void_p]
 release=library.trnm_task_owner_result_free;release.argtypes=[ctypes.c_void_p]
 owner=new();assert owner
 def native(raw):
  source=ctypes.create_string_buffer(raw);result=ctypes.c_void_p();size=ctypes.c_uint64();code=invoke(owner,source,len(raw),ctypes.byref(result),ctypes.byref(size));assert source.raw[:len(raw)]==raw
  data=ctypes.string_at(result,size.value) if result else b''
  if result:release(result)
  return code,data
 cases=[]
 def add(name,method,sql=(),maximum=(1<<64)-1,reseal=False,custom_bundle=None,database=None):cases.append((name,method,list(sql),maximum,reseal,custom_bundle,database))
 for method in range(15):add('baseline-'+str(method),method)
 # Only fixture mutation happens in Python/SQLite; every expected semantic result
 # comes from the original private Rust method on the exact resulting bytes.
 for column in ['object_kind','object_id','object_version','immutable_body','mutable_state','row_checksum']:
  for label,value in [('text','text'),('null',None),('integer',-1)]:
   if column=='object_kind' and label=='integer':continue
   add('state-type-'+column+'-'+label,0,[('DELETE FROM agent_market_objects_v1',()),('INSERT INTO agent_market_objects_v1 VALUES (2,?,?,?,?,?)',(bytes(32),bytes(8),b'',b'',bytes(32))),('UPDATE agent_market_objects_v1 SET '+column+'=?',(value,))])
 for kind in [-1,65535,65536,(1<<63)-1]:add('state-kind-'+str(kind),0,[('UPDATE agent_market_objects_v1 SET object_kind=? WHERE object_kind=45',(kind,))])
 big=b'x'*((1<<21)+257);add('state-large-blob',0,[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=45',(big,))])
 records=[]
 for i,seq in enumerate([(1<<64)-1,0,256,255,1,1,(1<<63),2]):records.append(('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(bytes([i+1])*32,struct.pack('<Q',seq),2+i,b'c'+bytes([i]),b'r'+bytes([i]),bytes([30+i])*32)))
 for maximum in [0,1,2,254,255,256,(1<<63)-1,(1<<63),(1<<64)-2,(1<<64)-1]:add('journal-u64-sort-'+str(maximum),1,records,maximum)
 for size in [0,1,7,9]:add('journal-sequence-width-'+str(size),1,records+[('UPDATE agent_market_operations_v1 SET sequence=? WHERE operation_id=?',(bytes(size),bytes([8])*32))],0)
 for column in ['operation_id','sequence','operation_kind','command','receipt','row_checksum']:
  for label,value in [('text','x'),('null',None),('integer',-1)]:add('journal-type-'+column+'-'+label,1,records+[('UPDATE agent_market_operations_v1 SET '+column+'=? WHERE operation_id=?',(value,bytes([1])*32))])
 # Width rejection before a later type error differs from collected audit rows.
 add('journal-early-width-before-late-type',1,records+[('UPDATE agent_market_operations_v1 SET sequence=? WHERE operation_id=?',(b'',bytes([1])*32)),('UPDATE agent_market_operations_v1 SET command=? WHERE operation_id=?',('bad',bytes([8])*32))])
 for method,column in [(2,'sequence'),(3,'order_height'),(3,'order_block_id'),(4,'durable_state_root'),(5,'durable_journal_root')]:
  for size in [0,1,7,8,31,32,33]:add('read-width-'+column+'-'+str(size),method,[('UPDATE agent_market_metadata_v1 SET '+column+'=?',(bytes(size),))])
 add('order-tip-block-width-before-height',3,[('UPDATE agent_market_metadata_v1 SET order_height=?,order_block_id=?',(b'',b''))])
 for method in range(2,6):
  add('read-no-row-'+str(method),method,[('DELETE FROM agent_market_metadata_v1',())])
  add('read-table-absent-'+str(method),method,[('DROP TABLE agent_market_metadata_v1',())])
 add('schema-extra-index',6,[('CREATE INDEX fixture_index ON agent_market_metadata_v1(sequence)',())])
 add('schema-extra-table',6,[('CREATE TABLE extra(x BLOB)',())])
 add('schema-trigger',6,[('CREATE TRIGGER fixture_trigger AFTER UPDATE ON agent_market_metadata_v1 BEGIN SELECT 1; END',())])
 add('schema-table-before-trigger',6,[('CREATE TABLE extra(x BLOB)',()),('CREATE TRIGGER fixture_trigger AFTER UPDATE ON agent_market_metadata_v1 BEGIN SELECT 1; END',())])
 add('schema-sql-whitespace',6,[('PRAGMA writable_schema=ON',()),("UPDATE sqlite_master SET sql=replace(sql,'NOT NULL','NOT  NULL') WHERE name='agent_market_objects_v1'",())])
 for table in ['agent_market_metadata_v1','agent_market_objects_v1','agent_market_operations_v1','agent_market_committed_blocks_v1']:add('schema-missing-'+table,6,[('DROP TABLE '+table,())])
 for column in ['schema_version','store_id','config_hash','sequence','order_height','order_block_id','durable_state_root','durable_journal_root','fenced','row_checksum']:
  for label,value in [('text','x'),('null',None),('integer',-1)]:add('metadata-type-'+column+'-'+label,7,[('UPDATE agent_market_metadata_v1 SET '+column+'=?',(value,))])
 for column,value in [('schema_version',2),('store_id',b''),('config_hash',bytes(32)),('sequence',b''),('order_height',b''),('order_block_id',b''),('durable_state_root',b''),('durable_journal_root',b''),('fenced',2),('row_checksum',bytes(32))]:add('metadata-mismatch-'+column,7,[('UPDATE agent_market_metadata_v1 SET '+column+'=?',(value,))])
 for name,sql in [
  ('zero-block',[('UPDATE agent_market_metadata_v1 SET order_block_id=?',(bytes(32),))]),
  ('genesis-block-conflict',[('UPDATE agent_market_metadata_v1 SET order_block_id=?',(bytes([7])*32,))]),
  ('later-block-allowed',[('UPDATE agent_market_metadata_v1 SET order_height=?,order_block_id=?',(struct.pack('<Q',1),bytes([7])*32))]),
  ('state-root-mismatch',[('UPDATE agent_market_metadata_v1 SET durable_state_root=?',(bytes(32),))]),
  ('journal-root-mismatch',[('UPDATE agent_market_metadata_v1 SET durable_journal_root=?',(bytes(32),))]),
  ('fenced',[('UPDATE agent_market_metadata_v1 SET fenced=1',())]),
  ('state-root-before-fence',[('UPDATE agent_market_metadata_v1 SET durable_state_root=?,fenced=1',(bytes(32),))]),
  ('journal-root-before-fence',[('UPDATE agent_market_metadata_v1 SET durable_journal_root=?,fenced=1',(bytes(32),))]),
  ('object-type-before-fence',[('UPDATE agent_market_metadata_v1 SET fenced=1',()),('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=45',('wrong',))])]:add('metadata-'+name,7,sql,reseal=True)
 for size in [0,1,len(bundle)-1]:add('bundle-truncated-'+str(size),7,custom_bundle=bundle[:size])
 # IDs, canonical normalization and row checksums are produced by original
 # methods solely for fixture construction, separately from comparisons.
 def prepare_object(label,kind,body,state,normalization=1,funding=500):
  data=f'object:{kind}:{body.hex()}:{state.hex()}:{funding}:{normalization}\n'.encode()
  raw=bytes.fromhex(stage('fixture-object-'+label,ORIGINAL,data).strip().decode());report['fixture_preparations']+=1
  bn,sn=struct.unpack_from('<QQ',raw,42);assert len(raw)==90+bn+sn
  assert struct.unpack_from('<H',raw)[0]==kind
  return (kind,raw[2:34],raw[34:42],raw[58:58+bn],raw[58+bn:58+bn+sn],raw[-32:])
 def object_case(label,record,extra=(),reseal=False,custom_bundle=None):
  add('objects-'+label,8,[('DELETE FROM agent_market_objects_v1',()),('INSERT INTO agent_market_objects_v1 VALUES (?,?,?,?,?,?)',record),*extra],reseal='objects' if reseal else False,custom_bundle=custom_bundle)
 kinds={2:(33,36),3:(37,38),4:(48,50),5:(54,55),6:(56,57),7:(51,53),44:(39,40),45:(43,44),47:(45,46)}
 object_records={}
 for kind,(body_type,state_type) in kinds.items():
  for mode in range(3):
   record=prepare_object(f'{kind}-{mode}',kind,fixture.value(body_type,mode),fixture.value(state_type,mode))
   object_records[kind,mode]=record;object_case(f'valid-{kind}-{mode}',record)
  record=object_records[kind,0]
  object_case(f'id-{kind}',record,[('UPDATE agent_market_objects_v1 SET object_id=?',(bytes([240])*32,))],True)
  object_case(f'version-{kind}',record,[('UPDATE agent_market_objects_v1 SET object_version=?',(struct.pack('<Q',(1<<64)-1),))],True)
  state=record[4]
  wrong_id=fixture.replace_field(state_type,state,2,bytes([241])*32)
  object_case(f'state-id-{kind}',record,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(wrong_id,))],True)
  wrong_version=fixture.replace_field(state_type,state,3,struct.pack('<Q',1))
  object_case(f'state-version-{kind}',record,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(wrong_version,))],True)
  object_case(f'body-decode-before-state-{kind}',record,[('UPDATE agent_market_objects_v1 SET immutable_body=?,mutable_state=?',(b'',b''))],True)
  object_case(f'state-decode-{kind}',record,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state[:-1],))],True)
  # The original row audit intentionally does not impose fresh context/schema
  # policy; valid but different state context must retain its original result.
  different=fixture.replace_field(state_type,state,1,fixture.value(25,2))
  object_case(f'different-state-context-{kind}',record,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(different,))],True)
 record=object_records[45,0]
 for column,size in [('object_id',31),('object_version',7)]:object_case('width-'+column,record,[('UPDATE agent_market_objects_v1 SET '+column+'=?',(bytes(size),)),('UPDATE agent_market_objects_v1 SET row_checksum=?',(bytes(32),))])
 object_case('checksum-before-borsh',record,[('UPDATE agent_market_objects_v1 SET immutable_body=?,row_checksum=?',(b'',bytes(32)))])
 object_case('unknown-kind',record,[('UPDATE agent_market_objects_v1 SET object_kind=65535',())],True)
 object_case('early-width-before-late-sql-type',record,[('UPDATE agent_market_objects_v1 SET object_id=?',(b'',)),('INSERT INTO agent_market_objects_v1 VALUES (47,?,?,?,?,?)',(bytes([254])*32,bytes(8),None,b'',bytes(32)))])
 object_case('early-checksum-before-late-sql-type',record,[('UPDATE agent_market_objects_v1 SET row_checksum=?',(bytes(32),)),('INSERT INTO agent_market_objects_v1 VALUES (47,?,?,?,?,?)',(bytes([254])*32,bytes(8),None,b'',bytes(32)))])
 # Account audit has no balance-total check; adding one would reject original
 # states. Escrow and bond have the exact separate u128 conservation rules.
 state=record[4]
 for index in [4,5,6]:state=fixture.replace_field(44,state,index,((1<<128)-1).to_bytes(16,'little'))
 object_case('account-total-unchecked',record,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 escrow=object_records[7,0]
 state=fixture.replace_field(53,escrow[4],4,((1<<128)-1).to_bytes(16,'little'));state=fixture.replace_field(53,state,5,(1).to_bytes(16,'little'))
 object_case('escrow-total-overflow',escrow,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 entry=fixture.value(52,0)
 a=fixture.replace_field(52,entry,4,((1<<128)-1).to_bytes(16,'little'));b=fixture.replace_field(52,entry,4,(1).to_bytes(16,'little'))
 state=fixture.replace_field(53,escrow[4],9,struct.pack('<I',2)+a+b)
 object_case('escrow-reservation-overflow',escrow,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 for field,value in [(4,(1).to_bytes(16,'little')),(5,(1).to_bytes(16,'little')),(10,bytes([55])*32)]:
  state=fixture.replace_field(53,escrow[4],field,value);object_case('escrow-conservation-'+str(field),escrow,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 body=fixture.replace_field(51,fixture.value(51,0),8,(10).to_bytes(16,'little'))
 reserved=prepare_object('escrow-reserved',7,body,fixture.value(53,0),2);object_case('escrow-reservations-valid',reserved)
 state=fixture.replace_field(53,reserved[4],5,(4).to_bytes(16,'little'));object_case('escrow-reserved-sum-mismatch',reserved,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 bond=object_records[47,0]
 state=fixture.replace_field(46,bond[4],4,((1<<128)-1).to_bytes(16,'little'));state=fixture.replace_field(46,state,5,(1).to_bytes(16,'little'))
 object_case('bond-total-overflow',bond,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 state=fixture.replace_field(46,bond[4],4,(499).to_bytes(16,'little'));object_case('bond-funding-mismatch',bond,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True)
 state=fixture.replace_field(46,bond[4],4,((1<<64)-1).to_bytes(16,'little'));state=fixture.replace_field(46,state,5,(1).to_bytes(16,'little'))
 custom=fixture.replace_field(27,bundle,11,(1<<64).to_bytes(16,'little'));object_case('bond-u128-carry',bond,[('UPDATE agent_market_objects_v1 SET mutable_state=?',(state,))],True,custom)
 context=fixture.value(25,0);chain=b'L'*((1<<21)+257);context=fixture.replace_field(25,context,1,struct.pack('<I',len(chain))+chain)
 body=fixture.replace_field(43,fixture.value(43,0),1,context)
 large_record=prepare_object('large-account-context',45,body,fixture.value(44,0));object_case('large-account-context',large_record)
 code,root_reply=original('fixture-original-state-root',frame(0,bundle));assert successful(code,root_reply) and len(root_reply)==64
 state_root=root_reply[32:];report['fixture_preparations']+=1
 operation_records=[]
 for variant in range(6):
  command=bytes([variant])+fixture.value(68+variant,0)
  auth=fixture.fields(68+variant,command,1)[-1][0]
  command=fixture.replace_field(59,command,11,struct.pack('<Q',variant),auth)
  data=f'operation:{command.hex()}:{variant+1}:{variant//3}:{(bytes([3+variant//3])*32).hex()}:{state_root.hex()}\n'.encode()
  raw=bytes.fromhex(stage('fixture-operation-'+str(variant),ORIGINAL,data).strip().decode());report['fixture_preparations']+=1
  cn,rn=struct.unpack_from('<QQ',raw,42);assert len(raw)==90+cn+rn
  operation_records.append((raw[2:34],raw[34:42],struct.unpack_from('<H',raw)[0],raw[58:58+cn],raw[58+cn:58+cn+rn],raw[-32:]))
 def operation_case(label,method,records,extra=(),reseal=False):
  sql=[('DELETE FROM agent_market_operations_v1',())]+[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',record) for record in records]+[('UPDATE agent_market_metadata_v1 SET sequence=?',(struct.pack('<Q',len(records)),))]+list(extra)
  add('operations-'+label,method,sql,reseal='operations' if reseal else False)
 operation_case('six-variants-valid',9,operation_records)
 operation_case('u64-sort-valid',9,list(reversed(operation_records)))
 operation_case('tail-valid',10,operation_records)
 first=operation_records[0];second=operation_records[1]
 for column,value in [('operation_id',bytes(31)),('operation_kind',65535),('command',b''),('receipt',b'')]:operation_case('binding-'+column,9,[first],[('UPDATE agent_market_operations_v1 SET '+column+'=?',(value,))],True)
 for column,value in [('operation_id',bytes(31)),('sequence',b''),('command',b''),('receipt',b'')]:operation_case('checksum-before-'+column,9,[first],[('UPDATE agent_market_operations_v1 SET '+column+'=?,row_checksum=?',(value,bytes(32)))])
 for field,value in [(0,bytes(2)),(1,bytes(32)),(2,struct.pack('<Q',2)),(3,bytes(32)),(4,bytes(2)),(5,bytes(32)),(6,struct.pack('<Q',1)),(7,bytes(32)),(8,bytes(32))]:
  receipt=fixture.replace_field(61,first[4],field,value)
  operation_case('receipt-field-'+str(field),9,[first],[('UPDATE agent_market_operations_v1 SET receipt=?',(receipt,))],True)
 operation_case('gap-before-checksum',9,[second],[('UPDATE agent_market_operations_v1 SET row_checksum=?',(bytes(32),))])
 operation_case('gap-before-command',9,[second],[('UPDATE agent_market_operations_v1 SET command=?',(b'',))],True)
 operation_case('duplicate-sequence',9,[first,second],[('UPDATE agent_market_operations_v1 SET sequence=?',(struct.pack('<Q',1),))],True)
 operation_case('metadata-high-watermark',9,[first],[('UPDATE agent_market_metadata_v1 SET sequence=?',(bytes(8),))])
 operation_case('metadata-high-watermark-width',9,[first],[('UPDATE agent_market_metadata_v1 SET sequence=?',(bytes(7),))])
 operation_case('late-width-before-early-gap',9,[second,first],[('UPDATE agent_market_operations_v1 SET sequence=? WHERE operation_id=?',(bytes(7),first[0]))])
 operation_case('late-sql-type-before-early-width',9,[first,second],[('UPDATE agent_market_operations_v1 SET sequence=? WHERE operation_id=?',(b'',first[0])),('UPDATE agent_market_operations_v1 SET command=? WHERE operation_id=?',('wrong',second[0]))])
 operation_case('command-decode-before-receipt',9,[first],[('UPDATE agent_market_operations_v1 SET command=?,receipt=?',(b'',b''))],True)
 # Original operation audit requires monotonic block/height relationships, but
 # does not require every intermediate empty block to appear in this table.
 receipt=fixture.replace_field(61,second[4],6,struct.pack('<Q',100));receipt=fixture.replace_field(61,receipt,7,bytes([8])*32)
 operation_case('height-gap-allowed',9,[first,second],[('UPDATE agent_market_operations_v1 SET receipt=? WHERE operation_id=?',(receipt,second[0]))],True)
 receipt=fixture.replace_field(61,second[4],6,struct.pack('<Q',1))
 operation_case('height-increase-same-block',9,[first,second],[('UPDATE agent_market_operations_v1 SET receipt=? WHERE operation_id=?',(receipt,second[0]))],True)
 receipt=fixture.replace_field(61,second[4],7,bytes([8])*32)
 operation_case('same-height-different-block',9,[first,second],[('UPDATE agent_market_operations_v1 SET receipt=? WHERE operation_id=?',(receipt,second[0]))],True)
 for sequence in [0,255,256,(1<<63),(1<<64)-1]:operation_case('tail-u64-'+str(sequence),10,[first],[('UPDATE agent_market_operations_v1 SET sequence=?',(struct.pack('<Q',sequence),))])
 for size in [0,1,7,9]:operation_case('tail-sequence-width-'+str(size),10,[first],[('UPDATE agent_market_operations_v1 SET sequence=?',(bytes(size),))])
 bad_root=fixture.replace_field(61,second[4],8,bytes(32))
 for label,records in [('first-valid',[first,second]),('first-invalid',[second,first])]:operation_case('tail-duplicate-max-'+label,10,records,[('UPDATE agent_market_operations_v1 SET sequence=?',(struct.pack('<Q',(1<<64)-1),)),('UPDATE agent_market_operations_v1 SET receipt=? WHERE operation_id=?',(bad_root,second[0]))])
 for field,value in [(0,bytes(2)),(1,bytes(32)),(2,struct.pack('<Q',(1<<64)-1)),(8,bytes(32))]:
  receipt=fixture.replace_field(61,first[4],field,value);operation_case('tail-receipt-field-'+str(field),10,[first],[('UPDATE agent_market_operations_v1 SET receipt=?',(receipt,))])
 operation_case('tail-empty-skips-state-root',10,[],[('UPDATE agent_market_objects_v1 SET immutable_body=?',('wrong',))])
 operation_case('tail-receipt-decode-before-state',10,[first],[('UPDATE agent_market_operations_v1 SET receipt=?',(b'',)),('UPDATE agent_market_objects_v1 SET immutable_body=?',('wrong',))])
 operation_case('tail-late-sql-type-before-width',10,[first,second],[('UPDATE agent_market_operations_v1 SET sequence=? WHERE operation_id=?',(b'',first[0])),('UPDATE agent_market_operations_v1 SET receipt=? WHERE operation_id=?',('wrong',second[0]))])
 # The complete original owner creates real empty committed successors before
 # any private table corruption. These bytes are independently retained.
 code,out=original('fixture-three-empty-blocks',frame(0,bundle,3),b'empty-blocks:');assert successful(code,out);report['fixture_preparations']+=1
 empty_chain=DB.read_bytes();report['empty_block_chain_database']=blob(empty_chain);DB.write_bytes(baseline)
 marker_columns='marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum'
 marker_names=marker_columns.split(',');marker_sizes=[8,8,32,8,32,8,8,32,32,32,32,32,32]
 for method in range(11,15):add('three-empty-blocks-'+str(method),method,database=empty_chain)
 for column,size in zip(marker_names,marker_sizes):
  for label,value in [('text','wrong'),('null',None),('integer',-1)]:add('markers-type-'+column+'-'+label,11,[('UPDATE agent_market_committed_blocks_v1 SET '+column+'=?',(value,))])
  for length in [0,size-1,size+1]:add('markers-width-'+column+'-'+str(length),11,[('UPDATE agent_market_committed_blocks_v1 SET '+column+'=?',(bytes(length),))])
 for method in range(11,15):add('markers-empty-'+str(method),method,[('DELETE FROM agent_market_committed_blocks_v1',())])
 add('markers-checksum',11,[('UPDATE agent_market_committed_blocks_v1 SET row_checksum=?',(bytes(32),))])
 add('markers-late-sql-type-before-early-width',11,[('UPDATE agent_market_committed_blocks_v1 SET marker_sequence=? WHERE marker_sequence=?',(b'',bytes(8))),('UPDATE agent_market_committed_blocks_v1 SET order_height=? WHERE marker_sequence=?',('wrong',struct.pack('<Q',3)))],database=empty_chain)
 add('markers-early-width-before-late-checksum',11,[('UPDATE agent_market_committed_blocks_v1 SET marker_sequence=? WHERE marker_sequence=?',(b'',bytes(8))),('UPDATE agent_market_committed_blocks_v1 SET row_checksum=? WHERE marker_sequence=?',(bytes(32),struct.pack('<Q',3)))],database=empty_chain)
 for values in [[3,2,1,0],[(1<<64)-1,256,255,0],[7,7,7,7]]:
  sql=[('UPDATE agent_market_committed_blocks_v1 SET marker_sequence=? WHERE order_block_id=?',(struct.pack('<Q',sequence),bytes([block])*32)) for sequence,block in zip(values,[3,100,101,102])]
  # The initial block is read from the actual original metadata below rather
  # than assumed by the fixture. Only later IDs were specified above.
  con=sqlite3.connect(DB);initial_block=con.execute('SELECT order_block_id FROM agent_market_metadata_v1').fetchone()[0];con.close()
  sql[0]=(sql[0][0],(sql[0][1][0],initial_block))
  add('markers-u64-stable-sort-'+str(values),11,sql,reseal='markers',database=empty_chain)
 for column,value in [('marker_sequence',struct.pack('<Q',1)),('order_height',struct.pack('<Q',1)),('order_block_id',bytes([201])*32),('parent_order_height',struct.pack('<Q',1)),('parent_order_block_id',bytes(32)),('source_operation_sequence',struct.pack('<Q',1)),('previous_marker_checksum',bytes(32))]:
  add('blocks-anchor-'+column,12,[('UPDATE agent_market_committed_blocks_v1 SET '+column+'=?',(value,))],reseal='markers')
 for column,value in [('marker_sequence',struct.pack('<Q',4)),('order_height',struct.pack('<Q',5)),('parent_order_height',struct.pack('<Q',1)),('parent_order_block_id',bytes(32)),('order_block_id',bytes([101])*32),('source_operation_sequence',struct.pack('<Q',1)),('source_state_root',bytes(32)),('source_operation_root',bytes(32)),('previous_marker_checksum',bytes(32))]:
  add('blocks-successor-'+column,12,[('UPDATE agent_market_committed_blocks_v1 SET '+column+'=? WHERE marker_sequence=?',(value,struct.pack('<Q',3)))],reseal='markers',database=empty_chain)
 for column in ['source_operation_root','target_operation_root','target_state_root']:
  add('blocks-anchor-'+column,12,[('UPDATE agent_market_committed_blocks_v1 SET '+column+'=?',(bytes(32),))],reseal='markers')
 for column in ['sequence','durable_state_root','durable_journal_root','order_height','order_block_id']:
  size=8 if column in ['sequence','order_height'] else 32
  add('blocks-metadata-value-'+column,12,[('UPDATE agent_market_metadata_v1 SET '+column+'=?',(bytes([219])*size,))])
  add('blocks-metadata-width-'+column,12,[('UPDATE agent_market_metadata_v1 SET '+column+'=?',(bytes(size-1),))])
 for left,right in [('sequence','durable_state_root'),('durable_state_root','durable_journal_root'),('durable_journal_root','order_height'),('order_block_id','order_height')]:
  add('blocks-metadata-order-'+left+'-'+right,12,[('UPDATE agent_market_metadata_v1 SET '+left+'=?,'+right+'=?',(b'',b''))])
 add('blocks-marker-error-before-operation-sql',12,[('UPDATE agent_market_committed_blocks_v1 SET row_checksum=?',(bytes(32),)),('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(bytes(32),None,2,b'',None,bytes(32)))])
 for column in ['sequence','receipt']:
  for label,value in [('null',None),('text','wrong')]:add('blocks-operation-type-'+column+'-'+label,12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('UPDATE agent_market_operations_v1 SET '+column+'=?',(value,))])
 for size in [0,1,7,9]:add('blocks-operation-sequence-width-'+str(size),12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('UPDATE agent_market_operations_v1 SET sequence=?',(bytes(size),))])
 add('blocks-operation-receipt-decode',12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('UPDATE agent_market_operations_v1 SET receipt=?',(b'',))])
 mismatched=fixture.replace_field(61,first[4],2,struct.pack('<Q',2))
 add('blocks-operation-receipt-sequence-mismatch',12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('UPDATE agent_market_operations_v1 SET receipt=?',(mismatched,))])
 duplicate=fixture.replace_field(61,second[4],2,struct.pack('<Q',1))
 add('blocks-operation-duplicate',12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(second[0],struct.pack('<Q',1),second[2],second[3],duplicate,second[5]))])
 add('blocks-duplicate-before-late-receipt-decode',12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(second[0],struct.pack('<Q',1),second[2],second[3],duplicate,second[5])),('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(operation_records[2][0],struct.pack('<Q',3),2,b'',b'',bytes(32)))])
 add('blocks-late-type-before-early-width',12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',second),('UPDATE agent_market_operations_v1 SET sequence=? WHERE operation_id=?',(b'',first[0])),('UPDATE agent_market_operations_v1 SET receipt=? WHERE operation_id=?',('wrong',second[0]))])
 # To reach range and receipt-binding branches, use original checksums and
 # original operation-root methods when preparing each database. This helper
 # mutates fixtures only; no Python implementation supplies expected results.
 con=sqlite3.connect(DB);initial_height,initial_block=con.execute('SELECT order_height,order_block_id FROM agent_market_metadata_v1').fetchone();con.close()
 block_records=[]
 for record in operation_records[:3]:
  receipt=fixture.replace_field(61,record[4],6,initial_height);receipt=fixture.replace_field(61,receipt,7,initial_block)
  block_records.append((*record[:4],receipt,record[5]))
 def operated_database(label,records,target):
  DB.write_bytes(baseline);con=sqlite3.connect(DB)
  for table,columns in [('agent_market_operations_v1','operation_id,sequence,operation_kind,command,receipt,row_checksum'),('agent_market_committed_blocks_v1',marker_columns)]:
   rows=con.execute('SELECT '+columns+' FROM '+table).fetchall();con.execute('DROP TABLE '+table);con.execute('CREATE TABLE '+table+' ('+columns+')');con.executemany('INSERT INTO '+table+' VALUES ('+','.join('?' for _ in columns.split(','))+')',rows)
  con.execute('DELETE FROM agent_market_operations_v1');con.executemany('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',records);con.commit();con.close()
  code,out=original('fixture-block-operations-reseal-'+label,frame(0,bundle),b'reseal-operations:');assert successful(code,out);report['fixture_preparations']+=1
  roots=[]
  for maximum in [0,target]:
   code,out=original('fixture-block-operation-root-'+label+'-'+str(maximum),frame(1,bundle,maximum));assert successful(code,out) and len(out)==64;roots.append(out[32:]);report['fixture_preparations']+=1
  con=sqlite3.connect(DB);con.execute('UPDATE agent_market_committed_blocks_v1 SET target_operation_sequence=?,source_operation_root=?,target_operation_root=?',(struct.pack('<Q',target),*roots));con.execute('UPDATE agent_market_metadata_v1 SET sequence=?,durable_journal_root=?',(struct.pack('<Q',target),roots[1]));con.commit();con.close()
  for suffix in [b'reseal-markers:',b'reseal:']:
   code,out=original('fixture-block-'+suffix.decode()[:-1]+'-'+label,frame(0,bundle),suffix);assert successful(code,out);report['fixture_preparations']+=1
  data=DB.read_bytes();report.setdefault('operation_block_databases',{})[label]=blob(data);DB.write_bytes(baseline);return data
 operated=operated_database('three-valid',block_records,3)
 for method in [7,9,10,11,12,13,14]:add('blocks-three-operations-valid-'+str(method),method,database=operated)
 gap=operated_database('missing-two',[block_records[0],block_records[2]],3);add('blocks-operation-range-gap',12,database=gap)
 for column,field,value in [('height',6,struct.pack('<Q',17)),('block',7,bytes([220])*32),('state',8,bytes([221])*32)]:
  record=block_records[-1];receipt=fixture.replace_field(61,record[4],field,value)
  data=operated_database('wrong-'+column,block_records[:-1]+[(*record[:4],receipt,record[5])],3);add('blocks-operation-wrong-'+column,12,database=data)
 maximum=(1<<64)-1;record=block_records[0];receipt=fixture.replace_field(61,record[4],2,struct.pack('<Q',maximum))
 add('blocks-u64-maximum-map-no-truncation',12,[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(record[0],struct.pack('<Q',maximum),record[2],record[3],receipt,record[5]))])
 for sql,label in [([('UPDATE agent_market_objects_v1 SET object_version=?',(b'',)),('DELETE FROM agent_market_committed_blocks_v1',())],'objects-before-markers'),([('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',first),('DELETE FROM agent_market_committed_blocks_v1',())],'operations-before-markers')]:add('full-audit-order-'+label,14,sql)
 DB.write_bytes(baseline)
 with (WORK/'observations.jsonl').open('x') as stream:
  for index,(name,method,sql,maximum,reseal,custom_bundle,database) in enumerate(cases):
   DB.write_bytes(baseline if database is None else database)
   if sql:
    connection=sqlite3.connect(DB)
    connection.execute('PRAGMA ignore_check_constraints=ON')
    # Private audit probes also cover malformed SQLite cell types that the
    # public schema gate would reject sooner. Rebuild fixture tables without
    # constraints so NULL/type-corrupt rows can reach the original private
    # readers; both implementations receive these same actual database bytes.
    if method!=6:
     for table,columns in [
      ('agent_market_metadata_v1','singleton,schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,row_checksum'),
      ('agent_market_objects_v1','object_kind,object_id,object_version,immutable_body,mutable_state,row_checksum'),
      ('agent_market_operations_v1','operation_id,sequence,operation_kind,command,receipt,row_checksum'),
      ('agent_market_committed_blocks_v1',marker_columns)]:
      rows=connection.execute('SELECT '+columns+' FROM '+table).fetchall()
      connection.execute('DROP TABLE '+table)
      connection.execute('CREATE TABLE '+table+' ('+columns+')')
      connection.executemany('INSERT INTO '+table+' VALUES ('+','.join('?' for _ in columns.split(','))+')',rows)
    for command,parameters in sql:connection.execute(command,parameters)
    connection.commit();connection.close()
   if reseal:
    prefix={'objects':b'reseal-objects:','operations':b'reseal-operations:','markers':b'reseal-markers:'}.get(reseal,b'reseal:')
    code,out=original(f'fixture-reseal-{index:03d}',frame(0,bundle if custom_bundle is None else custom_bundle),prefix);assert successful(code,out),name;report['fixture_preparations']+=1
   raw=frame(method,bundle if custom_bundle is None else custom_bundle,maximum);before=inventory()
   expected_code,expected=original(f'original-{index:03d}',raw);assert inventory()==before
   row={'index':index,'name':name,'input':blob(raw),'before':before,'expected_code':expected_code,'expected_output':blob(expected)}
   (WORK/'current-call.json').write_text(json.dumps(row,indent=2)+'\n');start=time.monotonic_ns();code,data=native(raw);after=inventory()
   row.update(return_code=code,actual_output=blob(data),native_after=after,elapsed_ns=time.monotonic_ns()-start,equal=code==expected_code and data==expected and after==before)
   stream.write(json.dumps(row)+'\n');stream.flush();report['native_calls']+=1;report['original_calls']+=1;save();assert row['equal'],name
  for index,raw in enumerate([b'',b'TKSA0001'+bytes(63),b'TKSA0001'+struct.pack('<Q',15)+bytes(56),b'TKSA0001'+bytes(16)+struct.pack('<Q',1)+bytes(40)]):
   expected_code,expected=original(f'original-frame-{index}',raw);code,data=native(raw);row={'name':'frame-'+str(index),'input':blob(raw),'expected_code':expected_code,'expected_output':blob(expected),'return_code':code,'actual_output':blob(data),'equal':code==expected_code and data==expected};stream.write(json.dumps(row)+'\n');stream.flush();report['native_calls']+=1;report['original_calls']+=1;save();assert row['equal']
 free(owner);owner=None
 report['source_after']={p:identity(p) for p in inputs};assert report['source_after']==inputs
 report.update(status='PASS',finalized=True,sqlite_provider_shared=True,full_task_kernel_owner_qualified=False);save()
except BaseException as error:
 report.update(status='FAIL',failure=repr(error));save();raise
finally:
 if 'owner' in globals() and owner:free(owner)
print(json.dumps({k:v for k,v in report.items() if k not in ['source_before','source_after','stages']}))
