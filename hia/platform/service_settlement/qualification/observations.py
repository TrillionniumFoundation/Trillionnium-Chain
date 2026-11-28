"""Finite independent readback of the captured Engine run; performs no native calls.

The archived producer checks input guards at execution time. This reader checks
the recorded owner bytes, complete response bytes, exact call order, captures,
compiler inputs/outputs and observed collector terminal outcome independently.
"""
from pathlib import Path,PurePosixPath
import argparse,ast,collections,hashlib,json,lzma,math,os,struct,tarfile,time,traceback,zlib
if not __debug__: raise RuntimeError('qualification reader requires assertions enabled')
EXPECTED_EXPORTS=sorted('trnm_settlement_'+x for x in [
'engine_new','engine_apply','engine_replay','engine_validate_execution','engine_clone',
'owned_clone','owned_drop','owned_kind','engine_history_count','error_code',
'engine_state_copy','error_display','engine_trust','engine_state','engine_state_root',
'error_message','bytes_view','consumption_receipt_id','consumption_rollup_id',
'settlement_policy_hash','operation_id'])

def ident(data):return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def file_id(path):
 assert path.is_file() and not path.is_symlink(),str(path)
 with path.open('rb') as f:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def pairs(items):
 result={}
 for k,v in items:
  assert k not in result,('duplicate JSON key',k)
  result[k]=v
 return result
def floating(text):
 value=float(text);assert math.isfinite(value),'nonfinite JSON number';return value
def document(raw):
 return json.loads(raw,object_pairs_hook=pairs,parse_float=floating,
                   parse_constant=lambda s:(_ for _ in ()).throw(AssertionError(('nonfinite token',s))))
def exact_int(x,minimum=0):
 assert type(x) is int and x>=minimum,('integer required',x);return x
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def basic_process(r,seconds):
 assert r['status']=='PASS' and r['started'] is True and r['exit_code']==0
 assert exact_int(r['exit_code'])==0 and exact_int(r['collector_exit_code'])==0 and r['timed_out'] is False
 assert r['execution_deadline_seconds']==seconds and r['cleanup_deadline_seconds']==3
 assert r['cleanup_complete'] is True and r['cleanup_errors']==[]
 elapsed=exact_int(r['elapsed_ns']);assert 0<elapsed<=(seconds+3)*10**9
 c=r['collector_readback'];assert c['terminal_state']=='observed'
 for k in ['collector_wait_domain_reaped','command_success','deadline_qualified']:assert c[k] is True,k
 v=c['result']
 assert v['cause'] is None and v['error'] is None and v['cancellation'] is None
 assert v['collector_wait_domain_reaped'] is True and v['records_truncated'] is False
 assert v['command_success_before_handoff'] is True and exact_int(v['root_returncode'])==exact_int(v['wrapper_returncode'])==0
 assert v['root_exec_released'] is True and v['may_dispatch_again'] is False
 assert v['original_boot_id']==r['original_boot_id']
 assert v['original_deadline_monotonic_ns']==r['original_deadline_monotonic_ns']
 assert exact_int(v['completed_monotonic_ns'])<=r['original_deadline_monotonic_ns']
 assert v['final_echild']['errno']==10 and v['final_echild']['boot_id']==v['original_boot_id']
 assert v['final_echild']['monotonic_ns']<=v['completed_monotonic_ns']
 root=v['root_identity']
 matching=[w for w in v['wait4_records'] if all(w['identity_before_reap'][k]==root[k] for k in ['pid','start_ticks','boot_id'])]
 assert len(matching)==1 and matching[0]['returncode']==0 and matching[0]['wait4_status']==0
 for w in v['wait4_records']:
  for k in ['user_seconds','system_seconds']:
   assert type(w['rusage'][k]) in (float,int) and math.isfinite(w['rusage'][k]) and w['rusage'][k]>=0
  assert w['reaped_monotonic_ns']<=v['final_echild']['monotonic_ns']
 for s in v['streams'].values():
  assert s['eof'] is True and s['truncated'] is False and s['seen_bytes']==s['stored_bytes']
 return v

class Blobs:
 def __init__(self,f,observations,expected_chunks=18728):
  O=observations
  self.path=f.root/O/'actual-bytes.chunked-zlib.bin';self.stream=self.path.open('rb')
  index=f.doc(O+'/chunk-index.json');journal=[document(x) for x in f.read(O+'/chunks.jsonl').splitlines()]
  assert len(journal)==len(index)
  if expected_chunks is not None:assert len(index)==expected_chunks
  self.index=index;self.chunks=collections.OrderedDict();self.validated={};self.blobs=collections.OrderedDict();self.blob_bytes=0
  offset=0;uncompressed=0
  for row in journal:
   assert index[row['sha256']]==row and row['offset']==offset
   assert set(row)=={'bytes','sha256','compressed_bytes','compressed_sha256','offset'}
   assert 0<exact_int(row['bytes'])<=65536 and 0<exact_int(row['compressed_bytes'])<=131072
   data=self.chunk(row['sha256']);assert len(data)==row['bytes']
   offset+=row['compressed_bytes'];uncompressed+=row['bytes']
  assert offset==self.path.stat().st_size
  self.unique_bytes=uncompressed
 def chunk(self,digest):
  if digest in self.chunks:
   self.chunks.move_to_end(digest);return self.chunks[digest]
  r=self.index[digest];self.stream.seek(r['offset']);packed=self.stream.read(r['compressed_bytes'])
  assert ident(packed)=={'bytes':r['compressed_bytes'],'sha256':r['compressed_sha256']}
  d=zlib.decompressobj();raw=d.decompress(packed,65537)
  assert d.eof and not d.unconsumed_tail and not d.unused_data
  assert ident(raw)=={'bytes':r['bytes'],'sha256':digest}
  self.chunks[digest]=raw
  while len(self.chunks)>256:self.chunks.popitem(last=False)
  return raw
 def descriptor(self,d):
  assert type(d) is dict and set(d)=={'bytes','sha256','chunks'}
  n=exact_int(d['bytes']);assert type(d['sha256']) is str and len(d['sha256'])==64 and type(d['chunks']) is list
  key=(n,d['sha256'],tuple(d['chunks']))
  if key in self.validated:return key
  total=0;h=hashlib.sha256()
  for i,k in enumerate(d['chunks']):
   raw=self.chunk(k)
   if i+1<len(d['chunks']):assert len(raw)==65536
   total+=len(raw);h.update(raw)
  assert total==n and h.hexdigest()==d['sha256']
  assert bool(n)==bool(d['chunks'])
  self.validated[key]=True;return key
 def read(self,d):
  key=self.descriptor(d)
  if key in self.blobs:self.blobs.move_to_end(key);return self.blobs[key]
  raw=b''.join(self.chunk(k) for k in d['chunks'])
  assert ident(raw)=={'bytes':d['bytes'],'sha256':d['sha256']}
  if len(raw)<=8*1024*1024:
   self.blobs[key]=raw;self.blob_bytes+=len(raw)
   while self.blob_bytes>64*1024*1024:
    _,old=self.blobs.popitem(last=False);self.blob_bytes-=len(old)
  return raw

class Recorded:
 def __init__(self,records,blobs,codes):
  self.records=records;self.blobs=blobs;self.pos=0;self.live={};self.next_id=1;self.native=0;self.native_ns=0;self.codes=codes;self.errors=[];self.implicit_height_calls=0;self.explicit_height_calls=0;self.require_heights=False
 def take(self,name,native):
  assert self.pos<len(self.records),('missing recorded call',name,self.pos)
  r=self.records[self.pos];assert r['ordinal']==self.pos and r['function']==name,(self.pos,name,r.get('function'))
  self.pos+=1
  if native:
   assert r['native_call'] is True;self.native+=1;self.native_ns+=exact_int(r['elapsed_ns'])
  else:assert 'native_call' not in r
  return r
 def snapshot(self,owner):
  assert owner in self.live,('dead owner',owner)
  return self.live[owner]
 def header(self,raw):
  assert len(raw)>=32 and raw[:8]==b'SSOWN001'
  kind,size,reserved=struct.unpack_from('<3Q',raw,8)
  assert kind in [1,2,3,4,255] and reserved==0 and len(raw)==32+size and size<1<<32
  return kind
 def call(self,name,owners=(),body=None,result=False):
  r=self.take(name,True)
  assert r['owners']==list(owners) and all(type(x) is int and x>0 for x in r['owners']) and len(r['before'])==len(r['after'])==len(owners)
  exact_int(r['status'])
  for owner,before,after in zip(owners,r['before'],r['after'],strict=True):
   assert self.blobs.read(before)==self.blobs.read(after)==self.snapshot(owner)
  if body is None:assert 'request' not in r
  else:assert self.blobs.read(r['request'])==body,(name,'wrong request bytes')
  if name=='owned_kind':assert r['status']==self.header(self.snapshot(owners[0]))
  else:assert r['status']==0,(name,r['status'])
  if result:
   assert r['result_pointer_nonnull'] is True and exact_int(r['result_owner'],1)==self.next_id
   owner=self.next_id;self.next_id+=1;assert owner not in self.live
   raw=self.blobs.read(r['result']);self.header(raw);self.live[owner]=raw
   return owner
  assert 'result' not in r and 'result_owner' not in r and 'result_pointer_nonnull' not in r
  return r['status']
 def owned(self,name,owner=None,body=None,height=None):
  if name in ['engine_apply','engine_replay']:
   row=self.records[self.pos];exact_int(height)
   if 'scalar_inputs' in row:
    assert row['scalar_inputs']=={'height':height} and type(row['scalar_inputs']['height']) is int
    self.explicit_height_calls+=1
   else:
    assert not self.require_heights,'actual FFI height missing from journal'
    self.implicit_height_calls+=1
  return self.call(name,() if owner is None else (owner,),body,True)
 def kind(self,owner):return self.call('owned_kind',(owner,))
 def scalar(self,name,owner):
  self.call(name,(owner,));r=self.take(name+':scalar',False)
  assert set(r)=={'ordinal','function','value'};return exact_int(r['value'])
 def view(self,name,owner):
  self.call(name,(owner,));r=self.take(name+':view',False)
  assert exact_int(r['owner'],1)==owner
  value=self.blobs.read(r['value']);start=exact_int(r['relative_offset'],32);raw=self.snapshot(owner)
  assert start<=len(raw) and len(value)<=len(raw)-start and raw[start:start+len(value)]==value
  return value
 def drop(self,owner):
  r=self.take('owned_drop',True);assert exact_int(r['status'])==0 and exact_int(r['owner'],1)==owner
  assert self.blobs.read(r['before'])==self.snapshot(owner);del self.live[owner]
 def error(self,owner):
  assert self.kind(owner)==255
  code=self.scalar('error_code',owner);assert 1<=code<=len(self.codes)
  message=self.view('error_message',owner)
  display=self.owned('error_display',owner);assert self.kind(display)==3
  actual=self.view('bytes_view',display);assert actual==self.codes[code-1].encode()+b': '+message
  clone=self.owned('owned_clone',owner);assert clone!=owner and self.snapshot(clone)==self.snapshot(owner)
  self.drop(owner);assert self.scalar('error_code',clone)==code and self.view('error_message',clone)==message
  self.drop(clone);assert self.view('bytes_view',display)==actual;self.drop(display)
  self.errors.append({'code':code,'message':message.decode(),'display':actual.decode()})
  return code,message
 def fee(self,data):
  r=self.take('private_proportional_fee',True);assert exact_int(r['status'])==0
  before=[self.blobs.read(x) for x in r['before']];after=[self.blobs.read(x) for x in r['after']]
  assert len(before)==len(after)==3 and before[0]==after[0]
  inp=struct.pack('<Q',0)+data
  assert before[0]==b'\x6b'*32+inp+b'\x6b'*32
  assert before[1]==b'\x6b'*81 and before[2]==b'\x6b'*224
  for i in [1,2]:assert len(before[i])==len(after[i]) and after[i][:32]==after[i][-32:]==b'\x6b'*32
  assert after[1][32] in [0,1]
  n=1+16*after[1][32];body=after[1][32:32+n]
  assert after[1][32+n:]==before[1][32+n:]
  return body

def validate_summary(native,records,fixtures):
 assert native['status']=='PASS' and native['fixtures']==len(fixtures)==320
 assert native['fixture_operations']==sum(f['operation_count'] for f in fixtures)==2636
 assert native['live_owners']==0 and native['complete_fixture_bytes_equal'] is True
 assert native['capture']['records']==len(records)==23140 and native['capture']['native_calls']==16066
 assert native['fresh_original_executed_here'] is False and native['retained_fixtures_only'] is True

def replay(api,fixtures,results,error_ids):
 assert len(fixtures)==len(results)==320
 count_ops=0;fees=0;names=set()
 for case,row in zip(fixtures,results,strict=True):
  name=case['name'];assert name not in names;names.add(name)
  request=bytes.fromhex(case['input']);expected=bytes.fromhex(case['expected'])
  assert row['name']==name and row['equal'] is True
  assert api.blobs.read(row['input'])==request and api.blobs.read(row['expected'])==expected
  assert len(request)>=16
  p=16;count=struct.unpack_from('<Q',request,8)[0];assert count==case['operation_count']
  slots=[None,None];actual=bytearray(b'SSR10001'+struct.pack('<3Q',count,0,0))
  for ordinal in range(count):
   assert len(request)-p>=32
   op,slot,height,n=struct.unpack_from('<4Q',request,p);p+=32
   assert slot<2 and n<=len(request)-p;data=request[p:p+n];p+=n
   code=0;body=b'';result=None
   if op==0:
    if slots[slot] is not None:code=104
    else:result=api.owned('engine_new',body=data)
   elif op in [1,5,10]:
    if slots[slot] is None:code=103
    else:result=api.owned({1:'engine_apply',5:'engine_replay',10:'engine_validate_execution'}[op],slots[slot],data,height)
   elif op==2:
    if slots[slot] is None:code=103
   elif op==3:
    if slots[slot] is None:code=103
    elif slots[1-slot] is not None:code=104
    else:
     result=api.owned('engine_clone',slots[slot]);assert api.snapshot(result)==api.snapshot(slots[slot])
     slots[1-slot]=result;result=None
   elif op==4:
    if slots[slot] is None:code=103
    else:api.drop(slots[slot]);slots[slot]=None
   elif op in [6,7,8,11]:result=api.owned({6:'consumption_receipt_id',7:'consumption_rollup_id',8:'settlement_policy_hash',11:'operation_id'}[op],body=data)
   elif op==9:body=api.fee(data);fees+=1
   else:raise AssertionError(('unrecognized original operation',op))
   if result is not None:
    kind=api.kind(result)
    if kind==255:code=error_ids.get(api.error(result),101)
    elif op in [0,1,5]:
     assert kind==1
     if slots[slot] is not None:api.drop(slots[slot])
     slots[slot]=result
    elif op==10:
     assert kind==4 and api.view('bytes_view',result)==b'';api.drop(result)
    else:
     assert kind==2;body=api.view('bytes_view',result);assert len(body)==32;api.drop(result)
   if (op<6 or op==10) and slots[slot] is not None:
    root=api.view('engine_state_root',slots[slot]);assert len(root)==32
    body+=root+struct.pack('<Q',api.scalar('engine_history_count',slots[slot]))
    if op==2:
     state=api.view('engine_state',slots[slot]);copy=api.owned('engine_state_copy',slots[slot])
     assert api.kind(copy)==3 and api.view('bytes_view',copy)==state;api.drop(copy);body+=state
    if op==0 and code==0:assert api.view('engine_trust',slots[slot])==data
   actual.extend(struct.pack('<4Q',op,slot,code,len(body))+body);count_ops+=1
  assert p==len(request);struct.pack_into('<Q',actual,16,len(actual))
  assert bytes(actual)==expected==api.blobs.read(row['actual']),(name,'response differs from fresh Rust')
  for owner in slots:
   if owner is not None:api.drop(owner)
  assert not api.live
 assert count_ops==2636 and fees==169 and api.pos==len(api.records) and api.native==16066
 return {'fixtures':320,'operations':count_ops,'fee_calls':fees,'records':api.pos,'native_calls':api.native,'native_elapsed_ns_sum':api.native_ns,'owners_created':api.next_id-1,'live_owners':len(api.live)}
