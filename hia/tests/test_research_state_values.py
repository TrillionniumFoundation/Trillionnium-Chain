"""Original public state-value encoders, without adding state admission rules."""
from __future__ import annotations
import base64,copy,gzip,hashlib,json,os,random,shutil,struct,subprocess,tempfile,unittest
from pathlib import Path
from hia.tests.native_support import NativeModule
from hia.tests.test_research_external_key import build_original
from hia.tests.test_research_payload import fixtures,key,ref,shares,MAX
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'hia/src/research_protocol/state_values.hepta'
REFERENCE=ROOT/'hia/tests/rust_research_state_values_reference.rs'
BUCKETS=('matches','evaluations','workload_receipts','claims','licenses','challenges','resolutions')
FIELDS=('commitment','commitment','receipt','claim','declaration','challenge','resolution')
PRIMARY=('commitment_id','evaluation_id','receipt_id','claim_id','declaration_id','challenge_id','resolution_id')
def objects():
 out=[]
 for k,(f,c) in enumerate(zip(FIELDS,fixtures()),1):
  p=c['payload'];r=ref(k);r['key']=p[PRIMARY[k-1]].copy();o=dict(object_ref=r);o[f]=p
  if k==4:o.update(current_claimants=shares(),status='active',active_challenge=None)
  if k==6:o.update(status='open',resolution_ref=None)
  out.append(o)
 return out
def snapshot(full=False):
 d=dict(protocol_version=2,authorities=dict(nakama_authorities=[],hepta_authorities=[]),applied_commands=[])
 for k,b in enumerate(BUCKETS):d[b]=[objects()[k]] if full else []
 return d
def record():return dict(command_id=key(31),fingerprint=key(32),primary_object_ref=ref(1),chain_id='trnm:test',signer_did='did:research',signer_role='nakama_authority',nonce=1,public_key=key(99))
def wire(op,data):return b'RSV1'+bytes([op])+bytes(19)+data
class ResearchStateValueNativeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.directory=tempfile.TemporaryDirectory(prefix='trnm-research-state-values-')
  cls.capture=None;cls.observations=None;cls.module=None
  try:
   _,cls.original=build_original(cls.directory.name);deps=cls.original['dependency_sha256'];args=['rustc','--edition=2021','--deny=warnings',str(REFERENCE)]
   for name,prefix in [('trnm_research_protocol','libtrnm_research_protocol.rlib'),('serde_json','libserde_json-')]:
    candidates=[Path(p) for p in deps if Path(p).name==prefix or Path(p).name.startswith(prefix)];assert len(candidates)==1;args+=['--extern',name+'='+str(candidates[0])]
   for p in sorted({Path(p).parent for p in deps}):args+=['-L','dependency='+str(p)]
   cls.oracle=Path(cls.directory.name)/'research-state-values-original';args+=['-o',str(cls.oracle)];p=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=60)
   if p.returncode:raise AssertionError(p.stderr)
   cls.original['state_values_adapter_sha256']=hashlib.sha256(cls.oracle.read_bytes()).hexdigest();cls.module=NativeModule(SOURCE,byte_exports=('f0',));cls.compared=cls.hashes=cls.abi=0
   destination=os.environ.get('HIA_RESEARCH_STATE_VALUES_OBSERVATIONS')
   if destination:
    cls.capture=Path(destination);cls.capture.mkdir(parents=True,exist_ok=False)
    cls.observations=gzip.open(cls.capture/'observations.jsonl.gz','wt')
    for source,name in [(cls.module.library,'values.so'),(cls.oracle,'values-original'),(SOURCE,SOURCE.name),(REFERENCE,REFERENCE.name),(Path(__file__),Path(__file__).name)]:shutil.copyfile(source,cls.capture/name)
    for name,row in [('receipt',cls.module.receipt),('canonical',cls.module.document)]: (cls.capture/('values.'+name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
    invoke=cls.module.call_many
    def observed(cases,*,timeout=30):
     cases=list(cases);results=invoke(cases,timeout=timeout)
     for (function,arguments),got in zip(cases,results):
      cls.observations.write(json.dumps(dict(type='native-call',function=function,request=[base64.b64encode(x).decode() for x in arguments],status=got.status,returncode=got.returncode,value=got.value,abi_status=got.abi_status,stderr=got.stderr,arguments=None if got.arguments is None else [base64.b64encode(x).decode() for x in got.arguments]),separators=(',',':'))+'\n')
     return results
    cls.module.call_many=observed
  except BaseException:
   if cls.observations:cls.observations.close()
   if cls.module:cls.module.close()
   cls.directory.cleanup();raise
 @classmethod
 def tearDownClass(cls):
  row={'schema':'trnm.hia.research-state-values-observation.v1','original_native_pairs':cls.compared,'independent_hashes':cls.hashes,'abi_controls':cls.abi,'original':cls.original,'native':{'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'artifact_sha256':cls.module.artifact_sha256,'compiler_sha256':cls.module.receipt['compiler_sha256']},'whole_state_owner_complete':False}
  print(json.dumps(row,sort_keys=True))
  if cls.observations:cls.observations.close()
  if cls.capture:
   row['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(cls.capture.iterdir()) if p.is_file()}
   (cls.capture/'report.json').write_text(json.dumps(row,indent=2)+'\n')
  cls.module.close();cls.directory.cleanup()
 @classmethod
 def reference(cls,rows):
  p=subprocess.run([str(cls.oracle)],input=''.join(json.dumps(r)+'\n' for r in rows),capture_output=True,text=True,timeout=30)
  if p.returncode:raise AssertionError(p.stderr)
  result=[json.loads(x) for x in p.stdout.splitlines()];assert len(result)==len(rows)
  if cls.observations:cls.observations.write(json.dumps(dict(type='original-call',request=rows,result=result,returncode=p.returncode,stderr=p.stderr),separators=(',',':'))+'\n')
  return result
 def compare(self,rows):
  for start in range(0,len(rows),6):
   batch=rows[start:start+6];refs=self.reference(batch);calls=[];wants=[];needs=[]
   for req,r in zip(batch,refs):
    data,cb,h=[bytes.fromhex(r[k]) for k in ('flat','canonical','hash')];need=8192+16*len(data);out=struct.pack('<4Q',len(cb),r['kind'],int(r['hash_present']),0)+h+cb+b'\xa5'*19
    if req['op']!=3:
     domain=b'trnm-research-protocol-object-leaf-v1' if req['op']==1 else b'trnm-research-protocol-snapshot-v2'
     self.assertEqual(h,hashlib.sha256(b'TRNM_RESEARCH_PROTOCOL_HASH_V1\0'+len(domain).to_bytes(4,'big')+domain+len(cb).to_bytes(8,'big')+cb).digest());type(self).hashes+=1
    calls.append(('f0',[wire(req['op'],data),b'\xa5'*len(out),b'\x5a'*(need+19)]));wants.append(out);needs.append(need)
   for req,r,call,want,need,got in zip(batch,refs,calls,wants,needs,self.module.call_many(calls,timeout=60)):
    got.require_returned()
    with self.subTest(op=req['op'],kind=req.get('kind'),request=str(req)[:160]):
     self.assertEqual(got.value,0);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[2][need:],b'\x5a'*19)
     if got.arguments[1]!=want:
      j=next(j for j,(a,b) in enumerate(zip(got.arguments[1],want)) if a!=b);self.fail(f'output {j}: {got.arguments[1][j:j+40].hex()} != {want[j:j+40].hex()}')
    type(self).compared+=1
 def test_seven_raw_object_encoders_and_full_width_versions(self):
  rows=[]
  for k,o in enumerate(objects(),1):
   for version in (0,1,23,24,255,256,65535,65536,1<<32,MAX):
    for actual_kind in (1,k,7):
     v=copy.deepcopy(o);v['object_ref']=ref(actual_kind,0,version);rows.append(dict(op=1,kind=k,object=v))
  for status in ('active','challenged','rejected','amended','license_amendment_required'):
   for active in (None,key(0),key(MAX)):
    v=objects()[3];v.update(status=status,active_challenge=active);rows.append(dict(op=1,kind=4,object=v))
  for status in ('open','resolved'):
   for active in (None,ref(1,0,0),ref(7,MAX,MAX)):
    v=objects()[5];v.update(status=status,resolution_ref=active);rows.append(dict(op=1,kind=6,object=v))
  self.compare(rows)
 def test_raw_snapshot_encoder_keeps_input_order_duplicates_and_version(self):
  rows=[]
  for version in (0,1,2,23,24,255):
   for full in (False,True):
    s=snapshot(full);s['protocol_version']=version;rows.append(dict(op=2,snapshot=s))
  for count in (0,1,23,24,64):
   s=snapshot();s['matches']=[copy.deepcopy(objects()[0]) for _ in range(count)]
   for j,o in enumerate(s['matches']):o['object_ref']['key']=key(count-j);o['commitment']['event_count']=j
   rows.append(dict(op=2,snapshot=s));s=copy.deepcopy(s);s['matches'].reverse();rows.append(dict(op=2,snapshot=s))
  for did in ('','not-an-authority','did:研究','a\0b','\\', 'x'*1024):
   s=snapshot(True);raw=dict(signer_did=did,public_key=[0]*32);s['authorities']=dict(nakama_authorities=[raw,raw],hepta_authorities=[raw]);s['applied_commands']=[record(),record()];rows.append(dict(op=2,snapshot=s))
  self.compare(rows)
 def test_journal_records_preserve_all_context_and_do_not_admit_state(self):
  rows=[]
  for nonce in (0,1,23,24,255,256,1<<32,MAX):
   for role in ('nakama_authority','hepta_authority'):
    for text in ('','A BAD CHAIN','trnm:test','研究\0\\', 'z'*257):
     r=record();r.update(nonce=nonce,signer_role=role,chain_id=text,signer_did=text,command_id=key(0),fingerprint=key(nonce));r['primary_object_ref']=ref(7,nonce,MAX);rows.append(dict(op=3,record=r))
  self.compare(rows)
 def test_dynamic_collection_lengths_options_unicode_and_random_typed_values(self):
  rows=[];rng=random.Random(61120)
  for n in (0,1,23,24,127,128,129):
   v=objects()[3];v['claim']['claimants']=shares(n);v['current_claimants']=list(reversed(shares(n)));v['claim']['evidence_refs']=[ref(2,j,MAX) for j in range(n)];rows.append(dict(op=1,kind=4,object=v))
   v=objects()[6];v['resolution']['amended_claimants']=shares(n);rows.append(dict(op=1,kind=7,object=v))
  for t in ('','MIT','研究\0😀','x'*4096):
   for option in (None,key(0),key(MAX)):
    v=objects()[4];v['declaration'].update(spdx_expression=t,additional_terms_hash=option);rows.append(dict(op=1,kind=5,object=v))
  for _ in range(100):
   k=rng.randrange(1,8);v=objects()[k-1];v['object_ref']=ref(rng.randrange(1,8),rng.getrandbits(256),rng.getrandbits(64));p=v[FIELDS[k-1]];p[PRIMARY[k-1]]=key(rng.getrandbits(256));rows.append(dict(op=1,kind=k,object=v))
  self.compare(rows)
 def test_every_typed_truncation_invalid_tag_and_atomic_capacity_refusal(self):
  requests=[dict(op=1,kind=k,object=o) for k,o in enumerate(objects(),1)]+[dict(op=2,snapshot=snapshot()),dict(op=3,record=record())]
  cases=[]
  for req,r in zip(requests,self.reference(requests)):
   data=bytes.fromhex(r['flat']);cb=bytes.fromhex(r['canonical']);raw=wire(req['op'],data);size=64+len(cb);need=8192+16*len(data)
   cases += [(wire(req['op'],data[:j]),size,8192+16*j,65) for j in range(len(data))]
   cases += [(raw[:j],size,need,65) for j in range(24)]
   cases += [(raw,no,need,64) for no in (0,1,63,64,size-1)]
   cases += [(raw,size,ns,64) for ns in (0,1,4096,need-1)]
   cases.append((wire(req['op'],data+b'\0'),size,need+16,65))
   for j in (0,1,2,3,5,8,23):
    d=bytearray(raw);d[j]^=1;cases.append((bytes(d),size,need,65))
   if req['op']==1:
    for invalid in (0,8,MAX):cases.append((wire(1,struct.pack('<Q',invalid)+data[8:]),size,need,65))
  for start in range(0,len(cases),16):
   batch=cases[start:start+16];calls=[('f0',[r,b'\xa5'*no,b'\x5a'*ns]) for r,no,ns,_ in batch]
   for case,call,got in zip(batch,calls,self.module.call_many(calls,timeout=60)):
    got.require_returned();self.assertEqual(got.value,case[3]);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[1],call[1][1]);type(self).abi+=1
if __name__=='__main__':unittest.main()
