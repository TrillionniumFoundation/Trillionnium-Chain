"""Private snapshot index/admission against the actual original state API.

These components do not expose an owned State or authorize a foreign arena.
All expected decisions and error fields come from the retained Rust methods.
"""
from __future__ import annotations
import base64,copy,gzip,hashlib,json,os,random,shutil,struct,subprocess,tempfile,unittest
from pathlib import Path
from hia.tests.native_support import NativeModule
from hia.tests.test_research_external_key import build_original
from hia.tests.test_research_payload import key,ref,MAX,KINDS,NAMES
from hia.tests.test_research_state_values import objects,snapshot,record,BUCKETS,FIELDS,PRIMARY

ROOT=Path(__file__).resolve().parents[2]
INDEX=ROOT/'hia/src/research_protocol/state_index.hepta'
GRAPH=ROOT/'hia/src/research_protocol/state_graph.hepta'
REFERENCE=ROOT/'hia/tests/rust_research_state_reference.rs'
VALUES=ROOT/'hia/tests/rust_research_state_values_reference.rs'
G=225280
PUBLIC=list(bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'))

def connected(stage=7,journal=False):
    s=snapshot();values=objects()
    values[2]['receipt']['evaluation_ref']=ref(2,9)
    values[3]['claim'].update(workload_receipt_ref=ref(3,13),evidence_refs=[ref(1,1),ref(2,9)])
    values[4]['declaration'].update(claim_ref=ref(4,17),licensor=key(1))
    values[5]['challenge']['claim_ref']=ref(4,17)
    values[6]['resolution']['challenge_ref']=ref(6,22)
    if stage>=6:
        values[3].update(status='challenged',active_challenge=key(22))
        values[3]['object_ref']['object_version']=2
    if stage>=7:
        values[3].update(status='amended',active_challenge=None)
        values[3]['object_ref']['object_version']=3
        values[5].update(status='resolved',resolution_ref=ref(7,25))
        values[5]['object_ref']['object_version']=2
    for k,b in enumerate(BUCKETS):s[b]=[values[k]] if k<stage else []
    if journal:
        for k in range(stage):
            r=record();r.update(command_id=key(100+k),fingerprint=key(200+k),primary_object_ref=copy.deepcopy(values[k]['object_ref']),nonce=k+1,public_key=PUBLIC.copy())
            r['primary_object_ref']['object_version']=1;s['applied_commands'].append(r)
    return s

def uint(b,p):return struct.unpack_from('<Q',b,p)[0]
def graph_details(code,out,arena):
    w=struct.unpack('<8Q',out[:64])
    if w[0]!=code:raise AssertionError('Return code differs from its output record')
    def text(p):return arena[p+8:p+8+uint(arena,p)].decode()
    def reference(p):return dict(kind=KINDS[uint(arena,p)-1],key=list(arena[p+8:p+40]),object_version=uint(arena,p+40))
    if code==402:return dict(code=w[1],name=NAMES[w[2]],a=w[3],b=w[4])
    if code in (404,408):return dict(expected=text(w[4]),actual=text(w[5]))
    if code==410:return dict(kind=w[2],key=list(arena[w[4]:w[4]+32]))
    if code==411:return dict(object_ref=reference(w[4]))
    if code==412:return dict(object_ref=reference(w[4]),actual=w[2])
    if code==423:return dict(version=w[2])
    return {}

class ResearchStateGraphNativeTests(unittest.TestCase):
    SOURCES=(INDEX,GRAPH)
    MODULE_NAMES=('index','graph')
    CAPTURE_ENV='HIA_RESEARCH_STATE_GRAPH_OBSERVATIONS'
    OBSERVATION_SCHEMA='trnm.hia.research-state-graph-observation.v1'
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='trnm-research-state-graph-')
        cls.capture=None;cls.observations=None;cls.modules=[]
        try:
            _,cls.original=build_original(cls.directory.name)
            deps=cls.original['dependency_sha256'];extern=[]
            for name,prefix in [('trnm_research_protocol','libtrnm_research_protocol.rlib'),('serde_json','libserde_json-'),('ed25519_dalek','libed25519_dalek-')]:
                paths=[Path(p) for p in deps if Path(p).name==prefix or Path(p).name.startswith(prefix)]
                if len(paths)!=1:raise AssertionError('Ambiguous original dependency')
                extern.append((name,paths[0]))
            cls.oracles=[]
            for source,name in [(REFERENCE,'state-original'),(VALUES,'values-original')]:
                output=Path(cls.directory.name)/name
                args=['rustc','--edition=2021','--deny=warnings',str(source),'-o',str(output)]
                for name,path in extern:args+=['--extern',name+'='+str(path)]
                for path in sorted({Path(p).parent for p in deps}):args+=['-L','dependency='+str(path)]
                p=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=60)
                if p.returncode:raise AssertionError(p.stderr)
                cls.oracles.append(output)
            cls.modules=[NativeModule(p,byte_exports=('f0',)) for p in cls.SOURCES]
            cls.pairs=cls.abi=0;cls.codes=set()
            destination=os.environ.get(cls.CAPTURE_ENV)
            if destination:
                cls.capture=Path(destination);cls.capture.mkdir(parents=True,exist_ok=False)
                cls.observations=gzip.open(cls.capture/'observations.jsonl.gz','wt')
                for name,m in zip(cls.MODULE_NAMES,cls.modules):
                    shutil.copyfile(m.library,cls.capture/(name+'.so'))
                    (cls.capture/(name+'.receipt.json')).write_text(json.dumps(m.receipt,indent=2)+'\n')
                    (cls.capture/(name+'.canonical.json')).write_text(json.dumps(m.document,indent=2)+'\n')
                for p in cls.oracles:shutil.copyfile(p,cls.capture/p.name)
                for p in [*cls.SOURCES,REFERENCE,VALUES]:shutil.copyfile(p,cls.capture/p.name)
        except BaseException:
            for m in cls.modules:m.close()
            if cls.observations:cls.observations.close()
            cls.directory.cleanup();raise
    @classmethod
    def tearDownClass(cls):
        row=dict(schema=cls.OBSERVATION_SCHEMA,original_native_pairs=cls.pairs,abi_controls=cls.abi,observed_returns=sorted(cls.codes),original=cls.original,native=[dict(source_sha256=hashlib.sha256(m.source.read_bytes()).hexdigest(),artifact_sha256=m.artifact_sha256,compiler_sha256=m.receipt['compiler_sha256']) for m in cls.modules],whole_state_owner_complete=False)
        print(json.dumps(row,sort_keys=True))
        if cls.observations:cls.observations.close()
        if cls.capture:
            row['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(cls.capture.iterdir()) if p.is_file()}
            (cls.capture/'report.json').write_text(json.dumps(row,indent=2)+'\n')
        for m in cls.modules:m.close()
        cls.directory.cleanup()
    @classmethod
    def reference(cls,index,rows):
        p=subprocess.run([str(cls.oracles[index])],input=''.join(json.dumps(r)+'\n' for r in rows),capture_output=True,text=True,timeout=60)
        if p.returncode:raise AssertionError(p.stderr)
        out=[json.loads(l) for l in p.stdout.splitlines()]
        if len(out)!=len(rows):raise AssertionError('Original dropped a request')
        return out
    def retain(self,row):
        if self.observations:self.observations.write(json.dumps(row,separators=(',',':'))+'\n')
    def compare(self,rows):
        for start in range(0,len(rows),8):
            batch=rows[start:start+8];expected=self.reference(0,batch)
            values=self.reference(1,[dict(op=2,snapshot=r['snapshot']) for r in batch]);index_calls=[]
            for v in values:
                data=bytes.fromhex(v['flat']);need=266752+32*len(data)
                index_calls.append(('f0',[b'RSI1'+bytes(20)+data,b'\xa5'*35,b'\x5a'*(need+19)]))
            arenas=self.modules[0].call_many(index_calls,timeout=60);graph_calls=[]
            for req,a in zip(batch,arenas):
                a.require_returned();self.assertEqual(a.value,0)
                mode=2 if 'chain' in req else 1;raw=b'RSG1'+bytes([mode])+bytes(19)+(req['chain'].encode() if mode==2 else b'')
                graph_calls.append(('f0',[raw,b'\xa5'*83,a.arguments[2]]))
            results=self.modules[1].call_many(graph_calls,timeout=60)
            for req,want,v,ic,a,gc,b in zip(batch,expected,values,index_calls,arenas,graph_calls,results):
                b.require_returned();got=graph_details(b.value,b.arguments[1],b.arguments[2]);need=len(a.arguments[2])-19
                self.retain(dict(type='pair',request=req,original=want,values=v,index_request=[base64.b64encode(x).decode() for x in ic[1]],index_value=a.value,index_arguments=[base64.b64encode(x).decode() for x in a.arguments],graph_request=[base64.b64encode(x).decode() for x in gc[1]],graph_value=b.value,graph_arguments=[base64.b64encode(x).decode() for x in b.arguments]))
                with self.subTest(code=want['code'],details=want['details'],request=str(req)[:180]):
                    self.assertEqual((b.value,got),(want['code'],want['details']))
                    self.assertEqual(a.arguments[0],ic[1][0]);self.assertEqual(b.arguments[0],gc[1][0])
                    self.assertEqual(a.arguments[1],struct.pack('<2Q',int.from_bytes(b'RSINDEX1','little'),len(bytes.fromhex(v['flat'])))+b'\xa5'*19)
                    self.assertEqual(a.arguments[2][need:],b'\x5a'*19);self.assertEqual(b.arguments[2][need:],b'\x5a'*19)
                    self.assertEqual(b.arguments[1][64:],b'\xa5'*19)
                    p,n=uint(a.arguments[2],G+80),uint(a.arguments[2],G+88)
                    self.assertEqual(a.arguments[2][p:p+n],bytes.fromhex(v['canonical']))
                type(self).pairs+=1;type(self).codes.add(b.value)
    def test_empty_version_chain_and_raw_authority_error_order(self):
        rows=[]
        for version in (0,1,2,23,24,255):
            for chain in (None,'','a','trnm:test','UPPER','研究','a'*64,'a'*65):
                s=snapshot();s['protocol_version']=version;r=dict(op='restore',snapshot=s)
                if chain is not None:r['chain']=chain
                rows.append(r)
        for bucket in ('nakama_authorities','hepta_authorities'):
            for did in ('','did:','did:a','did:a\\','did:研究','did:'+'x'*188,'did:'+'x'*189):
                for public in (PUBLIC,key(0),[255]*32):
                    s=snapshot();s['authorities'][bucket]=[dict(signer_did=did,public_key=public)];rows.append(dict(op='restore',snapshot=s))
            for count in (0,1,2,127,128,129):
                s=snapshot();s['authorities'][bucket]=[dict(signer_did=f'did:{j:03d}',public_key=PUBLIC) for j in range(count)];rows.append(dict(op='restore',snapshot=s))
            for mode in ('duplicate','reverse'):
                s=snapshot();a=[dict(signer_did='did:a',public_key=PUBLIC),dict(signer_did='did:b',public_key=PUBLIC)];s['authorities'][bucket]=[a[0],a[0]] if mode=='duplicate' else a[::-1];rows.append(dict(op='restore',snapshot=s))
        self.compare(rows)
    def test_complete_graph_stages_journals_and_input_permutations(self):
        rows=[]
        for stage in range(8):
            for journal in (False,True):
                for chain in (None,'trnm:test'):
                    r=dict(op='restore',snapshot=connected(stage,journal))
                    if chain is not None:r['chain']=chain
                    rows.append(r)
        rng=random.Random(911)
        for count in (1,2,7,23,24,64):
            s=snapshot();s['matches']=[objects()[0] for _ in range(count)]
            for j,o in enumerate(s['matches']):o['object_ref']['key']=key(j+1);o['commitment']['commitment_id']=key(j+1)
            rng.shuffle(s['matches']);rows.append(dict(op='restore',snapshot=s))
        s=connected(7,True)
        for j in range(12):
            s=copy.deepcopy(s);rng.shuffle(s['applied_commands']);rows.append(dict(op='restore',snapshot=s,chain='trnm:test'))
        # The restore API intentionally does not enforce apply-time temporal or
        # claimant/contributor relationships beyond its original graph rules.
        for field,value in [('created_at_unix_s',0),('evidence_refs',[ref(1,999)]),('claimants',[dict(contributor=key(999),share_bps=10000)])]:
            s=connected();s['claims'][0]['claim'][field]=value;rows.append(dict(op='restore',snapshot=s))
        self.compare(rows)
    def test_object_collection_payload_and_reference_error_precedence(self):
        rows=[]
        for kind,bucket in enumerate(BUCKETS,1):
            for version in (0,1,2,MAX):
                s=connected();s[bucket][0]['object_ref']['object_version']=version;rows.append(dict(op='restore',snapshot=s))
            for field,value in [('key',key(0)),('kind',KINDS[kind%7])]:
                s=connected();s[bucket][0]['object_ref'][field]=value;rows.append(dict(op='restore',snapshot=s))
            s=connected();s[bucket][0][FIELDS[kind-1]][PRIMARY[kind-1]]=key(0);rows.append(dict(op='restore',snapshot=s))
            s=connected();s[bucket].append(copy.deepcopy(s[bucket][0]));rows.append(dict(op='restore',snapshot=s))
            s=connected();s[bucket]=[];rows.append(dict(op='restore',snapshot=s))
        for bucket,field in [('evaluations','match_evidence_ref'),('workload_receipts','evaluation_ref'),('claims','workload_receipt_ref'),('licenses','claim_ref'),('challenges','claim_ref'),('resolutions','challenge_ref')]:
            k=BUCKETS.index(bucket)
            for key_value,version in [(999,1),(0,1),(1,0),(1,MAX)]:
                s=connected();r=s[bucket][0][FIELDS[k]][field]
                if key_value!=1:r['key']=key(key_value)
                r['object_version']=version;rows.append(dict(op='restore',snapshot=s))
        for reverse in (False,True):
            s=connected();a=copy.deepcopy(s['matches'][0]);a['object_ref']['key']=key(999);a['commitment']['commitment_id']=key(999);a['commitment']['event_count']=0;s['matches'].append(a)
            s['matches'][0]['commitment']['event_root']=key(0)
            if reverse:s['matches'].reverse()
            rows.append(dict(op='restore',snapshot=s))
        self.compare(rows)
    def test_journal_chain_nonce_identity_and_historical_reference_rules(self):
        rows=[]
        for field,values in [('chain_id',['','BAD','trnm:other','研究','a'*64,'a'*65]),('signer_did',['','did:','did:a','did:a\\','did:研究','did:'+'x'*188,'did:'+'x'*189]),('nonce',[0,1,2,MAX]),('command_id',[key(0),key(101)]),('fingerprint',[key(0)]),('public_key',[key(0),[255]*32]),('primary_object_ref',[ref(4,17,0),ref(4,17,1),ref(4,17,MAX),ref(7,999)])]:
            for value in values:
                s=connected(7,True);s['applied_commands'][0][field]=value;rows.append(dict(op='restore',snapshot=s))
        for count in (1,2,7):
            s=connected(7,True);s['applied_commands']=s['applied_commands'][:count]
            rows += [dict(op='restore',snapshot=copy.deepcopy(s),chain=chain) for chain in ('trnm:test','trnm:other','')]
        for role in ('nakama_authority','hepta_authority'):
            for did in ('did:research','did:different'):
                s=connected(7,True);s['applied_commands'][1].update(nonce=1,signer_role=role,signer_did=did);rows.append(dict(op='restore',snapshot=s))
        for reverse in (False,True):
            s=connected(7,True);s['applied_commands'][0]['chain_id']='first';s['applied_commands'][1]['chain_id']='second'
            if reverse:s['applied_commands'].reverse()
            rows.append(dict(op='restore',snapshot=s,chain='bound'))
        self.compare(rows)
    def test_claim_challenge_resolution_bidirectional_graph_and_overflow(self):
        rows=[]
        for stage in (6,7):
            for status in ('active','challenged','rejected','amended','license_amendment_required'):
                for active in (None,key(22),key(999)):
                    for version in (1,2,3,MAX):
                        s=connected(stage);s['claims'][0].update(status=status,active_challenge=active);s['claims'][0]['object_ref']['object_version']=version;rows.append(dict(op='restore',snapshot=s))
        for status in ('open','resolved'):
            for reference in (None,ref(7,25),ref(1,25),ref(7,999),ref(7,25,MAX)):
                for version in (1,2,3,MAX):
                    s=connected();s['challenges'][0].update(status=status,resolution_ref=reference);s['challenges'][0]['object_ref']['object_version']=version;rows.append(dict(op='restore',snapshot=s))
        for version in (0,1,2,3,MAX):
            for bucket,field in [('challenges','claim_ref'),('resolutions','challenge_ref')]:
                s=connected();k=BUCKETS.index(bucket);s[bucket][0][FIELDS[k]][field]['object_version']=version;rows.append(dict(op='restore',snapshot=s))
        for claimants in ([],[dict(contributor=key(0),share_bps=10000)],[dict(contributor=key(1),share_bps=9999)],[dict(contributor=key(999),share_bps=10000)]):
            s=connected();s['claims'][0]['current_claimants']=claimants;rows.append(dict(op='restore',snapshot=s))
        self.compare(rows)
    def test_private_abi_boundaries_and_atomic_refusals(self):
        requests=[dict(op=2,snapshot=snapshot()),dict(op=2,snapshot=connected())]
        cases=[];valid=[]
        for v in self.reference(1,requests):
            data=bytes.fromhex(v['flat']);raw=b'RSI1'+bytes(20)+data;need=266752+32*len(data)
            a=self.modules[0].call('f0',[raw,b'\xa5'*35,b'\x5a'*(need+19)]).require_returned();self.assertEqual(a.value,0);valid.append((raw,need,a.arguments[2]))
            cuts=set(range(24))|{24,25,len(raw)-1}
            for k in range(8):
                row=G+128+k*64;start=uint(a.arguments[2],row+24)-262656+24;end=uint(a.arguments[2],row+32)-262656+24
                for p in (start,end):cuts.update(j for j in (p-1,p,p+1) if 0<=j<len(raw))
                d=uint(a.arguments[2],row+16)
                for j in range(uint(a.arguments[2],row)):
                    for p in (uint(a.arguments[2],d+192*j),uint(a.arguments[2],d+192*j+8)):
                        cuts.update(q for q in (p-262656+23,p-262656+24,p-262656+25) if 0<=q<len(raw))
            cases += [(raw[:n],35,need,65) for n in sorted(cuts)]
            cases += [(raw,n,need,64) for n in (0,1,15)]
            cases += [(raw,35,n,64) for n in (0,1,266751,need-1)]
            cases.append((raw+b'\0',35,need+32,65))
            for j in (0,1,2,3,4,5,23):
                x=bytearray(raw);x[j]^=1;cases.append((bytes(x),35,need,65))
        for start in range(0,len(cases),8):
            batch=cases[start:start+8];calls=[('f0',[r,b'\xa5'*no,b'\x5a'*ns]) for r,no,ns,_ in batch]
            for case,call,got in zip(batch,calls,self.modules[0].call_many(calls,timeout=60)):
                got.require_returned();self.assertEqual(got.value,case[3]);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[1],call[1][1]);type(self).abi+=1
                self.retain(dict(type='index-refusal',expected=case[3],request=[base64.b64encode(x).decode() for x in call[1]],value=got.value,arguments=[base64.b64encode(x).decode() for x in got.arguments]))
        raw,need,arena=valid[1];header=b'RSG1\1'+bytes(19);calls=[];wanted=[]
        for size in (0,1,23):calls.append(('f0',[header[:size],b'\xa5'*83,arena]));wanted.append(64)
        for size in (0,1,63):calls.append(('f0',[header,b'\xa5'*size,arena]));wanted.append(64)
        for j in (0,1,2,3,4,5,23):
            h=bytearray(header);h[j]=255;calls.append(('f0',[bytes(h),b'\xa5'*83,arena]));wanted.append(65)
        calls.append(('f0',[header+b'\0',b'\xa5'*83,arena]));wanted.append(65)
        for call,code,got in zip(calls,wanted,self.modules[1].call_many(calls,timeout=60)):
            got.require_returned();self.assertEqual(got.value,code);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[1],call[1][1]);type(self).abi+=1
            self.retain(dict(type='graph-refusal',expected=code,request=[base64.b64encode(x).decode() for x in call[1]],value=got.value,arguments=[base64.b64encode(x).decode() for x in got.arguments]))

if __name__=='__main__':unittest.main()
