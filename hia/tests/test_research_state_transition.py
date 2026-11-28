"""Native admission/transition/value chain against original State.apply.

The final opaque ownership wrapper is a separate requirement. The harness
transports native outputs to the next native input without applying host rules.
"""
from __future__ import annotations
import base64,copy,json,struct,unittest
from pathlib import Path
from hia.tests import test_research_state_graph as graph_support
from hia.tests.test_research_payload import key,ref,MAX,KINDS,TYPES,shares
from hia.tests.test_research_state_values import BUCKETS,FIELDS

ROOT=Path(__file__).resolve().parents[2]
INDEX=ROOT/'hia/src/research_protocol/state_index.hepta'
GRAPH=ROOT/'hia/src/research_protocol/state_graph.hepta'
TRANSITION=ROOT/'hia/src/research_protocol/state_transition.hepta'
VALUES=ROOT/'hia/src/research_protocol/state_values.hepta'
COMMAND=ROOT/'hia/src/research_protocol/command.hepta'
G=225280;CHAIN=G+6144;T=G+8192;FP=T+512
SEED='9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

def state_fixture(stage=0,journal=False):
    s=graph_support.connected(stage,journal)
    a=dict(signer_did='did:research',public_key=graph_support.PUBLIC.copy())
    s['authorities']=dict(nakama_authorities=[copy.deepcopy(a)],hepta_authorities=[copy.deepcopy(a)])
    return s
def signed_request(kind,payload,nonce,command_id=None,**kw):
    d=dict(chain_id='trnm:test',command_id=key(nonce+100 if command_id is None else command_id),signer_did='did:research',signer_role='nakama_authority' if kind==1 else 'hepta_authority',nonce=nonce,command=dict(type=TYPES[kind-1],payload=copy.deepcopy(payload)),seed=SEED)
    d.update(kw);return d
def sequence(decision='amend_contributor_shares'):
    full=state_fixture(7);out=[signed_request(k+1,full[b][0][FIELDS[k]],k+1) for k,b in enumerate(BUCKETS)]
    out[-1]['command']['payload']['decision']=decision
    if decision!='amend_contributor_shares':out[-1]['command']['payload']['amended_claimants']=[]
    return out
def error_details(code,out,arena):
    raw=out[256:320];w=struct.unpack('<8Q',raw)
    if code in (403,405,409,413,418,419):
        if w[0]!=code:raise AssertionError('Error record and returned code differ')
        def text(p):return arena[p+8:p+8+graph_support.uint(arena,p)].decode()
        def reference(p):return dict(kind=KINDS[graph_support.uint(arena,p)-1],key=list(arena[p+8:p+40]),object_version=graph_support.uint(arena,p+40))
        if code==403:return dict(command_id=list(arena[w[4]:w[4]+32]))
        if code==405:return dict(chain_id=text(w[4]),signer_did=text(w[5]),nonce=w[2],last_nonce=w[3])
        if code==409:return dict(signer_did=text(w[4]),role=['nakama_authority','hepta_authority'][w[2]-1],public_key=list(arena[w[5]:w[5]+32]))
        if code==413:return dict(object_ref=reference(w[4]))
        return dict(status=w[2])
    return graph_support.graph_details(code,raw,arena)

class ResearchStateTransitionNativeTests(unittest.TestCase):
    SOURCES=(INDEX,GRAPH,TRANSITION,VALUES,COMMAND)
    MODULE_NAMES=('index','graph','transition','values','command')
    CAPTURE_ENV='HIA_RESEARCH_STATE_TRANSITION_OBSERVATIONS'
    OBSERVATION_SCHEMA='trnm.hia.research-state-transition-observation.v1'
    reference=classmethod(graph_support.ResearchStateGraphNativeTests.reference.__func__)
    tearDownClass=classmethod(graph_support.ResearchStateGraphNativeTests.tearDownClass.__func__)
    retain=graph_support.ResearchStateGraphNativeTests.retain
    @classmethod
    def setUpClass(cls):
        graph_support.ResearchStateGraphNativeTests.setUpClass.__func__(cls)
        cls.commands=sequence();request=dict(op='apply',snapshot=state_fixture(),chain='trnm:test',commands=cls.commands)
        result=cls.reference(0,[request])[0]
        if result['code'] or any(s.get('construction_error') or s['outcome']['code'] for s in result['steps']):raise AssertionError(result)
        cls.current=result['steps'][-1]['state']['snapshot']
        if cls.observations:cls.observations.write(json.dumps(dict(type='original-fixture-construction',request=request,result=result),separators=(',',':'))+'\n')
    def invoke(self,module,args):
        c=self.modules[module].call('f0',args,timeout=30).require_returned()
        self.retain(dict(type='native-call',module=self.MODULE_NAMES[module],request=[base64.b64encode(x).decode() for x in args],value=c.value,arguments=[base64.b64encode(x).decode() for x in c.arguments]))
        return c
    def prepare(self,flat,result,chain):
        n=len(flat);need=266752+32*n
        indexed=self.invoke(0,[b'RSI1'+bytes(20)+flat,b'\xa5'*35,b'\x5a'*(need+19)]);self.assertEqual(indexed.value,0)
        raw=b'RSG1'+bytes([1 if chain is None else 2])+bytes(19)+(chain.encode() if chain is not None else b'')
        graph=self.invoke(1,[raw,b'\xa5'*83,indexed.arguments[2]]);self.assertEqual(graph.value,0)
        data=bytes.fromhex(result['flat']);c=len(data)
        signed=self.invoke(4,[b'RSC1\2'+bytes(19)+data,b'\xa5'*(160+6*c+1024),b'\x5a'*(266752+16*c+19)])
        self.assertEqual(signed.value,0);a,b=struct.unpack_from('<2Q',signed.arguments[1])
        self.assertEqual(signed.arguments[1][160+a:160+a+b],data);self.assertEqual(signed.arguments[1][64:96].hex(),result['fingerprint'])
        full=299520+33*n+32*c;arena=bytearray(graph.arguments[2][:need]+b'\x5a'*(full-need+19));binding=(chain or '').encode()
        struct.pack_into('<Q',arena,CHAIN,len(binding));arena[CHAIN+8:CHAIN+8+len(binding)]=binding;arena[FP:FP+32]=signed.arguments[1][64:96]
        return [b'RST1'+bytes(20)+data,b'\xa5'*(320+n+4*c+1024+19),bytes(arena)],full
    def compare(self,rows):
        for req in rows:
            expected=self.reference(0,[req])[0];self.assertEqual(expected['code'],0,expected)
            value=self.reference(1,[dict(op=2,snapshot=expected['initial']['snapshot'])])[0];flat=bytes.fromhex(value['flat'])
            self.retain(dict(type='original-scenario',request=req,result=expected,initial_value=value))
            for j,result in enumerate(expected['steps']):
                self.assertNotIn('construction_error',result,result)
                self.assertEqual(result['validation']['code'],0,result['validation'])
                old=flat;args,need=self.prepare(flat,result,req.get('chain'));actual=self.invoke(2,args);want=result['outcome']
                with self.subTest(step=j,expected=want,command=result['signed']['command']['type']):
                    self.assertEqual(actual.value,want['code']);self.assertEqual(actual.arguments[0],args[0]);self.assertEqual(actual.arguments[2][need:],b'\x5a'*19)
                    self.assertEqual(actual.arguments[2][262656:262656+len(old)],old)
                    if actual.value:
                        self.assertEqual(error_details(actual.value,actual.arguments[1],actual.arguments[2]),want['details'])
                        self.assertEqual(actual.arguments[1][320:],args[1][320:])
                    else:
                        outcome,n,count=struct.unpack_from('<3Q',actual.arguments[1]);self.assertEqual(outcome,1 if want['kind']=='applied' else 2)
                        def reference(p):return dict(kind=KINDS[graph_support.uint(actual.arguments[1],p)-1],key=list(actual.arguments[1][p+8:p+40]),object_version=graph_support.uint(actual.arguments[1],p+40))
                        self.assertEqual(reference(32),want['primary_object_ref']);self.assertEqual([reference(80+48*k) for k in range(count)],want['changed_object_refs'])
                        if outcome==1:flat=actual.arguments[1][320:320+n]
                        else:self.assertEqual((n,count),(0,0))
                        self.assertEqual(actual.arguments[1][320+n:],args[1][320+n:])
                v=self.reference(1,[dict(op=2,snapshot=result['state']['snapshot'])])[0]
                self.retain(dict(type='expected-state-value',value=v))
                self.assertEqual(flat,bytes.fromhex(v['flat']))
                cb=bytes.fromhex(result['state']['canonical']);native=self.invoke(3,[b'RSV1\2'+bytes(19)+flat,b'\xa5'*(64+len(cb)+19),b'\x5a'*(8192+16*len(flat)+19)])
                self.assertEqual(native.value,0);self.assertEqual(native.arguments[1][32:64].hex(),result['state']['hash']);self.assertEqual(native.arguments[1][64:64+len(cb)],cb)
                type(self).pairs+=1;type(self).codes.add(actual.value)
    def test_all_seven_transitions_replays_and_four_resolution_decisions(self):
        rows=[]
        for decision in ('uphold','reject','amend_contributor_shares','require_license_amendment'):
            commands=sequence(decision);commands+=copy.deepcopy(commands)
            if decision!='reject':
                challenge=copy.deepcopy(sequence()[5]['command']['payload']);challenge.update(challenge_id=key(122),claim_ref=ref(4,17,3))
                resolution=copy.deepcopy(sequence()[6]['command']['payload']);resolution.update(resolution_id=key(125),challenge_ref=ref(6,122))
                commands += [signed_request(6,challenge,8),signed_request(7,resolution,9)]
            rows.append(dict(op='apply',snapshot=state_fixture(),chain='trnm:test',commands=commands))
        self.compare(rows)
    def test_authentication_replay_nonce_and_chain_order(self):
        rows=[]
        for k,original in enumerate(self.commands):
            altered=copy.deepcopy(original);altered['nonce']=88
            replay=copy.deepcopy(original);replay['command_id']=key(1000+k)
            for signed in (original,altered,replay):rows.append(dict(op='apply',snapshot=copy.deepcopy(self.current),chain='trnm:test',commands=[copy.deepcopy(signed)]))
        for chain,did,nonce in [('other','did:other',1),('trnm:test','did:other',1),('trnm:test','did:research',1),('trnm:test','did:research',MAX)]:
            c=copy.deepcopy(self.commands[1]);c.update(chain_id=chain,signer_did=did,nonce=nonce,command_id=key(900));rows.append(dict(op='apply',snapshot=copy.deepcopy(self.current),chain='trnm:test',commands=[c]))
        rows.append(dict(op='apply',snapshot=copy.deepcopy(self.current),commands=[copy.deepcopy(self.commands[0])]))
        s=copy.deepcopy(self.current);s['authorities']=dict(nakama_authorities=[],hepta_authorities=[])
        rows.append(dict(op='apply',snapshot=s,chain='trnm:test',commands=[copy.deepcopy(self.commands[0])]))
        self.compare(rows)
    def test_reference_timestamp_claimant_status_and_atomic_version_preconditions(self):
        rows=[]
        def add(stage,kind,changes,mutate=None):
            s=state_fixture(stage);p=copy.deepcopy(sequence()[kind-1]['command']['payload']);changes=copy.deepcopy(changes)
            # A zero timestamp is rejected by signed.validate before State.apply
            # reaches its transition. Use two positive times for this layer.
            if any(k.endswith('_unix_s') and v==0 for k,v in changes.items()):
                for bucket,field in zip(BUCKETS,FIELDS):
                    for obj in s[bucket]:
                        for name in obj[field]:
                            if name.endswith('_unix_s'):obj[field][name]=2
                changes={k:(1 if k.endswith('_unix_s') and v==0 else v) for k,v in changes.items()}
            p.update(changes)
            if mutate:mutate(s)
            rows.append(dict(op='apply',snapshot=s,chain='trnm:test',commands=[signed_request(kind,p,20,900)]))
        add(1,1,{})
        for reference in (ref(1,999),ref(1,1,2)):add(1,2,dict(match_evidence_ref=reference,completed_at_unix_s=0))
        add(1,2,dict(completed_at_unix_s=0))
        add(2,3,dict(issued_at_unix_s=0))
        add(2,3,dict(issued_at_unix_s=0),lambda s:s['evaluations'][0]['commitment'].update(accepted=False))
        add(3,4,dict(claimants=[dict(contributor=key(999),share_bps=10000)]))
        add(3,4,dict(evidence_refs=[ref(1,1)]))
        add(3,4,dict(evidence_refs=[ref(1,999)],claimants=[dict(contributor=key(999),share_bps=10000)],created_at_unix_s=0))
        add(3,4,dict(created_at_unix_s=0));add(4,4,dict(created_at_unix_s=0));add(4,4,{})
        for stage,version in [(4,1),(6,2),(7,3)]:
            add(stage,5,dict(claim_ref=ref(4,17,version),licensor=key(999),effective_at_unix_s=0))
        add(4,5,dict(licensor=key(1),effective_at_unix_s=0))
        add(4,6,dict(opened_at_unix_s=0));add(6,6,dict(claim_ref=ref(4,17,2),opened_at_unix_s=0))
        add(7,6,dict(claim_ref=ref(4,17,3)),lambda s:s['claims'][0].update(status='rejected'))
        add(4,6,dict(claim_ref=ref(4,17,MAX)),lambda s:s['claims'][0]['object_ref'].update(object_version=MAX))
        add(7,6,dict(claim_ref=ref(4,17,MAX)),lambda s:s['claims'][0]['object_ref'].update(object_version=MAX))
        add(6,7,dict(decided_at_unix_s=0));add(6,7,dict(challenge_ref=ref(6,22,2)))
        add(6,7,dict(amended_claimants=[dict(contributor=key(999),share_bps=10000)]))
        add(7,7,dict(challenge_ref=ref(6,22,2),decided_at_unix_s=0))
        self.compare(rows)
    def test_dynamic_ordered_objects_and_journal_survive_multiple_steps(self):
        commands=[];template=sequence()[0]['command']['payload']
        for j in range(32):
            payload=copy.deepcopy(template);payload['commitment_id']=key(32-j);commands.append(signed_request(1,payload,j+1,1000+32-j))
        commands += [copy.deepcopy(commands[k]) for k in (0,7,15,23,31)]
        self.compare([dict(op='apply',snapshot=state_fixture(),chain='trnm:test',commands=commands)])
    def test_capacity_refusal_keeps_public_output_and_original_state(self):
        req=dict(op='apply',snapshot=state_fixture(),chain='trnm:test',commands=[self.commands[0]])
        expected=self.reference(0,[req])[0];v=self.reference(1,[dict(op=2,snapshot=req['snapshot'])])[0];flat=bytes.fromhex(v['flat']);result=expected['steps'][0]
        args,need=self.prepare(flat,result,'trnm:test');correct=self.invoke(2,args);self.assertEqual(correct.value,0);required=320+struct.unpack_from('<Q',correct.arguments[1],8)[0]
        cases=[]
        for n in (0,1,319,320,required-1):cases.append([args[0],b'\xa5'*n,args[2]])
        for n in (0,1,266751,need-1):cases.append([args[0],args[1],args[2][:n]])
        for call in cases:
            got=self.invoke(2,call);self.assertEqual(got.value,64);self.assertEqual(got.arguments[0],call[0]);self.assertEqual(got.arguments[1],call[1])
            if len(call[2])>=262656+len(flat):self.assertEqual(got.arguments[2][262656:262656+len(flat)],flat)
            type(self).abi+=1
    def test_private_frame_truncation_and_header_refusal(self):
        req=dict(op='apply',snapshot=state_fixture(),chain='trnm:test',commands=[self.commands[0]])
        expected=self.reference(0,[req])[0];v=self.reference(1,[dict(op=2,snapshot=req['snapshot'])])[0];flat=bytes.fromhex(v['flat']);args,need=self.prepare(flat,expected['steps'][0],'trnm:test')
        raws=[args[0][:n] for n in list(range(24))+[24,25,31,32,63,64,len(args[0])-1]]
        raws.append(args[0]+b'\0')
        for j in (0,1,2,3,4,5,23):
            b=bytearray(args[0]);b[j]=255;raws.append(bytes(b))
        for raw in raws:
            # The declared scratch extent depends on actual command bytes.
            # Admit the extra byte before expecting typed trailing-data refusal.
            extra=32*max(0,len(raw)-len(args[0]));arena=args[2][:-19]+b'\x5a'*extra+args[2][-19:]
            call=[raw,args[1],arena];got=self.invoke(2,call);self.assertEqual(got.value,65);self.assertEqual(got.arguments[0],raw);self.assertEqual(got.arguments[1],args[1]);self.assertEqual(got.arguments[2][262656:262656+len(flat)],flat);type(self).abi+=1
        got=self.invoke(2,[args[0]+b'\0',args[1],args[2]])
        self.assertEqual(got.value,64);self.assertEqual(got.arguments[1],args[1]);self.assertEqual(got.arguments[2],args[2]);type(self).abi+=1

if __name__=='__main__':unittest.main()
