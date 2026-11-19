"""Real native per-message contract controls; Python retains opaque test bytes only."""
from pathlib import Path
import hashlib,json,os,struct
from native_support import Module
from test_delta import start,tape,q,MAX
HERE=Path(__file__).resolve().parent

def ack(ticket,*,kind=0,value=0,payload=b''):
    return b'NDLEVT01'+q(2)+q(ticket)+q(kind)+q(value)+q(len(payload))+payload

def main():
    out=Path(os.environ.get('TRNM_DELTA_CONTRACT_OUTPUT',HERE/'qualification-contracts'))
    out.mkdir(mode=0o700)
    module=Module(HERE/'delta_owner.hepta',out/'build')
    observations=[]
    rows=[(b'a',b'1',b'2')]
    first=start(rows)
    used=256+len(tape(rows))
    zero=bytes(used)+b'\x6b'*31
    def call(event,command=b'\xa5'*128,context=zero,*,code,unchanged=False,label='contract'):
        actual=module.call_many([[event,command,context]])[0]
        assert actual['value']==code,(label,actual['value'],code)
        if unchanged:
            assert actual['arguments'][1]==command and actual['arguments'][2]==context,label
        assert actual['arguments'][2][used:]==context[used:]
        observations.append({'label':label,'event_sha256':hashlib.sha256(event).hexdigest(),'return':code,'status':'PASS'})
        return actual['arguments'][1],actual['arguments'][2]
    c,s=call(first,code=0,label='start')
    assert struct.unpack('<7Q',c[8:64])==(1,1,0,0,0,0,1)
    call(first,c,s,code=1024,unchanged=True,label='no-overwrite-live-context')
    call(ack(2),c,s,code=1024,unchanged=True,label='stale-ticket')
    call(b'BADMAGIC'+ack(1)[8:],c,s,code=1024,unchanged=True,label='wrong-magic')
    call(ack(1,kind=5),c,s,code=1024,unchanged=True,label='unknown-error-class')
    call(ack(1,value=1),c,s,code=1024,unchanged=True,label='progress-value')
    call(ack(1,payload=b'x'),c,s,code=1024,unchanged=True,label='progress-payload')
    call(ack(1),c[:64],s,code=1025,unchanged=True,label='command-extent-changed')
    call(ack(1),c,s[:used-1],code=1025,unchanged=True,label='context-extent-changed')
    for index in range(4):
        _,failed=call(ack(1,kind=index+1,value=MAX-index),c,s,code=512,label='opaque-error-class-'+str(index+1))
        assert struct.unpack('<2Q',failed[160:176])==(1,MAX-index)
        assert int.from_bytes(failed[224:232],'little')==index+1
        call(ack(1),c,failed,code=1024,unchanged=True,label='terminal-reply-refused')
        call(first,c,failed,code=0,label='terminal-context-reusable')
    for ticket,phase in ((1,2),(2,4),(3,5),(4,6)):
        c,s=call(ack(ticket),c,s,code=0,label='original-phase-'+str(phase))
        assert int.from_bytes(c[16:24],'little')==ticket+1
        assert int.from_bytes(c[56:64],'little')==phase
    assert c[104:105]==b'a'
    assert int.from_bytes(c[64:72],'little')==17 and c[72:104]==bytes([117])*32
    call(ack(5,value=2),c,s,code=1024,unchanged=True,label='invalid-read-presence')
    call(ack(5,value=0,payload=b'x'),c,s,code=1024,unchanged=True,label='absent-read-with-bytes')
    for payload in (b'',b'0',b'X'*4096):
        _,failed=call(ack(5,value=1,payload=payload),c,s,code=512,label='undo-root-complete-byte-comparison')
        assert struct.unpack('<2Q',failed[160:176])==(2,1)
    _,failed=call(ack(5,value=0),c,s,code=512,label='absence-is-not-empty')
    assert struct.unpack('<2Q',failed[160:176])==(2,1)
    _,failed=call(ack(5,kind=2,value=777),c,s,code=512,label='original-read-error-kept')
    assert struct.unpack('<2Q',failed[160:176])==(1,777)
    c,s=call(ack(5,value=1,payload=b'1'),c,s,code=0,label='exact-read-produces-put')
    assert struct.unpack('<4Q',c[8:40])==(3,6,1,1) and c[104:106]==b'a2'
    call(ack(6,value=1,payload=b'x'),c,s,code=1024,unchanged=True,label='write-extra-bytes')
    for changed in (0,2,MAX):
        _,failed=call(ack(6,value=changed),c,s,code=512,label='exactly-one-write-required')
        assert struct.unpack('<2Q',failed[160:176])==(2,2)
    c,done=call(ack(6,value=1),c,s,code=256,label='staging-only-completion')
    assert int.from_bytes(done[8:16],'little')==8
    assert struct.unpack('<3Q',done[176:200])==(4,1,1)
    call(ack(6,kind=2,value=777),c,done,code=1024,unchanged=True,label='no-post-completion-callback')
    call(first,c,done,code=0,label='completed-context-reusable')
    for cut in range(len(first)):
        shortened=first[:cut]
        if cut>=48:shortened=shortened[:40]+q(cut-48)+shortened[48:]
        call(shortened,code=1024,unchanged=True,label='constructor-truncation')
    bads=[start([(b'b',None,b'x'),(b'a',None,b'x')]),start([(b'a',None,b'x'),(b'a',None,b'x')]),
          start([(b'\xff',None,b'x')]),first+ b'x']
    for bad in bads:call(bad,context=bytes(4096),command=bytes(4096),code=1024,unchanged=True,label='constructor-admission')
    call(first,command=bytes(63),code=1025,unchanged=True,label='short-command')
    call(first,context=bytes(255),code=1025,unchanged=True,label='short-context')
    module.check_pin()
    report={'schema':'trnm.hia.delta-message-contracts.v1','status':'PASS','native_controls':len(observations),'controls':observations,'build':module.receipt,'source_inputs_stable':True,'original_rust':'NOT_RUN','durable_transaction_complete':False}
    (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':'PASS','controls':len(observations),'report':str(out/'report.json')}))

if __name__=='__main__':main()
