"""Independent relational oracle and real HIA-owned KV/command execution."""
from pathlib import Path
import hashlib, json, os, random, struct, sys
from native_support import Module

HERE=Path(__file__).resolve().parent
MAX=(1<<64)-1

def q(value):return struct.pack('<Q',value)
def kv(rows):
    ordered=sorted(rows.items())
    return b'NKV00001'+q(len(ordered))+b''.join(q(len(k))+q(len(v))+k+v for k,v in ordered)
def tape(rows,block=bytes([117])*32,slot=17):
    return b'NDLT0001'+q(len(rows))+block+q(slot)+b''.join(q(len(k))+q(MAX if b is None else len(b))+q(MAX if a is None else len(a))+k+(b or b'')+(a or b'') for k,b,a in rows)
def start(rows,detach=False):
    raw=tape(rows)
    return b'NDLEVT01'+q(1)+q(0)+q(0)+q(int(detach))+q(len(raw))+raw

def fixture(before,rows,*,detach=False,cancel=MAX,read_error=MAX,write_fault=MAX,token=0x8877665544332211):
    original=kv(before)
    command=start(rows,detach)
    raw=b'NDFIX001'+q(cancel)+q(read_error)+q(write_fault)+q(token)+q(len(original))+q(len(command))+q(0)+original+command
    return raw,256+len(tape(rows))

def reference(before,rows,*,detach=False,cancel=MAX,read_error=MAX,write_fault=MAX,token=0x8877665544332211):
    current=dict(before)
    progresses=reads=writes=0
    class Refusal(Exception):
        def __init__(self,origin,value,kind):self.row=(512,origin,value,kind)
    def progress():
        nonlocal progresses
        point=progresses
        progresses+=1
        if point==cancel:raise Refusal(1,token,2)
    outcome=(256,0,0,0)
    try:
        progress()  # apply_delta initial
        progress()  # delta_rows initial
        for index,_ in enumerate(rows,1):
            if index%256==0:progress()
        progress()  # delta_rows final, even empty
        for index,(key,before_value,after_value) in enumerate(rows):
            progress()
            expected,new=(after_value,before_value) if detach else (before_value,after_value)
            reads+=1
            if index==read_error:raise Refusal(1,token,1)
            actual=current.get(key)
            if actual!=expected:raise Refusal(2,1,0)
            writes+=1
            changed=1 if new is not None or key in current else 0
            if index==write_fault:changed=0
            if changed!=1:raise Refusal(2,2,0)
            if new is None:current.pop(key)
            else:current[key]=new
    except Refusal as failure:
        outcome=failure.row
        current=dict(before)
    return outcome+(progresses,reads,writes),kv(current)


def cases():
    result=[]
    def add(before,rows,**options):
        encoded,used=fixture(before,rows,**options)
        expected,body=reference(before,rows,**options)
        result.append((encoded,used,expected,body,options.get('label','relational')))
    keys=[b'',b'a\0', 'λ'.encode()]
    choices=[None,b'',b'null',b'\xff\0']
    states=[]
    for mask in range(64):
        state={}
        for index,key in enumerate(keys):
            value=choices[(mask//(4**index))%4]
            if value is not None:state[key]=value
        states.append(state)
    for before in states:
        for after in states:
            rows=[(key,before.get(key),after.get(key)) for key in sorted(set(before)|set(after)) if before.get(key)!=after.get(key)]
            add(before,rows)
            add(after,rows,detach=True)
    # Option<Vec<u8>> has a separate absence alternative, including deletion of
    # an already absent row: exact comparison succeeds, DELETE changes zero.
    for before,rows in [({},[(b'',None,None)]),({b'':b''},[(b'',None,b'x')]),({},[(b'',b'',None)]),
                        ({b'a':b'1'},[(b'a',b'1',b'1')]),({b'a':b'1'},[(b'a',b'2',b'3')]),
                        ({b'a':b'1'},[(b'b',b'1',b'2')])]:
        add(before,rows)
    rng=random.Random(0x4e444c31)
    for _ in range(100):
        values={f'key:{i:04}'.encode():rng.randbytes(rng.randrange(65)) for i in range(rng.randrange(24))}
        after=dict(values)
        for _ in range(rng.randrange(12)):
            key=f'key:{rng.randrange(30):04}'.encode()
            if rng.randrange(3):after[key]=rng.randbytes(rng.randrange(129))
            else:after.pop(key,None)
        rows=[(key,values.get(key),after.get(key)) for key in sorted(set(values)|set(after)) if values.get(key)!=after.get(key)]
        add(values,rows)
    for n in (0,1,255,256,257,512):
        before={f'{i:06}'.encode():b'a' for i in range(n)}
        rows=[(k,b'a',b'b') for k in sorted(before)]
        last=3+n+n//256
        points={0,1,2,last-1,last,last+1}
        if n>=256:points|={3,4,3+n//256}
        for point in sorted(points):add(before,rows,cancel=point)
        if n:
            for index in {0,n//2,n-1}:
                add(before,rows,read_error=index)
                add(before,rows,write_fault=index)
    # General typed byte vectors are not narrowed to the later wire/JSON layer.
    for n in (0,1,4095,4096,4097,32768):
        key=('é'*80).encode()
        add({key:b'\0'*n},[(key,b'\0'*n,b'\xff'*(n+1))])
    return result


def main():
    output=Path(os.environ.get('TRNM_DELTA_OUTPUT',HERE/'qualification-delta'))
    output.mkdir(mode=0o700)
    observed_inputs={p:p.read_bytes() for p in (Path(__file__), HERE/'native_support.py')}
    module=Module(HERE/'delta_fixture.hepta',output/'build')
    suite=cases()
    receipts=[]
    for begin in range(0,len(suite),100):
        selected=suite[begin:begin+100]
        sent=[[raw,b'\xa5'*(len(raw)+256),bytes(used)+b'\x6b'*37] for raw,used,_,_,_ in selected]
        answer=module.call_many(sent,timeout=60)
        for (raw,used,want,body,label),args,row in zip(selected,sent,answer):
            assert row['value']==want[0],(begin,want,row['value'])
            data=row['arguments'][1]
            assert data[:8]==b'NDFOUT01'
            header=struct.unpack('<9Q',data[8:80])
            assert header[:7]==want,(begin,want,header)
            assert header[7]==len(body) and header[8]==0
            assert data[80:80+len(body)]==body,(begin,'KV differs')
            assert row['arguments'][2][used:]==args[2][used:]
            receipts.append({'case':len(receipts),'input_sha256':hashlib.sha256(raw).hexdigest(),'input_bytes':len(raw),'status':'PASS','result':want[0],'progresses':want[4],'reads':want[5],'writes':want[6]})
    module.check_pin()
    assert all(path.read_bytes()==raw for path,raw in observed_inputs.items())
    report={'schema':'trnm.hia.native-delta-prototype.v1','status':'PASS','native_cases':len(receipts),
            'build':module.receipt,'cases':receipts,'source_inputs_stable':True,
            'actual_kv_transaction_logic':'Native HIA fixture; independent Python dictionary only predicts expected results',
            'cancellation':'Native explicit checkpoint events; no OS deadline or paid cleanup qualification',
            'whole_node_or_durable_transaction_qualified':False,'original_rust':'NOT_RUN'}
    (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':'PASS','native_cases':len(receipts),'report':str(output/'report.json')}))

if __name__=='__main__':main()
