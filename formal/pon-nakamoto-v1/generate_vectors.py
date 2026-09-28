"""Explicit, reviewable oracle vector generation; never run automatically by test gates."""
from pathlib import Path
import json
from contract_wire import *
from ledger import A,B,key,public,sign,FAMILY,PLAN
from work_oracle import prove,task_id
D=Path(__file__).parent/'vectors';D.mkdir(exist_ok=True)
h=dict(network=NETWORK,parameters=PARAMETER_HASH,parent=bytes([3])*32,height=17,timestamp=1800000170,target=bytes.fromhex(PARAMS['initial_target_hex']),miner=public(key(0)),transactions=H('vector-transactions'),state=H('vector-state'),receipts=H('vector-receipts'),work_task=task_id(A,B),nonce=42)
hb=header_encode(h);(D/'header.bin').write_bytes(hb)
v={'schema':'pon-independent-implementation-vectors-v1','derivation':'Python oracle, without invoking Rust; same author, not independent external acceptance',
 'header':{'file':'header.bin','challenge':H('challenge',hb).hex()},'transactions':[],'negative':[]}
for tag,s in COMMANDS.items():
    payload={}
    for i,f in enumerate(s['payload']):
        payload[f['name']]=bytes([i+1])*32 if f['type']=='hash32'else 7 if f['type']=='u64'else bytes([4])*64 if f['type']=='sig64'else [] if f['type']=='proof8'else [(bytes([7])*32,17)]
    b=sign(key(0),1,s['name'],payload,fee_limit=100000);name=f'tx-{tag:02d}.bin';(D/name).write_bytes(b)
    v['transactions'].append({'tag':tag,'file':name,'id':H('tx-id',b).hex(),'scope':'codec-valid; not necessarily application-valid'})
state={b'account:a':canonical({'balance':100,'nonce':1}),b'account:b':canonical({'balance':0,'nonce':0}),b'model:current':canonical('base')}
(D/'state.json').write_text(json.dumps([[k.hex(),val.hex()]for k,val in state.items()])+'\n');v['state']={'file':'state.json','root':state_root(state).hex()}
proof=prove(H('challenge',hb),A,B);(D/'work.bin').write_bytes(proof);(D/'matrices.bin').write_bytes(proof[4:4+32768])
v['work']={'file':'work.bin','inputs':'matrices.bin','task':task_id(A,B).hex(),'challenge':H('challenge',hb).hex(),'target':'ff'*32,'ticket':H('ticket',H('challenge',hb),proof[-32:]).hex()}
for name,kind,data in [('header-trailing','header',hb+b'\0'),('header-short','header',hb[:-1]),('header-version','header',hb[:4]+b'\x02\0'+hb[6:])]:
    (D/(name+'.bin')).write_bytes(data);v['negative'].append({'kind':kind,'file':name+'.bin'})
b=(D/'tx-01.bin').read_bytes()
for name,data in [('tx-trailing',b+b'\0'),('tx-short',b[:-1]),('tx-unknown',b[:92]+b'\xff'+b[93:]),('tx-zero-nonce',b[:68]+bytes(8)+b[76:]),('tx-bad-length',b[:93]+b'\xff\xff'+b[95:])]:
    (D/(name+'.bin')).write_bytes(data);v['negative'].append({'kind':'tx','file':name+'.bin'})
(D/'expected.json').write_text(json.dumps(v,indent=2)+'\n')
print('Wrote immutable cross-language vectors:',len(v['transactions']),'command tags, header, sparse root, real matrix work and rejection cases.')
