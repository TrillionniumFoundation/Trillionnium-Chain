"""Independent local W1 mathematics / four forged-ticket rejection reproduction.
NOT the original Chain repository test suite or native Node verification.
"""
import hashlib, json, struct, time
from pathlib import Path
N, R, Q=64,8,4294967291
CELL=N*N

def H(tag,*parts):
    if isinstance(tag,str):tag=tag.encode()
    h=hashlib.sha256(b'TRNM-PON1\0'+struct.pack('<H',len(tag))+tag)
    for p in parts:
        h.update(struct.pack('<I',len(p)))
        h.update(p)
    return h.digest()

def fields(words):
    return struct.pack('<'+'I'*len(words),*words)

def expand(challenge,label,number):
    result=[]
    for counter in range(128):
        block=H('noise',challenge,bytes([label]),struct.pack('<I',counter))
        result.extend(v[0] for v in struct.iter_unpack('<I',block) if v[0] < Q)
        if len(result)>=number:
            return result[:number]
    raise ValueError('NOISE_BUDGET')

def matmul(a,b,rows,inner,cols):
    return [sum(a[i*inner+k]*b[k*cols+j] for k in range(inner))%Q for i in range(rows) for j in range(cols)]

def actual_transcript(challenge,a,b):
    el,er,fl,fr=[expand(challenge,j,N*R) for j in range(4)]
    ee=matmul(el,er,N,R,N)
    ff=matmul(fl,fr,N,R,N)
    aa=[(x+y)%Q for x,y in zip(a,ee)]
    bb=[(x+y)%Q for x,y in zip(b,ff)]
    cp=[0]*CELL
    transcript=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge)
    tiles=0
    for bi in range(0,N,R):
        for bj in range(0,N,R):
            for bk in range(0,N,R):
                tile=[]
                for i in range(bi,bi+R):
                    for j in range(bj,bj+R):
                        idx=i*N+j
                        cp[idx]=(cp[idx]+sum(aa[i*N+k]*bb[k*N+j] for k in range(bk,bk+R)))%Q
                        tile.append(cp[idx])
                transcript.update(fields(tile))
                tiles+=1
    assert tiles==512
    return transcript.digest(),tiles

def run():
    zeros=[0]*CELL
    raw=fields(zeros)
    challenge=bytes(range(32))
    target=bytes.fromhex('7f'+'ff'*31)
    task=H('task',raw,raw)
    assert task.hex()=='6618f8a794517852f621993ccb6ac311c684e1db2b9d1d47166fa00a744c4c29'
    fake=[]
    start=time.process_time_ns()
    for nonce in range(128):
        claim=H('public-v3-from-zero-v1',challenge,struct.pack('<Q',nonce))
        ticket=H('ticket',challenge,claim)
        if ticket<=target:
            proof=b'PNW1'+raw*3+claim
            fake.append((nonce,claim,ticket,proof))
            if len(fake)==4:break
    build_cpu_ns=time.process_time_ns()-start
    assert [r[0] for r in fake]==[0,1,2,3]
    rows=[]
    for nonce,claim,ticket,proof in fake:
        assert len(proof)==49188
        start=time.process_time_ns()
        true_trace,tiles=actual_transcript(challenge,zeros,zeros)
        cpu=time.process_time_ns()-start
        assert true_trace!=claim and ticket<=target
        rows.append({'nonce':nonce,'trace_claim':claim.hex(), 'ticket':ticket.hex(),
                     'proof_sha256':hashlib.sha256(proof).hexdigest(),
                     'full_transcript_tiles':tiles,'full_replay_cpu_ns':cpu,
                     'error':'TRANSCRIPT','verified_work':False})
    return {'schema':'independent-w1-four-false-replay-local-20261027',
            'scope':'Python independent arithmetic using frozen W1 rules; no Node/WAN/native verification',
            'challenge':challenge.hex(),'target':target.hex(),'task':task.hex(),
            'from_zero_construction_cpu_ns':build_cpu_ns,
            'full_replay_four_distinct_claims':True,
            'node_state_not_tested':True,'production_activation':False,'cases':rows}

if __name__=='__main__':
    result=run()
    path=Path('/mnt/data/w1_four_replay_measurement_20261027.json')
    with path.open('x') as out:
        json.dump(result,out,indent=2,sort_keys=True)
    print(json.dumps({'task':result['task'], 'nonces':[v['nonce'] for v in result['cases']], 'replay_ms':[round(v['full_replay_cpu_ns']/1e6,3) for v in result['cases']], 'report':str(path)}))
