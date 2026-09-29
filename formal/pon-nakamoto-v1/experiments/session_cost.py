"""Paired single-shot/full-state versus persistent/delta compute on the SAME source.

Inputs are actual signed native commands and Python-verified transitions. Bootstrap is
measured separately, every block advances nonce/root, no cached repeated request earns a
sample. This is application execution, not work validation/inclusion/confirmation TPS.
"""
from __future__ import annotations
import argparse,copy,hashlib,json,os,random,resource,statistics,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *
from native_session import NativeExecutionSession
from bounded_process import run_bounded

def cases(samples):
    initial=genesis_state();height=0;nonce=0
    for batch in range(4):
        txs=[]
        for i in range(4+batch*64,4+(batch+1)*64):
            nonce+=1;amount=125000 if i<68 else 1000
            txs.append(sign(key(0),nonce,'transfer',dict(recipient=public(key(i)),amount=amount),expiry=100000))
        height+=1;initial,_=execute_reference(initial,txs,height,public(key(0)),H('session-funding',u64(height)))
    output=[]
    for name in ['independent','hot-recipient','hot-sender']:
        state=copy.deepcopy(initial);blocks=[]
        for index in range(samples+1):
            txs=[]
            for j in range(64):
                who=4 if name=='hot-sender'else j+4
                tx_nonce=(index*64+j+1)if name=='hot-sender'else(index+1)
                recipient=H('session-recipient',u64(j))if name=='independent'else public(key(1))
                txs.append(sign(key(who),tx_nonce,'transfer',dict(recipient=recipient,amount=1),expiry=100000))
            h=height+index+1;parent=H('session-case-parent',name.encode(),u64(index))
            next_state,receipts=execute_reference(state,txs,h,public(key(0)),parent)
            blocks.append({'sample':index,'warmup':index==0,'height':h,'parent':parent.hex(),'miner':public(key(0)).hex(),
                'transactions':[t.hex()for t in txs],'predecessor':state_root(state).hex(),'root':state_root(next_state).hex(),
                'expected':next_state,'receipts':[r.hex()for r in receipts]})
            state=next_state
        output.append({'scenario':name,'initial':initial,'initial_root':state_root(initial).hex(),'blocks':blocks})
    return output

def peak(pid):
    try:
        for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines():
            if line.startswith('VmHWM:'):return int(line.split()[1])
    except (OSError,ValueError):pass
    return None

def run(out,single,session,samples=5):
    if type(samples)is not int or not 3<=samples<=20:raise ValueError('SAMPLE_BUDGET')
    out=Path(out);out.mkdir(parents=True,exist_ok=False);inputs=cases(samples)
    (out/'requests.json').write_bytes(canonical(inputs));rows=[];boot=[];randomizer=random.Random(20260929)
    for case in inputs:
        for workers in [1,2,4,8]:
            cache=NativeExecutionSession(session);state=copy.deepcopy(case['initial'])
            try:
                start=time.perf_counter_ns();cache._open(state)
                boot.append({'scenario':case['scenario'],'workers':workers,'elapsed_ns':time.perf_counter_ns()-start,
                    'request_bytes':cache.process.bytes_sent,'response_bytes':cache.process.bytes_received,'state_keys':len(state),
                    'state_bytes':len(canonical(state)),'peak_rss_kib_native':peak(cache.process.child.pid)})
                for block in case['blocks']:
                    variants=['full-state','delta-session'];randomizer.shuffle(variants)
                    request=dict(network=NETWORK.hex(),parameters=PARAMETER_HASH.hex(),state=state,transactions=block['transactions'],height=block['height'],miner=block['miner'],parent=block['parent'],workers=workers)
                    raw=canonical(request);outputs={}
                    for variant in variants:
                        start=time.perf_counter_ns()
                        if variant=='full-state':
                            result=run_bounded([str(single)],raw)
                            if result.returncode:raise ValueError('SINGLE_NATIVE_'+result.stderr.decode(errors='replace'))
                            answer=json.loads(result.stdout,object_pairs_hook=unique)
                            if set(answer)!={'network','parameters','state','receipts','root','metrics','scope'}:raise ValueError('FIELDS')
                            if answer['network']!=NETWORK.hex()or answer['parameters']!=PARAMETER_HASH.hex():raise ValueError('CONTEXT')
                            # Independent verifier work is included in both wall-time cases.
                            if state_root(answer['state']).hex()!=answer['root']:raise ValueError('ROOT')
                            observed=answer['state'];receipts=answer['receipts'];metrics=answer['metrics']
                            sent=len(raw);received=len(result.stdout);hwm=None
                        else:
                            observed,r,metrics=cache.execute(state,[bytes.fromhex(x)for x in block['transactions']],block['height'],bytes.fromhex(block['miner']),bytes.fromhex(block['parent']),workers)
                            if metrics['request_cache_hit']:raise ValueError('CACHED_REQUEST_NOT_A_SAMPLE')
                            receipts=[x.hex()for x in r];sent=metrics['bridge_request_bytes'];received=metrics['bridge_response_bytes'];hwm=peak(cache.process.child.pid)
                        elapsed=time.perf_counter_ns()-start
                        if observed!=block['expected']or receipts!=block['receipts']:raise ValueError('TRANSITION_PARITY')
                        if state_root(observed).hex()!=block['root']:raise ValueError('EXPECTED_ROOT')
                        outputs[variant]=observed
                        rows.append({'scenario':case['scenario'],'workers':workers,'sample':block['sample'],'warmup':block['warmup'],
                            'variant':variant,'wall_ns':elapsed,'state_root_ns':int(metrics['state_root_ns']),'state_transition_ns':int(metrics['state_transition_ns']),
                            'root':block['root'],'predecessor':block['predecessor'],'receipt_digest':H('receipt-observation',canonical(receipts)).hex(),
                            'input_sha256':hashlib.sha256(raw).hexdigest(),'request_bytes':sent,'response_bytes':received,
                            'transactions':len(block['transactions']),'transaction_bytes':sum(len(x)//2 for x in block['transactions']),
                            'application_executed':len(block['transactions']),'admitted_to_mempool':None,'included':None,'confirmed':None,
                            'proof_verification_ns':None,'vram_bytes':None,'gpu_used':False,'peak_rss_kib_native_cumulative':hwm,
                            'state_keys':len(observed),'state_bytes':len(canonical(observed)),'metrics':metrics})
                    if outputs['full-state']!=outputs['delta-session']:raise ValueError('PAIRED_STATE')
                    state=copy.deepcopy(block['expected'])
                if cache.reset_count!=1:raise ValueError('UNEXPECTED_CACHE_RESET')
            finally:cache.close()
    summary=[]
    for case in inputs:
        for workers in [1,2,4,8]:
            selected=[r for r in rows if r['scenario']==case['scenario']and r['workers']==workers and not r['warmup']]
            record={'scenario':case['scenario'],'workers':workers}
            for variant in ['full-state','delta-session']:
                matching=[r for r in selected if r['variant']==variant]
                record[variant]={k:statistics.median(r[k]for r in matching)for k in ['wall_ns','state_root_ns','request_bytes','response_bytes']}
            record['wall_regression']=record['delta-session']['wall_ns']>record['full-state']['wall_ns'];summary.append(record)
    report={'schema':'pon-paired-native-session-cost-v5','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'context':{'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex()},
        'source_clean':not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip(),'samples_per_case':samples,
        'binary_sha256':{'full-state':hashlib.sha256(Path(single).read_bytes()).hexdigest(),'delta-session':hashlib.sha256(Path(session).read_bytes()).hexdigest()},
        'request_sha256':hashlib.sha256((out/'requests.json').read_bytes()).hexdigest(),'scope':'same-source native application; independent Python root verification included',
        'bootstrap_excluded_from_steady_state':True,'bootstrap':boot,'samples':rows,'summary':summary,
        'full_node':False,'chain_tps_claimed':False,'ordinary_hepta_entry':False,'independent_operators':False,'production_activation':False,
        'runner_peak_rss_kib_cumulative':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'samples':len(rows),'all_parity_passed':True,'summary':summary}),flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--single',required=True);p.add_argument('--session',required=True);p.add_argument('--samples',type=int,default=5)
    a=p.parse_args();run(a.out,a.single,a.session,a.samples)
