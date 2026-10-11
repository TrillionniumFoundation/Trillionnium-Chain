#!/usr/bin/env python3
"""Replay retained signed packets, compare actual serial and batch native CLI results; no public TPS."""
import hashlib,json,platform,subprocess,sys,time,tempfile
from pathlib import Path
R=Path(sys.argv[1]).resolve();B=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
def require(ok,message):
    if not ok:raise ValueError(message)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=R,text=True).strip()
def H(tag,raw):
    label=tag.encode();return hashlib.sha256(b'TRNM-PON1\0'+len(label).to_bytes(2,'little')+label+len(raw).to_bytes(4,'little')+raw).hexdigest()
require(not git('status','--porcelain'),'dirty source')
OUT.mkdir(parents=True,exist_ok=False);(OUT/'driver.py').write_bytes(Path(__file__).read_bytes())
head=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}');binary=sha(B)
original=R/'evidence/pon-native-session-v1/pipeline';reference=json.loads((original/'report.json').read_text())
inputs={str((original/name).relative_to(R)):sha(original/name)for name in ['report.json','independent-packets.json','hot-sender-packets.json']}
rows=[];scenarios=[];error=None;comparisons=[]
report={'schema':'pon-native-cli-retained-packet-replay-v1','source_commit':head,'source_tree':tree,'source_clean':True,'binary_sha256':binary,'driver_sha256':sha(OUT/'driver.py'),'inputs_sha256':inputs,'platform':platform.platform(),'results':rows,'scenarios':scenarios,'confirmation_comparisons':comparisons,'all_passed':False,'clock_scope':'explicit-logical-test-clock','public_confirmed_tps':None,'production_activation':False,'independent_operators':False,'physical_power_loss':False,'new_model_experiments':False}
def invoke(store,command,*args):
    argv=[str(B),command,'--development','--store',str(store),'--logical-now','1800010000',*map(str,args)]
    start=time.monotonic_ns();p=subprocess.run(argv,cwd=R,capture_output=True,timeout=30)
    row={'command':argv,'returncode':p.returncode,'elapsed_ns':time.monotonic_ns()-start,'stdout':p.stdout.decode(),'stderr':p.stderr.decode()};row['input_packet_sha256']=sha(Path(args[args.index('--packet')+1])) if '--packet' in args else None;rows.append(row)
    require(p.returncode==0,'native CLI failure '+p.stderr.decode())
    value=json.loads(p.stdout);require(value['production_activation']is False and value['clock_scope']=='logical-test','scope');return value['result']
try:
    with tempfile.TemporaryDirectory(prefix='trnm-native-replay-') as temporary:
        for scenario in ['independent','hot-sender']:
            root=Path(temporary)/scenario;root.mkdir();source=root/'source';receiver=root/'receiver'
            packets=json.loads((original/(scenario+'-packets.json')).read_text());confirmed=[]
            for index,packet in enumerate(packets):
                header=bytes.fromhex(packet['header']);txs=[bytes.fromhex(v)for v in packet['transactions']];proof=bytes.fromhex(packet['proof'])
                raw=header+len(txs).to_bytes(2,'little')+b''.join(len(v).to_bytes(2,'little')+v for v in txs)+proof
                input_path=root/(str(index)+'.packet');input_path.write_bytes(raw)
                for store in [source,receiver]:
                    result=invoke(store,'submit','--packet',input_path);require(result['block']==packet['block'],'block identity')
            expected=next(branch for branch in reference['branches']if branch['scenario']==scenario)
            for store in [source,receiver]:
                value=invoke(store,'status');require(value['tip']==expected['tip']and value['state_root']==expected['state_root'],'full final root')
            queries=[]
            for packet in packets:
                if packet['phase']!='application':continue
                for raw in packet['transactions']:
                    queries.append({'transaction':H('tx-id',bytes.fromhex(raw)),'block':packet['block']})
            query_path=OUT/(scenario+'-queries.json')
            query_path.write_text(json.dumps(queries,sort_keys=True)+'\n')
            for sample in range(3):
                observed={};elapsed={};commands={}
                for variant in (['serial','batch'] if sample%2==0 else ['batch','serial']):
                    first=len(rows);start=time.monotonic_ns()
                    if variant=='serial':
                        values=[invoke(receiver,'confirm','--transaction',query['transaction'],'--block',query['block']) for query in queries]
                    else:
                        batch=invoke(receiver,'confirm-batch','--queries',query_path)
                        require(batch['ancestry_checked']==len(packets),'one full actual ancestry pass')
                        require(batch['distinct_bodies_checked']==len({query['block']for query in queries}),'body count')
                        values=batch['observations']
                    elapsed[variant]=time.monotonic_ns()-start;commands[variant]=len(rows)-first
                    require(len(values)==len(queries),'complete observations')
                    for value,query in zip(values,queries):
                        require(value['transaction']==query['transaction'] and value['confirmed'] is True and value['reorged'] is False,'confirmation')
                        require(value['finalized']is False and value['execution_authority']is False,'no authority')
                        require(value['observed_tip']==expected['tip'],'observed tip')
                    observed[variant]=values
                require(observed['serial']==observed['batch'],'serial/batch exact result parity')
                comparisons.append({'scenario':scenario,'sample':sample,'queries':len(queries),'commands':commands,
                    'elapsed_ns':elapsed,'batch_ancestry_checks':len(packets),
                    'scope':'process-inclusive read observation amortization; not new transactions or public throughput'})
            confirmed=[query['transaction']for query in queries]
            scenarios.append({'scenario':scenario,'input_blocks':len(packets),'native_block_admission_executions':2*len(packets),'source_transactions':sum(len(p['transactions'])for p in packets),'receiver_transactions':sum(len(p['transactions'])for p in packets),'application_confirmations':len(confirmed),'confirmed_transaction_ids':confirmed,'final_tip':expected['tip'],'final_state_root':expected['state_root']})
    require(not git('status','--porcelain')and git('rev-parse','HEAD')==head,'source changed')
    require(sha(B)==binary,'binary changed');report['all_passed']=True
except Exception as exc:
    error=exc;report['error']=repr(exc)
finally:
    (OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'source_commit':head,'all_passed':report['all_passed'],'scenarios':scenarios},indent=2))
if error:raise error
