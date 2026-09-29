"""Application-only native measurements, not public chain TPS or WAN acceptance."""
from pathlib import Path
import argparse,json,os,subprocess,sys,tempfile,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *
from native_execution import execute_native

def run(out,binary):
    out=Path(out);out.mkdir(parents=True,exist_ok=False);state=genesis_state()
    funding=[sign(key(0),i+1,'transfer',dict(recipient=public(key(i+4)),amount=100000))for i in range(64)]
    state,_=execute_reference(state,funding,1,public(key(0)),GENESIS)
    cases={
      'independent-senders-and-recipients':[sign(key(i+4),1,'transfer',dict(recipient=H('independent-recipient',u64(i)),amount=1))for i in range(64)],
      'independent-senders-hot-recipient':[sign(key(i+4),1,'transfer',dict(recipient=public(key(1)),amount=1))for i in range(64)],
      'single-hot-sender-recipient':[sign(key(4),i+1,'transfer',dict(recipient=public(key(1)),amount=1))for i in range(64)]}
    samples=[]
    for name,txs in cases.items():
        expected,receipts=execute_reference(state,txs,2,public(key(0)),H('benchmark-parent'))
        request={'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex(),'state':state,'transactions':[t.hex()for t in txs],'height':2,'miner':public(key(0)).hex(),'parent':H('benchmark-parent').hex()}
        for workers in [1,2,4,8]:
            for sample in range(3):
                request['workers']=workers;usage=out/f'usage-{name}-{workers}-{sample}.txt'
                command=[str(binary)]
                measured=Path('/usr/bin/time').is_file()
                if measured:command=['/usr/bin/time','-f','%M %U %S','-o',str(usage)]+command
                start=time.perf_counter();p=subprocess.run(command,input=canonical(request),capture_output=True,timeout=30);elapsed=time.perf_counter()-start
                require(p.returncode==0,'NATIVE_BENCH_EXECUTION');actual=json.loads(p.stdout,object_pairs_hook=unique)
                require(actual['state']==expected and [bytes.fromhex(x)for x in actual['receipts']]==receipts,'PARALLEL_PARITY')
                memory=int(usage.read_text().split()[0])if measured else None
                samples.append({'scenario':name,'workers':workers,'sample':sample,'transactions':64,'transaction_bytes':sum(map(len,txs)),'request_bytes':len(canonical(request)),'wall_seconds_including_process_start':elapsed,'native_execution_ns':int(actual['metrics']['elapsed_ns']),'peak_rss_kib':memory,'vram_bytes':None,'gpu_used_by_this_executor':False,'speculative_reexec':actual['metrics']['reexecuted'],'peak_inflight':actual['metrics']['peak_inflight'],'serial_conflict_batches':actual['metrics']['serial_conflict_batches'],'prepared':64,'application_executed':64,'block_included':None,'client_confirmed':None,'proof_verification_ns':None,'state_keys':len(expected),'state_bytes':len(canonical(expected)),'root':actual['root']})
    report={'schema':'pon-native-application-cost-v2','samples':samples,'normal_native_application':True,'complete_native_node':False,'wan':False,'independent_operators':False,'includes_work_verification':False,'confirmation_policy':'not exercised by application benchmark','production_activation':False}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'samples':len(samples),'all_roots_match':True,'scope':report['schema']}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--native',required=True);a=p.parse_args();run(a.out,Path(a.native))
