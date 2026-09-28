"""Three real subprocesses, framed localhost TCP, full Python work/state verification.
This is an executable-spec transport/benchmark, not native P2P, independent operators,
WAN throughput, Byzantine security qualification, or a production miner.
"""
from __future__ import annotations
import argparse,base64,json,os,selectors,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *
MAX_FRAME=PARAMS['max_p2p_frame_bytes']

def exact(sock,n):
    out=bytearray()
    while len(out)<n:
        b=sock.recv(n-len(out))
        if not b:raise ValueError('SHORT_FRAME')
        out.extend(b)
    return bytes(out)
def recv(sock):
    n=struct.unpack('>I',exact(sock,4))[0]
    if not 0<n<=MAX_FRAME:raise ValueError('FRAME_LIMIT')
    return json.loads(exact(sock,n),object_pairs_hook=unique)
def send(sock,obj):
    data=json.dumps(obj,separators=(',',':')).encode();require(len(data)<=MAX_FRAME,'FRAME_LIMIT');sock.sendall(struct.pack('>I',len(data))+data)
def request(port,obj):
    start=time.perf_counter()
    with socket.create_connection(('127.0.0.1',port),timeout=10)as sock:
        sock.settimeout(10);send(sock,obj);result=recv(sock)
    return result,time.perf_counter()-start

def serve(directory):
    ledger=Ledger(directory);ledger.recover()
    with socket.socket()as server:
        server.bind(('127.0.0.1',0));server.listen(16);server.settimeout(30)
        print(json.dumps({'port':server.getsockname()[1],'pid':os.getpid(),'genesis':GENESIS.hex()}),flush=True)
        running=True
        try:
            while running:
                conn,_=server.accept()
                with conn:
                    conn.settimeout(10)
                    try:
                        obj=recv(conn);op=obj.get('op')
                        if op=='submit':
                            require(set(obj)=={'op','header','transactions','proof'},'FIELDS')
                            hb=bytes.fromhex(obj['header']);txs=[bytes.fromhex(x)for x in obj['transactions']];proof=base64.b64decode(obj['proof'],validate=True)
                            start=time.perf_counter();bid=ledger.admit(hb,txs,proof,PARAMS['genesis_timestamp']+1000000);ledger.activate(bid);tip,g,state=ledger.read_active()
                            result={'ok':True,'block':bid.hex(),'tip':tip.hex(),'root':state_root(state).hex(),'generation':g,'validation_seconds':time.perf_counter()-start}
                        elif op=='head':
                            tip,g,s=ledger.read_active();result={'ok':True,'tip':tip.hex(),'root':state_root(s).hex(),'generation':g}
                        elif op=='stop':result={'ok':True};running=False
                        else:raise ValueError('OPERATION')
                    except (ValueError,KeyError,TypeError,OverflowError)as e:result={'ok':False,'error':str(e)}
                    send(conn,result)
        finally:ledger.close()

def percentiles(xs):
    ordered=sorted(xs)
    return {'count':len(xs),'p50':ordered[(len(xs)-1)//2],'p95':ordered[min(len(xs)-1,int(.95*len(xs)))],'max':max(xs)}

def run(out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True);children=[];ports=[];metrics=[]
    try:
        for i in range(3):
            child=subprocess.Popen([sys.executable,__file__,'--node','--out',str(out/f'peer-{i}')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(child)
            selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
            ready=selector.select(20);selector.close();require(bool(ready),'NODE_START_TIMEOUT')
            metadata=json.loads(child.stdout.readline());require(metadata['genesis']==GENESIS.hex(),'GENESIS');ports.append(metadata['port'])
        origin=Ledger(out/'origin');tip=GENESIS;nonce=0
        def propagate(h,txs,p,label):
            message={'op':'submit','header':h.hex(),'transactions':[x.hex()for x in txs],'proof':base64.b64encode(p).decode()}
            with ThreadPoolExecutor(max_workers=3)as pool:responses=list(pool.map(lambda port:request(port,message),ports))
            for reply,elapsed in responses:require(reply['ok'],'PEER_'+str(reply));metrics.append({'scenario':label,'roundtrip_seconds':elapsed,'validation_seconds':reply['validation_seconds'],'transactions':len(txs)})
            require(len({r[0]['root']for r in responses})==1,'PEER_ROOT_DISAGREEMENT')
        for scenario in ['disjoint-recipients','hot-recipient']:
            for batch in range(4):
                txs=[]
                for j in range(8):
                    nonce+=1;recipient=H('new-payee',u64(nonce))if scenario=='disjoint-recipients'else public(key(1))
                    txs.append(sign(key(0),nonce,'transfer',dict(recipient=recipient,amount=100)))
                start=time.perf_counter();h,t,p=origin.make(tip,txs);generation=time.perf_counter()-start
                tip=origin.admit(h,t,p,PARAMS['genesis_timestamp']+1000000);origin.activate(tip);propagate(h,t,p,scenario)
                metrics.append({'scenario':scenario,'generation_seconds':generation,'transactions':len(txs)})
        # Backfill confirmations with real work; no fabricated chain weight.
        for _ in range(PARAMS['confirmation_depth']):
            h,t,p=origin.make(tip,[]);tip=origin.admit(h,t,p,PARAMS['genesis_timestamp']+1000000);origin.activate(tip);propagate(h,t,p,'confirmation-fill')
        heads=[request(port,{'op':'head'})[0]for port in ports];require(all(x['tip']==tip.hex()for x in heads),'TIP')
        # Invalid proof with a cheap forged trace chosen to pass the threshold.
        h,t,p=origin.make(tip,[]);challenge=H('challenge',h);target=header_decode(h)['target']
        k=0
        while True:
            fake=H('forged-transcript',u64(k));k+=1
            if H('ticket',challenge,fake)<=target:break
        bad=p[:-32]+fake;message={'op':'submit','header':h.hex(),'transactions':[],'proof':base64.b64encode(bad).decode()}
        attacks=[]
        for port in ports:
            result,elapsed=request(port,message);require(not result['ok']and result['error']=='TRANSCRIPT','INVALID_ACCEPTED');attacks.append(elapsed)
        # Oversized frame is rejected without allocating the claimed payload.
        frame_rejections=0
        for port in ports:
            with socket.create_connection(('127.0.0.1',port),timeout=10)as sock:
                sock.settimeout(10);sock.sendall(struct.pack('>I',MAX_FRAME+1));answer=recv(sock);require(answer=={'ok':False,'error':'FRAME_LIMIT'},'FRAME_ADMISSION');frame_rejections+=1
        # Actual minority branch becomes heavier; every node executes detach/attach.
        fork=origin.block(origin.block(tip)[0])[0];count=0
        while count<3:
            h,t,p=origin.make(fork,[],public(key(1)),timestamp=origin.ancestor_headers(fork)[0]['timestamp']+11)
            fork=origin.admit(h,t,p,PARAMS['genesis_timestamp']+1000000);propagate(h,t,p,'fork-reorg');count+=1
        origin.activate(fork);require(all(request(port,{'op':'head'})[0]['tip']==fork.hex()for port in ports),'REORG_DISAGREEMENT')
        origin.close()
        report={'schema':'pon-loopback-executable-contract-cost-v1','transport':'framed TCP on 127.0.0.1 only','peer_processes':3,'independent_operators':False,'native_node':False,'network_security_accepted':False,'temporary_storage':'normal output directory; SQLite WAL FULL, no power-loss test','actual_work_verification':True,'actual_signed_transactions':64,'miner_target_initial':PARAMS['initial_target_hex'],'statistics_include_python_scalar_work_and_full_state_roots':True,'configured_block_spacing_seconds':10,'chain_clock':'fixed logical timestamps for reproducibility, not live UTC consensus-time acceptance','no_sleep_to_enforce_spacing':True,'samples':metrics,'invalid_transcript_roundtrip_seconds':attacks,'oversized_frame_rejections':frame_rejections,'final_tip':fork.hex(),'production_activation':False}
        report['roundtrip_by_scenario']={s:percentiles([r['roundtrip_seconds']for r in metrics if r['scenario']==s and 'roundtrip_seconds'in r])for s in {r['scenario']for r in metrics}}
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='samples'}),flush=True)
    finally:
        for port in ports:
            try:request(port,{'op':'stop'})
            except (OSError,ValueError):pass
        for child in children:
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
            if child.stdout:child.stdout.close()
            if child.stderr:child.stderr.close()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--node',action='store_true');p.add_argument('--out',required=True);a=p.parse_args();serve(a.out)if a.node else run(a.out)
