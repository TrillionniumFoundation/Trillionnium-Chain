"""Physical-host conformance over owned SSH streams, with explicit evidence limits.

Run only in a source copy with an explicitly recorded live-clock test configuration.
Never installs a service, changes routing/firewalls, opens a listener or touches user keys.
"""
from __future__ import annotations
import argparse,base64,concurrent.futures,hashlib,io,json,os,select,shlex,signal,struct,subprocess,sys,tarfile,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *
from model_contract import load_model,infer

SSH=['ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2']
MAX_FRAME=2*1024*1024

class Peer:
    def __init__(self,host,root,out):
        self.host=host;self.root=root;self.out=out;self.p=None;self.errors=None;self.starts=0;self.start()
    def start(self):
        self.starts+=1
        self.errors=open(self.out/(self.host+'-stderr-'+str(self.starts)+'.log'),'wb')
        script=self.root+'/source/formal/pon-nakamoto-v1/experiments/remote_peer.py'
        command='python3 -u '+shlex.quote(script)+' --state-dir '+shlex.quote(self.root+'/state')+' --source-manifest '+shlex.quote(self.root+'/source-manifest.json')
        self.p=subprocess.Popen(SSH+[self.host,command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.errors,start_new_session=True)
        os.set_blocking(self.p.stdin.fileno(),False);os.set_blocking(self.p.stdout.fileno(),False)
        try:self.hello=self.read(time.monotonic()+40)
        except BaseException:
            self.stop(attempt_shutdown=False)
            raise
    def exact(self,count,deadline):
        data=bytearray()
        while len(data)<count:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('REMOTE_DEADLINE')
            if not select.select([self.p.stdout],[],[],remaining)[0]:raise TimeoutError('REMOTE_DEADLINE')
            chunk=os.read(self.p.stdout.fileno(),count-len(data))
            if not chunk:raise EOFError('REMOTE_EXIT')
            data.extend(chunk)
        return bytes(data)
    def read(self,deadline):
        size=struct.unpack('>I',self.exact(4,deadline))[0]
        require(0<size<=MAX_FRAME,'REMOTE_FRAME_LIMIT')
        return json.loads(self.exact(size,deadline),object_pairs_hook=unique)
    def call(self,obj):
        deadline=time.monotonic()+40;body=canonical(obj)
        require(len(body)<=MAX_FRAME,'LOCAL_FRAME_LIMIT');data=struct.pack('>I',len(body))+body;pos=0
        while pos<len(data):
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([],[self.p.stdin],[],remaining)[1]:raise TimeoutError('REMOTE_DEADLINE')
            pos+=os.write(self.p.stdin.fileno(),memoryview(data)[pos:pos+65536])
        return self.read(deadline)
    def stop(self,attempt_shutdown=True):
        if self.p is None:return
        if attempt_shutdown and self.p.poll()is None:
            try:self.call({'op':'shutdown'})
            except (OSError,ValueError,EOFError,TimeoutError):pass
        try:self.p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:os.killpg(self.p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            self.p.wait(timeout=5)
        for stream in [self.p.stdin,self.p.stdout]:stream.close()
        self.errors.close();self.p=None
    def restart(self):self.stop();self.start()


def archive_source(manifest):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz')as archive:
        for relative in manifest['files']:
            archive.add(ROOT/relative,arcname='source/'+relative,recursive=False)
        data=canonical(manifest);entry=tarfile.TarInfo('source-manifest.json');entry.size=len(data);entry.mode=0o600;archive.addfile(entry,io.BytesIO(data))
    return output.getvalue()


def prepare(host,archive):
    create="import tempfile;print(tempfile.mkdtemp(prefix='trnm-pon-host-qualification-'))"
    root=subprocess.check_output(SSH+[host,'python3 -c '+shlex.quote(create)],timeout=20,text=True).strip()
    require(root.startswith('/tmp/trnm-pon-host-qualification-'),'REMOTE_TEMP_PATH')
    # The archive is produced from our exact closed manifest, not received from a peer.
    command='tar -xzf - -C '+shlex.quote(root)
    subprocess.run(SSH+[host,command],input=archive,timeout=40,check=True,stdout=subprocess.DEVNULL)
    return root


def run(args):
    out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    manifest=json.loads(Path(args.source_manifest).read_text(),object_pairs_hook=unique)
    bundle=archive_source(manifest);peers=[];reports=[];origin=None;author_hidden=None
    begin=time.time_ns();identities=[]
    def observe(peer,op,expected=True):
        start=time.perf_counter_ns();result=peer.call(op)
        reports.append({'host':peer.host,'operation':op['op'],'roundtrip_ns':time.perf_counter_ns()-start,'request_bytes':len(canonical(op)),'response':result})
        require(result['ok'] is expected,'UNEXPECTED_REMOTE_'+str(result));return result
    try:
        for host in args.hosts:
            path=prepare(host,bundle);peer=Peer(host,path,out);peers.append(peer);identities.append({'host':host,'temporary_root':path,'hello':peer.hello})
            require(peer.hello['genesis']==GENESIS.hex()and peer.hello['parameters']==PARAMETER_HASH.hex(),'REMOTE_CONTEXT')
            require(peer.hello['source_manifest']==hashlib.sha256(canonical(manifest)).hexdigest(),'REMOTE_SOURCE')
            require(abs(peer.hello['utc_seconds']-int(time.time()))<=5,'HOST_CLOCK_SKEW')
        origin=Ledger(out/'origin');tip=GENESIS;made=[];nonce=0
        def block(parent,txs,miner=None):
            times=[h['timestamp']for h in origin.ancestor_headers(parent)[:11]]
            timestamp=max(int(time.time()),sorted(times)[len(times)//2]+1)
            header,transactions,proof=origin.make(parent,txs,miner=miner,timestamp=timestamp)
            bid=origin.admit(header,transactions,proof,int(time.time()));origin.activate(bid)
            return bid,{'op':'submit','header':header.hex(),'transactions':[x.hex()for x in transactions],'proof':base64.b64encode(proof).decode()}
        def deliver(message,selected):
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected))as pool:
                list(pool.map(lambda peer:observe(peer,message),selected))
        # Independent funded senders, not merely changing recipients of one nonce chain.
        funding=[sign(key(0),i-3,'transfer',dict(recipient=public(key(i)),amount=50000),expiry=10000)for i in range(4,12)]
        nonce=len(funding);tip,message=block(tip,funding);deliver(message,peers);made.append(message)
        transfers=[sign(key(i),1,'transfer',dict(recipient=H('remote-payee',u64(i)),amount=10),expiry=10000)for i in range(4,12)]
        tip,message=block(tip,transfers);deliver(message,peers);made.append(message)
        operation=H('cross-host-effect');payload=H('not-a-real-external-side-effect')
        for peer in peers:observe(peer,{'op':'effect','identity':operation.hex(),'payload':payload.hex(),'generation':2})
        fork_parent=tip
        # An intentional controller delivery partition: no firewall/OS network changes.
        lagging=peers[-1];withheld=[]
        for _ in range(3):
            tip,message=block(tip,[]);deliver(message,peers[:-1]);withheld.append(message);made.append(message)
        lag_head=observe(lagging,{'op':'head'})['result'];require(lag_head['tip']==fork_parent.hex(),'PARTITION_NOT_OBSERVED')
        for message in withheld:observe(lagging,message)
        # Actual process exit after accepted-block commit and before activation.
        tip,message=block(tip,[]);deliver(message,peers[1:]);victim=peers[0]
        try:victim.call(dict(message,op='admit_and_crash'));raise ValueError('CRASH_NOT_TAKEN')
        except EOFError:pass
        victim.restart();require(victim.hello['genesis']==GENESIS.hex(),'RESTART_CONTEXT')
        recovered=observe(victim,{'op':'head'})['result'];require(recovered['tip']==tip.hex(),'ADMITTED_BLOCK_NOT_RECOVERED')
        # Higher-work fork causes real detach/attach on each host; all effects remain.
        fork=fork_parent
        for _ in range(5):
            fork,message=block(fork,[],miner=public(key(1)));deliver(message,peers)
        tip=fork;origin.activate(tip)
        for peer in peers:
            result=observe(peer,{'op':'head'})['result'];require(result['tip']==tip.hex()and result['effect_count']==1,'REORG_EFFECT_BOUNDARY')
            observe(peer,{'op':'effect','identity':operation.hex(),'payload':payload.hex(),'generation':result['generation']},False)
        # Full bad-proof verification at the installed target, never fake an accepted certificate.
        candidate,message=block(tip,[]);header=bytes.fromhex(message['header']);proof=base64.b64decode(message['proof']);challenge=H('challenge',header);target=header_decode(header)['target']
        index=0
        while True:
            bad_trace=H('invalid-transcript',u64(index));index+=1
            if H('ticket',challenge,bad_trace)<=target:break
        bad=dict(message,proof=base64.b64encode(proof[:-32]+bad_trace).decode())
        for _ in range(3):
            for peer in peers:observe(peer,bad,False)
        deliver(message,peers);tip=candidate
        # Sponsor prepays exactly one service unit. No user balance debit is permitted.
        consumer=key(44);provider=public(key(2));nonce+=1
        quota=quota_identity(public(key(0)),nonce,public(consumer),provider,1,origin.block(tip)[1]+100)
        reservation=sign(key(0),nonce,'reserve_quota',dict(quota=quota,consumer=public(consumer),provider=provider,units=1,deadline=origin.block(tip)[1]+100),expiry=10000)
        tip,message=block(tip,[reservation]);deliver(message,peers)
        model_bytes=Path(args.model).read_bytes();model_id=H('artifact',model_bytes)
        tasks=json.loads(Path(args.tasks).read_text());inputs=[row['x']for row in tasks[:8]]
        expected=infer(load_model(args.model,model_id),inputs)
        for peer in peers:observe(peer,{'op':'put_artifact','artifact':model_id.hex(),'data':base64.b64encode(model_bytes).decode()})
        # Remove only an owned campaign copy of the author artifact, not the source corpus.
        author=out/'author-model.json';author.write_bytes(model_bytes);author_hidden=out/'author-model.hidden';author.rename(author_hidden)
        inferred=[]
        for peer in peers:
            value=observe(peer,{'op':'infer','artifact':model_id.hex(),'inputs':inputs})['result'];require(value['predictions']==expected,'INFERENCE_PARITY');inferred.append(value)
        from inference_receipt import receipt,verify
        fields={'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex(),'model':model_id.hex(),'request':H('request',quota).hex(),'input':inferred[0]['input'],'output':inferred[0]['output'],'provider':provider.hex(),'quota':quota.hex(),'units':1,'provider_nonce':1}
        raw=receipt(fields);result=verify(raw,{k:fields[k]for k in ['network','parameters','model','request','input','provider','quota']})
        signature=consumer.sign(H('use',NETWORK,PARAMETER_HASH,quota,provider,u64(1),u64(1),result))
        usage=sign(key(2),1,'consume_quota',dict(quota=quota,units=1,result=result,consumer_signature=signature),expiry=10000)
        tip,message=block(tip,[usage]);deliver(message,peers)
        state=origin.read_active()[2]
        require(state['quota:'+quota.hex()]['units']==0 and 'account:'+public(consumer).hex()not in state,'FREE_USE_ACCOUNTING')
        repeated=sign(key(2),2,'consume_quota',dict(quota=quota,units=1,result=result,consumer_signature=signature),expiry=10000)
        try:execute_reference(state,[repeated],origin.block(tip)[1]+1,public(key(0)),tip);raise AssertionError('depleted quota accepted')
        except ValueError:quota_replay_rejected=True
        included=tip;included_work=int.from_bytes(origin.block(tip)[2],'big');included_height=origin.block(tip)[1]
        for _ in range(PARAMS['confirmation_depth']):
            tip,message=block(tip,[]);deliver(message,peers)
        final=origin.block(tip);work_delta=int.from_bytes(final[2],'big')-included_work
        required_work=int.from_bytes(origin.block(included)[2],'big')-int.from_bytes(origin.block(origin.block(included)[0])[2],'big')
        require(final[1]-included_height>=PARAMS['confirmation_depth']and work_delta>=required_work*PARAMS['confirmation_work_multiplier'],'CONFIRMATION_POLICY')
        expected_root=origin.read_active()[2]
        for peer in peers:require(observe(peer,{'op':'head'})['result']['root']==state_root(expected_root).hex(),'FINAL_ROOT')
        report={'schema':'pon-owned-physical-host-conformance-v3','source_manifest':manifest,'hosts':identities,'started_utc_ns':begin,'finished_utc_ns':time.time_ns(),
                'same_operator':True,'independent_operators':False,'native_full_node':False,'ordinary_hepta_entry':False,'physical_power_loss':False,'public_network_security_accepted':False,
                'transport':'SSH authenticated stdio, no public listener','clock':'actual local UTC for admission; header=max(UTC,median+1)','target_spacing_enforced':False,'public_tps_claimed':False,
                'partition_model':'controller delivery withheld, no routing/firewall alteration','process_crash_exit':86,'recovered_admitted_block':True,'reorg_preserved_effects':True,
                'model_adopted_by_ledger':False,'model_scope':'controlled exploratory artifact; service test is not adoption acceptance','artifact_copies_physical_hosts':len(peers),'author_path_unavailable':True,'long_term_retention_accepted':False,'quota_depleted_replay_rejected':quota_replay_rejected,'consumer_paid':0,
                'confirmed_inclusion':{'block':included.hex(),'observed_tip':tip.hex(),'depth':final[1]-included_height,'work_delta':work_delta},'final_root':state_root(expected_root).hex(),
                'input_bytes':sum(row['request_bytes']for row in reports),'observations':reports,'production_activation':False}
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items()if k not in {'source_manifest','hosts','observations'}}),flush=True)
    finally:
        if origin is not None:origin.close()
        for peer in peers:peer.stop()
        # Owned remote roots are left as bounded evidence, with no running service.
        (out/'remote-roots.json').write_text(json.dumps(identities,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);parser.add_argument('--source-manifest',required=True);parser.add_argument('--model',required=True);parser.add_argument('--tasks',required=True);parser.add_argument('--hosts',nargs='+',required=True)
    run(parser.parse_args())
