"""Owned, bounded SSH-test peer. No listening port or installed service.

All privileged operations apply solely to its new test directory. Development signing
keys are public fixtures. Ledger work uses actual local UTC; this is not a native node.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,platform,resource,struct,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *
from model_contract import load_model,infer
MAX_FRAME=2*1024*1024

def send(value):
    data=canonical(value)
    require(len(data)<=MAX_FRAME,'FRAME_LIMIT')
    sys.stdout.buffer.write(struct.pack('>I',len(data))+data);sys.stdout.buffer.flush()

def receive():
    prefix=sys.stdin.buffer.read(4)
    if not prefix:return None
    require(len(prefix)==4,'SHORT_FRAME');size=struct.unpack('>I',prefix)[0]
    require(0<size<=MAX_FRAME,'FRAME_LIMIT')
    data=sys.stdin.buffer.read(size);require(len(data)==size,'SHORT_FRAME')
    return json.loads(data,object_pairs_hook=unique)

def verify_sources(path):
    manifest=json.loads(Path(path).read_text(),object_pairs_hook=unique)
    for relative,expected in manifest['files'].items():
        p=(ROOT/relative).resolve();require(p.is_relative_to(ROOT)and p.is_file(),'SOURCE_PATH')
        require(hashlib.sha256(p.read_bytes()).hexdigest()==expected,'SOURCE_HASH')
    return hashlib.sha256(canonical(manifest)).hexdigest()

def run(args):
    digest=verify_sources(args.source_manifest)
    directory=Path(args.state_dir);directory.mkdir(parents=True,exist_ok=True)
    ledger=Ledger(directory/'chain');ledger.recover();effects=EffectJournal(directory/'effects.sqlite')
    artifacts=directory/'artifacts';artifacts.mkdir(exist_ok=True)
    send({'ready':True,'source_manifest':digest,'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex(),
          'genesis':GENESIS.hex(),'utc_seconds':int(time.time()),'platform':platform.system(),'machine':platform.machine(),
          'python':platform.python_version(),'pid':os.getpid(),'native_node':False,'independent_operator':False})
    try:
        while True:
            message=receive()
            if message is None:return
            begin=time.perf_counter_ns();before=resource.getrusage(resource.RUSAGE_SELF);stop=False
            try:
                op=message['op']
                if op in {'submit','admit_and_crash'}:
                    require(set(message)=={'op','header','transactions','proof'},'FIELDS')
                    require(len(message['transactions'])<=PARAMS['max_transactions'],'LIMIT')
                    block=bytes.fromhex(message['header']);txs=[bytes.fromhex(t)for t in message['transactions']]
                    proof=base64.b64decode(message['proof'],validate=True)
                    bid=ledger.admit(block,txs,proof,int(time.time()))
                    if op=='admit_and_crash':os._exit(86)
                    ledger.activate(bid);tip,generation,state=ledger.read_active()
                    result={'block':bid.hex(),'tip':tip.hex(),'root':state_root(state).hex(),'generation':generation}
                elif op=='head':
                    tip,generation,state=ledger.read_active()
                    result={'tip':tip.hex(),'root':state_root(state).hex(),'generation':generation,'height':ledger.block(tip)[1],
                            'chainwork':int.from_bytes(ledger.block(tip)[2],'big'),'state_keys':len(state),
                            'effect_count':effects.db.execute('SELECT count(*) FROM effects').fetchone()[0]}
                elif op=='effect':
                    require(set(message)=={'op','identity','payload','generation'},'FIELDS')
                    effects.enter(bytes.fromhex(message['identity']),bytes.fromhex(message['payload']),message['generation'])
                    result={'entered':True}
                elif op=='put_artifact':
                    require(set(message)=={'op','artifact','data'},'FIELDS');identity=bytes.fromhex(message['artifact'])
                    require(len(identity)==32,'ARTIFACT_IDENTITY');data=base64.b64decode(message['data'],validate=True)
                    require(len(data)<=65536 and H('artifact',data)==identity,'ARTIFACT_IDENTITY')
                    path=artifacts/identity.hex()
                    if not path.exists():
                        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                        with os.fdopen(fd,'wb')as output:output.write(data);output.flush();os.fsync(output.fileno())
                        sync_directory(artifacts)
                    require(path.read_bytes()==data,'ARTIFACT_IDENTITY');load_model(path,identity)
                    result={'artifact':identity.hex(),'bytes':len(data)}
                elif op=='infer':
                    require(set(message)=={'op','artifact','inputs'},'FIELDS');identity=bytes.fromhex(message['artifact'])
                    require(len(identity)==32,'ARTIFACT_IDENTITY');model=load_model(artifacts/identity.hex(),identity)
                    predictions=infer(model,message['inputs'])
                    result={'artifact':identity.hex(),'input':H('inference-input',canonical(message['inputs'])).hex(),
                            'output':H('inference-output',canonical(predictions)).hex(),'predictions':predictions,
                            'ordinary_hepta_entry':False,'author_source_required':False}
                elif op=='shutdown':result={'stopped':True};stop=True
                else:raise ValueError('OPERATION')
                result={'ok':True,'result':result}
            except (ValueError,KeyError,TypeError,OverflowError,OSError)as error:
                result={'ok':False,'error':str(error)[:200]}
            after=resource.getrusage(resource.RUSAGE_SELF)
            result['observed']={'elapsed_ns':time.perf_counter_ns()-begin,'cpu_ns':int(((after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime))*1e9),
                                'max_rss_kib':int(after.ru_maxrss),'utc_seconds':int(time.time()),'gpu_used':False,
                                'database_bytes':sum(p.stat().st_size for p in (directory/'chain').glob('ledger.sqlite*')if p.is_file())}
            send(result)
            if stop:return
    finally:effects.db.close();ledger.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--state-dir',required=True);parser.add_argument('--source-manifest',required=True)
    run(parser.parse_args())
