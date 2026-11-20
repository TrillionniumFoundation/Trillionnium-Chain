"""Decode recorded native bytes and compare the actual original executor output."""
from pathlib import Path
import json,struct
from . import safe_io as safe
from .batch_native_io import identity,need,parse
PREP={1:'ENCODING',2:'SERVICE_CONTRACT_PROFILE',3:'WORK_TASK_PROFILE',4:'PUBLIC_EVAL_PROFILE',
      5:'FACTOR_PROFILE',6:'EVOLUTION_PROFILE',7:'NETWORK',8:'EXPIRED',9:'SIGNATURE'}
APPLICATION={1:'RANGE',2:'STATE',3:'NONCE',4:'FEE',5:'FUNDS',6:'EXPIRED',7:'LIMIT',8:'RESOURCE_ID',
    9:'DUPLICATE',10:'AUTHORITY',11:'EVIDENCE',12:'SUBMISSION_ROUND',13:'ROOT',14:'CANDIDATE_WINDOW_FULL',
    15:'NONCANONICAL',16:'SIGNATURE',17:'LENGTH',18:'ENCODING',19:'VERSION',20:'EVALUATION_POLICY',21:'CONSERVATION'}

def decode_process(directory,name):
    report=safe.load(directory,'report.json')
    need(report['status']=='PASS' and report['exit_code']==0 and report['primary_error'] is None
         and report['cleanup_errors']==[],'Incomplete actual native Result')
    streams={key:safe.read(directory,key+'.raw') for key in ('stdin','stdout','stderr','progress','replies')}
    for key,raw in streams.items():need(identity(raw)==report['streams'][key],'Actual stream changed: '+key)
    need(streams['stdin']==safe.read(directory,'intended-input.raw') and not streams['stderr'],'Actual complete native input/diagnostics')
    raw=streams['stdin'];need(len(raw)>=136,'Input extent')
    size=struct.unpack_from('<Q',raw)[0];frame=raw[8:]
    need(size==len(frame) and frame[:8]==b'BPEXEC01','Actual private block frame')
    height,workers,count,seq,gw,gr,sn=struct.unpack_from('<7Q',frame,8)
    need(sn<=len(frame)-128,'State span')
    state=frame[128:128+sn];at=128+sn;transactions=[]
    for _ in range(count):
        need(at+8<=len(frame),'Transaction length')
        n=struct.unpack_from('<Q',frame,at)[0];at+=8
        need(n<=len(frame)-at,'Complete raw transaction')
        transactions.append(frame[at:at+n].hex());at+=n
    need(at==len(frame),'No trailing transaction data')
    result=parse(streams['stdout'],height=height,workers=workers,count=count,sequence=seq)
    need(result==report['result'],'Recorded result differs from actual stdout')
    need(result['parent_hex']==state.hex() or (not result['parent_hex'] and result['header'][2:5] in ([2,0,10],[2,0,11])),
         'Native parent extent/immutability')
    need(len(streams['progress'])%64==0 and len(streams['replies'])%48==0,'Whole callback records')
    events=[];seen=set();sequences={}
    for offset in range(0,len(streams['progress']),64):
        row=streams['progress'][offset:offset+64];p=struct.unpack('<8Q',row)
        need(row[:8]==b'BPPROG01' and p[1]==seq and p[6]==height and p[7]==0,'Actual callback identity')
        need(p[3]==sequences.get(p[2],0)+1,'Actual per-owner callback sequence')
        sequences[p[2]]=p[3];seen.add((p[2],p[3]))
        events.append({'worker':p[2],'sequence':p[3],'kind':p[4],'index':p[5]})
    actions=[];replied=set()
    for offset in range(0,len(streams['replies']),48):
        row=streams['replies'][offset:offset+48];p=struct.unpack('<6Q',row)
        need(row[:8]==b'BPGO0001' and p[1]==seq and (p[2],p[3]) in seen and (p[2],p[3]) not in replied,'Reply binding')
        replied.add((p[2],p[3]));need(p[4]<=2,'Reply class')
        if p[4]:actions.append({'worker':p[2],'sequence':p[3],'class':p[4],'token':p[5]})
        else:need(p[5]==0,'Continue token must be zero')
    need(seen==replied,'Every emitted callback received its actual reply')
    observed=[{k:e[k] for k in ('worker','sequence','kind','index')} for e in report['events']]
    need(observed==events,'Recorded callback projection differs from raw')
    case={'schema':'trnm.execution-batch-original-input.v1','name':name,'state_hex':state.hex(),
        'transactions':transactions,'height':height,'workers':workers,'miner_hex':frame[64:96].hex(),
        'parent_id_hex':frame[96:128].hex(),'actions':sorted(actions,key=lambda r:(r['worker'],r['sequence'])),
        'barrier':bool(report['barrier_kernel_tasks'])}
    return case,{'name':name,'result':result,'progress':events,'input':identity(streams['stdin']),
        'actual_native_process':identity(safe.read(directory,'report.json'))}

def expected_error(stage,code):
    if stage==0:return {10:'WORKERS',11:'LIMIT',12:'WORKER_START',13:'WORKER_PANIC'}[code]
    if stage==1:return PREP[code]
    if stage in (2,3,4):return APPLICATION[code]
    if stage==5:return {69:'LIMIT',70:'RANGE',71:'NONCANONICAL'}[code]
    raise ValueError('Unknown native semantic error')

def context(raw):
    value=bytes.fromhex(raw);pl=struct.unpack_from('<I',value,456)[0]
    return {'network':value[24:56].hex(),'parameters':value[56:88].hex(),'family':value[88:120].hex(),
        'plan':value[120:152].hex(),'params':json.loads(value[576:576+pl]),
        'fees':list(struct.unpack_from('<25Q',value,248)),
        'evaluators':sorted(value[480+i*32:512+i*32].hex() for i in range(3))}

def compare(native,actual,case,actual_context):
    result=native['result'];h=result['header'];differences=[]
    def check(condition,field):
        if not condition:differences.append(field)
    check(actual.get('name')==case['name'],'name')
    check(actual.get('parent_unchanged') is True and actual.get('parent_hex')==case['state_hex'],'actual original parent')
    check(actual.get('actual_original_execute_with_control') is True and actual.get('external_admission_or_root') is False,'actual method provenance')
    check(safe.same(context(result['context_hex']),actual_context),'actual complete default context')
    outcome={1:'ok',2:'error',3:'cancelled',4:'panic'}[h[2]]
    check(actual.get('outcome')==outcome,'outcome')
    if h[2]==1:
        for field in ('state_hex','receipts','root_hex'):check(actual.get(field)==result[field],field)
        expected={'workers':h[8],'workers_spawned':h[9],'peak_inflight':h[10],'committed_without_replay':h[11],
            'speculative':h[12],'reexecuted':h[13],'serial_conflict_batches':h[14],'signature_verifications':h[15]}
        check(safe.same(actual.get('metrics'),expected),'metrics')
    elif h[2]==2:check(actual.get('error')==expected_error(h[3],h[4]),'first error')
    elif h[2]==3:check(actual.get('token')==h[5],'cancellation token')
    for field in ('state_hex','receipts','root_hex','metrics'):
        if h[2]!=1:check(actual.get(field) is None,'no original partial '+field)
    sortkey=lambda row:(row['worker'],row['sequence'])
    actual_progress=[{k:row[k] for k in ('worker','sequence','kind','index')} for row in actual['progress']]
    check(sorted(actual_progress,key=sortkey)==sorted(native['progress'],key=sortkey),'per-owner progress')
    accounting=actual['worker_accounting']
    check(accounting['active']==0 and accounting['started']==accounting['stopped']==accounting['spawned'],'all actual original workers retired')
    return {'name':case['name'],'status':'FAIL' if differences else 'PASS','differences':differences,
            'native':native,'original':actual}
