"""Re-read every actual Prefix pipe; no ledger calculation or authority injection."""
from pathlib import Path
import json,struct
from . import safe_io as safe
from .prefix_native_io import identity,need,parse
from .batch_observations import PREP,APPLICATION,context
def expected_error(stage,code):
    if stage==0:return {11:'LIMIT',15:'PREFIX_BINDING'}[code]
    if stage==1:return PREP[code]
    if stage in (2,3,4):return APPLICATION[code]
    if stage==5:return {69:'LIMIT',70:'RANGE',71:'NONCANONICAL'}[code]
    raise ValueError('Unknown native Prefix error')
def decode_process(directory,case):
    report=safe.load(directory,'report.json')
    need(report['status']=='PASS' and report['failure'] is None and not report['cleanup_errors'] and report['exit_code']==0,'Complete actual Prefix process')
    streams={n:safe.read(directory,n+'.raw') for n in ('stdin','stdout','stderr','progress','replies')}
    for n,b in streams.items():need(identity(b)==report['streams'][n],'Changed actual pipe '+n)
    need(not streams['stderr'],'Unexpected diagnostics')
    need(len(streams['progress'])%64==0 and len(streams['replies'])%48==0,'Whole progress records')
    events={};seen=set();actions={};sequences={}
    for at in range(0,len(streams['progress']),64):
        raw=streams['progress'][at:at+64];p=struct.unpack('<8Q',raw)
        need(raw[:8]==b'PXPROG01' and p[2]==0 and p[7]==0,'Actual progress magic/owner')
        need(p[3]==sequences.get(p[1],0)+1,'Actual progress order')
        sequences[p[1]]=p[3];seen.add((p[1],p[3]))
        events.setdefault(p[1],[]).append({'sequence':p[3],'kind':p[4],'index':p[5],'height':p[6]})
    replied=set()
    for at in range(0,len(streams['replies']),48):
        raw=streams['replies'][at:at+48];p=struct.unpack('<6Q',raw)
        need(raw[:8]==b'PXGO0001' and p[2]==0 and (p[1],p[3]) in seen and (p[1],p[3]) not in replied,'Actual reply identity')
        replied.add((p[1],p[3]));need(p[4]<=2 and (p[4]!=0 or p[5]==0),'Actual reply class/token')
        if p[4]:actions.setdefault(p[1],[]).append({'sequence':p[3],'class':p[4],'token':p[5]})
    need(seen==replied,'All actual callbacks acknowledged')
    commands=[];stdin_at=0;stdout_at=0;ready=False;report_at=0;skipped=[];previous=None
    for index,cmd in enumerate(case['commands']):
        if cmd.get('requires_ready',False) and not ready:
            skipped.append(index);continue
        seq=len(commands)+1;op=cmd['op']
        need(stdin_at+8<=len(streams['stdin']),'Actual command word')
        n=struct.unpack_from('<Q',streams['stdin'],stdin_at)[0];stdin_at+=8
        frame=streams['stdin'][stdin_at:stdin_at+n];stdin_at+=n
        need(len(frame)==n and n>=144 and frame[:8]==b'PFXREQ01','Actual complete input frame')
        h=struct.unpack('<7Q',frame[8:64])
        need(h[:2]==(op,seq),'Actual request sequence/method')
        state_n,count=struct.unpack_from('<2Q',frame,128)
        if op==1:
            need(h[2:5]==(cmd['height'],int(cmd['timestamp'] is not None),cmd['timestamp'] or 0),'Actual fixed context')
            need(frame[64:96].hex()==cmd['miner_hex'] and frame[96:128].hex()==cmd['parent_id_hex'],'Actual miner/parent')
            need(count==0 and state_n==len(frame)-144 and frame[144:].hex()==cmd['state_hex'],'Actual original State bytes')
        else:
            need(h[2:5]==(0,0,0) and frame[64:128]==bytes(64) and state_n==0,'No public context rebind')
            need(count==(len(cmd.get('transactions',())) if op==2 else 0),'Actual raw transaction count')
            at=144;txs=[]
            for _ in range(count):
                need(at+8<=len(frame),'Raw transaction length');size=struct.unpack_from('<Q',frame,at)[0];at+=8
                need(size<=len(frame)-at,'Full raw transaction');txs.append(frame[at:at+size].hex());at+=size
            need(at==len(frame) and txs==cmd.get('transactions',[]),'Actual exact full raw prefix')
        need(stdout_at+256<=len(streams['stdout']),'Actual response header')
        oh=struct.unpack_from('<32Q',streams['stdout'],stdout_at)
        total=256+oh[18]+oh[16]+oh[17]+oh[15]
        raw=streams['stdout'][stdout_at:stdout_at+total];stdout_at+=total
        result=parse(raw,seq,op);r=report['commands'][report_at];report_at+=1
        need(result==r['result'] and r['sequence']==seq and r['opcode']==op and identity(raw)==r['output'],'Recorded result differs from actual output')
        actual_events=events.get(seq,[])
        need([{k:x[k] for k in ('sequence','kind','index','height')} for x in r['events']]==actual_events,'Actual progress projection')
        emitted={x['sequence'] for x in actual_events}
        expected_actions=[a for a in cmd.get('actions',[]) if a['sequence'] in emitted]
        need(actions.get(seq,[])==expected_actions,'Actual observer actions differ')
        ready=oh[25]==1
        need(oh[25] in (0,1),'Boolean private owner state')
        if op==2 and oh[3]!=1:
            need(previous is not None and result['held_state_hex']==previous['held_state_hex'] and list(oh[8:10])==previous['header'][8:10] and result['receipts']==previous['receipts'],'Failed attempt did not restore complete prior private state/fee/receipt')
        if op==2 and oh[3]==1:
            need(ready and oh[8]==len(cmd['transactions']),'Accepted exact prefix length')
        commands.append({'index':index,'sequence':seq,'opcode':op,'result':result,'progress':actual_events,'elapsed_ns':r['elapsed_ns'],'actual_input':r['input'],'actual_output':r['output']})
        previous=result
    need(stdin_at==len(streams['stdin']) and stdout_at==len(streams['stdout']) and report_at==len(report['commands']),'No unconsumed native I/O')
    need(not ready,'Actual close retired private owner')
    return {'name':case['name'],'commands':commands,'skipped':skipped,'actual_native_process':identity(safe.read(directory,'report.json')),'input':identity(streams['stdin'])}
def compare(native,actual,case,actual_context):
    differences=[]
    def check(c,label):
        if not c:differences.append(label)
    check(actual.get('name')==case['name'],'name')
    check(actual.get('actual_original_transaction_prefix') is True and actual.get('external_admission_or_root') is False,'actual original method provenance')
    check(safe.same(actual.get('skipped'),native['skipped']),'skipped unavailable owner')
    ac=actual.get('commands',[])
    check(len(ac)==len(native['commands']),'complete command count')
    for n,a in zip(native['commands'],ac):
        r=n['result'];h=r['header'];label='command '+str(n['index'])+' '
        check(a['index']==n['index'] and a['opcode']==n['opcode'] and a['sequence']==n['sequence'],label+'identity')
        check(safe.same(context(r['context_hex']),actual_context),label+'actual internal Config')
        check(a['outcome']=={1:'ok',2:'error',3:'cancelled',4:'panic'}[h[3]],label+'outcome')
        private=a['private']
        check(private['ready']==bool(h[25]) and private['length']==h[8] and private['fees']==h[9] and private['receipts']==r['receipts'] and private['held_state_hex']==r['held_state_hex'],label+'complete actual retained prefix')
        if h[3]==2:check(a['error']==expected_error(h[4],h[5]),label+'first error')
        if h[3]==3:check(a['token']==h[6],label+'actual cancellation token')
        if n['opcode']==2 and h[3]==1:
            for f in ('state_hex','root_hex'):check(a[f]==r[f],label+f)
            check(a['receipts']==r['receipts'],label+'full output receipts')
            expected={'workers':1,'workers_spawned':0,'peak_inflight':h[13],'committed_without_replay':h[12],
                'speculative':0,'reexecuted':0,'serial_conflict_batches':0,'signature_verifications':h[11]}
            check(safe.same(a['metrics'],expected),label+'actual suffix metrics')
        else:
            for f in ('state_hex','root_hex','receipts','metrics'):check(a[f] is None,label+'no output '+f)
        if n['opcode']==2 and h[3]!=1:check(a['rollback_exact'] is True,label+'actual original rollback')
        if n['opcode']==1:check(a['parent_unchanged'] is True,label+'actual original parent unchanged')
        check(a['progress']==n['progress'],label+'actual progress order')
    return {'name':case['name'],'status':'PASS' if not differences else 'FAIL','differences':differences,'native':native,'original':actual}
