"""Deterministic signed test inputs, never a production authority or executor."""
from pathlib import Path
from functools import lru_cache
import copy,hashlib,json,struct
from hia.platform.execution_prepare.cases import H,B,L,multiply,encode
from hia.platform.execution_state.cases import tape,normalized
ROOT=Path(__import__('hia.platform.execution_prepare.cases',fromlist=['ROOT']).ROOT)
MAX=(1<<64)-1
def u64(n):return struct.pack('<Q',n)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
@lru_cache(maxsize=1)
def config():
    params,ledger,work,model=[json.loads((ROOT/'config/pon'/name).read_bytes()) for name in ('devnet-v1.json','ledger-v1.json','work-profile-v1.json','model-family-v1.json')]
    return {'params':params,'network':H(b'network',params['chain_label'].encode()),
      'parameters':H(b'parameters',canonical(params),canonical(ledger),canonical(work),canonical(model)),
      'family':H(b'family',canonical(model)),'plan':H(b'plan',b'public-source-file-disjoint-v1'),
      'fees':{row['tag']:row['base_fee_units'] for row in ledger['commands']}}
@lru_cache(maxsize=16)
def material(index):
    seed=H(b'DEV-ONLY-KEY',u64(index));expanded=hashlib.sha512(seed).digest()
    scalar=(int.from_bytes(expanded[:32],'little')&((1<<254)-8))|(1<<254)
    return expanded,scalar,encode(multiply(scalar,B))
def public(index):return material(index)[2]
def sign(index,message):
    expanded,scalar,key=material(index);r=int.from_bytes(hashlib.sha512(expanded[32:]+message).digest(),'little')%L
    encoded=encode(multiply(r,B));k=int.from_bytes(hashlib.sha512(encoded+key+message).digest(),'little')%L
    return encoded+((r+k*scalar)%L).to_bytes(32,'little')
@lru_cache(maxsize=4096)
def wire(tag,payload,index=0,nonce=1,fee=10000000,expiry=MAX,network=None):
    if network is None:network=config()['network']
    body=b'PNX1'+network+public(index)+struct.pack('<QQQBH',nonce,expiry,fee,tag,len(payload))+payload
    return body+sign(index,H(b'tx-sign',body))
def account(index):return 'account:'+public(index).hex()
def base(balance=10000000,nonce=0):return {account(0):{'balance':balance,'nonce':nonce},'model:current':'0'*64}
def tx(tag,payload,*,index=0,nonce=1,fee=10000000,height=10,expiry=MAX,callback=True,cancel_at=None,commit=True,mutations=(),root=False,raw=None,expect=None):
    result={'wire_hex':(wire(tag,payload,index,nonce,fee,expiry) if raw is None else raw).hex(),'height':height,
      'callback':callback,'cancel_at':cancel_at,'commit':commit,'current_mutations':[{'key_hex':k.encode().hex(),'value_hex':None if v is ABSENT else tape(normalized(v)).hex()} for k,v in mutations],'root':root}
    if expect is not None:result['expect']=expect
    return result
ABSENT=object()
def history(name,rows,transactions):return {'schema':'trnm.execution-application-history.v1','name':name,
    'base':[{'key_hex':k.encode().hex(),'value_hex':tape(normalized(v)).hex()} for k,v in sorted(rows.items())],
    'transactions':transactions}
def task_payload(*,nonce=1,provider=1,budget=1000,deadline=20,index=0):
    c=config();tid=H(b'task-instance-v3',c['network'],c['parameters'],public(index),u64(nonce),public(provider),u64(budget),u64(deadline))
    return tid,tid+public(provider)+u64(budget)+u64(deadline)
def quota_payload(*,nonce=1,consumer=1,provider=2,units=10,deadline=20,index=0):
    c=config();qid=H(b'quota-instance-v3',c['network'],c['parameters'],public(index),u64(nonce),public(consumer),public(provider),u64(units),u64(deadline))
    return qid,qid+public(consumer)+public(provider)+u64(units)+u64(deadline)
def contribution_payload(*,nonce=1,index=0,height=10,artifact=bytes([41])*32,size=100,components=bytes([42])*32,parent=bytes(32),family=None,round=None):
    c=config();family=c['family'] if family is None else family
    if round is None:round=height//c['params']['candidate_round_blocks']
    cid=H(b'contribution-v3',public(index),family,parent,artifact,components,u64(round))
    return cid,cid+family+parent+artifact+u64(size)+components+u64(round)
def allocation_leaf(cid,who,score):return H(b'allocation-leaf',cid,who,u64(score))
def pair(a,b):return H(b'allocation-node',*sorted((a,b)))
def allocation_root(leaves):
    leaves=list(leaves)
    while len(leaves)>1:
        if len(leaves)%2:leaves.append(leaves[-1])
        leaves=[pair(a,b) for a,b in zip(leaves[::2],leaves[1::2])]
    return leaves[0]
def release_material(count=3,budget=1000):
    c=config();parent=bytes(32);bundle=bytes([100])*32
    entries=[(bytes([50+i])*32,i%3,i+1) for i in range(count)]
    total=sum(score for cid,index,score in entries);root=allocation_root([allocation_leaf(cid,public(index),score) for cid,index,score in entries])
    rid=H(b'release',parent,bundle,u64(budget),root,u64(total))
    rows=base()
    for cid,index,score in entries:rows['contribution:'+cid.hex()]={'owner':public(index).hex(),'score':score,'status':'evaluated','parent':parent.hex(),'unknown':[None,-0.0,{'λ':'preserved'}]}
    rows['contribution:'+bundle.hex()]={'owner':public(3).hex(),'score':10,'status':'evaluated','parent':parent.hex(),'components_root':root.hex(),'artifact':{'typed':'retained'},'family':['retained',1.0]}
    payload=rid+parent+bundle+u64(budget)+root+u64(total)+bytes([count])+b''.join(cid+u64(score) for cid,index,score in entries)
    return rows,rid,payload,entries,root
def claim_material(*,budget=2000,score=5,total=10,remaining=2000,leaves=1,siblings=(),claims=None,maturity=5,deadline=100):
    rid=bytes([70])*32;cid=bytes([71])*32;root=allocation_leaf(cid,public(0),score)
    for sibling in siblings:root=pair(root,sibling)
    row={'maturity':maturity,'deadline':deadline,'status':'open','claims':{} if claims is None else claims,
         'leaf_count':leaves,'root':root.hex(),'total':total,'budget':budget,'remaining':remaining,'unknown':'keep'}
    return rid,cid,row,rid+cid+u64(score)+bytes([len(siblings)])+b''.join(siblings)
def quota_use_payload(qid,*,units=1,nonce=1,index=0,consumer=1,result=bytes([72])*32):
    c=config();digest=H(b'use',c['network'],c['parameters'],qid,public(index),u64(nonce),u64(units),result)
    return qid+u64(units)+result+sign(consumer,digest)

def histories():
    cases=[]
    def add(name,rows,tag,payload,**kwargs):
        cases.append(history(name,rows,[tx(tag,payload,**kwargs)]))
    def changed(rows,key,field,value):
        rows=copy.deepcopy(rows)
        if value is ABSENT:rows[key].pop(field,None)
        else:rows[key][field]=value
        return rows
    transfer=public(1)+u64(100)
    add('transfer-valid',base(),1,transfer,expect='OK')
    add('transfer-to-self',base(),1,public(0)+u64(100),expect='OK')
    add('transfer-zero',base(),1,public(1)+u64(0),expect='FUNDS')
    add('transfer-insufficient',base(balance=300),1,transfer,expect='FUNDS')
    add('transfer-recipient-overflow',{**base(),account(1):{'balance':MAX,'nonce':9}},1,transfer,expect='RANGE')
    add('nonce-before-fee',base(nonce=7),1,transfer,fee=0,expect='NONCE')
    add('nonce-overflow-before-fee',base(nonce=MAX),1,transfer,fee=0,expect='RANGE')
    add('fee-before-balance',{**base(),account(0):{'nonce':0,'balance':None}},1,transfer,fee=0,expect='FEE')
    add('prepare-network-before-state',base(nonce=MAX),1,transfer,raw=wire(1,transfer,network=bytes(32)),expect='NETWORK')
    add('prepare-expiry-before-state',base(nonce=MAX),1,transfer,expiry=0,expect='EXPIRED')
    good=wire(1,transfer);add('prepare-signature-before-state',base(nonce=MAX),1,transfer,raw=good[:-1]+bytes([good[-1]^1]),expect='SIGNATURE')
    for index in range(1,6):add('transfer-callback-cancel-'+str(index),base(),1,transfer,cancel_at=index,expect='ACCOUNT_ACCESS')
    for value in (None,False,True,0,-1,0.0,'λ',[],{}):
        add('sender-object-type-'+tape(value).hex(),{**base(),account(0):value},1,transfer,expect='STATE')
    for field in ('nonce','balance'):
        for index,value in enumerate((ABSENT,None,False,-1,0.0,1.0,'0',[],{},MAX)):
            add('account-field-'+field+'-'+str(index),changed(base(),account(0),field,value),1,transfer)
    for size in (4097,65537,(1<<20)+1):
        rows=base();rows[account(0)]['unknown']={'s':'λ'+('x'*size),'f':[-0.0,1.0,MAX,-(1<<63)]}
        add('unbounded-unknown-account-'+str(size),rows,1,transfer,expect='OK')
    rows=base();rows[account(0)]['unknown']={'nested':[None,True,False,{'\0λ😀':[-0.0,0.0,1.0]}]}
    add('unknown-typed-fields-and-root-refusal',rows,1,transfer,root=True,expect='OK')
    add('stale-patch-still-consumes-apply',base(),1,transfer,mutations=((account(0),{'balance':8,'nonce':9}),),expect='OK')
    add('outside-patch-remains-current',base(),1,transfer,mutations=(('unrelated:λ',{'float':0.0}),),expect='OK')
    cases.append(history('repeated-owner-nonce-and-recovery',base(),[tx(1,transfer,expect='OK'),tx(1,transfer,expect='NONCE'),tx(1,transfer,nonce=2,expect='OK')]))

    tid,payload=task_payload();tk='task:'+tid.hex()
    add('reserve-task-valid',base(),2,payload,expect='OK')
    add('reserve-task-wrong-id',base(),2,bytes(32)+payload[32:],expect='RESOURCE_ID')
    add('reserve-task-duplicate-before-deadline',{**base(),tk:None},2,payload,expect='DUPLICATE')
    for deadline in (0,10,11,1010,1011,MAX):
        _,p=task_payload(deadline=deadline);add('task-deadline-'+str(deadline),base(),2,p)
    _,p=task_payload(budget=0);add('task-zero-budget-after-scans',base(),2,p,expect='FUNDS')
    for namespace in ('quota:','release:','task:'):
        for index,value in enumerate((None,{}, {'remaining':None}, {'remaining':0}, {'remaining':1}, {'remaining':1,'deadline':None}, {'remaining':1,'deadline':20})):
            add('deadline-row-'+namespace[:-1]+'-'+str(index),{**base(),namespace+'λ':value},2,payload)
    rows={**base(),'quota:a':{'remaining':None},'release:a':{},'task:a':{}}
    add('deadline-global-order-quota-first',rows,2,payload,expect='RANGE')
    for count in (15,16,255,256):
        rows=base();rows.update({'quota:'+str(i).zfill(4):{'remaining':1,'deadline':20 if count<100 else 30} for i in range(count)})
        add('deadline-count-'+str(count),rows,2,payload)
    add('deadline-zero-remaining-skips-bad-deadline',{**base(),'release:λ':{'remaining':0,'deadline':None}},2,payload,expect='OK')
    add('deadline-snapshot-current-change',{**base(),'task:old':{'remaining':0}},2,payload,mutations=(('quota:new',{'remaining':1,'deadline':20}),),expect='OK')
    original={'owner':public(0).hex(),'provider':public(1).hex(),'remaining':1000,'deadline':20,'status':'reserved','output':None,'unknown':{'λ':[-0.0,1.0]}}
    add('cancel-task-valid',{**base(),tk:original},3,tid,expect='OK')
    for field,values in [('owner',(ABSENT,None,public(1).hex())),('status',(ABSENT,None,'receipt')),('remaining',(ABSENT,None,0,MAX))]:
        for i,v in enumerate(values):add('cancel-task-'+field+'-'+str(i),changed({**base(),tk:original},tk,field,v),3,tid)
    output=bytes([33])*32
    receipt_row={**original,'owner':public(1).hex(),'provider':public(0).hex()}
    add('task-receipt-valid',{**base(),tk:receipt_row},4,tid+output,expect='OK')
    for field,values in [('provider',(ABSENT,None,public(1).hex())),('status',(ABSENT,None,'receipt')),('deadline',(ABSENT,None,10,11))]:
        for i,v in enumerate(values):add('task-receipt-'+field+'-'+str(i),changed({**base(),tk:receipt_row},tk,field,v),4,tid+output)
    add('task-receipt-zero-output',{**base(),tk:receipt_row},4,tid+bytes(32),expect='EVIDENCE')
    settled={**original,'status':'receipt','output':output.hex()}
    add('task-settlement-valid',{**base(),tk:settled},5,tid+output,expect='OK')
    for field,values in [('provider',(ABSENT,None,'unusual:λ')),('status',(ABSENT,None,'reserved')),('deadline',(ABSENT,None,10)),('output',(ABSENT,None,'wrong')),('remaining',(ABSENT,None,0,MAX))]:
        for i,v in enumerate(values):add('task-settlement-'+field+'-'+str(i),changed({**base(),tk:settled},tk,field,v),5,tid+output)
    # Real sequential reserve/cancel and reserve/provider-receipt/settle histories.
    cases.append(history('task-reserve-then-cancel',base(),[tx(2,payload,expect='OK'),tx(3,tid,nonce=2,expect='OK')]))
    rows=base();rows[account(1)]={'balance':10000000,'nonce':0}
    cases.append(history('task-complete-three-signers',rows,[tx(2,payload,expect='OK'),tx(4,tid+output,index=1,expect='OK'),tx(5,tid+output,nonce=2,expect='OK')]))

    cid,payload=contribution_payload();ck='contribution:'+cid.hex()
    add('contribution-valid',base(),6,payload,expect='OK')
    for name,kwargs in [('wrong-round',{'round':1}),('empty-artifact',{'artifact':bytes(32)}),('empty-size',{'size':0}),('too-large-size',{'size':config()['params']['max_artifact_bytes']+1}),('wrong-family',{'family':bytes(32)})]:
        _,p=contribution_payload(**kwargs);add('contribution-'+name,base(),6,p)
    add('contribution-wrong-id',base(),6,bytes(32)+payload[32:],expect='ROOT')
    for value in (None,0,0.0,[],{}):add('contribution-current-type-'+tape(value).hex(),{**base(),'model:current':value},6,payload,expect='STATE')
    for count in (255,256,511,512):
        rows=base();rows.update({'contribution:'+str(i).zfill(6):{'status':'submitted','submitted_height':10,'parent':'0'*64,'submission_round':0,'score':0} for i in range(count)})
        add('contribution-history-'+str(count),rows,6,payload)
    for i,value in enumerate((None,{}, {'status':'adopted'}, {'status':'submitted'}, {'status':'submitted','submitted_height':0,'parent':'bad'}, {'status':'submitted','submitted_height':10,'parent':'0'*64,'submission_round':0,'score':None})):
        add('contribution-active-type-'+str(i),{**base(),'contribution:old':value},6,payload)
    add('contribution-duplicate',{**base(),ck:None},6,payload)
    artifact=payload[96:128];duplicate='artifact:'+bytes(32).hex()+':0:'+artifact.hex()
    add('contribution-artifact-duplicate',{**base(),duplicate:None},6,payload,expect='DUPLICATE')
    add('contribution-scan-detects-phantom',base(),6,payload,mutations=(('contribution:late',None),),expect='OK')
    eval_payload=cid+config()['plan']+bytes([44])*32+u64(9)
    row={'owner':public(1).hex(),'parent':'0'*64,'status':'submitted','votes':{},'score':0,'unknown':{'λ':0.0}}
    add('evaluate-incomplete-valid',{**base(),ck:row},7,eval_payload,expect='OK')
    complete={**row,'votes':{public(2).hex():{'score':7,'evidence':'old','unknown':[]}}}
    add('evaluate-completes-minimum',{**base(),ck:complete},7,eval_payload,expect='OK')
    for field,values in [('owner',(ABSENT,None,public(0).hex())),('status',(ABSENT,None,'evaluated')),('parent',(ABSENT,None,0.0)),('votes',(ABSENT,None,[],False,1,0.0,'text',{public(0).hex():None},{'unknown':{}},{'unknown':{'score':1.0}}))]:
        for i,v in enumerate(values):add('evaluate-'+field+'-'+str(i),changed({**base(),ck:row},ck,field,v),7,eval_payload)
    for i,(current,parent) in enumerate(((0.0,-0.0),(0.0,0),({'a':[-0.0]},{'a':[0.0]}),([1],[1.0]))):
        add('evaluate-typed-parent-'+str(i),{**base(),'model:current':current,ck:{**row,'parent':parent}},7,eval_payload)
    rows=base();rows[account(3)]={'balance':10000000,'nonce':0};rows[ck]=row
    add('evaluate-nonauthority-skips-malformed-owner',changed(rows,ck,'owner',None),7,eval_payload,index=3,expect='AUTHORITY')
    for name,p in [('bad-plan',cid+bytes(32)+bytes([44])*32+u64(9)),('zero-evidence',cid+config()['plan']+bytes(32)+u64(9)),('score-high',cid+config()['plan']+bytes([44])*32+u64(1000001))]:add('evaluate-'+name,{**base(),ck:row},7,p,expect='EVIDENCE')

    for count in (1,2,3,16):
        rows,rid,payload,entries,root=release_material(count);add('release-'+str(count)+'-leaves',rows,8,payload,expect='OK')
    rows,rid,payload,entries,root=release_material();bk='contribution:'+bytes([100]).hex()*32
    add('release-wrong-id',rows,8,bytes(32)+payload[32:],expect='ROOT')
    add('release-existing-before-deadline',{**rows,'release:'+rid.hex():None},8,payload,expect='DUPLICATE')
    for field,values in [('score',(ABSENT,None,0)),('status',(ABSENT,None,'submitted')),('parent',(ABSENT,None,0.0)),('components_root',(ABSENT,None,'bad'))]:
        for i,v in enumerate(values):add('release-bundle-'+field+'-'+str(i),changed(rows,bk,field,v),8,payload)
    item='contribution:'+entries[0][0].hex()
    for field,values in [('owner',(ABSENT,None,'A'*64,'bad')),('score',(ABSENT,None,0,7)),('status',(ABSENT,None,'submitted')),('parent',(ABSENT,None,0.0))]:
        for i,v in enumerate(values):add('release-allocation-'+field+'-'+str(i),changed(rows,item,field,v),8,payload)
    for height in (MAX,MAX-1020,MAX-1019):add('release-height-'+str(height),rows,8,payload,height=height)

    rid,cid,row,payload=claim_material();rk='release:'+rid.hex()
    add('claim-valid',{**base(),rk:row},9,payload,expect='OK')
    for field,values in [('maturity',(ABSENT,None,11)),('deadline',(ABSENT,None,10)),('status',(ABSENT,None,'closed')),('claims',(ABSENT,None,False,0,[],{cid.hex():0})),('leaf_count',(ABSENT,None,0,2)),('root',(ABSENT,None,'bad','A'*64,'0'*64)),('total',(ABSENT,None,0)),('budget',(ABSENT,None)),('remaining',(ABSENT,None,0))]:
        for i,v in enumerate(values):add('claim-'+field+'-'+str(i),changed({**base(),rk:row},rk,field,v),9,payload)
    for index,(budget,score,total) in enumerate(((MAX,MAX,MAX),(MAX,MAX,1),(MAX,1,MAX),(MAX,MAX-1,MAX),(1<<63,2,2),(1<<63,2,1),(MAX,0,MAX),(MAX,1,0))):
        r,c,o,p=claim_material(budget=budget,score=score,total=total,remaining=MAX)
        fee=config()['fees'][9]+len(wire(9,p))*config()['params']['byte_fee_units']
        add('claim-full-u128-'+str(index),{**base(balance=fee),'release:'+r.hex():o},9,p)
    for leaves in (2,3,4,5,256):
        siblings=tuple(bytes([80+i])*32 for i in range((leaves-1).bit_length()))
        r,c,o,p=claim_material(leaves=leaves,siblings=siblings)
        add('claim-proof-width-'+str(leaves),{**base(),'release:'+r.hex():o},9,p,expect='OK')
    cases.append(history('claim-repeat-keeps-settled-state',{**base(),rk:row},[tx(9,payload,expect='OK'),tx(9,payload,nonce=2,expect='DUPLICATE')]))

    qid,payload=quota_payload();qk='quota:'+qid.hex()
    add('quota-reserve-valid',base(),10,payload,expect='OK')
    add('quota-wrong-id',base(),10,bytes(32)+payload[32:],expect='RESOURCE_ID')
    for units in (0,1,1000000,1000001,MAX):
        q,p=quota_payload(units=units);add('quota-units-'+str(units),base(balance=MAX),10,p)
    add('quota-duplicate-before-expiry',{**base(),qk:None},10,payload,expect='DUPLICATE')
    use_row={'owner':public(2).hex(),'consumer':public(1).hex(),'provider':public(0).hex(),'remaining':10240,'units':10,'deadline':20,'status':'reserved','unknown':{'λ':-0.0}}
    use_payload=quota_use_payload(qid)
    add('quota-use-valid',{**base(),qk:use_row},11,use_payload,expect='OK')
    add('quota-use-unfunded-provider',{qk:use_row},11,use_payload,expect='OK')
    add('quota-use-uppercase-consumer',{**base(),qk:{**use_row,'consumer':public(1).hex().upper()}},11,use_payload,expect='SIGNATURE')
    add('quota-use-spent',{**base(),qk:{**use_row,'units':1}},11,use_payload,expect='OK')
    for field,values in [('provider',(ABSENT,None,public(1).hex())),('status',(ABSENT,None,'spent')),('deadline',(ABSENT,None,10)),('units',(ABSENT,None,0)),('consumer',(ABSENT,None,'bad','0'*64)),('remaining',(ABSENT,None,0))]:
        for i,v in enumerate(values):add('quota-use-'+field+'-'+str(i),changed({**base(),qk:use_row},qk,field,v),11,use_payload)
    add('quota-use-bad-signature-before-remaining',changed({**base(),qk:use_row},qk,'remaining',None),11,use_payload[:-64]+bytes(64),expect='SIGNATURE')
    for units in (0,11,MAX):add('quota-use-request-units-'+str(units),{**base(),qk:use_row},11,quota_use_payload(qid,units=units),expect='LIMIT')
    add('quota-use-result-zero',{**base(),qk:use_row},11,quota_use_payload(qid,result=bytes(32)),expect='LIMIT')
    qid,p=quota_payload(provider=0);qk='quota:'+qid.hex()
    cases.append(history('quota-reserve-use-same-private-state',base(),[tx(10,p,expect='OK'),tx(11,quota_use_payload(qid,nonce=2),nonce=2,expect='OK')]))

    work=bytes([90])*32
    add('work-valid',base(),12,work,expect='OK')
    add('work-zero',base(),12,bytes(32),expect='DUPLICATE')
    add('work-present-null',{**base(),'work:'+work.hex():None},12,work,expect='DUPLICATE')
    for amount in (0,1,MAX):add('transfer-amount-'+str(amount),base(balance=MAX),1,public(1)+u64(amount))
    # Every default supported command still uses the genuine preparation gate.
    for tag,p in [(1,transfer),(2,task_payload()[1]),(3,tid),(4,tid+output),(5,tid+output),(6,contribution_payload()[1]),(7,eval_payload),(8,release_material()[2]),(9,claim_material()[3]),(10,quota_payload()[1]),(11,use_payload),(12,work)]:
        raw=wire(tag,p)
        add('prepare-truncation-tag-'+str(tag),base(nonce=MAX),tag,p,raw=raw[:-1],expect='ENCODING')
    # Actual original v1 rejected uppercase public keys before settlement; keep
    # all original 323 semantic inputs and add focused canonical-decoder order cases.
    qid,_=quota_payload();qk='quota:'+qid.hex();use_payload=quota_use_payload(qid)
    upper=public(1).hex().upper()
    mixed=''.join(x.upper() if i%2 else x for i,x in enumerate(public(1).hex()))
    add('quota-use-mixedcase-consumer',{**base(),qk:{**use_row,'consumer':mixed}},11,use_payload,expect='SIGNATURE')
    add('quota-use-uppercase-before-remaining',{**base(),qk:{**use_row,'consumer':upper,'remaining':None}},11,use_payload,expect='SIGNATURE')
    add('quota-use-uppercase-after-deadline',{**base(),qk:{**use_row,'consumer':upper,'deadline':10}},11,use_payload,expect='STATE')
    add('quota-use-uppercase-after-initial-callback',{**base(),qk:{**use_row,'consumer':upper}},11,use_payload,cancel_at=1,expect='ACCOUNT_ACCESS')
    add('quota-use-uppercase-before-settlement-callback',{**base(),qk:{**use_row,'consumer':upper}},11,use_payload,cancel_at=2,expect='SIGNATURE')
    names=[c['name'] for c in cases]
    if len(names)!=len(set(names)):raise ValueError('Duplicate fixture history name')
    return cases

def canonical_bytes():return b''.join(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()+b'\n' for row in histories())
