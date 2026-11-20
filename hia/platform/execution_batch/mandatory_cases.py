"""Source-defined default block inputs; all ledger results come from actual owners."""
import copy
from hia.platform.execution_application.cases import H as fx_H, account as fx_account, canonical as fx_canonical, public as fx_public, u64 as fx_u64, wire as fx_wire
MAX=(1<<64)-1

def cases():
    result=[]
    def base(issued=0):return {'model:current':'0'*64,'meta:issued':issued}
    def add(name,rows,txs=(),height=10,workers=1,expect=None):
        row={'name':name,'rows':rows,'transactions':[raw.hex() for raw in txs],
             'height':height,'workers':workers,'miner_hex':(bytes([1])*32).hex(),
             'parent_id_hex':(bytes([2])*32).hex()}
        if expect is not None:row['expect']=expect
        result.append(row)
    for height in (0,99999,100000,6399999,6400000,MAX-20,MAX-19,MAX):
        add('empty-height-'+str(height),base(),height=height)
    add('workers-before-state-and-count',{},[b'']*257,workers=3)
    add('count-before-state',{},[b'']*257,workers=8)
    add('maximum-count-malformed-preparation',base(),[b'']*256,workers=8)
    add('missing-current',{'meta:issued':0})
    for value in (None,False,0,0.0,[],{}):
        add('current-type-'+fx_canonical(value).decode(),{**base(),'model:current':value})
    add('missing-issued',{'model:current':'0'*64})
    add('maturity-overflow-before-missing-issued',{'model:current':'0'*64},height=MAX)
    add('issued-overflow-before-funds',base(MAX))
    add('issued-float-before-funds',base(0.0))
    add('bad-funds-before-root-float',{**base(100),'unrelated':0.0})
    add('root-float-after-conservation',{**base(),'unrelated':0.0})
    add('root-unicode-after-conservation',{**base(),'unrelated':'λ'})
    add('root-long-value-4096',{**base(),'unrelated':'a'*4094})
    add('root-long-value-4097',{**base(),'unrelated':'a'*4095})
    add('root-key-160',{**base(),'x'*160:None})
    add('root-key-161',{**base(),'x'*161:None})
    add('root-key-utf8',{**base(),'λ':None})
    contribution={'parent':'0'*64,'status':'submitted','votes':{'keep':9},'score':6,'submitted_height':0,'submission_round':0}
    add('contribution-expiry-at64',{**base(),'contribution:a':copy.deepcopy(contribution)},height=64)
    add('contribution-expiry-at65',{**base(),'contribution:a':copy.deepcopy(contribution)},height=65)
    add('contribution-parent-short-circuit',{**base(),'contribution:a':{'parent':'other','submission_round':None,'submitted_height':None}})
    add('contribution-round-short-circuit',{**base(),'contribution:a':{'parent':'0'*64,'submission_round':1,'submitted_height':None}})
    add('contribution-round-type',{**base(),'contribution:a':{'parent':'0'*64,'submission_round':None}})
    add('contribution-missing-parent',{**base(),'contribution:a':{'submission_round':0}})
    add('contribution-submitted-overflow-before-status',{**base(),'contribution:a':{'parent':'0'*64,'submitted_height':MAX}})
    add('contribution-unexpired-ignores-status',{**base(),'contribution:a':{'parent':'0'*64,'submitted_height':10}})
    add('contribution-expired-reads-status',{**base(),'contribution:a':{'parent':'0'*64,'submitted_height':0}},height=65)
    for suffix in ('bad','0'*64+':0:x','0'*64+':00:x','0'*64+':1:x','0'*64+':0:x:y'):
        add('artifact-'+suffix,{**base(),'artifact:'+suffix:None})
    closed={'public_evaluation':{'closed':{'closed_height':1}},'unknown':'kept'}
    add('archive-at256',{**base(),'evaluation-archive:a':copy.deepcopy(closed)},height=257)
    add('archive-at257',{**base(),'evaluation-archive:a':copy.deepcopy(closed)},height=258)
    add('archive-future-saturation',{**base(),'evaluation-archive:a':copy.deepcopy(closed)},height=0)
    add('archive-missing-closed',{**base(),'evaluation-archive:a':{}})
    add('archive-noninteger-closed',{**base(),'evaluation-archive:a':{'public_evaluation':{'closed':{'closed_height':1.0}}}})
    for namespace in ('quota:','task:'):
        for deadline in (9,10,11):
            add(namespace+'zero-deadline-'+str(deadline),{**base(),namespace+'a':{'remaining':0,'deadline':deadline}})
        add(namespace+'positive-future-owner-not-read',{**base(7),namespace+'a':{'remaining':7,'deadline':11,'owner':None}})
        add(namespace+'positive-due-bad-owner',{**base(7),namespace+'a':{'remaining':7,'deadline':10,'owner':None}})
    add('release-zero-retired-ignores-deadline',{**base(),'release:other':{'remaining':0}})
    add('release-zero-current-keeps',{**base(),'release:'+'0'*64:{'remaining':0}})
    add('release-float-zero-is-not-integer-zero',{**base(),'release:other':{'remaining':0.0}})
    add('future-malformed-row-before-due-owner',{**base(1),'quota:a':{'remaining':1,'deadline':10},
        'task:z':{'remaining':1,'deadline':None}})
    due={**base(20)}
    for i in range(20):
        namespace=('task:','quota:','release:')[i%3]
        due[namespace+str(i).zfill(2)]={'remaining':1,'deadline':(i%5)+1,'owner':fx_public(0).hex(),
                                    'status':'reserved','unknown':{'retained':i}}
    add('due-sort-deadline-key-limit16',due)
    add('expiry-unicode-receipt-after-credit',{**base(1),'quota:λ':{'remaining':1,'deadline':1,'owner':fx_public(0).hex()}})
    add('expiry-empty-suffix',{**base(1),'quota:':{'remaining':1,'deadline':1,'owner':fx_public(0).hex()}})
    add('reward-all-maturities-before-first-credit',{**base(),'reward:a':{'maturity':0},'reward:z':{'maturity':None}})
    add('reward-zero-still-creates-default-account',{**base(),'reward:a':{'maturity':10,'amount':0,'owner':fx_public(0).hex()}})
    add('reward-zero-still-reads-owner',{**base(),'reward:a':{'maturity':10,'amount':0}})
    add('reward-future-ignores-owner',{**base(1),'reward:a':{'maturity':11,'amount':1}})
    add('reward-future-bad-amount-in-funds',{**base(),'reward:a':{'maturity':11,'amount':None}})
    add('reward-due-amount-before-owner',{**base(),'reward:a':{'maturity':10,'amount':None}})
    add('reward-credit-overflow',{**base(MAX),'account:'+fx_public(0).hex():{'balance':MAX,'nonce':0},
        'reward:a':{'maturity':10,'amount':1,'owner':fx_public(0).hex()}})
    reward=fx_H(b'reward',bytes([2])*32,fx_u64(10),bytes([1])*32).hex()
    add('new-reward-overwrites-existing-key-conservation',{**base(10),'reward:'+reward:{'maturity':100,'amount':10,'owner':fx_public(0).hex()}})
    add('funds-account-before-quota',{**base(),'account:a':{},'quota:a':{'remaining':0,'deadline':11}})
    add('funds-overflow',{**base(MAX),'account:a':{'balance':MAX},'account:b':{'balance':1}},height=6400000)
    add('mandatory-before-bad-signature',{**base(),'reward:a':{'maturity':None}},[fx_wire(1,fx_public(1)+fx_u64(100))[:-64]+bytes(64)],workers=2)
    funded={**base(10000000),fx_account(0):{'balance':10000000,'nonce':0}}
    add('canonical-nonce-before-late-signature',funded,[fx_wire(1,fx_public(1)+fx_u64(100),nonce=2),fx_wire(1,fx_public(1)+fx_u64(100),nonce=3)[:-64]+bytes(64)],workers=2)
    add('canonical-signature-before-later-nonce',funded,[fx_wire(1,fx_public(1)+fx_u64(100))[:-64]+bytes(64),fx_wire(1,fx_public(1)+fx_u64(100),nonce=2)],workers=2)
    add('prepare-oversize-complete-input-drained',funded,[bytes(2049)],workers=8)
    add('prepare-network-before-signature',funded,[fx_wire(1,fx_public(1)+fx_u64(100),network=bytes(32))[:-64]+bytes(64)],workers=2)
    add('prepare-expiry-before-signature',funded,[fx_wire(1,fx_public(1)+fx_u64(100),expiry=9)[:-64]+bytes(64)],workers=2)
    add('full-maximum256-same-sender-signatures',funded,
        [fx_wire(1,fx_public(20)+fx_u64(1),nonce=i+1) for i in range(256)],workers=8)
    return result
