from pathlib import Path
import json,struct,hashlib,itertools,random

MAGIC=b'MTIN0001'

def command(op,a=0,b=0,c=0):
    return {'input':struct.pack('<8s4Q',MAGIC,op,a,b,c).hex()}

def envelope(op=1,*,digest=1,again=None,signer=7,body=b'a',nonce=1,fee=0,gas=1,max_bytes=None,
             canonical=0,signer_error=0,signature=0,replay=0,recheck=0,reserve=0,
             bound=1,owner=88,tag=17,handoff=0,commit=0,release=0):
    raw=bytearray(320+len(body));raw[:40]=bytes.fromhex(command(op)['input'])
    raw[40:72]=(digest.to_bytes(32,'little') if isinstance(digest,int) else digest)
    raw[72:104]=raw[40:72] if again is None else (again.to_bytes(32,'little') if isinstance(again,int) else again)
    raw[104:136]=(signer.to_bytes(32,'little') if isinstance(signer,int) else signer)
    for off,value in ((136,nonce),(144,fee&((1<<64)-1)),(152,fee>>64),(160,gas),
        (168,len(body) if max_bytes is None else max_bytes),(176,canonical),(184,signer_error),
        (192,signature),(200,replay),(208,recheck),(216,reserve),(224,bound),(232,owner),
        (240,tag),(248,handoff),(256,commit),(264,release),(272,len(body))):
        struct.pack_into('<Q',raw,off,value)
    raw[320:]=body
    return {'input':raw.hex()}

def history(name,commands,arena_bytes=65536,output_bytes=131072):
    return {'name':name,'commands':commands,'arena_bytes':arena_bytes,'output_bytes':output_bytes}

def smoke():
    return [
        history('legacy-exact-duplicate-and-owned-body',[
            command(0,3,1,32),envelope(),envelope(signature=13,replay=15,recheck=17),
            envelope(2,digest=2,body=b'\x00\xffstrict',fee=(1<<128)-1),
            command(8),command(6),command(11,1),command(12,1),command(19,1),
            command(5),command(5),command(22)]),
        history('pending-handoff-commit-release-conflict',[
            command(0,1,1,32),envelope(3,body=b'nonce-owner'),command(6),
            command(12,1),command(13,1),command(14,1),command(12,1),
            command(15,1),command(12,1),command(13,1),command(16,1),command(19,1),command(22)]),
        history('release-failure-is-terminal-and-drop-does-not-repeat',[
            command(0,1,0,32),envelope(3,release=17),command(6),command(16,1),
            command(12,1),command(16,1),command(19,1),command(22)]),
        history('post-reservation-recheck-keeps-primary-error',[
            command(0,1,0,32),envelope(3,recheck=17,release=15),command(8),command(22)]),
        history('capacity-before-canonical-or-signature',[
            command(0,1,1,32),envelope(),envelope(digest=2,canonical=2,signature=13),
            envelope(canonical=2),command(5),envelope(digest=2,canonical=2),command(22)]),
        history('canonical-snapshot-without-signature-or-replay',[
            command(0,0,0,32),envelope(10,signature=13,replay=15,recheck=17,body=b'\x00A\xff'),
            command(8),command(22)])]

def complete():
    rows=smoke()
    invalid=[('missing-canonical',{'canonical':1}),('canonical-failed',{'canonical':2}),
        ('digest-changed',{'again':2}),('zero-digest',{'digest':0}),('zero-signer',{'signer':0}),
        ('missing-signer',{'signer_error':6}),('empty-body',{'body':b''}),
        ('body-too-large',{'body':bytes(range(33))}),('nonce-zero',{'nonce':0}),
        ('gas-zero',{'gas':0}),('declared-zero',{'max_bytes':0}),
        ('body-exceeds-claim',{'body':b'ab','max_bytes':1})]
    for name,kw in invalid:
        for op in (1,2,3,4,10):
            rows.append(history(f'validation-{name}-op{op}',[command(0,3,1,32),envelope(op,**kw),command(8),command(22)]))
    for field in ('signature','replay','recheck','reserve'):
        for error in range(1,22):
            op=3 if field=='reserve' else 1
            rows.append(history(f'actual-callback-error-{field}-{error}',[
                command(0,3,1,32),envelope(op,**{field:error}),command(8),command(22)]))
    for op in (3,4):
        for primary,secondary in itertools.product((1,15,17,19),(0,15,17,19)):
            rows.append(history(f'recheck-release-primary-{op}-{primary}-{secondary}',[
                command(0,3,1,32),envelope(op,recheck=primary,release=secondary),command(8),command(22)]))
    duplicate_changes=[('exact',{}),('body',{'body':b'z'}),('body-long',{'body':b'az'}),
        ('nonce',{'nonce':2}),('fee-low',{'fee':1}),('fee-high',{'fee':1<<64}),
        ('gas',{'gas':2}),('claim',{'max_bytes':2}),('signer',{'signer':8}),
        ('canonical',{'canonical':1}),('reprobe',{'again':2}),('signature-skipped',{'signature':13}),
        ('replay-skipped',{'replay':15}),('reserve-skipped',{'reserve':18}),('recheck-skipped',{'recheck':17})]
    for name,kw in duplicate_changes:
        for op in (1,2,3,4):
            rows.append(history(f'duplicate-{name}-op{op}',[command(0,1,1,32),envelope(3),
                envelope(op,**kw),command(5),command(22)]))
    for code in (0,13,17,19):
        for method in ('handoff','commit','release'):
            for bound in (0,1):
                calls=[command(0,1,0,32),envelope(3,bound=bound,owner=0,tag=0,**{method:code}),
                    command(6),command(13,1),command(12,1),command(15,1),command(14,1),
                    command(12,1),command(14,1),command(17,1),command(15,1),command(12,1),
                    command(13,1),command(16,1),command(12,1),command(16,1),command(19,1),command(22)]
                rows.append(history(f'lease-transitions-{method}-{code}-bound{bound}',calls))
    for consumer in (5,18,19,20,21,22):
        calls=[command(0,2,1,32),envelope(3,tag=99,release=17)]
        if consumer in (18,19):calls.extend([command(6),command(consumer,1)])
        else:calls.append(command(consumer))
        if consumer!=22:calls.append(command(22))
        rows.append(history(f'actual-drop-release-exactly-once-{consumer}',calls))
    rows.append(history('ready-lease-survives-gate-drop-and-reconstruction',[
        command(0,2,1,32),envelope(3,tag=44),command(6),command(21),command(13,1),
        command(14,1),command(0,1,0,32),envelope(4,digest=2,tag=55),command(6),
        command(15,1),command(16,2),command(19,1),command(19,2),command(22)]))
    for total in range(0,10):
        for reserve in sorted({0,1,total,total+1,(1<<64)-1}):
            rng=random.Random(0x4d05+total*37+reserve)
            calls=[command(0,total,reserve,64)]
            for i in range(128):
                op=rng.choices((1,2,3,4,5,6,7,8,9,20),(16,16,12,12,15,10,3,3,4,2))[0]
                if op<=4:
                    d=rng.randrange(1,19);body=(b'\x00'+bytes([d])+b'\xff')*(1+d%5)
                    calls.append(envelope(op,digest=d,signer=7+d%3,nonce=1+d%7,body=body,fee=d<<64,
                        signature=13 if i%23==0 else 0,recheck=17 if i%41==0 else 0,tag=d))
                elif op==9:
                    calls.append({'input':(bytes.fromhex(command(9)['input'])+rng.randrange(1,19).to_bytes(32,'little')).hex()})
                else:calls.append(command(op))
            calls.extend(command(5) for _ in range(total+2))
            calls.extend(command(19,handle) for handle in range(1,30))
            calls.append(command(22))
            rows.append(history(f'random-public-owner-{total}-{reserve}',calls,262144,524288))
    for n,limit,default in ((1048576,1048576,True),(1048577,1048576,True),(1048593,1048593,False)):
        body=bytes(range(256))*(n//256)+bytes(range(n%256))
        calls=[command(23,2,1) if default else command(0,2,1,limit),
            envelope(3,body=body,fee=(1<<128)-1,nonce=(1<<64)-1,gas=(1<<64)-1,max_bytes=(1<<64)-1),
            envelope(4,body=body,fee=(1<<128)-1,nonce=(1<<64)-1,gas=(1<<64)-1,max_bytes=(1<<64)-1),
            command(5),envelope(10,body=body,max_bytes=(1<<64)-1),command(22)]
        rows.append(history(f'full-owned-body-{n}-{limit}-default{int(default)}',calls,4<<20,8<<20))
    return rows
