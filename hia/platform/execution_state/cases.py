"""Canonical ownership histories. No runtime State implementation lives here."""
from __future__ import annotations
import hashlib,json,struct


def node(tag:int,payload:bytes=b'')->bytes:return bytes([tag])+struct.pack('<I',len(payload))+payload


def primitive(value)->bytes:
    output=bytearray();stack=[('value',value)]
    while stack:
        action,item=stack.pop()
        if action=='close':
            struct.pack_into('<I',output,item+1,len(output)-item-5);continue
        if action=='key':
            raw=item.encode();output.extend(struct.pack('<I',len(raw))+raw);continue
        value=item
        if value is None:output.extend(node(0))
        elif value is False:output.extend(node(1))
        elif value is True:output.extend(node(2))
        elif type(value) is int:output.extend(node(3,struct.pack('<Q',value)) if value>=0 else node(4,struct.pack('<q',value)))
        elif type(value) is float:output.extend(node(5,struct.pack('<d',value)))
        elif type(value) is str:output.extend(node(6,value.encode()))
        elif type(value) in (list,dict):
            start=len(output);output.extend(bytes([7 if type(value) is list else 8])+bytes(4)+struct.pack('<I',len(value)));stack.append(('close',start))
            if type(value) is list:stack.extend(('value',v) for v in reversed(value))
            else:
                for key,v in reversed(list(value.items())):stack.append(('value',v));stack.append(('key',key))
        else:raise TypeError(type(value))
    return bytes(output)


def object_pairs(rows)->bytes:
    return node(8,struct.pack('<I',len(rows))+b''.join(struct.pack('<I',len(k.encode()))+k.encode()+v for k,v in rows))


def normalized(value):
    if type(value) is dict:return {k:normalized(value[k]) for k in sorted(value)}
    if type(value) is list:return [normalized(v) for v in value]
    return value


def tape(value)->bytes:return b'JVT1'+primitive(value)


def map_bytes(rows:dict)->bytes:
    output=bytearray(struct.pack('<Q',len(rows)))
    for key in sorted(rows):
        k=key.encode();v=rows[key];encoded=b'' if v is ABSENT else tape(normalized(v))
        output.extend(struct.pack('<QQ',len(k),len(encoded))+k+encoded)
    return bytes(output)


ABSENT=object()


def patch_bytes(writes,reads,scans,fee,receipt)->bytes:
    return struct.pack('<QQ',fee,len(receipt))+receipt+map_bytes(writes)+map_bytes(reads)+struct.pack('<Q',len(scans))+b''.join(struct.pack('<Q',len(k.encode()))+k.encode()+map_bytes(scans[k]) for k in sorted(scans))


class History:
    def __init__(self,name):self.name=name;self.steps=[];self.counter=0
    def step(self,op,*,a=None,b=None,label=None,key=None,data=None,arg=0,expect=None):
        row={'op':op}
        for k,v in (('a',a),('b',b),('as',label)):
            if v is not None:row[k]=v
        if key is not None:row['key_hex']=key.encode().hex()
        if data is not None:row['data_hex']=data.hex()
        if arg:row['arg']=arg
        if expect is not None:row['expect']={'status':0,**expect}
        self.steps.append(row);return label
    def value(self,value,label=None,raw=None):
        self.counter+=1;label=label or 'v'+str(self.counter);self.step('value.new',label=label,data=tape(value) if raw is None else raw,expect={'result_nonzero':True});return label
    def put(self,state,key,value):
        v=self.value(value);self.step('state.put',a=state,b=v,key=key);return v
    def state(self,label,rows):
        self.step('state.new',label=label,expect={'result_nonzero':True})
        for k,v in rows.items():self.put(label,k,v)
        return label
    def export(self,label,rows):self.step('state.export',a=label,expect={'data_hex':map_bytes(rows).hex()})
    def finish(self):
        self.step('close',expect={'live_objects':0,'result':0,'data_hex':''});return {'schema':'trnm.execution-state-history.v1','name':self.name,'commands':self.steps}


def histories()->list[dict]:
    result=[]
    h=History('empty-state-owner-and-empty-patch');h.state('s',{});h.step('state.get',a='s',key='',expect={'result':0});h.step('state.prefix',a='s',key='',label='empty');h.export('empty',{});h.step('view.new',a='s',label='view');h.step('view.get',a='view',key='missing',expect={'result':0});h.step('patch.take',a='view',label='p',arg=(1<<64)-1,data=b'\x00\xffreceipt');h.step('patch.export',a='p',expect={'data_hex':patch_bytes({}, {'missing':ABSENT},{},(1<<64)-1,b'\x00\xffreceipt').hex()});h.step('patch.current',a='p',b='s',expect={'result':1});h.step('patch.apply',a='p',b='s');h.step('state.root',a='s',expect={'data_hex':'3065e2b0b90b9dbec19b9e6d8c574dd19dc42d59628dbbe65826dbaa0c558f29'});result.append(h.finish())
    h=History('first-read-survives-multiple-writes-and-consumed-stale-apply');h.state('base',{'a':1,'keep':8});h.step('state.clone',a='base',label='current');h.step('view.new',a='base',label='view');h.step('view.get',a='view',key='a',label='old');h.step('value.export',a='old',expect={'data_hex':tape(1).hex()});v=h.value(2);h.step('view.put',a='view',b=v,key='a');v=h.value(3);h.step('view.put',a='view',b=v,key='a');h.step('view.get',a='view',key='a',label='latest');h.step('value.export',a='latest',expect={'data_hex':tape(3).hex()});h.step('patch.take',a='view',label='patch',arg=19,data=b'raw\0receipt');h.step('patch.export',a='patch',expect={'data_hex':patch_bytes({'a':3},{'a':1},{},19,b'raw\0receipt').hex()});h.put('current','a',9);h.step('patch.current',a='patch',b='current',expect={'result':0});h.step('patch.clone',a='patch',label='copy');h.step('patch.apply',a='patch',b='current');h.export('current',{'a':3,'keep':8});h.step('patch.current',a='copy',b='base',expect={'result':1});h.step('patch.drop',a='copy');result.append(h.finish())
    keys={'':0,'a':1,'a\0':2,'a\x7f':3,'aλ':4,'b':5,'λ':6,'😀':7,'\U0010ffff':8,'\U0010ffffx':9}
    for prefix in ('','a','a\0','a\x7f','aλ','λ','😀','\U0010ffff','absent','\U0010ffffz'):
        h=History('prefix-complete-'+prefix.encode().hex());h.state('base',keys);h.step('state.prefix',a='base',key=prefix,label='direct');snapshot={k:v for k,v in keys.items() if k.startswith(prefix)};h.export('direct',snapshot);h.step('view.new',a='base',label='view');h.step('view.scan',a='view',key=prefix,label='first');h.export('first',snapshot);newkey=prefix+'new';v=h.value({'n':0.0,'a':[1]});h.step('view.put',a='view',b=v,key=newkey);h.step('view.scan',a='view',key=prefix,label='second');overlay={**snapshot,newkey:{'n':0.0,'a':[1]}};h.export('second',overlay);h.put('first',prefix+'detached',77);h.step('view.scan',a='view',key=prefix,label='third');h.export('third',overlay);h.step('patch.take',a='view',label='p');h.step('patch.export',a='p',expect={'data_hex':patch_bytes({newkey:{'n':0.0,'a':[1]}},{newkey:ABSENT},{prefix:snapshot},0,b'').hex()});h.step('patch.current',a='p',b='base',expect={'result':1});result.append(h.finish())
    for mutation in ('insert','delete','change','outside','none-to-null','restore'):
        h=History('prefix-current-'+mutation);h.state('base',{'a:1':1,'a:2':2,'z':3});h.step('state.clone',a='base',label='current');h.step('view.new',a='base',label='view');h.step('view.scan',a='view',key='a:',label='scan');h.step('patch.take',a='view',label='p')
        if mutation=='insert':h.put('current','a:3',3)
        if mutation=='delete':h.step('state.remove',a='current',key='a:2',label='removed');h.step('value.export',a='removed',expect={'data_hex':tape(2).hex()})
        if mutation=='change':h.put('current','a:2',2.0)
        if mutation=='outside':h.put('current','z',99)
        if mutation=='none-to-null':h.put('current','a:3',None)
        if mutation=='restore':h.put('current','a:2',99);h.put('current','a:2',2)
        h.step('patch.current',a='p',b='current',expect={'result':int(mutation in ('outside','restore'))});h.step('patch.clone',a='p',label='clone');h.step('patch.apply',a='clone',b='current');h.step('patch.current',a='p',b='current',expect={'result':int(mutation in ('outside','restore'))});result.append(h.finish())
    pairs=[(-0.0,0.0,True),(0.0,0,False),(1.0,1,False),(False,0,False),(True,1,False),(None,False,False),(-1,-1,True),((1<<64)-1,(1<<64)-2,False),({'z':-0.0,'a':[1,'λ']},{'a':[1,'λ'],'z':0.0},True),({'a':0},{'a':0.0},False),([1,True],[1,1],False),('λ','λ',True),('','\0',False),({},[],False)]
    for index,(left,right,equal) in enumerate(pairs):
        h=History('typed-current-equality-'+str(index));h.state('base',{'key':left});h.step('state.clone',a='base',label='current');h.step('view.new',a='base',label='view');h.step('view.get',a='view',key='key',label='first');v=h.value(right);h.step('value.eq',a='first',b=v,expect={'result':int(equal)});h.step('state.put',a='current',b=v,key='key',label='old');h.step('patch.take',a='view',label='p');h.step('patch.current',a='p',b='current',expect={'result':int(equal)});h.step('value.export',a='first',expect={'data_hex':tape(normalized(left)).hex()});result.append(h.finish())
    for initial_present in (False,True):
        for after_present in (False,True):
            h=History('point-null-absence-'+str(int(initial_present))+str(int(after_present)));h.state('base',{'key':None} if initial_present else {});h.step('state.clone',a='base',label='current');h.step('view.new',a='base',label='view');h.step('view.get',a='view',key='key',label='value',expect={'result_nonzero':initial_present});h.step('patch.take',a='view',label='p')
            if after_present:h.put('current','key',None)
            else:h.step('state.remove',a='current',key='key')
            h.step('patch.current',a='p',b='current',expect={'result':int(initial_present==after_present)});result.append(h.finish())
    for n in (0,1,15,16,127,128,159,160,161,4097):
        h=History('unbounded-intermediate-key-'+str(n));key='k'*n;h.state('base',{key:1});h.step('state.clone',a='base',label='current');h.step('view.new',a='base',label='view');h.step('view.get',a='view',key=key,label='value');h.step('value.export',a='value',expect={'data_hex':tape(1).hex()});h.step('view.scan',a='view',key=key,label='scan');h.export('scan',{key:1});h.step('patch.take',a='view',label='p');h.step('patch.current',a='p',b='current',expect={'result':1});h.step('state.root',a='base',expect={'status':0 if n<=160 else 69});result.append(h.finish())
    for n in (0,1,4094,4095,4096,65537,(1<<20)+1):
        value='x'*n;h=History('unbounded-intermediate-value-'+str(n));h.state('base',{'a':value});h.step('view.new',a='base',label='view');h.step('view.get',a='view',key='a',label='value');h.step('value.export',a='value',expect={'data_hex':tape(value).hex()});h.step('view.scan',a='view',key='',label='snapshot');h.export('snapshot',{'a':value});h.step('patch.take',a='view',label='p');h.step('patch.current',a='p',b='base',expect={'result':1});h.step('patch.clone',a='p',label='clone');h.step('state.root',a='base',expect={'status':0 if n<=4094 else 69});result.append(h.finish())
    canonical=[('float',{'key':0.0},70),('nonascii-string',{'key':'λ'},71),('nonascii-object-key',{'key':{'λ':0.0}},71),('first-float-before-late-key',{'key':{'a':0.5,'λ':0}},70),('late-float-before-row-key-limit',{'a'*161:0,'z':0.5},70),('late-nonascii-before-value-limit',{'a':'x'*4095,'z':'λ'},71),('nonascii-state-key-permitted',{'λ':0},0),('canonical-escapes',{'':{'z':'\0\b\t\n\f\r\x1f\x7f"\\/','a':[None,True,-(1<<63),(1<<64)-1]}},0)]
    for name,rows,status in canonical:
        h=History('root-order-'+name);h.state('s',rows);h.step('state.root',a='s',expect={'status':status});h.export('s',rows);result.append(h.finish())
    h=History('duplicate-object-last-wins-and-type-normalization');raw=b'JVT1'+object_pairs([('z',primitive(0.5)),('a',primitive('λ')),('z',primitive(7)),('a',primitive(None))]);v=h.value(None,raw=raw);h.step('value.export',a=v,expect={'data_hex':tape({'a':None,'z':7}).hex()});h.state('s',{});h.step('state.put',a='s',b=v,key='');h.step('state.root',a='s');result.append(h.finish())
    for signed in (0,1,(1<<63)-1):
        h=History('positive-i64-normalizes-'+str(signed));left=h.value(None,raw=b'JVT1'+node(4,struct.pack('<q',signed)));right=h.value(signed);h.step('value.eq',a=left,b=right,expect={'result':1});h.step('value.export',a=left,expect={'data_hex':tape(signed).hex()});result.append(h.finish())
    for depth in (128,512):
        value=None
        for unused in range(depth):value=[value]
        h=History('constructed-deep-value-'+str(depth));h.state('s',{'x':value});h.step('state.get',a='s',key='x',label='v');h.step('value.export',a='v',expect={'data_hex':tape(value).hex()});h.step('state.root',a='s');result.append(h.finish())
    h=History('scan-clone-and-reclaim-independent-ownership');h.state('base',{'a':{'nested':[0,-0.0]},'b':'x'});h.step('view.new',a='base',label='view');h.step('view.scan',a='view',key='',label='scan');h.step('state.clear',a='scan');h.step('view.scan',a='view',key='',label='again');h.export('again',{'a':{'nested':[0,-0.0]},'b':'x'});h.step('patch.take',a='view',label='patch',arg=7,data=b'bytes\xff');h.step('patch.clone',a='patch',label='p2');h.step('patch.drop',a='patch');h.step('state.drop',a='base');h.step('state.new',label='empty');h.step('patch.current',a='p2',b='empty',expect={'result':0});h.step('patch.apply',a='p2',b='empty');h.export('empty',{});result.append(h.finish())
    return result


def canonical_bytes()->bytes:
    return b''.join(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()+b'\n' for row in histories())
