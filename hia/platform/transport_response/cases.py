"""Independent signed-response and digest-signing fixtures, never runtime authority."""
import copy,hashlib,json,random,struct
from hia.platform.transport_request.cases import Fixture,canonical,pon
from hia.tests.test_ed25519 import sign,L,P
from .values import Float,tape,render,node,value_wire_reference as value_wire_code

LIMIT=2097152
RESPONSE_SCHEMA='trnm-authenticated-response-v1'
FIELD_ORDER=('schema','session','replay_nonce','request_digest','terminal','ok','value','signature')

def frame(body):return len(body).to_bytes(4,'big')+body

class ResponseFixture:
    def __init__(self,request=None,nonce=1,generation=1,context=None):
        self.owner=Fixture(generation=generation,context=context)
        self.request=request or {'op':'head'}
        request=self.owner.envelope(self.request,nonce=nonce)
        self.request_digest=pon(b'native-authenticated-request-sign-v1',canonical({k:request[k]for k in ('schema','session','replay_nonce','request')}))
        self.session=self.owner.session;self.nonce=nonce
        self.config=(b'TRNMAR01'+struct.pack('<Q',generation)+b''.join(bytes.fromhex(self.session[k])for k in
          ('network','parameters','genesis','profile','peer','server','session'))+struct.pack('<Q',nonce)+self.request_digest)

    def authority(self,value=None,terminal=True,ok=True):
        prefix=canonical(dict(schema=RESPONSE_SCHEMA,session=self.session,replay_nonce=self.nonce,
          request_digest=self.request_digest.hex(),terminal=terminal,ok=ok))[:-1]
        return prefix+b',"value":'+render(value)+b'}'

    def body(self,value=None,terminal=True,ok=True):
        authority=self.authority(value,terminal,ok)
        digest=pon(b'native-authenticated-response-sign-v1',authority)
        signature=sign(self.owner.server,digest)[1]
        return authority[:-1]+b',"signature":"'+signature.hex().encode()+b'"}'

    def encode_input(self,value=None,terminal=True,error=None):
        payload=tape(value,1)if error is None else error.encode('utf-8')
        return b'TRNMAS01'+self.config[8:]+bytes([int(terminal),int(error is not None)])+bytes(6)+self.owner.server+payload

    def metadata(self,body):
        marker=b'"value":';start=body.index(marker)+len(marker)
        boundary=body.rfind(b',"signature":')
        # Only the successful canonical envelope reaches this oracle branch.
        envelope=json.loads(body)
        digest=pon(b'native-authenticated-response-sign-v1',body[:boundary]+b'}')
        return(struct.pack('<5Q',len(body)+4,start+4,boundary-start,int(envelope['terminal']),int(envelope['ok']))+
          digest+struct.pack('<3Q',self.nonce,self.session['generation'],0))

def encoding_cases(context=None):
    fixtures=[]
    variants=[
      ({'op':'head'},{'network':'test','parameters':'02'*32,'genesis':'03'*32,'tip':'04'*32,'chainwork_hex':'00','state_root':'05'*32,
        'height':0,'generation':1,'state_keys':7,'stored_blocks':1,'events':0,'production_activation':False}),
      ({'op':'submit','packet':'deadbeef'},{'block':'01'*32,'active':'02'*32,'generation':1,'physical_execution':False}),
      ({'op':'history','tip':'UPPERCASE','after':''},{'schema':'pon-native-history-v1','network':'01'*32,'parameters':'02'*32,
        'genesis':'03'*32,'tip':'04'*32,'after':'','packets':[],'next':'','complete':True}),
      ({'op':'confirm','transaction':'x','block':''},{'transaction':'11'*32,'block':'12'*32,'known':False,'confirmations':0}),
      ({'op':'confirm_many','queries':[{'transaction':'x','block':'y'}]},{'observations':[],'ancestry_checked':0,'distinct_bodies_checked':0}),
    ]
    for i,(request,value)in enumerate(variants):
        f=ResponseFixture(request,context=context)
        body=f.body(value)
        fixtures.append(dict(name=f'five-request-contexts-{i}',input=f.encode_input(value),expected_frame=frame(body),body=body,fixture=f,value=value,terminal=True,error=None))
    f=ResponseFixture(context=context)
    def add(name,value=None,terminal=True,error=None):
        v=value if error is None else {'error':error}
        body=f.body(v,terminal,error is None)
        fixtures.append(dict(name=name,input=f.encode_input(value,terminal,error),expected_frame=frame(body),body=body,fixture=f,value=v,terminal=terminal,error=error))
    for terminal in (False,True):
        add(f'null-terminal-{terminal}',None,terminal)
        add(f'full-error-terminal-{terminal}',terminal=terminal,error='AUTH_RESPONSE_NOT_COMMITTED:'+('完整é🙂 error /\\"\0\n '*100))
    add('all-value-kinds',{'a':None,'b':False,'c':True,'d':[0,(1<<64)-1,-(1<<63),Float(0),Float(1<<63),Float(1),Float(0x7fefffffffffffff)],
      'e':'\0\b\t\n\f\r\x1f\x7f é 🙂 \u2028','f':{'\n':0,'A':1,'é':2,'\ue000':3,'\U00010000':4}})
    add('untruncated-error-10000',error='E'*10000)
    add('stable-floats',[Float(0),Float(1<<63),Float(0x3ff0000000000000),Float(0x3fb999999999999a)])
    base=len(f.body(''))
    add('exact-body-2MiB','x'*(LIMIT-base))
    errorbase=len(f.body({'error':''},False,False))
    add('exact-error-body-2MiB',terminal=False,error='E'*(LIMIT-errorbase))
    # Dense nodes retain the full framing/body boundary instead of using a
    # verifier message bound. Values are decoded/hashed as one exact stream.
    base=len(f.body([]));count=(LIMIT-base)//2
    dense=[0]*count
    body=f.body(dense)
    assert len(body)<=LIMIT
    add('dense-near-2MiB-array',dense)
    return fixtures

def verification_cases(context=None,encoded=None):
    encoded=encoded or encoding_cases(context)
    rows=[]
    f=ResponseFixture(context=context);body=f.body({'a':1,'b':2});base=json.loads(body)
    def add(name,raw=body,code=0,config=None,wire=None,tail=b'',fixture=f):
        rawframe=frame(raw)if wire is None else wire
        rows.append(dict(name=name,input=(fixture.config if config is None else config)+rawframe+tail,expected_code=code,
          expected_output=fixture.metadata(raw)if code==0 else None,body=raw))
    for row in encoded:
        raw=row['body'];start=raw.index(b'"value":')+8;end=raw.rfind(b',"signature":')
        code=0 if value_wire_code(raw[start:end],1)==0 else 4
        add('produced-'+row['name'],raw,code,fixture=row['fixture'])
    add('valid-terminal-true')
    add('next-frame-retained',tail=b'\0\0\0\x01x')
    for n in range(4):add('prefix-truncated-'+str(n),wire=b'\0'*n,code=1)
    add('body-truncated',wire=(len(body)+1).to_bytes(4,'big')+body,code=1)
    add('body-empty',b'',2)
    add('body-over-limit',b'x'*(LIMIT+1),2)
    add('prefix-little-endian',wire=len(body).to_bytes(4,'little')+body,code=2)
    def changed(name,key,value,code):
        obj=copy.deepcopy(base);obj[key]=value;add(name,canonical(obj),code)
    for key in FIELD_ORDER:
        obj=copy.deepcopy(base);del obj[key];add('missing-'+key,canonical(obj),3)
    for key in f.session:
        obj=copy.deepcopy(base);del obj['session'][key];add('session-missing-'+key,canonical(obj),3)
    for key,value in [('schema',0),('session',False),('replay_nonce',-1),('replay_nonce',1.0),('replay_nonce',1<<64),
      ('request_digest',None),('terminal',0),('terminal','true'),('ok',None),('signature',0)]:
        changed('type-'+key+'-'+str(len(rows)),key,value,3)
    changed('unknown-envelope','extra',1,3)
    obj=copy.deepcopy(base);obj['session']['extra']=1;add('unknown-session',canonical(obj),3)
    add('duplicate-envelope',body[:-1]+b',"schema":"x"}',3)
    add('duplicate-session',body.replace(b'"network":',b'"network":"x","network":',1),3)
    for token in (b'-0',b'01',b'1e0',b'1.0',b'+1',b'18446744073709551616'):
        add('nonce-token-'+token.decode(),body.replace(b'"replay_nonce":1,',b'"replay_nonce":'+token+b',',1),3)
    for raw in [b'{}',b'[]',b'null',b'true',b'1',b'"x"',body+b'x',b'\xef\xbb\xbf'+body]:add('root-'+str(len(rows)),raw,3)
    for raw in [b' '+body,body+b' ',body.replace(b'"schema":',b'"schema": ',1),canonical(dict(reversed(list(base.items())))),canonical(list(base.values()))]:
        add('noncanonical-'+str(len(rows)),raw,4)
    obj=copy.deepcopy(base);obj['session']=dict(reversed(list(obj['session'].items())));add('session-order',canonical(obj),4)
    obj=copy.deepcopy(base);obj['session']=list(obj['session'].values());add('session-sequence',canonical(obj),4)
    add('escaped-key',body.replace(b'"schema"',b'"sch\\u0065ma"',1),4)
    add('escaped-schema',body.replace(b'trnm-authenticated-response-v1',b'trnm-authenticated-response-v\\u0031',1),4)
    value=render({'a':1,'b':2})
    for raw,code in [(b'{"b":2,"a":1}',4),(b'{"a":0,"a":1,"b":2}',4),(b'1e0',4),(b'-0',4),(b'0e9999999999',4),
      (b'1e9999999999',3),(b'1e-',3),(b'"\\ud800"',3),(b'"\xff"',3),(b'"\\u00e9"',4),(b'"\\/"',4),
      (b'"\\u001F"',4),(b'[1,]',3),(b'{"a":1,}',3),(b'{"b":0,"a":1,"x":1e999}',3)]:
        add('value-grammar-'+str(len(rows)),body.replace(b'"value":'+value,b'"value":'+raw,1),code)
    for depth in (125,126,127,128):
        raw=b'['*depth+b'0'+b']'*depth
        # Correct syntax/canonicality survives up to depth126; its stale
        # signature then fails. Deeper values are serialization failures first.
        add('value-depth-'+str(depth),body.replace(b'"value":'+value,b'"value":'+raw,1),6 if depth<=126 else 3)
    for key in ('schema','request_digest'):
        changed('context-'+key,key,'wrong',5)
    changed('context-nonce','replay_nonce',0,5)
    for key in f.session:
        obj=copy.deepcopy(base);obj['session'][key]=2 if key=='generation'else'00'*32;add('context-session-'+key,canonical(obj),5)
    for label,signature in [('upper',base['signature'].upper()),('short',base['signature'][:-2]),('nonhex','g'*128),('zero','0'*128),
      ('noncanonical-r',P.to_bytes(32,'little').hex()+base['signature'][64:]),
      ('negative-zero-r',(1|(1<<255)).to_bytes(32,'little').hex()+base['signature'][64:]),
      ('scalar-order',base['signature'][:64]+L.to_bytes(32,'little').hex()),
      ('scalar-plus-order',base['signature'][:64]+(
        int.from_bytes(bytes.fromhex(base['signature'][64:]),'little')+L).to_bytes(32,'little').hex())]:
        changed('signature-'+label,'signature',signature,6)
    for key,new in [('terminal',False),('ok',False),('value',{'a':1,'b':3})]:changed('signed-field-'+key,key,new,6)
    obj=copy.deepcopy(base);obj['schema']='wrong';obj['signature']='g'*128;add('context-before-signature',canonical(obj),5)
    obj=copy.deepcopy(base);obj['schema']='wrong';obj['extra']=0;add('typed-before-context',canonical(obj),3)
    obj=copy.deepcopy(base);obj['signature']='g'*128;add('canonical-before-signature',b' '+canonical(obj),4)
    large=next(r for r in encoded if r['name']=='exact-body-2MiB')['body']
    at=large.rfind(b'x"');assert at>=0
    add('last-value-byte-signature-bound',large[:at]+b'y'+large[at+1:],6)
    for name,config in [('owner-short',f.config[:279]),('owner-magic',b'xxxxxxxx'+f.config[8:])]:
        rows.append(dict(name=name,input=config,expected_code=101 if name=='owner-short' else 102,expected_output=None,body=b''))
    return rows

def encoding_negatives(context=None):
    f=ResponseFixture(context=context);valid=f.encode_input(None)
    rows=[]
    def add(name,payload,code):rows.append(dict(name=name,input=payload,expected_code=code))
    add('short',valid[:319],4294967264)
    add('magic',b'xxxxxxxx'+valid[8:],4294967264)
    for at,value in [(280,2),(281,2),(282,1),(287,1)]:
        raw=bytearray(valid);raw[at]=value;add('flag-'+str(at),bytes(raw),4294967264)
    add('bad-tape-magic',valid[:320]+b'JVT1'+valid[324:],4294967265)
    add('bad-tape-outer',valid[:324]+b'\0'+valid[325:],4294967265)
    add('bad-tape-trailing',valid+b'x',4294967265)
    add('nonfinite',valid[:320]+b'JVT2\1'+node(5,struct.pack('<Q',0x7ff0000000000000)),4294967265)
    raw=bytearray(f.encode_input(error=''));raw+=b'\xff';add('error-utf8',bytes(raw),4294967265)
    raw=bytearray(valid);raw[288]^=1;add('seed-does-not-own-server',bytes(raw),4294967269)
    deep=node(0)
    for _ in range(127):deep=node(7,struct.pack('<I',1)+deep)
    add('response-value-depth',valid[:320]+b'JVT2\1'+deep,4294967266)
    base=len(f.body(''));add('over-body-limit',f.encode_input('x'*(LIMIT-base+1)),4294967267)
    add('valid-value-over-limit-string',f.encode_input('x'*(LIMIT-1)),4294967267)
    add('valid-value-over-limit-dense',f.encode_input([0]*(LIMIT//2)),4294967267)
    add('value-syntax-before-output-limit',f.encode_input('x'*(LIMIT-1))+b'x',4294967265)
    add('typed-input-limit',valid[:320]+b'x'*16777222,4294967267)
    return rows


def signing_cases():
    rng=random.Random(0x5349474e)
    rows=[(bytes(32),bytes(32)),(b'\xff'*32,b'\xff'*32),(bytes(range(32)),bytes(range(31,-1,-1)))]
    for i in range(32):
        rows.append((bytes([1<<i%8 if j==i else 0 for j in range(32)]),hashlib.sha256(b'bit'+bytes([i])).digest()))
    rows += [(rng.randbytes(32),rng.randbytes(32))for _ in range(32)]
    return [dict(name=f'sign-{i:03d}',input=seed+message,expected_output=b''.join(sign(seed,message)))
            for i,(seed,message)in enumerate(rows)]
