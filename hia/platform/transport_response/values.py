"""Independent complete JSON Value syntax, canonicality, and typed-tape controls."""
import json,random,struct
from .numbers import format64,float_cases,number_reference

class Number:
    def __init__(self,raw):self.render=number_reference(raw.encode())[3].decode()

def literal_invalid(x):raise ValueError('non-JSON constant')

def wire_canonical(value,depth=0):
    if isinstance(value,Number):return value.render
    if value is None:return 'null'
    if value is True:return 'true'
    if value is False:return 'false'
    if isinstance(value,str):
        if any(0xd800<=ord(c)<=0xdfff for c in value):raise ValueError('surrogate')
        return json.dumps(value,ensure_ascii=False,separators=(',',':'))
    if depth>=127:raise ValueError('recursion')
    if isinstance(value,list):return '['+','.join(wire_canonical(v,depth+1)for v in value)+']'
    return '{'+','.join(wire_canonical(k,depth+1)+':'+wire_canonical(v,depth+1)for k,v in sorted(value.items()))+'}'

def value_wire_reference(raw,outer):
    try:
        text=raw.decode('utf-8')
        v=json.loads(text,parse_int=Number,parse_float=Number,parse_constant=literal_invalid)
        return 0 if wire_canonical(v,outer).encode()==raw else 1
    except (ValueError,UnicodeError,RecursionError):return 2

def value_wire_cases():
    values=[b'null',b'true',b'false',b'[]',b'{}',b'0',b'-0',b'-0.0',b'1e0',b'1.0',b'""',
      b'{"a":1,"b":2}',b'{"b":2,"a":1}',b'{"a":1,"a":2}',b'{"a":1,"a":null}',
      b'{"":0,"a":1}',b'{"a":1,"":0}',b'{"\\u0061":1,"b":2}',b'{"a":1,"\\u0061":2}',
      b'{"\\n":0,"A":1}',b'{"A":1,"\\n":0}',b'{"\\u0001":0,"\\b":1,"\\t":2}',
      b'[0,true,null,"x",{"y":[1.0,-0.0]}]',b' [ 1 , { "b": 2, "a" : true } ] ',
      b'{"\xf0\x90\x80\x80":0,"\xee\x80\x80":1}',b'{"\xee\x80\x80":0,"\xf0\x90\x80\x80":1}',
      b'"/"',b'"\\/"',b'"\\u002f"',b'"\\ud834\\udd1e"',b'"\xf0\x9d\x84\x9e"',
      b'"\\u2028"','"\u2028"'.encode(),b'"\\u007f"',b'"\x7f"']
    for cp in list(range(256))+[0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]:
        text=json.dumps(chr(cp),ensure_ascii=False).encode()
        values.append(text)
        values.append(json.dumps(chr(cp),ensure_ascii=True).encode())
        if cp<65536:values.append(('"\\u%04X"'%cp).encode())
    invalid=[b'',b'nul',b'NULL',b'True',b'falsex',b'01',b'NaN',b'Infinity',b'[]x',b'{}{}',b'[1,]',b'[,1]',
      b'{,}',b'{"a":1,}',b'{"a"}',b'{a:1}',b'{"a":}',b'{"a"::1}',b'{"a":1 "b":2}',b'"',b'"x',
      b'"\x00"',b'"\x1f"',b'"\\x20"',b'"\\u"',b'"\\u000"',b'"\\uXXXX"',b'"\\ud800"',b'"\\udc00"',
      b'"\\ud800\\u0000"',b'"\\udc00\\ud800"',b'"\\ud800\\uD800"',b'"\xc0\x80"',b'"\xc2"',
      b'"\xe0\x80\x80"',b'"\xed\xa0\x80"',b'"\xf0\x80\x80\x80"',b'"\xf4\x90\x80\x80"',b'"\xf5\x80\x80\x80"',
      b'"\xff"',b'"\x80"',b'[ {"b":0,"a":1}, {"z":1,} ]',b'{"b":0,"a":1,"x":1e999}']
    values+=invalid
    for n in (124,125,126,127,128,129):
        values += [b'['*n+b'0'+b']'*n,b'{"a":'*n+b'null'+b'}'*n]
    rng=random.Random(0x56414c55)
    scalars=[None,False,True,0,1,-1,18446744073709551615,-9223372036854775808,'A','\0','𝄞','é','\n','\x1f','\\"']
    def value(depth):
        if depth>4 or rng.randrange(3)==0:return rng.choice(scalars)
        if rng.randrange(2):return[value(depth+1)for _ in range(rng.randrange(6))]
        pairs={rng.choice(['A','a','b','𝄞','é','\n','\x00','\\','"','']):value(depth+1)for _ in range(rng.randrange(6))}
        return pairs
    for _ in range(1024):
        v=value(0)
        values.append(json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode())
        values.append(json.dumps(v,sort_keys=False,ensure_ascii=True).encode())
    values += [b'"'+b'x'*(2097152-2)+b'"',b'['+b'0,'*((2097152-2)//2-1)+b'0]',
      b'"'+b'\xc3\xa9'*((2097152-2)//2)+b'"',b'['+b'1e-4,'*300000+b'0]',
      b'{"'+b'a'*1000000+b'":0,"'+b'a'*999999+b'b":1}',
      b'{"'+b'a'*999999+b'b":0,"'+b'a'*1000000+b'":1}']
    return list(dict.fromkeys(values))

INVALID=4294967280
DEPTH=4294967281
LIMIT=4294967282

class Float:
    def __init__(self,bits):self.bits=bits

def node(tag,payload=b''):return bytes([tag])+struct.pack('<I',len(payload))+payload

def encode(value):
    if value is None:return node(0)
    if value is False:return node(1)
    if value is True:return node(2)
    if isinstance(value,Float):return node(5,struct.pack('<Q',value.bits))
    if isinstance(value,int):return node(3 if value>=0 else 4,struct.pack('<Q',value&((1<<64)-1)))
    if isinstance(value,str):return node(6,value.encode('utf-8'))
    if isinstance(value,list):return node(7,struct.pack('<I',len(value))+b''.join(encode(v)for v in value))
    return node(8,struct.pack('<I',len(value))+b''.join(struct.pack('<I',len(k.encode()))+k.encode()+encode(v)for k,v in sorted(value.items())))

def render(value):
    if value is None:return b'null'
    if value is False:return b'false'
    if value is True:return b'true'
    if isinstance(value,Float):return format64(value.bits).encode()
    if isinstance(value,int):return str(value).encode()
    if isinstance(value,str):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
    if isinstance(value,list):return b'['+b','.join(render(v)for v in value)+b']'
    return b'{'+b','.join(render(k)+b':'+render(v)for k,v in sorted(value.items()))+b'}'

def tape(value,outer=0):return b'JVT2'+bytes([outer])+encode(value)

def value_encode_cases():
    values=[None,False,True,0,1,-1,(1<<64)-1,-(1<<63),'',[],{},'A/\\"\n\r\t\b\f\0\x1f é 𝄞 \u2028',
      {'\0':0,'\n':1,'"':2,'/':3,'A':4,'\\':5,'é':6,'\ue000':7,'\U00010000':8},
      {'error':'AUTH_RESPONSE_NOT_COMMITTED:'+('failure details; '*1000)},
      {'block':'00'*32,'active':'01'*32,'generation':(1<<64)-1,'physical_execution':False},
      {'observations':[],'ancestry_checked':0,'distinct_bodies_checked':0},
      {'schema':'pon-native-history-v1','network':'x','parameters':'ab'*32,'genesis':'cd'*32,'tip':'00'*32,'after':'11'*32,'packets':[],'next':'11'*32,'complete':True},
      ''.join(chr(c)for c in range(0x100)),[chr(c)for c in range(0x100)]+['\u07ff','\u0800','\ud7ff','\ue000','\uffff','\U00010000','\U0010ffff']]
    rng=random.Random(0x54595045)
    leaves=[None,False,True,0,1,-1,1<<63,(1<<64)-1,-(1<<63),'A','\n','\x1f','𝄞','é']
    def value(depth):
        if depth>=5 or rng.randrange(3)==0:
            if rng.randrange(4)==0:return Float((rng.randrange(2047)<<52)|rng.getrandbits(52)|(rng.randrange(2)<<63))
            return rng.choice(leaves)
        if rng.randrange(2):return[value(depth+1)for _ in range(rng.randrange(5))]
        return{rng.choice(['a','b','A','𝄞','é','\0','\n','"','\\','']):value(depth+1)for _ in range(rng.randrange(5))}
    values += [value(0)for _ in range(256)]
    rows=[(f'value-{i:03d}',tape(v),render(v))for i,v in enumerate(values)]
    floats=[Float(v)for v in float_cases()]
    rows.append(('complete-finite-f64-array',tape(floats),render(floats)))
    for outer in (0,1):
        for count in (125,126,127,128):
            encoded=node(3,bytes(8));wanted=b'0'
            for _ in range(count):encoded=node(7,struct.pack('<I',1)+encoded);wanted=b'['+wanted+b']'
            rows.append((f'depth-{count}-outer-{outer}',b'JVT2'+bytes([outer])+encoded,DEPTH if count+outer>127 else wanted))
    malformed=[b'',b'JVT2',b'JVT2\0',b'JVT1'+bytes(6),b'JVT2\x02'+bytes(5),b'JVT2\0'+node(9),
      b'JVT2\0'+node(0,b'x'),b'JVT2\0'+node(1,b'x'),b'JVT2\0'+node(2,b'x'),b'JVT2\0'+node(3,b'x'*7),
      b'JVT2\0'+node(4,b'x'*9),b'JVT2\0'+node(5,b'x'*7),b'JVT2\0'+node(5,struct.pack('<Q',0x7ff0000000000000)),
      b'JVT2\0'+node(5,struct.pack('<Q',0xfff0000000000000)),b'JVT2\0'+node(5,struct.pack('<Q',0x7ff8000000000001)),
      b'JVT2\0'+node(6,b'\xc0\x80'),b'JVT2\0'+node(6,b'\xed\xa0\x80'),b'JVT2\0'+node(6,b'\xf4\x90\x80\x80'),
      b'JVT2\0'+node(7,struct.pack('<I',1)),b'JVT2\0'+node(7,struct.pack('<I',0)+node(0)),
      b'JVT2\0'+node(7,struct.pack('<I',0xffffffff)),b'JVT2\0'+node(8,struct.pack('<I',0xffffffff)),
      b'JVT2\0'+node(8,struct.pack('<I',1)+struct.pack('<I',2)+b'a'),tape(None)+b'x']
    for pairs in [[('b',0),('a',1)],[('a',0),('a',1)],[('a',0),('',1)]]:
        payload=struct.pack('<I',len(pairs))+b''.join(struct.pack('<I',len(k))+k.encode()+encode(v)for k,v in pairs)
        malformed.append(b'JVT2\0'+node(8,payload))
    valid=tape({'a':[1,True,'é']})
    malformed += [valid[:i]for i in range(len(valid))]
    rows += [(f'malformed-{i:03d}',raw,INVALID)for i,raw in enumerate(malformed)]
    # Every original-possible output Value fits this 16 MiB typed tape bound;
    # the million-u64 array exercises the largest per-JSON-byte tape overhead.
    count=(2097152-1)//2
    rows.append(('million-u64-nodes',b'JVT2\0'+node(7,struct.pack('<I',count)+node(3,bytes(8))*count),b'['+b'0,'*(count-1)+b'0]'))
    rows.append(('exact-2MiB-ascii-string',tape('x'*(2097152-2)),b'"'+b'x'*(2097152-2)+b'"'))
    rows.append(('exact-2MiB-utf8-string',tape('é'*((2097152-2)//2)),b'"'+b'\xc3\xa9'*((2097152-2)//2)+b'"'))
    rows.append(('exact-2MiB-control-expansion',tape('\0'*349525),b'"'+b'\\u0000'*349525+b'"'))
    rows.append(('over-2MiB-ascii-string',tape('x'*(2097152-1)),LIMIT))
    rows.append(('over-2MiB-control-expansion',tape('\0'*349526),LIMIT))
    rows.append(('syntax-before-output-limit',tape('\0'*349526)+b'x',INVALID))
    rows.append(('typed-input-limit',b'JVT2\0'+b'x'*16777217,LIMIT))
    return rows
