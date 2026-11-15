"""Independent test data for native M06 String / finite typed Value codecs.

These models create expected test data. Production HIA receives original bytes;
no host parser, sort, normalization, hash, or supplied verdict runs on its behalf.
The Rust differential tests use the retained original crate independently.
"""
from __future__ import annotations

import json
import random
import struct

FRAME, NONCANONICAL, CAPACITY, RANGE = 0xfffffffb, 0xfffffffc, 0xfffffffd, 0xfffffffa
ARENA = 721152

def canonical_string(raw):
    return json.dumps(raw.decode('ascii'), ensure_ascii=False, separators=(',', ':')).encode('ascii')


def node(tag, payload=b''):
    return bytes([tag]) + struct.pack('<I', len(payload)) + payload


def primitive(value):
    if value is None: return node(0)
    if value is False: return node(1)
    if value is True: return node(2)
    if type(value) is int:
        return node(3 if value >= 0 else 4, struct.pack('<Q' if value >= 0 else '<q', value))
    if type(value) is float: return node(5, struct.pack('<d', value))
    if type(value) is str: return node(6, value.encode())
    if type(value) is list:
        return node(7, struct.pack('<I', len(value)) + b''.join(primitive(v) for v in value))
    if type(value) is dict:
        return object_pairs([(k, primitive(v)) for k,v in value.items()])
    raise TypeError(value)


def object_pairs(pairs):
    return node(8, struct.pack('<I', len(pairs)) + b''.join(
        struct.pack('<I', len(k.encode())) + k.encode() + value for k,value in pairs))


def semantic(value):
    if type(value) is float: return RANGE
    if type(value) is str and not value.isascii(): return NONCANONICAL
    if type(value) is list:
        for child in value:
            result = semantic(child)
            if result is not None: return result
    if type(value) is dict:
        for key in sorted(value):
            if not key.isascii(): return NONCANONICAL
            result = semantic(value[key])
            if result is not None: return result
    return None


def canonical_value(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def string_cases():
    randomizer = random.Random(0x4d3036)
    strings = [bytes([i]) for i in range(128)] + [b'', bytes(range(128))]
    strings += [bytes(randomizer.randrange(128) for _ in range(n))
                for n in list(range(32)) + [63,64,65,127,128,129,4093,4094,4095,8192]]
    cases, expected = [], []

    def add(raw, target, code=None, capacity=None):
        capacity = len(target) + 17 if capacity is None else capacity
        sent = [raw, bytes([0xa5]) * capacity, bytes([0x6b]) * 37]
        cases.append(sent)
        expected.append((len(target) if code is None else code, target if code is None else None))

    for raw in strings:
        encoded = canonical_string(raw)
        add(b'\x00' + raw, encoded)
        add(b'\x01' + encoded, raw)
        add(b'\x00' + raw, encoded, CAPACITY, len(encoded)-1)
        add(b'\x00' + raw, encoded, capacity=len(encoded))
        if raw:
            add(b'\x01' + encoded, raw, CAPACITY, len(raw)-1)
    for value in range(128, 256):
        add(b'\x00prefix' + bytes([value]), b'', NONCANONICAL, 0)
    for bad in [b'', b'"', b'null', b'"a" ', b' "a"', b'"a""', b'"\\/"',
                b'"\\u0041"', b'"\\u007f"', b'"\\u0008"', b'"\\u0009"',
                b'"\\u000a"', b'"\\u000c"', b'"\\u000d"', b'"\\u001F"',
                b'"\\u00ff"', b'"\\uD800"', b'"\\x00"', b'"\\"', b'"a"b"',
                b'"\xce\xbb"', b'"\xff"'] + [b'"' + bytes([i]) + b'"' for i in range(32)]:
        add(b'\x01' + bad, b'', NONCANONICAL, 0)
    add(b'', b'', FRAME, 0)
    add(b'\x02valid', b'', FRAME, 0)

    # Exercise the actual 1 MiB borrowed-buffer boundary without extending the
    # official profile. Escaping expansion is capacity, not a grammar error.
    plain = b'x' * ((1 << 20) - 3)
    add(b'\x00' + plain, b'"' + plain + b'"', capacity=(1 << 20) - 1)
    escaped = b'\x00' * 174762
    add(b'\x00' + escaped, canonical_string(escaped), capacity=(1 << 20))
    add(b'\x00' + escaped + b'\x00', b'', CAPACITY, (1 << 20))

    # Exact accepted borrowed input extent in both directions. The encoder's
    # required output can exceed the borrowed output profile and must refuse.
    add(b'\x00' + b'x' * ((1 << 20) - 1), b'', CAPACITY, (1 << 20))
    add(b'\x01' + b'"' + plain + b'"', plain, capacity=(1 << 20))
    return cases, expected


def value_cases():
    cases = []

    def add(frame, expected, result=None, capacity=None, scratch=ARENA+32, label='typed'):
        capacity = len(expected) + 19 if capacity is None else capacity
        cases.append({'input':frame,'expected':expected if result is None else None,
                      'return':len(expected) if result is None else result,'capacity':capacity,
                      'scratch':scratch,'label':label})

    def value(value, label='typed'):
        code = semantic(value)
        raw = b'JVT1' + primitive(value)
        encoded = b'' if code is not None else canonical_value(value)
        add(raw, encoded, code, label=label)
        if code is None and encoded:
            add(raw, b'', CAPACITY, len(encoded)-1, label='output-capacity')

    values = [None, False, True, 0, 1, 9, 10, 99, 100, (1<<63)-1, 1<<63, (1<<64)-1,
              -1, -9, -10, -99, -100, -(1<<63), '', ''.join(chr(i) for i in range(128)),
              [], {}, [None, True, -1, 1<<63, 'a\x00z'], {'z':1,'a':2,'\x01':False,'\\':True},
              0.5, -0.0, 1.0, 'λ', '😀', {'a':0.5,'z':'λ'}, {'a':'λ','z':0.5},
              {'λ':0.5}, {'a':0.5,'λ':0}, {'a':[1,{'z':1,'a':False}]}]
    rng = random.Random(0x4d303650)
    def random_value(depth=0):
        choices = 5 if depth >= 4 else 7
        kind = rng.randrange(choices)
        if kind == 0: return None
        if kind == 1: return bool(rng.randrange(2))
        if kind == 2: return rng.randrange(-(1<<63),(1<<64))
        if kind == 3: return ''.join(chr(rng.randrange(128)) for _ in range(rng.randrange(33)))
        if kind == 4: return rng.choice([0.5, -0.0, 'λ', 0, True])
        if kind == 5: return [random_value(depth+1) for _ in range(rng.randrange(8))]
        return {''.join(chr(rng.randrange(32,128)) for _ in range(rng.randrange(8))):random_value(depth+1) for _ in range(rng.randrange(8))}
    values.extend(random_value() for _ in range(100))
    for item in values: value(item)
    for signed in [0,1,(1<<63)-1]:
        add(b'JVT1'+node(4,struct.pack('<q',signed)),str(signed).encode(),label='signed-positive-original-number')
    for exponent in range(1,20):
        for integer in [10**exponent-1,10**exponent,10**exponent+1]:
            value(integer,label='all-decimal-width-edges')

    pairs_cases = [
        ([('z',0.5),('a','λ')], {'z':0.5,'a':'λ'}),
        ([('z','λ'),('a',0.5)], {'z':'λ','a':0.5}),
        ([('a',0.5),('a',None)], {'a':None}),
        ([('a','λ'),('a',1)], {'a':1}),
        ([('a',1),('a',0.5)], {'a':0.5}),
        ([('é',0),('a',False),('é',None)], {'é':None,'a':False}),
        ([('z',{'x':'λ'}),('z',{'x':1}),('a',[True])], {'z':{'x':1},'a':[True]}),
    ]
    for pairs, normalized in pairs_cases:
        code = semantic(normalized)
        add(b'JVT1'+object_pairs([(k,primitive(v)) for k,v in pairs]),
            b'' if code is not None else canonical_value(normalized), code, label='last-wins-and-error-order')
    # Sorted output must depend on decoded keys, including controls, not the
    # textual escape spelling. Input order is deliberately reversed.
    wide = [(f'k-{i:04}',primitive(i)) for i in range(999,-1,-1)]
    add(b'JVT1'+object_pairs(wide), canonical_value({f'k-{i:04}':i for i in range(1000)}), label='wide-heapsort')
    duplicate = [('same',primitive(0.5)) for _ in range(2000)] + [('same',primitive(7))]
    add(b'JVT1'+object_pairs(duplicate), b'{"same":7}', label='many-overwritten-range-values')
    deep = primitive(0)
    for _ in range(1500): deep = node(7,struct.pack('<I',1)+deep)
    add(b'JVT1'+deep, b'['*1500+b'0'+b']'*1500, label='iterative-depth-1500')
    children = [node(0)]*8191
    add(b'JVT1'+node(7,struct.pack('<I',len(children))+b''.join(children)),
        b'['+b','.join([b'null']*len(children))+b']', label='node-cap-exact')
    add(b'JVT1'+node(7,struct.pack('<I',8192)+b''.join([node(0)]*8192)),b'',CAPACITY,label='node-cap-plus-one')
    prefix=b''.join([node(0)]*8191)
    for malformed in [node(6,b'\x80'),node(7),node(5,struct.pack('<d',float('nan')))]:
        add(b'JVT1'+node(7,struct.pack('<I',8192)+prefix+malformed),b'',FRAME,
            label='node-shape-before-node-capacity')
    add(b'JVT1'+node(7,struct.pack('<I',8192)+prefix+primitive('λ')),b'',CAPACITY,
        label='local-constructor-capacity-is-not-m06-limit')
    big = b'\0'*65527
    add(b'JVT1'+node(6,big), b'"'+b'\\u0000'*len(big)+b'"', label='tape-max-escape-expansion')
    add(b'JVT1'+node(6,big+b'\0'),b'',CAPACITY,label='tape-cap-plus-one')
    add(b'JVT1'+node(6,b'x'*4095+b'\xce\xbb'),b'',NONCANONICAL,capacity=0,label='late-nonascii-before-capacity')
    add(b'JVT1'+primitive(0.5),b'',RANGE,capacity=0,label='range-before-output-capacity')
    add(b'JVT1'+primitive(0),b'',CAPACITY,scratch=ARENA-1,label='scratch-capacity')
    example = b'JVT1'+primitive({'a':[1,2,'x'],'b':True})
    for cut in range(len(example)):
        add(example[:cut],b'',FRAME,capacity=0,label='every-truncation')
    for bad in [b'BAD1'+node(0), b'JVT1'+node(0)+b'x', b'JVT1'+node(9),
                b'JVT1'+node(0,b'x'), b'JVT1'+node(3,b'1234567'),
                b'JVT1'+node(5,struct.pack('<d',float('inf'))),
                b'JVT1'+node(5,struct.pack('<d',float('nan'))),
                b'JVT1'+node(7,struct.pack('<I',1)), b'JVT1'+node(8,struct.pack('<I',1)),
                b'JVT1'+node(7,struct.pack('<I',0)+node(0))]:
        add(bad,b'',FRAME,capacity=0,label='malformed-tape')
    for bad in [b'\x80',b'\xc0\x80',b'\xc1\xbf',b'\xe0\x80\x80',b'\xed\xa0\x80',
                b'\xf0\x80\x80\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xe2\x82']:
        add(b'JVT1'+node(6,bad),b'',FRAME,capacity=0,label='invalid-utf8-tape')
    for codepoint in [0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]:
        add(b'JVT1'+primitive(chr(codepoint)),b'',NONCANONICAL,capacity=0,
            label='valid-utf8-nonascii-is-semantic')

    # The shortest child is Null (5 bytes), and each wrapping array adds 9.
    # 4 + 5 + 7280*9 = 65529; another layer exceeds the 65536-byte tape.
    deepest = node(0)
    for _ in range(7280):
        deepest = node(7, struct.pack('<I', 1) + deepest)
    add(b'JVT1' + deepest, b'[' * 7280 + b'null' + b']' * 7280,
        label='maximum-constructible-array-depth')
    return cases
