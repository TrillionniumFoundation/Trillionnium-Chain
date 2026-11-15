"""Independent finite binary64 and locked default-serde numeric test data.

These Python references never supply results to a native component.
"""
import math,random,re,struct

def format64(bits):
    x=struct.unpack('<d',struct.pack('<Q',bits))[0]
    if not math.isfinite(x):raise ValueError('nonfinite')
    sign='-' if bits>>63 else ''
    if x==0:return sign+'0.0'
    value=repr(abs(x)).lower()
    coef,rawexp=value.split('e') if 'e'in value else(value,'0')
    exp=int(rawexp)
    before=coef.index('.')if '.'in coef else len(coef)
    raw=coef.replace('.','')
    first=len(raw)-len(raw.lstrip('0'))
    exponent=exp+before-first-1
    digits=raw.lstrip('0').rstrip('0')
    if -5<=exponent<=15:
        if exponent+1>=len(digits):result=digits+'0'*(exponent+1-len(digits))+'.0'
        elif exponent>=0:result=digits[:exponent+1]+'.'+digits[exponent+1:]
        else:result='0.'+'0'*(-exponent-1)+digits
    else:result=digits[0]+('.'+digits[1:]if len(digits)>1 else'')+'e'+('+'if exponent>=0 else'-')+str(abs(exponent))
    return sign+result

def float_cases():
    values=[0,1,2,3,(1<<52)-1,1<<52,((1<<52)-1)|(2046<<52)]
    for x in [6.62607015e-34,5.444310685350916e14,1e-323,1.2e-322,1.24e-322,
              1.234e-320,-4.932096661796888e-226,3.439070283483335e35,
              6.606854224493745e-17,6.079537928711555e61,9.061488e15,1.0,1e-5,1e-6,1e15,1e16]:
        values.append(struct.unpack('<Q',struct.pack('<d',x))[0])
    for e in range(2047):
        for m in (0,1,(1<<52)-1):values.append((e<<52)|m)
    rng=random.Random(0x5c11b)
    values += [rng.randrange(2047)<<52|rng.getrandbits(52) for _ in range(4096)]
    values=list(dict.fromkeys(values))
    values += [v^(1<<63)for v in values]
    return values

MAX=(1<<64)-1

def bits(x):return struct.unpack('<Q',struct.pack('<d',x))[0]

def number_reference(raw):
    text=raw.decode('ascii')
    match=re.fullmatch(r'(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?)([0-9]+))?',text)
    if match is None:raise ValueError('syntax')
    minus,whole,frac,expsign,expdigits=match.groups()
    coefficient=0;exponent=0;floating=False
    for digit in whole:
        value=ord(digit)-48
        if not floating and coefficient<=(MAX-value)//10:
            coefficient=coefficient*10+value
        else:
            floating=True;exponent+=1
    if frac is not None:
        floating=True;retaining=True
        for digit in frac:
            value=ord(digit)-48
            if retaining and coefficient<=(MAX-value)//10:
                coefficient=coefficient*10+value;exponent-=1
            else:retaining=False
    overflow=False
    if expdigits is not None:
        floating=True;exp=0
        for digit in expdigits:
            if not overflow:
                exp=exp*10+ord(digit)-48
                if exp>(1<<31)-1:overflow=True
        if overflow:
            if coefficient!=0 and expsign!='-':raise ValueError('range')
            coefficient=0;exponent=0
        else:
            exponent=max(-(1<<31),min((1<<31)-1,exponent+(-exp if expsign=='-'else exp)))
    if not floating:
        if not minus:kind=0;value=coefficient;render=str(value)
        elif 0<coefficient<=1<<63:kind=1;value=(-coefficient)&MAX;render=str(-coefficient)
        else:kind=2;value=bits(-float(coefficient));render=format64(value)
    else:
        x=float(coefficient)
        while abs(exponent)>308 and x!=0.0:
            if exponent>=0:raise ValueError('range')
            x/=1e308;exponent+=308
        if x!=0.0:
            power=float('1e'+str(abs(exponent)))
            x=x*power if exponent>=0 else x/power
            if not math.isfinite(x):raise ValueError('range')
        if minus:x=-x
        kind=2;value=bits(x);render=format64(value)
    return value,kind,int(render==text),render.encode()

def number_candidates():
    values=[b'0',b'-0',b'0.0',b'-0.0',b'1',b'-1',b'18446744073709551615',b'18446744073709551616',
      b'184467440737095516150',b'184467440737095516159.1234567',b'-9223372036854775808',b'-9223372036854775809',
      b'1e0',b'1E+0',b'1e-0',b'1e308',b'1e309',b'0e309',b'0e-309',b'1e-308',b'1e-309',b'1e-324',
      b'5e-324',b'2.2250738585072014e-308',b'1.7976931348623157e308',b'1.7976931348623159e308',
      b'12345678901234567890.1234567890e5',b'1e2147483647',b'1e2147483648',b'1e-2147483648',
      b'0e2147483648',b'-0e2147483648',b'-1e-2147483649',b'184467440737095516150e-2147483647',
      b'0.000000000000000000000000001e2147483647',b'1.0000000000000002',b'100000000000000000000000000000000000000000']
    for e in range(-350,351):
        for coef in ('1','5','17976931348623157','18446744073709551615'):
            values.append((coef+'e'+str(e)).encode())
    rng=random.Random(0x53455244)
    for _ in range(4096):
        width=rng.randrange(1,100)
        whole=str(rng.randrange(1,10))+''.join(str(rng.randrange(10))for _ in range(width-1))
        frac='.'+''.join(str(rng.randrange(10))for _ in range(rng.randrange(1,100)))if rng.randrange(2)else''
        exp=('e'+rng.choice(['+','-',''])+str(rng.randrange(0,600)))if rng.randrange(2)else''
        values.append(('-'if rng.randrange(2)else'').encode()+(whole+frac+exp).encode())
    values += [b'00',b'01',b'-01',b'+1',b'1.',b'.1',b'1e',b'1e+',b'1e-',b'1ee2',b'--1',b'NaN',b'Infinity',
      b'1 2',b' 1',b'1 ',b'1,',b'1\0',b'\xff',b'-',b'1e2.1',b'1e+01',b'1.000',b'1.0e0']
    values += [b'0.'+b'0'*(2097152-2),b'1e-'+b'9'*(2097152-3),b'1e'+b'9'*(2097152-2),
               b'9'*2097152,b'1.'+b'0'*(2097152-3)+b'1']
    return list(dict.fromkeys(values))
