"""Reconstructed SHA-256 compression and explicit prefix reuse algorithms.

Achieved compression counts, not lower bounds against arbitrary algorithms.
"""
INITIAL=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
K=(
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
MASK=2**32-1

def rotr(x,n):return ((x>>n)|(x<<(32-n)))&MASK

def pad(message):
    n=len(message)
    if n>=2**61:raise ValueError('SHA-256 length bound')
    return message+b'\x80'+b'\x00'*((55-n)%64)+(8*n).to_bytes(8,'big')

def compress(state,block):
    if len(state)!=8 or len(block)!=64:raise ValueError('compression shape')
    w=[int.from_bytes(block[i:i+4],'big') for i in range(0,64,4)]
    for i in range(16,64):
        x,y=w[i-15],w[i-2]
        s0=rotr(x,7)^rotr(x,18)^(x>>3);s1=rotr(y,17)^rotr(y,19)^(y>>10)
        w.append((w[i-16]+s0+w[i-7]+s1)&MASK)
    a,b,c,d,e,f,g,h=state
    for i in range(64):
        s1=rotr(e,6)^rotr(e,11)^rotr(e,25);choose=(e&f)^((~e)&g)
        t1=(h+s1+choose+K[i]+w[i])&MASK
        s0=rotr(a,2)^rotr(a,13)^rotr(a,22);majority=(a&b)^(a&c)^(b&c)
        t2=(s0+majority)&MASK
        a,b,c,d,e,f,g,h=(t1+t2)&MASK,a,b,c,(d+t1)&MASK,e,f,g
    return tuple((x+y)&MASK for x,y in zip(state,(a,b,c,d,e,f,g,h)))

class PrefixSHA256:
    """Full diagnostic prefix trie; memory grows with retained history."""
    def __init__(self):
        self.states={b'':INITIAL};self.compressions=0;self.calls=0;self.input_bytes=0
    def digest(self,message):
        self.calls+=1;self.input_bytes+=len(message);raw=pad(message);state=INITIAL
        for stop in range(64,len(raw)+1,64):
            prefix=raw[:stop]
            if prefix not in self.states:
                self.states[prefix]=compress(state,raw[stop-64:stop]);self.compressions+=1
            state=self.states[prefix]
        return b''.join(x.to_bytes(4,'big') for x in state)
    def payload(self):
        return {'chaining_state_bytes':32*(len(self.states)-1),'prefix_key_bytes':sum(map(len,self.states)),
                'python_object_overhead_included':False}

class BoundedPrefixSHA256:
    """Five first-block slots and two full-digest slots, with full-key equality.

    Tag hints only select slots. A wrong hint may reduce reuse, never alter SHA.
    """
    PREFIX_SLOTS=frozenset(('leaf','node','noise-seed','event','noise-eight'))
    FULL_SLOTS=frozenset(('task','context'))
    def __init__(self):self.prefixes={};self.outputs={};self.compressions=0
    def digest(self,message,tag):
        if tag in self.FULL_SLOTS:
            saved=self.outputs.get(tag)
            if saved is not None and saved[0]==message:return saved[1]
        raw=pad(message);state=INITIAL;start=0
        if tag in self.PREFIX_SLOTS:
            prefix=raw[:64];saved=self.prefixes.get(tag)
            if saved is not None and saved[0]==prefix:state=saved[1]
            else:
                state=compress(INITIAL,prefix);self.compressions+=1;self.prefixes[tag]=(prefix,state)
            start=64
        for offset in range(start,len(raw),64):
            state=compress(state,raw[offset:offset+64]);self.compressions+=1
        digest=b''.join(x.to_bytes(4,'big') for x in state)
        if tag in self.FULL_SLOTS:self.outputs[tag]=(message,digest)
        return digest
    def payload(self):
        return {'prefix_state_bytes':32*len(self.prefixes),
                'prefix_key_bytes':sum(len(v[0]) for v in self.prefixes.values()),
                'full_digest_bytes':32*len(self.outputs),
                'full_digest_key_bytes':sum(len(v[0]) for v in self.outputs.values()),
                'max_prefix_slots':5,'max_full_digest_slots':2,
                'python_object_overhead_included':False,'transient_compression_workspace_included':False}
