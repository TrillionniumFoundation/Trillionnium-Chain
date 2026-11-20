"""Actual native classical request controls; original Rust differential is separate."""
from __future__ import annotations
import copy
import hashlib
import json
import math
import struct

from hia.tests.test_ed25519 import sign

LIMIT=2097152
SCHEMA="trnm-authenticated-request-v1"


def canonical(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()


def pon(tag,*parts):
    digest=hashlib.sha256()
    digest.update(b"TRNM-PON1\0")
    digest.update(len(tag).to_bytes(2,"little"));digest.update(tag)
    for part in parts:
        digest.update(len(part).to_bytes(4,"little"));digest.update(part)
    return digest.digest()


def public(secret):
    return sign(secret, b" ")[0]


class Fixture:
    def __init__(self,generation=1,peer_count=1,peer_public=None,signer=None,context=None):
        self.peer=bytes([72])*32
        self.server=bytes([71])*32
        self.peer_public=public(self.peer) if peer_public is None else peer_public
        self.signer=(lambda message: sign(self.peer,message)[1]) if signer is None else signer
        self.peers=[self.peer_public]
        self.peers += [public(hashlib.sha256(b"peer"+bytes([i])).digest())
                       for i in range(peer_count-1)]
        self.peers=sorted(self.peers)
        context = context or {"network": "01"*32, "parameters": "02"*32, "genesis": "03"*32}
        self.network=bytes.fromhex(context["network"]);self.parameters=bytes.fromhex(context["parameters"]);self.genesis=bytes.fromhex(context["genesis"])
        assert all(len(x)==32 for x in (self.network,self.parameters,self.genesis))
        self.generation=generation
        self.profile=pon(b"native-authenticated-development-v1",b"ed25519-strict/canonical-json/durable-replay")
        self.peer_id=pon(b"native-authenticated-peer-v1",self.peer_public)
        server_id=pon(b"native-authenticated-peer-v1",public(self.server))
        self.session_id=pon(b"native-authenticated-session-v1",self.network,self.parameters,self.genesis,
                            self.profile,self.peer_id,server_id,struct.pack("<Q",generation))
        self.session=dict(network=self.network.hex(),parameters=self.parameters.hex(),genesis=self.genesis.hex(),
            profile=self.profile.hex(),peer=self.peer_public.hex(),server=public(self.server).hex(),
            session=self.session_id.hex(),generation=generation)
        self.config=(b"TRNMAQ01"+struct.pack("<Q",generation)+self.network+self.parameters+self.genesis+
                     public(self.server)+struct.pack("<Q",peer_count)+b"".join(self.peers))

    def envelope(self,request=None,nonce=1,**changes):
        authority=dict(schema=SCHEMA,session=copy.deepcopy(self.session),replay_nonce=nonce,
                       request=copy.deepcopy(request if request is not None else {"op":"head"}))
        authority.update(changes)
        digest=pon(b"native-authenticated-request-sign-v1",canonical(authority))
        return dict(**authority,signature=self.signer(digest).hex())

    def expected(self,envelope,body):
        payload=canonical(envelope["request"])
        authority={key:envelope[key] for key in ("schema","session","replay_nonce","request")}
        digest=pon(b"native-authenticated-request-sign-v1",canonical(authority))
        op={"head":1,"submit":2,"history":3,"confirm":4,"confirm_many":5}[envelope["request"]["op"]]
        payload_at=body.index(b'"request":')+len(b'"request":')+4
        count=len(envelope["request"].get("queries",[]))
        return (struct.pack("<6Q",len(body)+4,payload_at,len(payload),envelope["replay_nonce"],self.generation,op)+
            digest+pon(b"native-authenticated-payload-v1",payload)+self.peer_id+self.session_id+self.profile+
            self.genesis+self.parameters+self.network+self.peer_public+public(self.server)+struct.pack("<QQ",count,0))


def cases(context=None):
    def owner_fixture(**options):
        return Fixture(context=context, **options)
    fixture=owner_fixture()
    head=fixture.envelope();raw=canonical(head)
    result=[]
    def add(name,body=raw,expected=0,*,config=None,envelope=None,framed=None,tail=b"",f=fixture):
        wire=len(body).to_bytes(4,"big")+body if framed is None else framed
        expect_out=f.expected(envelope if envelope is not None else head,body) if expected==0 else None
        result.append(dict(name=name,input=(f.config if config is None else config)+wire+tail,
                           expected_code=expected,expected_output=expect_out,body=body))
    def changed(name,expected,fn):
        value=copy.deepcopy(head);fn(value);add(name,canonical(value),expected)
    variants=[
        {"op":"head"},
        {"op":"submit","packet":"deadbeef"},
        {"op":"submit","packet":"任意é🙂 /\"\\\x00\b\t\n\f\r\x1f\x7f\u2028"},
        {"op":"history","tip":"UPPERCASE","after":""},
        {"op":"confirm","transaction":"x","block":""},
        {"op":"confirm_many","queries":[]},
        {"op":"confirm_many","queries":[{"transaction":"x","block":"y"}]},
        {"op":"confirm_many","queries":[{"transaction":"","block":""} for _ in range(257)]},
    ]
    for i,request in enumerate(variants):
        env=fixture.envelope(request);add("valid-variant-"+str(i),canonical(env),envelope=env)
    for nonce in (1,2,2**63-1):
        env=fixture.envelope(nonce=nonce);add("nonce-valid-"+str(nonce),canonical(env),envelope=env)
    for generation in (2,2**63-1):
        owner=owner_fixture(generation=generation);env=owner.envelope()
        add("generation-valid-"+str(generation),canonical(env),envelope=env,f=owner)
    owner=owner_fixture(peer_count=64);env=owner.envelope()
    add("allowlist-64",canonical(env),envelope=env,f=owner)
    # Original strict Dalek policy rejects weak points, while allowing a
    # nonweak mixed-order key with a valid full-group signature equation.
    from hia.tests.test_ed25519 import torsion_generator,multiply,compress,add as point_add,B,L,little,status
    torsion=torsion_generator();scalar=123456789
    mixed_public=compress(point_add(multiply(scalar,B),torsion))
    def mixed_sign(message):
        for nonce in range(1,64):
            for j in range(8):
                r=compress(point_add(multiply(nonce,B),multiply(j,torsion)))
                k=int.from_bytes(hashlib.sha512(r+mixed_public+message).digest(),"little")%L
                if (j+k)%8==0:
                    signature=r+little((nonce+k*scalar)%L)
                    assert status(mixed_public+signature+message)==0
                    return signature
        raise AssertionError("Mixed-order signing fixture search exhausted")
    owner=owner_fixture(peer_public=mixed_public,signer=mixed_sign);env=owner.envelope()
    add("nonweak-mixed-order-peer",canonical(env),envelope=env,f=owner)
    add("next-frame-not-consumed",tail=b"\x00\x00\x00\x01x")
    # Original 2 MiB is the entire JSON body, with a separate 4-byte BE prefix.
    empty=fixture.envelope({"op":"submit","packet":""})
    base=len(canonical(empty))
    for size in (131168,131169,LIMIT-1,LIMIT):
        env=fixture.envelope({"op":"submit","packet":"a"*(size-base)})
        body=canonical(env);assert len(body)==size
        add("body-exact-"+str(size),body,envelope=env)
        if size==LIMIT:
            position=body.index(b'"packet":"')+len(b'"packet":"')+len(env["request"]["packet"])-1
            assert body[position:position+3]==b'a"}' and position<body.index(b'"signature":')
            changed_last=body[:position]+b'b'+body[position+1:]
            assert len(changed_last)==size
            add("body-last-payload-byte-signature-bound",changed_last,9)
    # The auth layer has no downstream confirmation-query count cap. Exercise
    # its maximum dense query container as well as the single large string.
    empty_many=fixture.envelope({"op":"confirm_many","queries":[]})
    n=(LIMIT-len(canonical(empty_many)))//30
    request={"op":"confirm_many","queries":[{"transaction":"","block":""} for _ in range(n)]}
    env=fixture.envelope(request);body=canonical(env)
    assert len(body)<=LIMIT
    request["queries"][-1]["block"]="a"*(LIMIT-len(body))
    env=fixture.envelope(request);body=canonical(env)
    assert len(body)==LIMIT and len(request["queries"])>256
    add("confirm-many-exact-body-limit",body,envelope=env)
    add("empty-body",b"",2)
    add("body-too-large",b"x"*(LIMIT+1),2)
    for n in (0,1,2,3):add("prefix-truncated-"+str(n),expected=1,framed=b"\0"*n)
    add("body-truncated",expected=1,framed=(len(raw)+1).to_bytes(4,"big")+raw)
    add("prefix-big-endian",expected=2,framed=len(raw).to_bytes(4,"little")+raw)
    for body in (b"{}",b"null",b"true",b"123",b'"str"',b"[]",raw+b"x",b"\xef\xbb\xbf"+raw):
        add("json-root-"+str(len(result)),body,3)
    for name in list(head):
        env=copy.deepcopy(head);del env[name];add("missing-envelope-"+name,canonical(env),3)
    for name in list(head["session"]):
        env=copy.deepcopy(head);del env["session"][name];add("missing-session-"+name,canonical(env),3)
    changed("unknown-envelope",3,lambda x:x.update(unknown=1))
    changed("unknown-session",3,lambda x:x["session"].update(unknown=1))
    add("duplicate-envelope",raw[:-1]+b',"schema":"x"}',3)
    add("duplicate-session",raw.replace(b'"network":',b'"network":"x","network":',1),3)
    for name,value in (("schema",1),("signature",None),("session",False),("request",None),
                        ("replay_nonce",-1),("replay_nonce",1.0),("replay_nonce",2**64)):
        env=copy.deepcopy(head);env[name]=value;add("wrong-type-"+name+"-"+str(len(result)),canonical(env),3)
    for token in (b"-0",b"01",b"1e0",b"1.0",b"+1",b"18446744073709551616",b"1e9999"):
        add("u64-token-"+token.decode(),raw.replace(b'"replay_nonce":1,',b'"replay_nonce":'+token+b',',1),3)
    for nonce in (0,2**63,2**64-1):
        env=fixture.envelope(nonce=nonce);add("nonce-refused-"+str(nonce),canonical(env),8)
    for key in head["session"]:
        value=copy.deepcopy(head)
        value["session"][key]=2 if key=="generation" else "0"*64
        add("session-mismatch-"+key,canonical(value),6 if key=="peer" else 7)
    changed("schema",5,lambda x:x.update(schema="wrong"))
    changed("signature-upper",9,lambda x:x.update(signature=x["signature"].upper()))
    changed("signature-short",9,lambda x:x.update(signature=x["signature"][:-2]))
    changed("signature-nonhex",9,lambda x:x.update(signature="g"*128))
    changed("signature-zero",9,lambda x:x.update(signature="0"*128))
    for label,signature in [("noncanonical-r",(2**255-19).to_bytes(32,"little")+bytes.fromhex(head["signature"])[32:]),
                            ("negative-zero-r",(1+(1<<255)).to_bytes(32,"little")+bytes.fromhex(head["signature"])[32:]),
                            ("scalar-order",bytes.fromhex(head["signature"])[:32]+L.to_bytes(32,"little")),
                            ("scalar-plus-order",bytes.fromhex(head["signature"])[:32]+(int.from_bytes(bytes.fromhex(head["signature"])[32:],"little")+L).to_bytes(32,"little"))]:
        changed("signature-"+label,9,lambda x,v=signature:x.update(signature=v.hex()))
    changed("signature-different-message",9,lambda x:x.update(request={"op":"submit","packet":"changed"}))
    for name,body in [("trailing-space",raw+b" "),("leading-space",b" "+raw),("newlines",b"\n"+raw+b"\r\n"),
                      ("separator-space",raw.replace(b'"schema":',b'"schema": ',1)),
                      ("escaped-op",raw.replace(b'"head"',b'"h\\u0065ad"',1)),
                      ("escaped-key",raw.replace(b'"schema"',b'"sch\\u0065ma"',1))]:
        add("noncanonical-"+name,body,4)
    add("noncanonical-order-envelope",canonical(dict(reversed(list(head.items())))),4)
    changed("noncanonical-order-session",4,lambda x:x.update(session=dict(reversed(list(x["session"].items())))))
    add("noncanonical-array-envelope",canonical(list(head.values())),4)
    changed("noncanonical-array-session",4,lambda x:x.update(session=list(x["session"].values())))
    changed("noncanonical-array-request-head",4,lambda x:x.update(request=["head"]))
    for request in ({"packet":"x","op":"submit"},{"op":"head","extra":1},
                    {"extra":False,"op":"head"},["submit","x"],["history","a","b"],
                    ["confirm","a","b"],["confirm_many",[]],
                    {"op":"confirm_many","queries":[["a","b"]]},
                    {"op":"confirm_many","queries":[{"block":"b","transaction":"a"}]}):
        changed("noncanonical-request-"+str(len(result)),4,lambda x,r=request:x.update(request=r))
    changed("noncanonical-signed-slash",9,lambda x:x.update(request={"op":"submit","packet":"/"}))
    env=fixture.envelope({"op":"submit","packet":"/"})
    add("noncanonical-slash-escape",canonical(env).replace(b'"packet":"/"',b'"packet":"\\/"'),4)
    env=fixture.envelope({"op":"submit","packet":"é🙂"})
    add("noncanonical-unicode-escape",json.dumps(env,separators=(",",":"),ensure_ascii=True).encode(),4)
    env=fixture.envelope({"op":"submit","packet":"\x1f"})
    add("noncanonical-unicode-uppercase-hex",canonical(env).replace(b"\\u001f",b"\\u001F"),4)
    for escaped in (b"\\ud800",b"\\udc00",b"\\ud800\\u0000",b"\\uZZZZ",b"\\x00",b"\x00",b"\xc0\x80",b"\xed\xa0\x80",b"\xf4\x90\x80\x80",b"\xff"):
        body=canonical(fixture.envelope({"op":"submit","packet":"MARK"})).replace(b"MARK",escaped)
        add("string-invalid-"+str(len(result)),body,3)
    for request in ({"op":"unknown"},{"op":0},{"op":"HEAD"},{"op":"submit"},
                    {"op":"submit","packet":1},{"op":"submit","packet":"x","extra":1},
                    {"op":"history","tip":"x","after":"y","packet":"z"},
                    {"op":"confirm_many","queries":{}},
                    {"op":"confirm_many","queries":[{"transaction":"x","block":"y","extra":1}]},
                    {"op":"confirm_many","queries":[{"transaction":0,"block":"y"}]},
                    ["head",1],["submit"],["submit","x","y"]):
        changed("request-type-"+str(len(result)),3,lambda x,r=request:x.update(request=r))
    add("duplicate-op",raw.replace(b'{"op":"head"}',b'{"op":"head","op":"head"}'),3)
    add("duplicate-ignored-head",raw.replace(b'{"op":"head"}',b'{"op":"head","x":1,"x":2}'),4)
    for depth in (124,125,126,127):
        body=raw.replace(b'{"op":"head"}',b'{"op":"head","x":'+b"["*depth+b"0"+b"]"*depth+b"}")
        add("head-json-depth-"+str(depth),body,4 if depth<=125 else 3)
    for token,expected in [(b"1e308",4),(b"1e309",3),(b"-1e9999",3),(b"0e9999",4),
                           (b"1e-9999",4),(b"-0",4),(b"18446744073709551616",4),
                           (b"1.",3),(b"1e+",3),(b"01",3),(b"NaN",3),(b"Infinity",3),
                           (b"[1,]",3),(b'{"x":1,}',3)]:
        body=raw.replace(b'{"op":"head"}',b'{"op":"head","extra":'+token+b"}")
        add("ignored-head-number-"+str(len(result)),body,expected)
    # Exact default-serde conversion near binary64 overflow: first u64
    # significand rounded to binary64, then multiplied by its rounded POW10.
    for coefficient in (17976931348623155,17976931348623156,17976931348623157,17976931348623158,
                        17976931348623159,17976931348623160,18446744073709551615):
        token=str(coefficient).encode()+b"e292"
        expected=4 if math.isfinite(float(coefficient)*float("1e292")) else 3
        body=raw.replace(b'{"op":"head"}',b'{"op":"head","extra":'+token+b"}")
        add("ignored-head-f64-overflow-"+str(coefficient),body,expected)
    # Stage precedence is asserted with two simultaneous defects.
    env=copy.deepcopy(head);env["schema"]="bad";add("precedence-noncanonical-before-schema",canonical(env)+b" ",4)
    env=copy.deepcopy(head);env["schema"]="bad";env["session"]["peer"]="bad";add("precedence-schema-before-peer",canonical(env),5)
    env=copy.deepcopy(head);env["session"]["peer"]="bad";env["session"]["network"]="bad";add("precedence-peer-before-session",canonical(env),6)
    env=copy.deepcopy(head);env["session"]["network"]="bad";env["replay_nonce"]=0;add("precedence-session-before-nonce",canonical(env),7)
    env=copy.deepcopy(head);env["replay_nonce"]=0;env["signature"]="bad";add("precedence-nonce-before-signature",canonical(env),8)
    env=copy.deepcopy(head);env["replay_nonce"]=0;env["request"]={"op":"submit","packet":False};add("precedence-json-before-nonce",canonical(env),3)
    # Owner-container inputs are distinct from original untrusted wire refusals.
    add("config-short",expected=101,config=b"",framed=b"")
    add("config-magic",expected=102,config=b"BADMAGIC"+fixture.config[8:])
    add("config-generation-zero",expected=103,config=fixture.config[:8]+bytes(8)+fixture.config[16:])
    add("config-peer-count-zero",expected=104,config=fixture.config[:144]+bytes(8)+fixture.config[152:])
    add("config-peer-small-order",expected=106,config=fixture.config[:152]+bytes(32))
    add("config-server-small-order",expected=107,config=fixture.config[:112]+bytes(32)+fixture.config[144:])
    owner=owner_fixture(peer_count=2)
    add("config-duplicate-peer",expected=105,config=owner.config[:152]+owner.config[152:184]*2)
    add("config-unsorted-peer",expected=105,config=owner.config[:152]+owner.config[184:216]+owner.config[152:184])
    return result
