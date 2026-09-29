"""Public-input Ed25519 prevalidation plus the installed crypto verifier.

Encoding/decompression and complete doubling follow RFC8032 sections5.1.3-5.1.4.
In addition to canonical encodings and S<L, this profile rejects small-order public
keys and R, matching the explicitly strict native verification policy. No secret
scalar operation is implemented here; Python arithmetic is not a signing primitive.
"""
from functools import lru_cache
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
P=(1<<255)-19
L=(1<<252)+27742317777372353535851937790883648493
D=(-121665*pow(121666,P-2,P))%P
SQRT_M1=pow(2,(P-1)//4,P)

@lru_cache(maxsize=1024)
def strict_point(encoded):
    if not isinstance(encoded,bytes)or len(encoded)!=32:raise ValueError('SIGNATURE')
    number=int.from_bytes(encoded,'little');sign=number>>255;y=number&((1<<255)-1)
    if y>=P:raise ValueError('SIGNATURE')
    yy=y*y%P;u=(yy-1)%P;v=(D*yy+1)%P
    x=u*pow(v,3,P)*pow(u*pow(v,7,P)%P,(P-5)//8,P)%P
    if (v*x*x-u)%P:
        if (v*x*x+u)%P:raise ValueError('SIGNATURE')
        x=x*SQRT_M1%P
    if x==0 and sign:raise ValueError('SIGNATURE')
    if x&1!=sign:x=P-x
    # Extended-coordinate doubling avoids inversions for the public cofactor check.
    X,Y,Z=x,y,1
    for _ in range(3):
        A=X*X%P;B=Y*Y%P;C=2*Z*Z%P;negative=(-A)%P
        E=((X+Y)*(X+Y)-A-B)%P;G=(negative+B)%P
        F=(G-C)%P;H=(negative-B)%P
        X,Y,Z=E*F%P,G*H%P,F*G%P
    if Z==0 or (X==0 and (Y-Z)%P==0):raise ValueError('SIGNATURE')

def verify(public,signature,message):
    if not isinstance(public,bytes)or len(public)!=32:raise ValueError('SIGNATURE')
    if not isinstance(message,bytes):raise ValueError('SIGNATURE')
    if not isinstance(signature,bytes)or len(signature)!=64:raise ValueError('SIGNATURE')
    if int.from_bytes(signature[32:],'little')>=L:raise ValueError('SIGNATURE')
    strict_point(public);strict_point(signature[:32])
    try:Ed25519PublicKey.from_public_bytes(public).verify(signature,message)
    except (ValueError,InvalidSignature)as error:raise ValueError('SIGNATURE')from error
