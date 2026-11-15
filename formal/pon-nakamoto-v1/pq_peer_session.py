"""PPH1 offline authenticated-peer payload bound to a native PQ-hybrid TLS exporter.

Non-authoritative research decoder and real ML-DSA-65 verification only. The 32-byte
channel tag must be independently obtained from an authenticated TLS 1.3 session;
a remote packet cannot supply its own expected tag. Does not grant membership,
block admission, work validity, API permission or deployment authority.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
from pathlib import Path
from pq_envelope import (Reject, make_unsigned, parse_signed, public_key_id,
                         sign_reference, verify_reference)

MAGIC = b"PPH1"
VERSION = 1
FRAME_BYTES = 256
MAX_TTL = 60
CONTEXT_DOMAIN = b"TRNM/PoN/PQPeerContext/v1\x00"
OBS_DOMAIN = b"TRNM/PoN/PQPeerObservation/v1\x00"


def _exact(b, size=32, *, nonzero=True):
    if type(b) is not bytes or len(b)!=size or (nonzero and b==bytes(size)):
        raise Reject("PPH1 exact bytes")
    return b


def _u64(x, *, nonzero=True):
    if type(x) is not int or not int(nonzero) <= x < (1<<64):
        raise Reject("PPH1 integer")
    return x.to_bytes(8,"big")


@dataclass(frozen=True)
class PeerHello:
    network: bytes
    genesis: bytes
    profile: bytes
    sender_key_id: bytes
    receiver_key_id: bytes
    channel_tag: bytes
    generation: int
    sequence: int
    expires_at: int
    nonce: bytes

    def encode(self):
        return (MAGIC + bytes([VERSION,0,0,0]) +
                b"".join(_exact(b) for b in (
                    self.network,self.genesis,self.profile,self.sender_key_id,
                    self.receiver_key_id,self.channel_tag)) +
                _u64(self.generation)+_u64(self.sequence)+_u64(self.expires_at)+
                _exact(self.nonce))


def parse_hello(raw):
    if type(raw) is not bytes or len(raw)!=FRAME_BYTES or raw[:8]!=MAGIC+bytes([VERSION,0,0,0]):
        raise Reject("PPH1 framing")
    s=[raw[8+i*32:8+(i+1)*32] for i in range(6)]
    p=200
    nums=[int.from_bytes(raw[p+i*8:p+(i+1)*8],"big") for i in range(3)]
    value=PeerHello(*s,*nums,raw[224:256])
    if value.encode()!=raw:raise Reject("PPH1 canonical")
    return value


def context_for(hello):
    return hashlib.sha256(CONTEXT_DOMAIN+hello.genesis+hello.profile+hello.receiver_key_id).digest()


def sign_hello(hello, *, private_key_path: Path):
    raw=hello.encode()
    u=make_unsigned(purpose=6, network=hello.network, context=context_for(hello),
                    signer_key_id=hello.sender_key_id,
                    owner_generation=hello.generation,operation_sequence=hello.sequence,
                    expires_at=hello.expires_at,payload=raw)
    return raw+sign_reference(u,private_key_path=private_key_path)


@dataclass(frozen=True)
class PeerResearchObservation:
    """A signed statement was checked; not a peer admission or permission."""
    statement_digest: bytes
    signer_key_id: bytes
    channel_tag: bytes


def verify_hello(frame, *, remote_public_pem: bytes, expected_network: bytes,
                 expected_genesis: bytes, expected_profile: bytes,
                 expected_remote_key_id: bytes, expected_local_key_id: bytes,
                 independently_verified_tls_channel_tag: bytes,
                 expected_generation: int, expected_sequence: int, now: int):
    if type(frame) is not bytes or len(frame)!=FRAME_BYTES+3487:
        raise Reject("PPH1 signed length")
    hello=parse_hello(frame[:FRAME_BYTES])
    if (hello.network!=_exact(expected_network) or
        hello.genesis!=_exact(expected_genesis) or
        hello.profile!=_exact(expected_profile) or
        hello.sender_key_id!=_exact(expected_remote_key_id) or
        hello.receiver_key_id!=_exact(expected_local_key_id) or
        hello.channel_tag!=_exact(independently_verified_tls_channel_tag) or
        hello.sender_key_id==hello.receiver_key_id or
        hello.sender_key_id!=public_key_id(remote_public_pem) or
        type(now) is not int or not 0 <= now < (1<<64) or
        type(expected_generation) is not int or type(expected_sequence) is not int or
        hello.generation!=expected_generation or hello.sequence!=expected_sequence or
        not now <= hello.expires_at <= min(now+MAX_TTL,(1<<64)-1)):
        raise Reject("PPH1 context/owner/timing")
    s,_=parse_signed(frame[FRAME_BYTES:])
    if (s.purpose!=6 or s.signer_key_id!=hello.sender_key_id or
        s.context!=context_for(hello)):
        raise Reject("PPH1 signature purpose/key")
    verify_reference(frame[FRAME_BYTES:],payload=hello.encode(),public_pem=remote_public_pem,
                     expected_network=hello.network,expected_context=context_for(hello),
                     expected_purpose=6,expected_generation=hello.generation,
                     expected_sequence=hello.sequence,now=now)
    return PeerResearchObservation(
        hashlib.sha384(OBS_DOMAIN+len(hello.encode()).to_bytes(4,"big")+hello.encode()).digest(),
        hello.sender_key_id,hello.channel_tag)
