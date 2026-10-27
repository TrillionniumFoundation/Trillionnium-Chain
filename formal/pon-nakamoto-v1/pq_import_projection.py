"""PQI1: exact, read-only, fail-closed PQG1/PQS1 liability projection.

Research ONLY. Consumes the already evaluated *PQS1 bytes* from PQG1's
verify_handoff and independently pinned source/state/genesis commitments.
This module DOES NOT verify original dual-possession signatures, authorize an old
Chain state, decide fork choice, create a production genesis, mint supply, import
accounts into a Node, or issue Final-use. Caller-provided pins are NOT authority.

No PQL1 fallback: PQL1 cannot preserve source nonce floors/liabilities/quarantine.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

MAX_ACCOUNTS = 128
MAX_LIABILITIES = 256
MAX_STATE_BYTES = 65536
U64_MAX = (1 << 64) - 1
ACCOUNT_SIZE = 129
LIABILITY_SIZE = 81
STATE_DOMAIN = b"TRNM/PQ/GenesisState/v1\x00"
GENESIS_ID_DOMAIN = b"TRNM/PQ/GenesisID/v1\x00"
IMPORT_DOMAIN = b"TRNM/PQ/ImportProjection/v1\x00"
ACCOUNT_DOMAIN = b"TRNM/PQ/Account/v1\x00"
QUARANTINE_DOMAIN = b"TRNM/PQ/Quarantine/v1\x00"
KINDS = frozenset((1, 2, 3, 4))

class Reject(ValueError):
    """A malformed or context-mismatched non-authoritative import candidate."""


def _exact(data: bytes, n: int, label: str, *, nonzero: bool = False) -> bytes:
    if type(data) is not bytes or len(data) != n or (nonzero and data == bytes(n)):
        raise Reject(label)
    return data


def _u64(data: bytes) -> int:
    return int.from_bytes(data, 'big')


def _frame_hash(domain: bytes, data: bytes) -> bytes:
    return hashlib.sha384(domain + len(data).to_bytes(8, 'big') + data).digest()


@dataclass(frozen=True)
class AccountObservation:
    old_key: bytes
    account_id: bytes
    pq_key_id: bytes
    balance: int
    next_nonce: int
    old_generation: int
    new_generation: int
    quarantined: bool
    raw: bytes


@dataclass(frozen=True)
class LiabilityObservation:
    liability_id: bytes
    owner_old_key: bytes
    amount: int
    due_height: int
    kind: int
    raw: bytes


@dataclass(frozen=True)
class ImportObservation:
    """No implicit verified/grant/adopt/chainwork property or mutable state owner."""
    projection_bytes: bytes
    projection_digest: bytes
    source_digest: bytes
    state_root: bytes
    genesis_id: bytes
    issued_units: int
    active_count: int
    quarantined_count: int
    liability_count: int


def project_pqs1(raw: bytes, *, expected_network: bytes,
                 expected_profile: bytes, expected_source_digest: bytes,
                 expected_state_root: bytes, expected_genesis_id: bytes) -> ImportObservation:
    """Validate/canonicalize PQS1 bytes and preserve EVERY imported liability.

    `expected_*` are EXTERNAL pins, never derived from untrusted raw input by caller.
    The source claim and old-chain authority still require separate independent checks.
    """
    network = _exact(expected_network, 32, 'network', nonzero=True)
    profile = _exact(expected_profile, 32, 'profile', nonzero=True)
    source_digest = _exact(expected_source_digest, 48, 'source digest', nonzero=True)
    state_root = _exact(expected_state_root, 48, 'state root', nonzero=True)
    genesis_id = _exact(expected_genesis_id, 48, 'genesis id', nonzero=True)
    if type(raw) is not bytes or not 5+32+32+2+ACCOUNT_SIZE+2+8 <= len(raw) <= MAX_STATE_BYTES:
        raise Reject('PQS1 bytes/type/bound')
    if raw[:5] != b'PQS1\x01' or raw[5:37] != network or raw[37:69] != profile:
        raise Reject('PQS1 version/network/profile')
    count = int.from_bytes(raw[69:71], 'big')
    if not 1 <= count <= MAX_ACCOUNTS:
        raise Reject('account count')
    pos = 71
    if pos + count*ACCOUNT_SIZE + 2 + 8 > len(raw):
        raise Reject('account framing')
    accounts = []
    seen_old, seen_new = set(), set()
    last_old = None
    for _ in range(count):
        item = raw[pos:pos+ACCOUNT_SIZE]
        pos += ACCOUNT_SIZE
        mode, aid, kid = item[0], item[1:33], item[33:65]
        old = item[65:97]
        balance, nonce, prior, current = [_u64(item[j:j+8]) for j in (97,105,113,121)]
        if (mode not in (0,1) or old == bytes(32) or
            (last_old is not None and old <= last_old) or old in seen_old or
            nonce == 0 or prior == 0 or prior == U64_MAX or current != prior + 1):
            raise Reject('account identity/order/generation/nonce')
        last_old = old
        seen_old.add(old)
        if mode == 0:
            if kid != bytes(32):
                raise Reject('quarantined key cannot be spendable')
            expected_id = hashlib.sha256(QUARANTINE_DOMAIN + network + old).digest()
        else:
            if kid == bytes(32) or kid in seen_new:
                raise Reject('duplicate/missing PQ key')
            seen_new.add(kid)
            expected_id = hashlib.sha256(ACCOUNT_DOMAIN + network + old + kid).digest()
        if aid != expected_id:
            raise Reject('account id substitution')
        accounts.append(AccountObservation(old,aid,kid,balance,nonce,prior,current,mode==0,item))
    if pos+2 > len(raw):
        raise Reject('liability count missing')
    nl = int.from_bytes(raw[pos:pos+2], 'big'); pos += 2
    if nl > MAX_LIABILITIES or len(raw) != pos + nl*LIABILITY_SIZE + 8:
        raise Reject('liability framing/trailing')
    liabilities = []
    last_id = None
    for _ in range(nl):
        item = raw[pos:pos+LIABILITY_SIZE]
        pos += LIABILITY_SIZE
        lid, owner = item[0:32], item[32:64]
        amount, due, kind = _u64(item[64:72]), _u64(item[72:80]), item[80]
        if (lid == bytes(32) or (last_id is not None and lid <= last_id) or
                owner not in seen_old or amount == 0 or kind not in KINDS):
            raise Reject('liability identity/owner/value/order')
        last_id = lid
        liabilities.append(LiabilityObservation(lid,owner,amount,due,kind,item))
    total = _u64(raw[pos:pos+8])
    if total != sum(a.balance for a in accounts) + sum(x.amount for x in liabilities):
        raise Reject('issuance and all liabilities not conserved')
    if _frame_hash(STATE_DOMAIN,raw) != state_root:
        raise Reject('PQS1 external state root mismatch')
    derived_genesis = _frame_hash(GENESIS_ID_DOMAIN,network+profile+source_digest+state_root)
    if derived_genesis != genesis_id:
        raise Reject('new genesis external identity mismatch')
    # Distinct protocol tag. Account bytes and obligation bytes are copied in order,
    # preserving nonce, generation, custody/quarantine, amount, due and kind exactly.
    output = (b'PQI1\x01' + network + profile + source_digest + state_root + genesis_id
              + total.to_bytes(8,'big') + count.to_bytes(2,'big')
              + nl.to_bytes(2,'big') + b''.join(a.raw for a in accounts)
              + b''.join(x.raw for x in liabilities))
    assert len(output) <= MAX_STATE_BYTES  # all terms bounded by validated PQS1
    return ImportObservation(output, _frame_hash(IMPORT_DOMAIN,output), source_digest,
                             state_root,genesis_id,total,
                             sum(not a.quarantined for a in accounts),
                             sum(a.quarantined for a in accounts),nl)


def decode_import_exact(data: bytes) -> ImportObservation:
    """Decode a PQI1 observation; never accept it as an on-chain genesis grant."""
    if type(data) is not bytes or not 5+32+32+48*3+8+2+2+ACCOUNT_SIZE <= len(data) <= MAX_STATE_BYTES:
        raise Reject('PQI1 bounds')
    if data[:5] != b'PQI1\x01':
        raise Reject('PQI1 version')
    network, profile = data[5:37], data[37:69]
    source, root, genesis = data[69:117],data[117:165],data[165:213]
    n=int.from_bytes(data[221:223],'big')
    m=int.from_bytes(data[223:225],'big')
    if not 1<=n<=MAX_ACCOUNTS or m>MAX_LIABILITIES or len(data)!=225+n*ACCOUNT_SIZE+m*LIABILITY_SIZE:
        raise Reject('PQI1 framing')
    supply=data[213:221]
    pqs=(b'PQS1\x01'+network+profile+n.to_bytes(2,'big')+
         data[225:225+n*ACCOUNT_SIZE]+m.to_bytes(2,'big')+
         data[225+n*ACCOUNT_SIZE:]+supply)
    observation=project_pqs1(pqs,expected_network=network, expected_profile=profile,
        expected_source_digest=source,expected_state_root=root,expected_genesis_id=genesis)
    if observation.projection_bytes != data:
        raise Reject('PQI1 noncanonical bytes')
    return observation
