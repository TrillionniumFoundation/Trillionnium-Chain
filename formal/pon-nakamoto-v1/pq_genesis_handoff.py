"""PQG1: exact, non-authoritative Ed25519 -> ML-DSA-65 genesis handoff oracle.

Research only. This verifies byte identity, two real possession signatures, no
cross-network replay, a conservation check, and explicit quarantine of unmigrated
balances. It DOES NOT validate source Chain state or grant mining, release, Final-use,
model export, activation, or historical ownership. It cannot prevent a quantum adversary
from forging an already compromised Ed25519 key before migration.

A trusted independent old-chain observer MUST supply the exact expected source digest,
source head, revocation head and issued supply. Self-consistent source bytes are not
proof that the old state or liabilities are authentic or complete.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

from strict_signature import verify as verify_ed25519_strict

SOURCE_MAGIC = b"PQG1"
MIGRATION_DOMAIN = b"TRNM/PQ/GenesisMigration/v1\x00"
SOURCE_DOMAIN = b"TRNM/PQ/GenesisSource/v1\x00"
GENESIS_DOMAIN = b"TRNM/PQ/GenesisState/v1\x00"
KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\x00"
MLDSA_OID = bytes.fromhex("0609608648016503040312")
MAX_ACCOUNTS = 128
MAX_LIABILITIES = 256
MAX_SOURCE_BYTES = 65536
MAX_PUBLIC_PEM = 8192
SIGNATURE_SIZE = 3309
U64_MAX = (1 << 64) - 1
KIND_TASK = 1
KIND_REWARD = 2
KIND_QUOTA = 3
KIND_ESCROW = 4


class Reject(ValueError):
    pass


def b32(v: bytes, label: str, *, positive: bool = True) -> bytes:
    if type(v) is not bytes or len(v) != 32 or (positive and v == bytes(32)):
        raise Reject(label)
    return v


def u64(v: int, label: str, *, positive: bool = False) -> bytes:
    if type(v) is not int or not int(positive) <= v <= U64_MAX:
        raise Reject(label)
    return v.to_bytes(8, 'big')


def sha384(domain: bytes, raw: bytes) -> bytes:
    if type(raw) is not bytes:
        raise Reject('hash input type')
    return hashlib.sha384(domain + len(raw).to_bytes(8, 'big') + raw).digest()


def _openssl(argv: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        child = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject('OpenSSL unavailable') from exc
    if child.returncode:
        raise Reject('ML-DSA-65 cryptographic operation rejected')
    return child.stdout


def _der_len(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise Reject('SPKI truncated')
    marker = raw[offset]; offset += 1
    if marker < 128:
        return marker, offset
    n = marker & 127
    if n == 0 or n > 3 or offset+n > len(raw) or raw[offset] == 0:
        raise Reject('SPKI noncanonical length')
    value = int.from_bytes(raw[offset:offset+n], 'big')
    if value < 128:
        raise Reject('SPKI overlong')
    return value, offset+n


def pq_key_id(public_pem: bytes) -> bytes:
    """Require exact FIPS 204 ML-DSA-65 SPKI, never Ed25519/classical downgrade."""
    if type(public_pem) is not bytes or not 1 <= len(public_pem) <= MAX_PUBLIC_PEM:
        raise Reject('PQ public key bytes')
    with tempfile.TemporaryDirectory(prefix='pqg-pub-') as tmp:
        path = Path(tmp) / 'key.pem'; path.write_bytes(public_pem)
        der = _openssl(['openssl','pkey','-pubin','-in',str(path),'-outform','DER'])
    if not der or der[0] != 0x30:
        raise Reject('SPKI outer')
    n, start = _der_len(der, 1)
    if start + n != len(der) or der[start:start+1] != b'\x30':
        raise Reject('SPKI envelope')
    alg_n, alg_start = _der_len(der, start+1)
    if der[alg_start:alg_start+alg_n] != MLDSA_OID:
        raise Reject('SPKI wrong algorithm/parameters')
    bit = alg_start+alg_n
    if bit >= len(der) or der[bit] != 0x03:
        raise Reject('SPKI missing public bytes')
    bit_n, bit_start = _der_len(der, bit+1)
    if bit_n != 1953 or bit_start + bit_n != len(der) or der[bit_start] != 0:
        raise Reject('SPKI wrong key size/padding')
    return hashlib.sha256(KEY_DOMAIN + der).digest()


def verify_pq(public_pem: bytes, message: bytes, signature: bytes) -> None:
    pq_key_id(public_pem)
    if type(signature) is not bytes or len(signature) != SIGNATURE_SIZE:
        raise Reject('ML-DSA-65 signature size')
    if type(message) is not bytes or len(message) > 65536:
        raise Reject('signed statement length')
    with tempfile.TemporaryDirectory(prefix='pqg-verify-') as tmp:
        root = Path(tmp)
        for name, data in (('p',public_pem),('m',message),('s',signature)):
            (root/name).write_bytes(data)
        _openssl(['openssl','pkeyutl','-verify','-pubin','-inkey',str(root/'p'),
                  '-rawin','-in',str(root/'m'),'-sigfile',str(root/'s')])


def sign_pq_fixture(private_key: Path, message: bytes) -> bytes:
    """Development tests ONLY; never a production key-custody or signer port."""
    if type(message) is not bytes or len(message) > 65536:
        raise Reject('signed statement size')
    with tempfile.TemporaryDirectory(prefix='pqg-sign-') as tmp:
        root=Path(tmp)
        (root/'message').write_bytes(message)
        _openssl(['openssl','pkeyutl','-sign','-inkey',os.fspath(private_key),
                  '-rawin','-in',str(root/'message'),'-out',str(root/'signature')])
        result=(root/'signature').read_bytes()
    if len(result)!=SIGNATURE_SIZE:
        raise Reject('signature provider output size')
    return result


@dataclass(frozen=True)
class LegacyAccount:
    old_ed25519_public: bytes
    balance: int
    next_nonce: int
    generation: int

    def encode(self) -> bytes:
        return (b32(self.old_ed25519_public,'old public')
                + u64(self.balance,'balance')
                + u64(self.next_nonce,'old next nonce',positive=True)
                + u64(self.generation,'old generation',positive=True))


@dataclass(frozen=True)
class Liability:
    liability_id: bytes
    owner_old_public: bytes
    amount: int
    due_height: int
    kind: int

    def encode(self) -> bytes:
        if type(self.kind) is not int or self.kind not in (KIND_TASK,KIND_REWARD,KIND_QUOTA,KIND_ESCROW):
            raise Reject('liability kind')
        return (b32(self.liability_id,'liability identity')
                + b32(self.owner_old_public,'liability owner')
                + u64(self.amount,'liability amount',positive=True)
                + u64(self.due_height,'liability due') + bytes([self.kind]))


@dataclass(frozen=True)
class SourceSnapshot:
    legacy_network: bytes
    new_network: bytes
    legacy_head: bytes
    revocation_head: bytes
    new_protocol_hash: bytes
    issued_units: int
    accounts: tuple[LegacyAccount, ...]
    liabilities: tuple[Liability, ...]

    def encode(self) -> bytes:
        if (type(self.accounts) is not tuple or not 1 <= len(self.accounts) <= MAX_ACCOUNTS
            or type(self.liabilities) is not tuple or len(self.liabilities) > MAX_LIABILITIES):
            raise Reject('source roster bound')
        if self.legacy_network == self.new_network:
            raise Reject('in-place network reinterpretation forbidden')
        keys=[a.old_ed25519_public for a in self.accounts]
        if keys != sorted(set(keys)):
            raise Reject('unsorted/duplicate old signer')
        lid=[o.liability_id for o in self.liabilities]
        if lid != sorted(set(lid)):
            raise Reject('unsorted/duplicate liability')
        if any(o.owner_old_public not in keys for o in self.liabilities):
            raise Reject('liability missing owner')
        accounts=b''.join(a.encode() for a in self.accounts)
        obligations=b''.join(o.encode() for o in self.liabilities)
        total=sum(a.balance for a in self.accounts)+sum(o.amount for o in self.liabilities)
        if total>U64_MAX or total!=self.issued_units:
            raise Reject('issued supply/escrow liability not conserved')
        result=(SOURCE_MAGIC+b'\x01'
                +b32(self.legacy_network,'old network')
                +b32(self.new_network,'new network')
                +b32(self.legacy_head,'old head')
                +b32(self.revocation_head,'revocation head')
                +b32(self.new_protocol_hash,'new protocol profile')
                +u64(self.issued_units,'issued supply')
                +len(self.accounts).to_bytes(2,'big')
                +len(self.liabilities).to_bytes(2,'big')
                +accounts+obligations)
        if len(result)>MAX_SOURCE_BYTES:
            raise Reject('snapshot input bound')
        return result


def decode_snapshot(raw: bytes) -> SourceSnapshot:
    if type(raw) is not bytes or not 5+160+8+4+56 <= len(raw) <= MAX_SOURCE_BYTES:
        raise Reject('snapshot byte bound')
    if raw[:5] != SOURCE_MAGIC + b'\x01':
        raise Reject('snapshot magic/version')
    count=int.from_bytes(raw[173:175],'big'); count_l=int.from_bytes(raw[175:177],'big')
    if not 1<=count<=MAX_ACCOUNTS or count_l>MAX_LIABILITIES or len(raw)!=177+56*count+81*count_l:
        raise Reject('snapshot framing')
    pos=177; acc=[]; liabilities=[]
    for _ in range(count):
        v=raw[pos:pos+56]
        acc.append(LegacyAccount(v[:32],int.from_bytes(v[32:40],'big'),
                                 int.from_bytes(v[40:48],'big'),int.from_bytes(v[48:56],'big')))
        pos+=56
    for _ in range(count_l):
        v=raw[pos:pos+81]
        liabilities.append(Liability(v[:32],v[32:64],int.from_bytes(v[64:72],'big'),
                                     int.from_bytes(v[72:80],'big'),v[80]))
        pos+=81
    obj=SourceSnapshot(raw[5:37],raw[37:69],raw[69:101],raw[101:133],raw[133:165],
                       int.from_bytes(raw[165:173],'big'),tuple(acc),tuple(liabilities))
    if obj.encode()!=raw:
        raise Reject('snapshot noncanonical')
    return obj


@dataclass(frozen=True)
class MigrationEvidence:
    old_public: bytes
    new_pq_public_pem: bytes
    expires_at: int
    old_signature: bytes
    pq_signature: bytes


def migration_statement(snapshot: SourceSnapshot, account: LegacyAccount,
                        pq_public_key_id: bytes, expiry: int) -> bytes:
    if account not in snapshot.accounts:
        raise Reject('unrecognized source account')
    if account.generation == U64_MAX:
        raise Reject('generation exhausted')
    return (MIGRATION_DOMAIN + sha384(SOURCE_DOMAIN,snapshot.encode())
            + b32(snapshot.legacy_network,'old network')
            + b32(snapshot.new_network,'new network')
            + b32(snapshot.legacy_head,'old head')
            + b32(snapshot.revocation_head,'revocation head')
            + b32(snapshot.new_protocol_hash,'new profile')
            + account.encode() + b32(pq_public_key_id,'PQ signer')
            + u64(account.generation+1,'next generation')
            + u64(expiry,'expiry',positive=True))


def sign_migration_fixture(snapshot: SourceSnapshot, account: LegacyAccount, *,
                           old_private, new_pq_public: bytes,
                           new_pq_private: Path, expires_at: int) -> MigrationEvidence:
    """Test-only two private-key fixture; actual owner authorization remains external."""
    kid=pq_key_id(new_pq_public)
    payload=migration_statement(snapshot,account,kid,expires_at)
    old_signature=old_private.sign(payload)
    return MigrationEvidence(account.old_ed25519_public,new_pq_public,expires_at,
                             old_signature,sign_pq_fixture(new_pq_private,payload))


@dataclass(frozen=True)
class GenesisObservation:
    """Read-only analysis facts, never adoption/activation/consensus authority."""
    source_digest: bytes
    target_genesis_id: bytes
    target_state_root: bytes
    target_state_bytes: bytes
    migrated_count: int
    quarantined_count: int
    imported_liability_count: int
    conserved_units: int


def _state_bytes(snapshot: SourceSnapshot, account_records: tuple[bytes,...]) -> bytes:
    # Canonical, explicitly non-consensus test state. No old account signature may spend.
    return (b'PQS1'+b'\x01'+snapshot.new_network+snapshot.new_protocol_hash
            +len(account_records).to_bytes(2,'big')+b''.join(account_records)
            +len(snapshot.liabilities).to_bytes(2,'big')
            +b''.join(o.encode() for o in snapshot.liabilities)
            +u64(snapshot.issued_units,'target supply'))


def verify_handoff(raw_source: bytes, *, expected_source_digest: bytes,
                   expected_legacy_network: bytes, expected_new_network: bytes,
                   expected_legacy_head: bytes, expected_revocation_head: bytes,
                   expected_new_protocol_hash: bytes, expected_issued_units: int,
                   migration_evidence: tuple[MigrationEvidence, ...],
                   independently_revoked_old_keys: frozenset[bytes],
                   now: int) -> GenesisObservation:
    """All trusted expected inputs must come from distinct authorized source owners.

    In particular expected_source_digest obtained from raw_source is insufficient;
    caller trust, historical chain validation, obligations and rollback anchoring
    remain outside this oracle. Reject unknown/revoked migrations rather than invent
    an authorization or a classical fallback.
    """
    snap=decode_snapshot(raw_source)
    if type(expected_source_digest) is not bytes or len(expected_source_digest)!=48 or expected_source_digest==bytes(48):
        raise Reject('trusted digest length/identity')
    if (sha384(SOURCE_DOMAIN,raw_source)!=expected_source_digest
        or snap.legacy_network!=b32(expected_legacy_network,'expected old network')
        or snap.new_network!=b32(expected_new_network,'expected new network')
        or snap.legacy_head!=b32(expected_legacy_head,'expected source head')
        or snap.revocation_head!=b32(expected_revocation_head,'expected revocation')
        or snap.new_protocol_hash!=b32(expected_new_protocol_hash,'expected profile')
        or type(expected_issued_units) is not int or snap.issued_units!=expected_issued_units):
        raise Reject('untrusted/stale/wrong source snapshot')
    u64(now,'observation time')
    if type(migration_evidence) is not tuple or len(migration_evidence)>len(snap.accounts):
        raise Reject('migration count')
    if type(independently_revoked_old_keys) is not frozenset or not all(
            type(x) is bytes and len(x)==32 for x in independently_revoked_old_keys):
        raise Reject('revocation authority type')
    if any(k not in {a.old_ed25519_public for a in snap.accounts}
           for k in independently_revoked_old_keys):
        raise Reject('foreign revocation identity')
    mapping={}
    pqs=set()
    for m in migration_evidence:
        if not isinstance(m,MigrationEvidence) or m.old_public in mapping:
            raise Reject('duplicated/invalid migration')
        match=next((a for a in snap.accounts if a.old_ed25519_public==m.old_public),None)
        if match is None or m.old_public in independently_revoked_old_keys:
            raise Reject('unknown/revoked original authority')
        kid=pq_key_id(m.new_pq_public_pem)
        if kid in pqs:
            raise Reject('shared PQ identity across old accounts')
        if type(m.old_signature) is not bytes or len(m.old_signature)!=64:
            raise Reject('old signature length')
        payload=migration_statement(snap,match,kid,m.expires_at)
        if now>m.expires_at:
            raise Reject('expired migration')
        try:
            verify_ed25519_strict(m.old_public,m.old_signature,payload)
        except ValueError as exc:
            raise Reject('old owner possession invalid') from exc
        verify_pq(m.new_pq_public_pem,payload,m.pq_signature)
        mapping[m.old_public]=kid
        pqs.add(kid)
    records=[]
    for account in snap.accounts:
        old=account.old_ed25519_public
        kid=mapping.get(old)
        if kid is None:
            # Legacy-only signature cannot spend from a new-PQ-only account.
            account_id=hashlib.sha256(b'TRNM/PQ/Quarantine/v1\x00'+snap.new_network+old).digest()
            records.append(b'\x00'+account_id+bytes(32)+account.encode()+u64(account.generation+1,'generation'))
        else:
            account_id=hashlib.sha256(b'TRNM/PQ/Account/v1\x00'+snap.new_network+old+kid).digest()
            records.append(b'\x01'+account_id+kid+account.encode()+u64(account.generation+1,'generation'))
    target=_state_bytes(snap,tuple(records))
    root=sha384(GENESIS_DOMAIN,target)
    genesis=sha384(b'TRNM/PQ/GenesisID/v1\x00',snap.new_network+snap.new_protocol_hash+expected_source_digest+root)
    return GenesisObservation(expected_source_digest,genesis,root,target,
                              len(mapping),len(snap.accounts)-len(mapping),len(snap.liabilities),snap.issued_units)
