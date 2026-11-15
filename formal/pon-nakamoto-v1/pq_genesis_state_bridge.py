"""PQL2: exact PQG1/PQS1 -> fork-independent PQ account/liability projection.

RESEARCH / HOLD_NO_GO. This is deliberately NOT the installed PQL1 ledger,
not a source-chain verifier, PQ-signature verifier, account import authority,
Final-use grant, or full-node activation. The caller MUST first verify the
actual PQG1 Ed25519+ML-DSA signatures and independently authenticate all
external anchor values; matching an attacker-supplied hash is not provenance.

In contrast to PQL1's clean-fixture genesis, PQL2 preserves the old next_nonce,
keeps every liability locked, and marks unmigrated identities quarantined.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

SOURCE_DOMAIN = b"TRNM/PQ/GenesisSource/v1\x00"
STATE_DOMAIN = b"TRNM/PQ/GenesisState/v1\x00"
GENESIS_ID_DOMAIN = b"TRNM/PQ/GenesisID/v1\x00"
PQL2_DOMAIN = b"TRNM/PQ/PQL2State/v1\x00"
SOURCE_MAGIC = b"PQG1\x01"
STATE_MAGIC = b"PQS1\x01"
NEW_MAGIC = b"PQL2\x01"
MAX_ACCOUNTS = 128
MAX_LIABILITIES = 256
MAX_SOURCE_BYTES = 65536
U64_MAX = (1 << 64) - 1
LIABILITY_KINDS = (1, 2, 3, 4)  # task, reward, quota, escrow


class Reject(ValueError):
    """Incorrect framing, untrusted anchor, stale identity or lost liability."""


def _blob(value: bytes, n: int, label: str, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != n or (nonzero and value == bytes(n)):
        raise Reject(label)
    return value


def _u64(value: int, label: str, *, positive: bool = False) -> bytes:
    if type(value) is not int or value < int(positive) or value > U64_MAX:
        raise Reject(label)
    return value.to_bytes(8, "big")


def _u16(value: int, label: str) -> bytes:
    if type(value) is not int or not 0 <= value <= 65535:
        raise Reject(label)
    return value.to_bytes(2, "big")


def _get64(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def _commit(domain: bytes, value: bytes) -> bytes:
    if type(value) is not bytes:
        raise Reject("commit input must be bytes")
    return hashlib.sha384(domain + len(value).to_bytes(8, "big") + value).digest()


@dataclass(frozen=True)
class SourceAccount:
    old_key: bytes
    balance: int
    next_nonce: int
    generation: int

    def encode(self) -> bytes:
        return (_blob(self.old_key, 32, "old identity", nonzero=True)
                + _u64(self.balance, "balance")
                + _u64(self.next_nonce, "source nonce", positive=True)
                + _u64(self.generation, "source generation", positive=True))


@dataclass(frozen=True)
class Liability:
    liability_id: bytes
    old_owner: bytes
    amount: int
    due_height: int
    kind: int

    def encode(self) -> bytes:
        if type(self.kind) is not int or self.kind not in LIABILITY_KINDS:
            raise Reject("liability kind")
        return (_blob(self.liability_id, 32, "liability ID", nonzero=True)
                + _blob(self.old_owner, 32, "liability owner", nonzero=True)
                + _u64(self.amount, "liability amount", positive=True)
                + _u64(self.due_height, "liability due") + bytes([self.kind]))


@dataclass(frozen=True)
class Source:
    legacy_network: bytes
    new_network: bytes
    legacy_head: bytes
    revocation_head: bytes
    protocol: bytes
    issued: int
    accounts: tuple[SourceAccount, ...]
    liabilities: tuple[Liability, ...]

    def encode(self) -> bytes:
        if (type(self.accounts) is not tuple or not 1 <= len(self.accounts) <= MAX_ACCOUNTS
                or type(self.liabilities) is not tuple or len(self.liabilities) > MAX_LIABILITIES):
            raise Reject("source counts")
        legacy = _blob(self.legacy_network, 32, "legacy network", nonzero=True)
        new = _blob(self.new_network, 32, "new network", nonzero=True)
        if legacy == new:
            raise Reject("must use new chain identity")
        ids = [a.old_key for a in self.accounts]
        lids = [l.liability_id for l in self.liabilities]
        if ids != sorted(set(ids)) or lids != sorted(set(lids)):
            raise Reject("duplicate or unordered source")
        if any(l.old_owner not in ids for l in self.liabilities):
            raise Reject("orphaned liability")
        if sum(a.balance for a in self.accounts) + sum(l.amount for l in self.liabilities) != self.issued:
            raise Reject("issuance/obligations mismatch")
        value = (SOURCE_MAGIC + legacy + new
                 + _blob(self.legacy_head, 32, "legacy head", nonzero=True)
                 + _blob(self.revocation_head, 32, "withdrawal head", nonzero=True)
                 + _blob(self.protocol, 32, "new protocol", nonzero=True)
                 + _u64(self.issued, "issued supply")
                 + _u16(len(self.accounts), "accounts")
                 + _u16(len(self.liabilities), "liabilities")
                 + b"".join(a.encode() for a in self.accounts)
                 + b"".join(l.encode() for l in self.liabilities))
        if len(value) > MAX_SOURCE_BYTES:
            raise Reject("source length")
        return value


def parse_source(raw: bytes) -> Source:
    if type(raw) is not bytes or not 233 <= len(raw) <= MAX_SOURCE_BYTES:
        raise Reject("source byte ceiling")
    if raw[:5] != SOURCE_MAGIC:
        raise Reject("source magic")
    ac, lc = int.from_bytes(raw[173:175], "big"), int.from_bytes(raw[175:177], "big")
    if not 1 <= ac <= MAX_ACCOUNTS or lc > MAX_LIABILITIES or len(raw) != 177 + 56*ac + 81*lc:
        raise Reject("source framing")
    accounts, liabilities, pos = [], [], 177
    for _ in range(ac):
        b = raw[pos:pos+56]
        accounts.append(SourceAccount(b[:32],_get64(b[32:40]),_get64(b[40:48]),_get64(b[48:56])))
        pos += 56
    for _ in range(lc):
        b = raw[pos:pos+81]
        liabilities.append(Liability(b[:32],b[32:64],_get64(b[64:72]),_get64(b[72:80]),b[80]))
        pos += 81
    source = Source(raw[5:37],raw[37:69],raw[69:101],raw[101:133],raw[133:165],
                    _get64(raw[165:173]),tuple(accounts),tuple(liabilities))
    if source.encode() != raw:
        raise Reject("source noncanonical")
    return source


@dataclass(frozen=True)
class NewAccount:
    status: int  # 0 quarantined, 1 PQ key eligible *in research source only*
    account_id: bytes
    pq_key_id: bytes
    source: SourceAccount
    generation: int

    def encode_pqs1(self, network: bytes) -> bytes:
        if type(self.status) is not int or self.status not in (0,1):
            raise Reject("account status")
        if self.source.generation >= U64_MAX or self.generation != self.source.generation + 1:
            raise Reject("generation rollback/wrap")
        if self.status == 0:
            if self.pq_key_id != bytes(32):
                raise Reject("quarantine must have no signer")
            expected = hashlib.sha256(b"TRNM/PQ/Quarantine/v1\x00"+network+self.source.old_key).digest()
        else:
            _blob(self.pq_key_id,32,"PQ identity",nonzero=True)
            expected = hashlib.sha256(b"TRNM/PQ/Account/v1\x00"+network+self.source.old_key+self.pq_key_id).digest()
        if self.account_id != expected:
            raise Reject("new account identity")
        return (bytes([self.status])+self.account_id+self.pq_key_id
                + self.source.encode()+_u64(self.generation,"target generation",positive=True))


def _parse_pqs1(raw: bytes, source: Source) -> tuple[NewAccount, ...]:
    if type(raw) is not bytes or len(raw) < 71 + 129 + 2 + 8:
        raise Reject("PQS1 length")
    if raw[:5]!=STATE_MAGIC or raw[5:37]!=source.new_network or raw[37:69]!=source.protocol:
        raise Reject("PQS1 context")
    count = int.from_bytes(raw[69:71], "big")
    if count != len(source.accounts):
        raise Reject("PQS1 account count")
    pos, out, pqids, accountids = 71, [], set(), set()
    for original in source.accounts:
        if pos+129 > len(raw):
            raise Reject("PQS1 truncated account")
        data = raw[pos:pos+129]
        from_source = SourceAccount(data[65:97],_get64(data[97:105]),
                                    _get64(data[105:113]),_get64(data[113:121]))
        a = NewAccount(data[0],data[1:33],data[33:65],from_source,_get64(data[121:129]))
        if a.source != original or a.encode_pqs1(source.new_network)!=data:
            raise Reject("PQS1 source nonce, ownership or status changed")
        if a.account_id in accountids or (a.status==1 and a.pq_key_id in pqids):
            raise Reject("duplicate target/PQ owner")
        accountids.add(a.account_id)
        if a.status==1:
            pqids.add(a.pq_key_id)
        out.append(a)
        pos += 129
    if pos+2 > len(raw):
        raise Reject("PQS1 missing liability count")
    count_l = int.from_bytes(raw[pos:pos+2],"big"); pos += 2
    if count_l != len(source.liabilities):
        raise Reject("PQS1 liability count")
    for liability in source.liabilities:
        block = liability.encode()
        if raw[pos:pos+81] != block:
            raise Reject("PQS1 altered liability")
        pos += 81
    if len(raw)!=pos+8 or _get64(raw[pos:pos+8])!=source.issued:
        raise Reject("PQS1 supply/trailing bytes")
    return tuple(out)


@dataclass(frozen=True)
class Projection:
    """Non-authoritative deterministic bytes; NOT a validator/admission capability."""
    source_digest: bytes
    projected_genesis_id: bytes
    projected_state_root: bytes
    pql2_root: bytes
    state: bytes
    active_accounts: int
    quarantined_accounts: int
    carried_liabilities: int
    inherited_nonce_floors: tuple[tuple[bytes,int], ...]
    spendable_units: int
    quarantined_units: int
    locked_liability_units: int
    issued_units: int


def project(raw_source: bytes, raw_pqs1: bytes, *,
            expected_source_digest: bytes, expected_pqs1_root: bytes,
            expected_genesis_id: bytes, expected_legacy_network: bytes,
            expected_new_network: bytes, expected_legacy_head: bytes,
            expected_withdrawal_head: bytes, expected_protocol: bytes,
            expected_issued: int) -> Projection:
    """Pin both independent roots and every source context; NEVER infer anchors from inputs.

    This projects authenticated-by-caller bytes. Upstream verify_handoff MUST independently
    verify both real old/PQ signatures and source-owner policy before invoking it.
    It does not itself execute those signatures or authenticate the caller.
    """
    src = parse_source(raw_source)
    if (_commit(SOURCE_DOMAIN,raw_source)!=_blob(expected_source_digest,48,"source pin",nonzero=True)
       or src.legacy_network!=_blob(expected_legacy_network,32,"legacy net",nonzero=True)
       or src.new_network!=_blob(expected_new_network,32,"target net",nonzero=True)
       or src.legacy_head!=_blob(expected_legacy_head,32,"old chain head",nonzero=True)
       or src.revocation_head!=_blob(expected_withdrawal_head,32,"revocation head",nonzero=True)
       or src.protocol!=_blob(expected_protocol,32,"protocol hash",nonzero=True)
       or type(expected_issued) is not int or src.issued!=expected_issued):
        raise Reject("source authority pin/context mismatch")
    root = _commit(STATE_DOMAIN,raw_pqs1)
    if root != _blob(expected_pqs1_root,48,"PQS1 pin",nonzero=True):
        raise Reject("PQS1 independent root mismatch")
    genesis_data = src.new_network+src.protocol+expected_source_digest+root
    gid = _commit(GENESIS_ID_DOMAIN,genesis_data)
    if gid != _blob(expected_genesis_id,48,"genesis pin",nonzero=True):
        raise Reject("new genesis identity mismatch")
    accounts = _parse_pqs1(raw_pqs1,src)
    spend = sum(a.source.balance for a in accounts if a.status==1)
    quarantine = sum(a.source.balance for a in accounts if a.status==0)
    locked = sum(l.amount for l in src.liabilities)
    if spend+quarantine+locked != src.issued or any(x>U64_MAX for x in (spend,quarantine,locked)):
        raise Reject("source liabilities conservation")
    # PQL2 uniquely represents quarantined and locked claims, unlike PQL1's
    # new-account-only/next_nonce=1 fixture. None of these bytes are an asset.
    out = bytearray(NEW_MAGIC+src.new_network+src.protocol+src.legacy_head+
                    src.revocation_head+expected_source_digest+gid)
    out.extend(_u16(len(accounts),"target account count"))
    for a in accounts:
        out.extend(a.encode_pqs1(src.new_network))
    out.extend(_u16(len(src.liabilities),"target liability count"))
    for l in src.liabilities:
        out.extend(l.encode())
    out.extend(_u64(src.issued,"supply"))
    out.extend(_u64(quarantine,"quarantine"))
    out.extend(_u64(locked,"locked liabilities"))
    serialized = bytes(out)
    return Projection(expected_source_digest,gid,root,_commit(PQL2_DOMAIN,serialized),serialized,
                      sum(a.status==1 for a in accounts),sum(a.status==0 for a in accounts),
                      len(src.liabilities),tuple((a.account_id,a.source.next_nonce) for a in accounts),
                      spend,quarantine,locked,src.issued)
