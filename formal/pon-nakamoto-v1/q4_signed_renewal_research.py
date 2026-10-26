"""Read-only cryptographic Q4 tag22 research verifier (non-authoritative).

Exact PNX1/QDL2/QWA2/QWT1 bytes, PoN signing domains, and *both* Ed25519
signatures are checked before a synthetic outbox may log a prepared renewal.
This is not the native strict Ed25519/Node verifier: registered source ownership,
current withdrawal frontier, funds, account nonce and real W1 material/chain
remain the original M01/M06/M07 authority. No automatic signing or submission.
The optional `cryptography` dependency is required to evaluate a signature; an
unavailable backend fails closed rather than producing a verification receipt.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

MAGIC = b"TRNM-PON1\0"
ZERO = bytes(32)
UINT64_MAX = (1 << 64) - 1
QDL_BYTES = 344
QWA_BYTES = 684
QWT_BYTES = 584
PNX_BYTES = 1187


class Q4PacketError(ValueError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise Q4PacketError(why)


def hash_pon(label: bytes, *parts: bytes) -> bytes:
    require(len(label) <= 0xffff and all(type(x) is bytes and len(x) <= 0xffffffff for x in parts), "HASH_INPUT")
    h = hashlib.sha256(MAGIC + struct.pack('<H', len(label)) + label)
    for p in parts:
        h.update(struct.pack('<I', len(p)))
        h.update(p)
    return h.digest()


def hash32(value: bytes, name: str, *, allow_zero: bool = False) -> bytes:
    require(type(value) is bytes and len(value) == 32 and (allow_zero or value != ZERO), name)
    return value


def u64le(data: bytes) -> int:
    require(len(data) == 8, "U64_LENGTH")
    return int.from_bytes(data, 'little')


def signature_valid(public: bytes, message: bytes, signature: bytes) -> bool:
    """Signature verification is deliberately not an authority-token factory."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise Q4PacketError('CRYPTO_BACKEND_UNAVAILABLE') from exc
    try:
        Ed25519PublicKey.from_public_bytes(hash32(public, "PUBLIC_KEY")).verify(signature, message)
        return True
    except (InvalidSignature, ValueError) as exc:
        return False


@dataclass(frozen=True)
class LeaseFields:
    raw: bytes
    slot: int
    purpose: int
    network: bytes
    parameters: bytes
    demand_id: bytes
    requester: bytes
    source: bytes
    source_record: bytes
    authorization: bytes
    availability_manifest: bytes
    availability_root: bytes
    generation: int
    revision: int
    not_before: int
    expires: int
    available_until: int
    cost_class: int
    lease_id: bytes


def decode_lease(raw: bytes) -> LeaseFields:
    require(type(raw) is bytes and len(raw) == QDL_BYTES, "QDL_LENGTH")
    require(raw[:4] == b'QDL2' and raw[4:6] == b'\x02\x00', "QDL_VERSION")
    slot, purpose = raw[6], raw[7]
    require(slot < 32 and purpose in (1, 2, 3, 4), "QDL_SLOT_PURPOSE")
    hashes = [hash32(raw[8+i*32:8+(i+1)*32], 'QDL_IDENTITY') for i in range(9)]
    network, parameters, demand, requester, source, source_record, auth, manifest, root = hashes
    values = [u64le(raw[296+8*i:304+8*i]) for i in range(5)]
    generation, revision, start, expires, retention = values
    require(generation > 0 and revision > 0 and requester != source, "QDL_IDENTITY")
    require(demand == hash_pon(b'qualified-demand-id-v2', network, parameters, requester, generation.to_bytes(8, 'little')), "QDL_DEMAND")
    require(start < expires and expires-start <= 1000 and expires <= UINT64_MAX - 100 and retention == expires+100, "QDL_WINDOW")
    require(raw[336] == 1 and raw[337:] == bytes(7), "QDL_CANONICAL")
    return LeaseFields(raw,slot,purpose,network,parameters,demand,requester,source,
                       source_record,auth,manifest,root,generation,revision,start,
                       expires,retention,raw[336],hash_pon(b'qualified-demand-lease-v2',raw))


@dataclass(frozen=True)
class ParsedRenewal:
    transaction_id: bytes
    raw_sha256: bytes
    old_lease_id: bytes
    new_lease_id: bytes
    requester_key: bytes
    source_key: bytes
    requester_sequence: int
    source_sequence: int
    new_start: int
    old_expires: int
    included_height: int


def verify_tag22(raw: bytes, old_lease_raw: bytes, network: bytes, parameters: bytes,
                 *, containing_height: int, old_source_sequence: int,
                 expected_requester_sequence: int,
                 expected_old_lease_id: bytes) -> ParsedRenewal:
    """Pure packet and signature check, never a chain or lease-ownership verdict."""
    require(type(raw) is bytes and len(raw) == PNX_BYTES, "PNX_LENGTH")
    network = hash32(network, "NETWORK")
    parameters = hash32(parameters, "PARAMETERS")
    old = decode_lease(old_lease_raw)
    # The successor's signatures DO NOT cover the predecessor lease bytes.
    # Refuse any old-lease rewrite absent the independently pinned original ID.
    require(old.lease_id == hash32(expected_old_lease_id, "OLD_LEASE_PIN"), "OLD_LEASE_PIN")
    require(old.network == network and old.parameters == parameters, "OLD_CONTEXT")
    require(type(containing_height) is int and 1 <= containing_height <= UINT64_MAX, "HEIGHT")
    require(type(old_source_sequence) is int and 1 <= old_source_sequence < UINT64_MAX, "SOURCE_SEQUENCE")
    require(type(expected_requester_sequence) is int and 1 <= expected_requester_sequence <= UINT64_MAX, "REQUESTER_SEQUENCE")
    require(raw[:4] == b'PNX1' and raw[4:36] == network, "PNX_CONTEXT")
    requester = hash32(raw[36:68], 'PNX_SENDER')
    nonce, expiry, fee = (u64le(raw[i:i+8]) for i in (68, 76, 84))
    require(raw[92] == 22 and raw[93:95] == (1028).to_bytes(2, 'little'), "PNX_TAG_SIZE")
    require(nonce == expected_requester_sequence and expiry >= containing_height and fee <= 10_000_000, "PNX_SEQUENCE_EXPIRY_FEE")
    next_ = decode_lease(raw[95:439])
    require(next_.network == network and next_.parameters == parameters and next_.requester == requester, "NEW_CONTEXT_REQUESTER")
    require(next_.slot == old.slot and next_.purpose == old.purpose and
            next_.generation == old.generation and next_.revision == old.revision+1,
            "Q4_IMMUTABLE_SLOT")
    require((next_.demand_id,next_.requester,next_.source,next_.source_record,
             next_.authorization,next_.availability_manifest,next_.availability_root,
             next_.cost_class) ==
            (old.demand_id,old.requester,old.source,old.source_record,
             old.authorization,old.availability_manifest,old.availability_root,
             old.cost_class), "Q4_IMMUTABLE_SOURCE")
    require(old.not_before <= next_.not_before <= containing_height <= old.expires and
            next_.expires > old.expires, "Q4_SIGNED_OVERLAP")
    signed = raw[439:1123]
    require(len(signed) == QWA_BYTES and signed[:4] == b'QWA2' and signed[4:36] == next_.lease_id, "QWA_LEASE_BINDING")
    manifest = signed[36:620]
    require(len(manifest) == QWT_BYTES and manifest[:4] == b'QWT1' and manifest[4:6] == b'\x01\x00', "QWT_VERSION")
    require(manifest[6:12] == bytes([next_.purpose, 1, 1, 0, 1, 0]), "QWT_FIXED_FIELDS")
    claims = [hash32(manifest[12+i*32:12+(i+1)*32], 'QWT_CLAIM') for i in range(16)]
    (mn,mp,wp,source,demand,source_record,model,layer,inp,recipe,mat_task,
     avail_manifest,avail_root,authorization,withdraw,output_meter) = claims
    require((mn,mp,source,demand,avail_manifest,avail_root,authorization) ==
            (network,parameters,next_.source,next_.demand_id,next_.availability_manifest,
             next_.availability_root,next_.authorization), "QWT_CONTEXT")
    require(wp == hash_pon(b'qualified-task-profile-v1', b'pon-matmul-transcript-64-v1') and
            recipe == hash_pon(b'qualified-task-recipe-v1', b'canonical-field-matrix64-product-v1') and
            layer == hash_pon(b'qualified-task-layer-v1',model,b'entire-row-major-field-layer-64x64'), "QWT_RECIPE")
    require(source_record == hash_pon(b'qualified-demand-source-record-v2', next_.lease_id, next_.source_record) and
            withdraw == hash_pon(b'qualified-demand-frontier-v2', next_.lease_id), "QWT_WITHDRAWAL")
    require(output_meter == hash_pon(b'qualified-task-output-meter-v1',network,parameters,demand,
                                     model,layer,inp,recipe,mat_task), "QWT_OUTPUT_METER")
    require(manifest[524:532] == b'@\x00@\x00@\x00\x00\x00', "QWT_SHAPE")
    seq,start,end,retained,ops = [u64le(manifest[532+i*8:540+i*8]) for i in range(5)]
    require(seq == old_source_sequence+1 and (start,end,retained) ==
            (next_.not_before,next_.expires,next_.available_until) and ops == 64**3,
            "QWT_SOURCE_SEQUENCE_WINDOW")
    require(manifest[572:584] == struct.pack('<III',16384,16384,0 if next_.purpose==1 else 1), "QWT_BOUNDS")
    require(signature_valid(next_.source, hash_pon(b'qualified-task-source-sign-v2', signed[:620]), signed[620:]), "QWA_BAD_SIGNATURE")
    require(signature_valid(requester, hash_pon(b'tx-sign',raw[:-64]), raw[-64:]), "PNX_BAD_SIGNATURE")
    return ParsedRenewal(hash_pon(b'tx-id',raw), hashlib.sha256(raw).digest(),
                         old.lease_id,next_.lease_id,requester,next_.source,
                         nonce,seq,next_.not_before,old.expires,containing_height)


def checked_prepare(outbox, intent, old_lease_raw: bytes, *, containing_height: int,
                    old_source_sequence: int, expected_old_lease_id: bytes) -> bytes:
    """Require dual-signature verification before invoking the SAME old research journal.

    Refuses on any mismatch and never writes journal state before both signatures,
    fixed wire, observed context and original operation bindings check out. The
    journal itself remains a research owner; it does not dispatch a transaction.
    """
    require((intent.network,intent.parameters,intent.genesis) == outbox.context, "INTENT_CONTEXT")
    # Caller must obtain expected_old_lease_id from the actual parent-state owner.
    # Intent.old_lease_digest itself is untrusted proposal metadata and cannot
    # independently authenticate its own predecessor even if signed next bytes match.
    require(intent.old_lease_digest == hash32(expected_old_lease_id, "OLD_LEASE_OWNER_PIN"),
            "OLD_LEASE_OWNER_PIN")
    parsed = verify_tag22(intent.signed_transaction, old_lease_raw,
                          intent.network,intent.parameters,
                          containing_height=containing_height,
                          old_source_sequence=old_source_sequence,
                          expected_requester_sequence=intent.requester_sequence,
                          expected_old_lease_id=expected_old_lease_id)
    require(intent.old_lease_digest == parsed.old_lease_id and
            intent.next_lease_digest == parsed.new_lease_id and
            intent.signed_from == parsed.new_start and
            intent.last_legal_height == parsed.old_expires and
            intent.source_sequence == parsed.source_sequence, "INTENT_PACKET_MISMATCH")
    # Call only the existing idempotent prepare. No new operation ID, signature,
    # nonce, payment, retry identity or dispatch permit is constructed here.
    return outbox.prepare(intent)
