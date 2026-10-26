"""Non-authoritative independent Python/Ed25519 check of original PoN Q4 tag22 bytes.

This is NOT an actual on-chain verifier. An external trusted native owner must still
provide the active parent lease, signature/withdrawal authorization, bound material,
source sequence, task availability, account state and exact containing height.
No signing key, network dispatch, effect or consensus activation is owned here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Mapping

U64 = (1 << 64) - 1
P = (1 << 255) - 19
HASH_NAMES = (
    'network', 'parameters', 'work_profile', 'source', 'demand_id', 'source_record',
    'model', 'layer', 'input', 'recipe', 'matrix_task', 'availability_manifest',
    'availability_root', 'authorization_scope', 'withdrawal_head', 'output_meter',
)
LEASE_HASH_NAMES = (
    'network', 'parameters', 'demand_id', 'requester', 'source', 'source_record',
    'authorization_scope', 'availability_manifest', 'availability_root',
)
BOUND_FIELDS = ('model', 'input', 'matrix_task', 'output_meter')

class Q4Reject(ValueError):
    """Invalid research input. Never grant a globally authoritative rejection."""


def H(domain: str, *pieces: bytes) -> bytes:
    name = domain.encode('ascii')
    if len(name) > 65535 or any(type(x) is not bytes for x in pieces):
        raise Q4Reject('HASH_INPUT')
    dig = hashlib.sha256(b'TRNM-PON1\0' + struct.pack('<H', len(name)) + name)
    for piece in pieces:
        dig.update(struct.pack('<I', len(piece)))
        dig.update(piece)
    return dig.digest()


def _id(value: bytes, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32 or not any(value):
        raise Q4Reject(label + '_ID')
    return value


def _num(value: int, label: str) -> int:
    if type(value) is not int or value < 0 or value > U64:
        raise Q4Reject(label + '_RANGE')
    return value


def _point_canonical(raw: bytes) -> bool:
    if len(raw) != 32: return False
    sign = raw[-1] >> 7
    y = int.from_bytes(raw, 'little') & ((1 << 255) - 1)
    return y < P and not (sign and y in (1, P - 1))


def _verify_ed25519(pub: bytes, msg: bytes, signature: bytes, label: str) -> None:
    if (type(signature) is not bytes or len(signature) != 64
            or not _point_canonical(pub) or not _point_canonical(signature[:32])
            or int.from_bytes(signature[32:], 'little') >= (1 << 252) + 27742317777372353535851937790883648493):
        raise Q4Reject(label + '_CANONICAL')
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, msg)
    except ImportError as exc:
        raise Q4Reject('CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE') from exc
    except Exception as exc:
        raise Q4Reject(label + '_SIGNATURE') from exc


def parse_lease(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) != 344 or raw[:6] != b'QDL2\x02\x00':
        raise Q4Reject('LEASE_CODEC')
    slot, purpose = raw[6], raw[7]
    if slot >= 32 or purpose not in (1, 2, 3, 4):
        raise Q4Reject('LEASE_SLOT_PURPOSE')
    values = {name: raw[8 + 32*i:40 + 32*i] for i, name in enumerate(LEASE_HASH_NAMES)}
    for name, value in values.items(): _id(value, name)
    for i, name in enumerate(('generation', 'revision', 'not_before', 'expires', 'available_until')):
        values[name] = struct.unpack_from('<Q', raw, 296 + i*8)[0]
    values.update(slot=slot, purpose=purpose, cost_class=raw[336])
    if raw[337:] != b'\0'*7 or raw[336] != 1:
        raise Q4Reject('LEASE_CANONICAL')
    if (values['generation'] == 0 or values['revision'] == 0
            or values['requester'] == values['source']
            or values['demand_id'] != H('qualified-demand-id-v2', values['network'],
                values['parameters'], values['requester'], struct.pack('<Q', values['generation']))):
        raise Q4Reject('LEASE_IDENTITY')
    if (values['expires'] <= values['not_before'] or
            values['expires'] - values['not_before'] > 1000 or
            values['expires'] > U64 - 100 or values['available_until'] != values['expires'] + 100):
        raise Q4Reject('LEASE_WINDOW')
    values['id'] = H('qualified-demand-lease-v2', raw)
    return values


def parse_manifest(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) != 584 or raw[:6] != b'QWT1\x01\x00':
        raise Q4Reject('MANIFEST_CODEC')
    purpose, cls, numerical, hardness, reuse, reserved = raw[6:12]
    if purpose not in (1, 2, 3, 4) or (cls,numerical,hardness,reuse,reserved)!=(1,1,0,1,0):
        raise Q4Reject('MANIFEST_FLAGS')
    info = {name: raw[12 + i*32:44 + i*32] for i,name in enumerate(HASH_NAMES)}
    for name,val in info.items(): _id(val, 'manifest_' + name)
    info['purpose'],info['cost_class'] = purpose,cls
    info['dims'] = struct.unpack_from('<4H',raw,524)
    info['demand_nonce'],info['not_before'],info['expires'],info['available_until'],info['units'] = struct.unpack_from('<5Q',raw,532)
    info['model_bytes'],info['input_bytes'],info['output_limit'] = struct.unpack_from('<3I',raw,572)
    if (info['dims'] != (64,64,64,0) or info['units'] != 262144
            or info['model_bytes'] != 16384 or info['input_bytes'] != 16384
            or info['output_limit'] != (0 if purpose == 1 else 1)
            or info['demand_nonce'] == 0 or info['expires'] < info['not_before']
            or info['expires']-info['not_before'] > 1000 or info['available_until'] < info['expires']):
        raise Q4Reject('MANIFEST_SHAPE_WINDOW')
    if (info['work_profile'] != H('qualified-task-profile-v1',b'pon-matmul-transcript-64-v1')
            or info['recipe'] != H('qualified-task-recipe-v1',b'canonical-field-matrix64-product-v1')
            or info['layer'] != H('qualified-task-layer-v1',info['model'],b'entire-row-major-field-layer-64x64')
            or info['output_meter'] != H('qualified-task-output-meter-v1',
                *(info[n] for n in ('network','parameters','demand_id','model','layer','input','recipe','matrix_task')))):
        raise Q4Reject('MANIFEST_BINDING')
    return info


@dataclass(frozen=True)
class CheckedQ4Bytes:
    transaction_id: bytes
    old_lease_id: bytes
    successor_lease_id: bytes
    source_statement_id: bytes
    containing_height: int
    transaction_sequence: int
    source_sequence: int
    # These are only local checked facts; no FinalUse or consensus authority.


def inspect_presigned_q4(raw: bytes, old_lease_bytes: bytes, *, containing_height: int,
                         network: bytes, parameters: bytes, expected_requester_sequence: int,
                         previous_source_sequence: int, previous_material: Mapping[str,bytes],
                         previous_status: str = 'active') -> CheckedQ4Bytes:
    """Offline, read-only independent signature/structural Q4 check for EXACT inclusion height.

    previous_* MUST come from a separately authenticated original branch owner;
    this routine cannot infer or authenticate that owner and cannot verify funding,
    source permissions, actual material bytes, peer retention or chain inclusion.
    """
    _id(network,'network');_id(parameters,'parameters')
    h = _num(containing_height,'height')
    request_nonce = _num(expected_requester_sequence,'requester_nonce')
    old_source_nonce = _num(previous_source_sequence,'source_nonce')
    if request_nonce == 0 or old_source_nonce == U64 or previous_status != 'active':
        raise Q4Reject('OWNER_STATE')
    if type(raw) is not bytes or len(raw) != 1187 or raw[:4] != b'PNX1':
        raise Q4Reject('TRANSACTION_LENGTH_OR_VERSION')
    if raw[4:36] != network:
        raise Q4Reject('NETWORK')
    sender = raw[36:68]
    nonce,expiry,fee = struct.unpack_from('<3Q',raw,68)
    if (nonce != request_nonce or nonce == 0 or expiry < h or fee > 10_000_000
            or raw[92] != 22 or struct.unpack_from('<H',raw,93)[0] != 1028):
        raise Q4Reject('TRANSACTION_CONTEXT')
    successor = parse_lease(raw[95:439]); old = parse_lease(old_lease_bytes)
    if (old['network'] != network or old['parameters'] != parameters or
            successor['network'] != network or successor['parameters'] != parameters):
        raise Q4Reject('LEASE_CONTEXT')
    if sender != old['requester'] or successor['requester'] != old['requester']:
        raise Q4Reject('REQUESTER')
    for name in ('slot','generation','demand_id','source','purpose','cost_class',
                 'source_record','authorization_scope','availability_manifest','availability_root'):
        if successor[name] != old[name]:
            raise Q4Reject('RENEW_'+name.upper())
    if successor['revision'] != old['revision']+1 or old['revision']==U64:
        raise Q4Reject('RENEW_REVISION')
    if not (old['not_before'] <= successor['not_before'] <= h <= old['expires']
            and successor['expires'] > old['expires']):
        raise Q4Reject('RENEW_OVERLAP')
    unsigned_statement = raw[439:439+620]
    if unsigned_statement[:4] != b'QWA2' or unsigned_statement[4:36] != successor['id']:
        raise Q4Reject('STATEMENT_LEASE_ID')
    manifest = parse_manifest(unsigned_statement[36:])
    for name,expected in (
        ('network', network),('parameters',parameters),('source',successor['source']),
        ('demand_id',successor['demand_id']),('purpose',successor['purpose']),
        ('cost_class',successor['cost_class']),
        ('source_record',H('qualified-demand-source-record-v2',successor['id'],successor['source_record'])),
        ('withdrawal_head',H('qualified-demand-frontier-v2',successor['id'])),
        ('authorization_scope',successor['authorization_scope']),
        ('availability_manifest',successor['availability_manifest']),
        ('availability_root',successor['availability_root']),
        ('not_before',successor['not_before']),('expires',successor['expires']),
        ('available_until',successor['available_until']),
    ):
        if manifest[name] != expected:
            raise Q4Reject('STATEMENT_'+name.upper())
    if manifest['demand_nonce'] != old_source_nonce+1:
        raise Q4Reject('SOURCE_SEQUENCE')
    if set(previous_material) != set(BOUND_FIELDS):
        raise Q4Reject('MATERIAL_BINDING_FIELDS')
    for field in BOUND_FIELDS:
        if _id(previous_material[field],'original_'+field) != manifest[field]:
            raise Q4Reject('MATERIAL_'+field.upper())
    source_signature = raw[1059:1123]
    _verify_ed25519(successor['source'],H('qualified-task-source-sign-v2',unsigned_statement),
                    source_signature,'SOURCE')
    _verify_ed25519(sender,H('tx-sign',raw[:1123]),raw[1123:],'REQUESTER')
    return CheckedQ4Bytes(
        transaction_id=H('tx-id',raw), old_lease_id=old['id'],
        successor_lease_id=successor['id'],
        source_statement_id=H('qualified-task-manifest-v2',unsigned_statement),
        containing_height=h, transaction_sequence=nonce,
        source_sequence=manifest['demand_nonce'],
    )
