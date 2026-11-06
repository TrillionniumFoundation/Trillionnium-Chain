"""Independent Python descriptor oracle for explicit legacy and candidate rules.

Uses explicit protocol fields and hashlib, never imports or executes Rust.
Explicit values below follow the reviewed protocol grammar; no Rust values are imported.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]

def field(data):
    return struct.pack('>I', len(data)) + data

def u64(value):
    return struct.pack('>Q', value)

work = (ROOT / 'config/pon/work-profile-v1.json').read_bytes()
work_digest = hashlib.sha512(
    b'TRNM/CryptoProfile/ExternalWork/v1\0' + u64(len(work)) + work
).digest()
purposes = [b'account', b'migration', b'task', b'operator', b'peer',
            b'governance', b'release', b'CURRENT', b'FinalUse', b'recovery']

ACCOUNT_NAMES = {
    2: b'pon-native-pq-accounts-v2', 3: b'pon-native-pq-quota-v3',
    4: b'pon-native-pq-tasks-v4', 5: b'pon-native-pq-tasks-v5',
    6: b'pon-native-pq-application-v6',
}
ACCOUNT_DOMAINS = {
    2: (b'NativePQCommandStatement', b'NativePQAccountContext', b'NativePQCommandWire'),
    3: (b'NativePQQuotaStatement', b'NativePQQuotaContext', b'NativePQQuotaWire'),
    4: (b'NativePQTaskStatement', b'NativePQTaskContext', b'NativePQTaskWire'),
    5: (b'NativePQTaskStatement', b'NativePQTaskContext', b'NativePQTaskWire'),
    6: (b'NativePQApplicationStatement', b'NativePQApplicationContext', b'NativePQApplicationWire'),
}
# This literal is verified against the statement/wire hashing implementations,
# not derived by parsing crypto_profile.rs.
ACCOUNT_HASH_GRAMMAR = b'owner-context:SHA256(domain,network,parameters,genesis,account,profile-name,kind,role);wire-id:SHA256(wire-domain,BE32-length,raw);statement-id:SHA384(statement-domain,body,witness-descriptors)'


def legacy_domains(scope, version):
    output = field(b'TPQ1') + bytes([1, 0x65, 1, 6, 0])
    for value in [
        b'TRNM/PoN/PQAuth/ML-DSA-65/v1\0', b'TRNM/PoN/PQKey/v1\0', b'payload\0',
        bytes.fromhex('308207b2300b0609608648016503040312038207a100'),
        b'TPQ1:network32,owner-context32,key-id32,BE64-generation,BE64-sequence,BE64-expiry,SHA384-payload,BE16-signature-length',
        b'payload:SHA384(domain,payload-tag,BE64-length,bytes);key-id:SHA256(key-domain,SPKI)',
    ]:
        output += field(value)
    if scope == 1:
        for value in [ACCOUNT_NAMES[version], f'NPQ{version}'.encode() + bytes([version]),
                      f'PQP{version}'.encode() + bytes([version, 0, 0, 0])]:
            output += field(value)
        for value in ACCOUNT_DOMAINS[version]:
            output += field(b'TRNM/PoN/' + value + f'/v{version}'.encode() + b'\0')
        output += field(ACCOUNT_HASH_GRAMMAR)
    elif scope == 2:
        assert version == 2
        for value in [
            b'native-pq-network-owner-v2', b'PNQ2', b'PNP2',
            b'native-pq-network-policy-v2', b'native-pq-network-peer-context-v2',
            b'native-pq-network-operation-v2', b'native-pq-network-response-bytes-v2',
            b'native-pq-network-response-v2', b'loopback-signed-plaintext-dev-only',
            b'TRNM-PON1\0', b'SHA256:LE16-tag-length,tag,LE32-part-length,part;policy:canonical-PolicyRecord-JSON',
        ]:
            output += field(value)
        output += bytes([6, 1, 2])
    else:
        raise ValueError('unregistered legacy scope')
    return output


def legacy_roles(version, kind):
    # Explicit specification of kind/role/carried-key requirements.
    if kind in range(1, 6):
        return [(1, 0)]
    if version >= 3 and kind in (10, 11):
        return [(1, 0)] if kind == 10 else [(1, 0), (2, 0)]
    if version >= 5:
        if kind in (18, 19, 20):
            return [(1, 0)]
        if kind in (21, 22):
            return [(1, 0), (2, 0)]
    if version == 4:
        if kind in (18, 20):
            return [(1, 0)]
        if kind == 21:
            return [(1, 0), (2, 0)]
    if version == 6 and kind in (6, 7, 8, 9, 14, 15, 16, 17, 23, 24):
        return [(1, 0)]
    return {128: [(2, 1)], 129: [(3, 0), (4, 1)], 130: [(5, 0), (6, 1)]}.get(kind)


def legacy_limits(scope, version):
    values = [
        (b'signed-message-bytes', 65536), (b'TPQ1-payload-bytes', 67108864),
        (b'TPQ1-unsigned-bytes', 176), (b'TPQ1-signed-bytes', 3487),
        (b'raw-public-key-bytes', 1952), (b'SPKI-bytes', 1974), (b'signature-bytes', 3309),
    ]
    if scope == 1:
        values += [
            (b'transaction-envelope-bytes', 16384 if version == 6 else 9432),
            (b'transactions-per-packet', 64 if version == 6 else 256),
            (b'verifications-per-packet', 64 if version == 6 else 512),
            (b'transaction-bytes-per-packet', 524288), (b'prefix-bytes', 16),
            (b'common-bytes', 160), (b'witness-descriptor-bytes', 46),
            (b'resolved-witness-bytes', 3533), (b'carried-witness-bytes', 5507),
            (b'minimum-envelope-bytes', 3741),
            (b'maximum-payload-bytes', {2: 554, 3: 554, 4: 652, 5: 1032, 6: 12675}[version]),
            (b'transfer-base-bytes', 42), (b'transfer-memo-bytes', 512),
            (b'conflict-envelope-bytes', 4096), (b'conflict-extra-verifications', 2),
        ]
    elif scope == 2:
        values += [
            (b'wire-bytes', 2097152), (b'signed-payload-bytes', 2093657),
            (b'ledger-bytes', 16777216), (b'ledger-records', 4096),
            (b'ingress-connections', 64), (b'ingress-bytes', 33554432),
            (b'inbound-verifications', 64), (b'pinned-peer-roster', 64),
            (b'lifetime-seconds-local-admission', 60), (b'signers-per-direction', 1),
        ]
    output = b''.join(field(name) + u64(value) for name, value in values)
    if scope == 1:
        output += field(b'signer-roles-and-count:exact-native-account-kind-registry')
        for kind in range(256):
            roles = legacy_roles(version, kind)
            output += bytes([kind])
            if roles is None:
                output += b'\0'
            else:
                output += bytes([1, len(roles)])
                for role, carried in roles:
                    output += bytes([role, carried])
    return output


def configuration(profile, scope=None, version=None):
    candidate = profile != 1
    scope = (4 if candidate else 1) if scope is None else scope
    version = (1 if candidate else 3) if version is None else version
    algorithm = b'ML-DSA-87' if profile == 3 else b'ML-DSA-65'
    public_key_bytes = 2592 if profile == 3 else 1952
    signature_bytes = 4627 if profile == 3 else 3309
    output = b'TRNM/CryptoProfile/Configuration/v1\0' + bytes([profile]) + field(algorithm)
    output += field(b'FIPS204-Pure-empty-context;complete-canonical-message;no-HashMLDSA')
    output += field(b'deterministic-or-hedged;verification-cannot-attest-signing-randomness')
    output += field(b'FIPS204-raw-public-key;raw-signature;CPQ1' if candidate else
                    b'strict-DER-SPKI-id-ml-dsa-65-no-parameters;raw-signature;legacy-owner-wire')
    output += struct.pack('>II', public_key_bytes, signature_bytes)
    output += bytes([1]) * 32 + bytes([2]) * 32 + bytes([3]) * 32
    output += bytes([scope]) + struct.pack('>I', version)
    output += u64(10) + b'\1' + u64(100)
    if candidate:
        output += field(b'CPQ1;candidate-only;no-current-effects')
        for value in [
            b'TRNM/CryptoProfile/Envelope/v1\0',
            b'TRNM/CryptoProfile/Commitment/v1\0',
            b'CPQ1',
            b'message:envelope-domain,profile-id64,work-config-digest64,BE16-purpose,BE64-owner-generation,BE64-key-epoch,BE64-sequence,BE64-valid-from-inclusive,BE64-valid-until-inclusive,BE16-signer-count,sorted-unique-signer-id64s,BE32-payload-length,payload;no-tail',
            b'wire:magic4,BE32-message-length,message,signer-count-times(BE32-key-length,raw-key,BE32-signature-length,raw-signature);signer-order-from-message;no-tail',
            b'commitment:SHA512(commitment-domain,profile-id64,U8-hash-purpose,BE64-byte-length,bytes)',
        ]:
            output += field(value)
        for index, purpose in enumerate(purposes, 1):
            output += struct.pack('>H', index) + field(b'TRNM/CPQ1/' + purpose + b'/v1\0')
    else:
        output += legacy_domains(scope, version)
    for index in range(1, 11):
        rule, length = ((4, 32) if index >= 9 else
                        ((3, 64) if candidate else
                         ((1, 32) if index == 1 else ((2, 48) if index == 2 else (0, 0)))))
        output += bytes([index, rule, length])
    if candidate:
        for limit in [65536, 131072, 64, 8388608, 8]:
            output += u64(limit)
    else:
        output += legacy_limits(scope, version)
    output += field(b'owner-limits-are-cumulative;failed-verification-is-charged;wall-clock-not-consensus-validity')
    output += field(b'pon-matmul-transcript-64-v1') + work_digest + bytes([int(candidate), 0])
    return output

result = {'work_bytes': len(work), 'work_digest': work_digest.hex(), 'profiles': {}}
for profile in [1, 2, 3]:
    raw = configuration(profile)
    digest = hashlib.sha512(raw).digest()
    row = {'configuration_bytes': len(raw), 'id': digest.hex()}
    if profile != 1:
        payload = b'fixed payload\0\xff'
        row['payload_commitment'] = hashlib.sha512(
            b'TRNM/CryptoProfile/Commitment/v1\0' + digest + b'\2' + u64(len(payload)) + payload
        ).hexdigest()
        key = bytes([7]) * (2592 if profile == 3 else 1952)
        row['key_id'] = hashlib.sha512(
            b'TRNM/CryptoProfile/Commitment/v1\0' + digest + b'\1' + u64(len(key)) + key
        ).hexdigest()
        message = b'TRNM/CryptoProfile/Envelope/v1\0' + digest + work_digest + struct.pack('>H', 9)
        for value in [7, 3, 11, 10, 99]:
            message += u64(value)
        message += struct.pack('>H', 2) + bytes([0x11]) * 64 + bytes([0x22]) * 64
        message += struct.pack('>I', len(payload)) + payload
        row['message_bytes'] = len(message)
        row['message_sha512'] = hashlib.sha512(message).hexdigest()
    result['profiles'][str(profile)] = row
result['accounts'] = {str(version): {'configuration_bytes': len(configuration(1, 1, version)), 'id': hashlib.sha512(configuration(1, 1, version)).hexdigest()} for version in range(2, 7)}
peer = configuration(1, 2, 2)
result['peer2'] = {'configuration_bytes': len(peer), 'id': hashlib.sha512(peer).hexdigest()}
print(json.dumps(result, indent=2))
