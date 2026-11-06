#!/usr/bin/env python3
"""Independent SHA-256 material readback; no Rust/native execution credit."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

repo = Path(sys.argv[1]).resolve(strict=True)
out = Path(sys.argv[2]).resolve(strict=True)
source_path = 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
scalar_path = 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs'
hash_path = 'trillionnium/crates/trnm-protocol/src/pon_wire.rs'
config_path = 'config/pon/public-resource-profile-vectors-v1.json'
source = (repo / source_path).read_text()
scalar = (repo / scalar_path).read_text()
wire = (repo / hash_path).read_text()
config = json.loads((repo / config_path).read_text())

def only(pattern, text):
    values = re.findall(pattern, text)
    assert len(values) == 1, (pattern, len(values))
    return values[0]

profile = only(r'pub const PROFILE: &str = "([^"]+)";', source)
contract = only(r'b"(resource-revision-r15/[^"]+)"', source)
policy = source[source.index('impl PublicPolicy {'):source.index('#[derive(Default, Clone, Debug, Serialize)]')]
domain = only(r'hash\(b"([^"]+)"', policy)
development = only(r'pub fn development\(\) -> Self \{\s*Self \{\s*bits: (\d+),\s*lifetime_ms: (\d+),', policy)
bits, lifetime = map(int, development)
assert (bits, lifetime) == (16, 2000)
names = ['MUTATION_CPU_BURST_NS', 'MUTATION_CPU_REFILL_NS_PER_SECOND',
         'MUTATION_CPU_START_RESERVE_NS', 'MUTATION_CPU_WORKERS']
values = [int(only(r'pub\(super\) const ' + name + r': (?:u64|usize) = ([\d_]+);', scalar).replace('_', '')) for name in names]
assert values == [2_000_000_000, 250_000_000, 100_000_000, 2]
assert config['current_revision'] == 'r15'
assert profile == config['transport_profile']
assert domain == config['hash_domain']
assert contract == config['revisions']['r15']['resource_contract']
assert values == [config[key] for key in ['burst_ns', 'refill_ns_per_second', 'start_reserve_ns', 'worker_limit']]
hash_function = wire[wire.index('pub fn hash(tag: &[u8]'):wire.index('/// Exact account-archive')]
for required in ['Sha256::new()', 'h.update(b"TRNM-PON1\\0")',
                 '(tag.len() as u16).to_le_bytes()', 'h.update(tag)',
                 '(p.len() as u32).to_le_bytes()', 'h.update(p)']:
    assert required in hash_function, required

def preimage(resource_contract, ticket_bits, lifetime_ms):
    tag = domain.encode('ascii')
    parts = [profile.encode('ascii'), resource_contract.encode('ascii'),
             bytes([ticket_bits]), struct.pack('<Q', lifetime_ms),
             *[struct.pack('<Q', value) for value in values[:3]],
             struct.pack('<I', values[3])]
    framed = b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag
    framed += b''.join(struct.pack('<I', len(part)) + part for part in parts)
    return framed, [len(part) for part in parts]

records = []
for revision, entry in config['revisions'].items():
    for row in entry['vectors']:
        framed, lengths = preimage(entry['resource_contract'], row['ticket_bits'], row['lifetime_ms'])
        actual = hashlib.sha256(framed).hexdigest()
        assert actual == row['policy_id'], (revision, row, actual)
        records.append(dict(revision=revision, ticket_bits=row['ticket_bits'],
                            lifetime_ms=row['lifetime_ms'], expected=row['policy_id'],
                            recomputed=actual, preimage_bytes=len(framed), part_lengths=lengths))
assert len(records) == 18
current, lengths = preimage(contract, bits, lifetime)
current_id = hashlib.sha256(current).hexdigest()
historical_r14 = next(row['recomputed'] for row in records if row['revision'] == 'r14' and row['ticket_bits'] == bits)
assert current_id != historical_r14
with (out / 'current-r15-preimage.bin').open('xb') as stream:
    stream.write(current)
def git(*args):
    return subprocess.check_output(['git', *args], cwd=repo, text=True).strip()
inputs = []
for name in [source_path, scalar_path, hash_path, config_path]:
    raw = (repo / name).read_bytes()
    inputs.append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), git_blob=git('hash-object', name)))
report = dict(schema='trnm-independent-public-policy-material-readback-v1',
    source_head=git('rev-parse', 'HEAD'), source_tree=git('rev-parse', 'HEAD^{tree}'),
    source_status=git('status', '--porcelain'), inputs=inputs,
    derivation='SHA256(TRNM-PON1-NUL || uint16le(tag_length) || tag || each(uint32le(part_length) || part))',
    current_contract_matches_config=True, unchanged_scalars=dict(zip(names, values)),
    current_development=dict(bits=bits, lifetime_ms=lifetime, policy_id=current_id,
                             preimage_bytes=len(current), part_lengths=lengths),
    historical_r14_development=historical_r14, recomputed_vectors=records,
    native_execution=False, production_qualified=False,
    scope='independent Python byte derivation from current Rust material and all six historical config revisions; no existing policy reader imported')
with (out / 'derivation-before.json').open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(dict(status='passed', source_head=report['source_head'],
    source_status=report['source_status'], recomputed_vectors=len(records),
    current_development=report['current_development'], historical_r14=historical_r14,
    native_execution=False), sort_keys=True))
