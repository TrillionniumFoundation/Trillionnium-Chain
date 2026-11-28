"""Independent fixed public TCV1 framing; no Rust invocation or numeric inference."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CANDIDATE = (ROOT / 'evidence/pft-candidate-readback-20261128/SYNTHETIC_CANDIDATE.json').read_bytes()
assert hashlib.sha256(CANDIDATE).hexdigest() == '8604161da990568566993ed0acd2f2421c03e845b8832e1faf20d977a46aa61a'
DOC = json.loads(CANDIDATE)
FAMILY = b'hcsn-pft-readout-research-v1'
PROFILE = hashlib.sha256(b'trnm.pft.selected-research-readout.v1\0hcsn-pft-readout-research-v1\0trnm.pft.native-pinned-json-loader.v1\0trnm.pft.binary64-rounded-products-exact-sum-rne.v1\0').digest()
ENV_BYTES = b'{"synthetic_only":true,"executable":false}\n'

def sha(raw):
    return hashlib.sha256(raw).digest()

def number(value, width):
    return value.to_bytes(width, 'big')

def context(parent, runtime):
    return bytes([len(FAMILY)]) + FAMILY + b''.join([
        bytes.fromhex(DOC['contract']['parent_model_sha256']), parent,
        bytes.fromhex('1c27e04702200ef16734dda728b803805be35ab3ab60a0bb11fb977af21c2168'),
        bytes.fromhex(DOC['contract_sha256']), runtime])

def closure(ctx, payload, name, role, generation, profile):
    assert 0 < len(payload) <= 16384
    digest = sha(payload)
    manifest = b'TCM1' + ctx + number(len(payload), 8) + digest + number(16384, 4)
    manifest += number(1, 4) + number(len(payload), 4) + digest
    mid = sha(b'trnm.cell-manifest.v1\0' + manifest)
    release = b'TCR1' + ctx + number(1, 4) + mid
    wire = b'TCD1' + number(generation, 8) + profile + number(len(release), 4) + release
    wire += number(1, 2) + number(0, 2) + number(1, 2)
    wire += number(len(name), 2) + name + bytes([role]) + mid + digest
    wire += number(len(payload), 8) + number(0, 2)
    return wire, (mid, manifest)

ORIGIN = sha(b'chain.pft-owner-fixture-origin.v1\0')
ENV, ENV_MANIFEST = closure(
    context(ORIGIN, sha(b'chain.pft-owner-fixture-runtime-reference-only.v1\0')),
    ENV_BYTES, b'synthetic/environment.json', 6, 1,
    sha(b'chain.pft-owner-fixture-environment-profile.v1\0'))
ENV_ID = sha(b'trnm.cell-dependency-closure.v1\0' + ENV)

def version(payload, profile=PROFILE, parent=ORIGIN, generation=2, lineage=()):
    model_closure, manifest = closure(context(parent, ENV_ID), payload,
                                     b'pft/online-candidate.json', 1, generation, profile)
    router = sha(b'trnm.cell-model-router-roster.v1\0' + number(0, 2))
    model = b'TMR1' + number(len(model_closure), 4) + model_closure + router
    model += number(len(lineage), 1) + b''.join(lineage)
    mid = sha(b'trnm.cell-model-release-root.v1\0' + model)
    wire = b'TCV1' + number(len(model), 4) + model + number(len(ENV), 4) + ENV
    wire += number(2, 2)
    for _, m in sorted([manifest, ENV_MANIFEST]):
        wire += number(len(m), 4) + m
    return {'wire_hex': wire.hex(), 'wire_sha256': sha(wire).hex(),
            'commitment_sha512': hashlib.sha512(b'TRNM/Cell/CompleteVersion/v1\0' + wire).hexdigest(),
            'model_root_sha256': mid.hex(), 'payload_sha256': sha(payload).hex(),
            'generation': generation}

selected = version(CANDIDATE)
parent = bytes.fromhex(selected['model_root_sha256'])
result = {
    'schema': 'chain-pft-selected-readout-synthetic-fixture-v1',
    'synthetic_only': True, 'host_authorization': False,
    'candidate_sha256': sha(CANDIDATE).hex(), 'loader_profile_sha256': PROFILE.hex(),
    'selected': selected,
    'successor': version(CANDIDATE, parent=parent, generation=3, lineage=(parent,)),
    'inspection_only': version(CANDIDATE, profile=bytes.fromhex('2aee77cf2cbb43000a9b73a957556d471fc470ec29b20a037fa85481a5e03d91')),
}
(HERE / 'SYNTHETIC_OWNER_FIXTURE.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
