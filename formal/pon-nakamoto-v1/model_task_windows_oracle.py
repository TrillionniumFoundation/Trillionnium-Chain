"""Independent controlled external text-window fixture, roots and owner signature.

The source payloads below are newly authored conformance text. They are neither a
recut of the 25 historical rows nor independent/prospective efficacy evidence.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from contract_wire import H, canonical
import model_evolution_oracle as evolution

SCHEMA = 'native-model-task-windows-manifest-v1'
FEATURE_PROFILE = 'signed-ascii-token-hash-256-clipped8-plus-bias-v1'
REPOSITORY = 'controlled-source:task-window-conformance-v1'
SOURCES = [
    [('pub fn amber_packet(nonce: u64) -> u64 { nonce + 17 }\n', 0),
     ('pub fn blue_tensor(product: i64) -> i64 { product * 3 }\n', 1),
     ('pub fn cedar_router(enabled: bool) -> bool { !enabled }\n', 2),
     ('pub fn delta_receipt(height: u64) -> u64 { height + 29 }\n', 0),
     ('pub fn ember_cipher(input: u8) -> u8 { input ^ 91 }\n', 1),
     ('pub fn frost_policy(allowed: bool) -> bool { allowed }\n', 2)],
    [('pub fn gold_frame(offset: u64) -> u64 { offset + 41 }\n', 2),
     ('pub fn hazel_digest(bytes: u8) -> u8 { bytes ^ 103 }\n', 0),
     ('pub fn ivory_gate(ready: bool) -> bool { !ready }\n', 1),
     ('pub fn jade_chunk(index: u64) -> u64 { index + 53 }\n', 2),
     ('pub fn kelp_matrix(value: i64) -> i64 { value * 5 }\n', 0),
     ('pub fn lilac_cell(enabled: bool) -> bool { enabled }\n', 1)],
]


def features(source):
    if not source.isascii() or '\x00' in source:
        raise ValueError('TASK_WINDOW_CONTENT')
    tokens = [token for token in re.findall(r'[a-zA-Z_][a-zA-Z_0-9]*', source.lower())
              if not token.startswith('trnm') and token not in {'m00', 'm04', 'm10'}]
    counts = [0] * 256
    for token in tokens[:1024]:
        digest = hashlib.sha256(token.encode()).digest()
        counts[int.from_bytes(digest[:2], 'little') % 256] += 1 if digest[2] & 1 else -1
    return [max(-8, min(8, value)) for value in counts] + [8]


def source_revision(repository, inputs):
    files = [{'source_path': task['source_path'], 'content_sha256': task['content_sha256']} for task in inputs]
    return hashlib.sha256(canonical(dict(source_repository=repository, files=files))).digest()


def rows(family, repository, revision, inputs):
    result = []
    for task in inputs:
        source = bytes.fromhex(task['content_utf8_hex'])
        if hashlib.sha256(source).hexdigest() != task['content_sha256']:
            raise ValueError('TASK_WINDOW_CONTENT_HASH')
        x = features(source.decode('ascii'))
        identifier = H('native-model-task-window-row-v1', family, repository.encode(), revision,
                       task['source_path'].encode(), bytes.fromhex(task['content_sha256']), bytes([task['label']]),
                       struct.pack('<257h', *x))
        result.append(dict(id=identifier.hex(), source_group=hashlib.sha256(task['source_path'].encode()).hexdigest(),
                           source_path=task['source_path'], source_content_sha256=task['content_sha256'],
                           label=task['label'], features=x))
    return result


def root(family, repository, revision, inputs):
    return H('native-model-task-window-tasks-v1', canonical(rows(family, repository, revision, inputs)))


def trained(tasks):
    weights = [[0] * 257 for _ in range(3)]
    for _ in range(12):
        for task in tasks:
            scores = [sum(w * x for w, x in zip(row, task['features'])) for row in weights]
            prediction = max(range(3), key=scores.__getitem__)
            if prediction != task['label']:
                weights[prediction] = [w - x for w, x in zip(weights[prediction], task['features'])]
                weights[task['label']] = [w + x for w, x in zip(weights[task['label']], task['features'])]
    return [[a - b for a, b in zip(row, weights[0])] for row in weights]


def generate():
    family = bytes.fromhex(evolution.context()['family'])
    key = Ed25519PrivateKey.from_private_bytes(H('DEV-ONLY-TASK-WINDOW-OWNER', struct.pack('<Q', 0)))
    owner = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    windows, derived = [], []
    for index, sources in enumerate(SOURCES):
        inputs = [dict(source_path=f'window-{index}/task-{i}.rs', content_sha256=hashlib.sha256(source.encode()).hexdigest(),
                       content_utf8_hex=source.encode().hex(), label=label) for i, (source, label) in enumerate(sources)]
        revision = source_revision(REPOSITORY, inputs)
        tasks = rows(family, REPOSITORY, revision, inputs)
        windows.append(dict(activate_round=index, source_revision=revision.hex(), tasks_root=root(family, REPOSITORY, revision, inputs).hex(), tasks=inputs))
        derived.append(tasks)
    manifest = dict(schema=SCHEMA, feature_profile=FEATURE_PROFILE, owner=owner, owner_revision=1,
                    source_repository=REPOSITORY, source_class='controlled-source', windows=windows)
    signature = key.sign(H('native-model-task-windows-owner-v1', family, canonical(manifest)))
    manifest['signature'] = signature.hex()
    raw = canonical(manifest) + b'\n'
    models = []
    for tasks in derived:
        values = [0] * evolution.COEFFICIENTS
        values[771 + 257 + 256] = 1
        flattened = sum(trained(tasks), [])
        values[3 * 771:4 * 771] = flattened
        models.append(values)
    def correct(model, tasks):
        return sum(prediction == task['label'] for prediction, task in zip(
            evolution.predictions(model, 7, [task['features'] for task in tasks]), tasks))
    controls = [struct.unpack('<3855h', bytes.fromhex(control['coefficients_le_i16_hex'])) for control in evolution.EMPIRICAL['controls']]
    observations = []
    for i, tasks in enumerate(derived):
        parent = [0] * evolution.COEFFICIENTS if i == 0 else models[i-1]
        strongest = max([correct(parent, tasks)] + [correct(control, tasks) for control in controls])
        score = max(0, correct(models[i], tasks) - strongest) * 1000000 // len(tasks)
        observations.append(dict(candidate_correct=correct(models[i], tasks), parent_correct=correct(parent, tasks),
                                 strongest_correct=strongest, score=score, rows=tasks, trained=trained(tasks)))
    return raw, dict(schema='independent-model-task-windows-v1-vector', owner=owner, sha256=hashlib.sha256(raw).hexdigest(),
                     family=family.hex(), windows=observations, source_class='controlled-source',
                     independent_accepted=False, prospective_accepted=False)


if __name__ == '__main__':
    directory = Path(__file__).with_name('vectors')
    raw, vector = generate()
    (directory / 'model-task-windows-v1.manifest.json').write_bytes(raw)
    (directory / 'model-task-windows-v1.json').write_text(json.dumps(vector, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'rows': [len(window['rows']) for window in vector['windows']],
                      'scores': [window['score'] for window in vector['windows']],
                      'independent_accepted': False, 'prospective_accepted': False}))
