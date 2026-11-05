"""Versioned, complete reference relation for the existing integer source router.

R(T, before, output, after, witness) binds a consumer-admitted contract to actual
source replay, all five W1 transcripts and the deterministic read-only decision.
This is a bounded research verifier, not a succinct proof, native owner, work-cost
qualification, BF16 equivalence argument, release authorization or consensus rule.
The caller MUST retain `expected` independently of the downloaded witness/contract.
"""
from __future__ import annotations

import copy
import ast
from functools import lru_cache
import hashlib
import inspect
import json
import os
import operator
from pathlib import Path
import re
import struct
import sys
import time
import types
import unicodedata

import cryptography
import numpy as np

from bounded_process import run_bounded
from contract_wire import H, PARAMETER_HASH, ROOT, canonical, unique, u64
from evaluation_bundle import MAX_TASK_BYTES, artifact_id, partition_manifest
from experiments import model_loop as source_model
from experiments import shared_cell_operator_v1 as cell
from model_contract import CLASSES, DIM, load_model_bytes
from useful_cell_numeric_v1 import NUMERIC_PROFILE, evaluate_exact
import work_oracle as work

RELATION_ID = 'pon-useful-cell-int257-v1'
VERIFIER_ID = 'pon-useful-cell-int257-python-reference-v1'
CHALLENGE_DOMAIN = 'useful-cell-int257-v1/challenge'
CONTRACT_LIMIT = 64 * 1024
WITNESS_LIMIT = 1024 * 1024
DECISION_PROFILE = {
    'router': 'argmax-three-experts', 'router_ties': 'lowest-frozen-index',
    'classifier': 'base-plus-selected-delta', 'class_ties': 'lowest-frozen-index',
    'stop': 'disabled', 'abstention': 'disabled',
    'randomness': 'forbidden', 'seed': None,
}
SCOPE = {
    'research_only': True, 'ordinary_hepta_product': False,
    'state_transition': 'read-only', 'public_reward_eligible': False,
    'production_activation': False,
}
SOURCE_FILES = (
    'formal/pon-nakamoto-v1/useful_cell_relation_v1.py',
    'formal/pon-nakamoto-v1/useful_cell_numeric_v1.py',
    'formal/pon-nakamoto-v1/contract_wire.py',
    'formal/pon-nakamoto-v1/work_oracle.py',
    'formal/pon-nakamoto-v1/model_contract.py',
    'formal/pon-nakamoto-v1/evaluation.py',
    'formal/pon-nakamoto-v1/evaluation_bundle.py',
    'formal/pon-nakamoto-v1/ledger.py',
    'formal/pon-nakamoto-v1/work_backend.py',
    'formal/pon-nakamoto-v1/strict_signature.py',
    'formal/pon-nakamoto-v1/bounded_process.py',
    'formal/pon-nakamoto-v1/experiments/model_loop.py',
    'formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py',
    'config/pon/ledger-v1.json', 'config/pon/work-profile-v1.json',
    'config/pon/model-family-v1.json', 'config/pon/devnet-v1.json',
    'config/pon/evaluation-round-v1.json',
)
# Capture source bytes at import, before an admitting owner can request a pin.
# A long-lived process must restart after source changes, not label old loaded
# functions with the digest of new bytes on disk.
_IMPORT_SOURCE = {path: (ROOT / path).read_bytes() for path in SOURCE_FILES}
_COMPILED_SOURCE = {}
_SOURCE_LITERALS = {}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha256(canonical(value))


def hex_value(value, length=64, code='DIGEST'):
    require(type(value) is str and len(value) == length and
            re.fullmatch('[0-9a-f]+', value) is not None, code)
    return value


def unsigned(value, code):
    require(type(value) is int and 0 <= value < 1 << 64, code)
    return value


def identity_text(value, code):
    require(type(value) is str and 1 <= len(value) <= 256 and
            re.fullmatch('[a-zA-Z0-9._:/-]+', value) is not None, code)
    return value


def strict_json(raw, maximum, code):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, code + '_LIMIT')
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError(code)))
        require(canonical(value) == raw, code + '_CANONICAL')
    except (UnicodeError, TypeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError(code) from error
    return value


def _code_inventory(code):
    found = {code.co_qualname: code}
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            found.update(_code_inventory(value))
    return found


def _same_literal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) in (tuple, list):
        return len(left) == len(right) and all(_same_literal(a, b) for a, b in zip(left, right))
    if type(left) is dict:
        return left.keys() == right.keys() and all(_same_literal(left[k], right[k]) for k in right)
    return left == right


def _source_constant(node, bindings):
    """Interpret only constant containers/names and bounded integer arithmetic."""
    if isinstance(node, ast.Constant):
        return ast.literal_eval(node)
    if isinstance(node, ast.Name) and node.id.isupper() and not node.id.startswith('_'):
        value = bindings[node.id]
        if type(value) not in (int, str, bool, bytes, tuple, list, dict, type(None)):
            raise ValueError('not a constant binding')
        return copy.deepcopy(value)
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [_source_constant(item, bindings) for item in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else values
    if isinstance(node, ast.Dict):
        return {_source_constant(key, bindings): _source_constant(value, bindings)
                for key, value in zip(node.keys, node.values)}
    unary = {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}
    binary = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
              ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
              ast.LShift: operator.lshift, ast.RShift: operator.rshift}
    if isinstance(node, ast.UnaryOp) and type(node.op) in unary:
        value = _source_constant(node.operand, bindings)
        if type(value) is int and value.bit_length() <= 256:
            return unary[type(node.op)](value)
    if isinstance(node, ast.BinOp) and type(node.op) in binary:
        left, right = _source_constant(node.left, bindings), _source_constant(node.right, bindings)
        if type(left) is int and type(right) is int and max(left.bit_length(), right.bit_length()) <= 256:
            if type(node.op) in (ast.LShift, ast.RShift) and not 0 <= right <= 256:
                raise ValueError('constant shift limit')
            value = binary[type(node.op)](left, right)
            if value.bit_length() <= 512:
                return value
    raise ValueError('unsupported source initializer')


def _literal_bindings(raw, bindings):
    result = {}

    def add(target, value):
        if isinstance(target, ast.Name) and target.id.isupper() and not target.id.startswith('_'):
            result[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)) and type(value) in (tuple, list):
            if len(target.elts) == len(value):
                for child, item in zip(target.elts, value):
                    add(child, item)

    for node in ast.parse(raw).body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        try:
            value = _source_constant(node.value, bindings)
        except (ValueError, TypeError, KeyError, ZeroDivisionError):
            continue  # No execution of arbitrary source initializers.
        for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
            add(target, value)
    return result


def _loaded_source_guard():
    """Check source origins and already loaded functions, including stale imports.

    Runtime/standard/extension libraries remain trusted installed dependencies.
    This is source consistency, not an attestation of the operating system.
    """
    for path, raw in _IMPORT_SOURCE.items():
        require((ROOT / path).read_bytes() == raw, 'PROGRAM_SOURCE_CHANGED_RESTART_REQUIRED')
        if not path.endswith('.py'):
            continue
        module_name = path.removeprefix('formal/pon-nakamoto-v1/').removesuffix('.py').replace('/', '.')
        if module_name == 'useful_cell_relation_v1':
            module_name = __name__
        module = sys.modules.get(module_name)
        require(module is not None and Path(module.__file__).resolve() == (ROOT / path).resolve(),
                'PROGRAM_MODULE_ORIGIN')
        if path not in _COMPILED_SOURCE:
            _COMPILED_SOURCE[path] = _code_inventory(compile(
                raw, str((ROOT / path).resolve()), 'exec', dont_inherit=True))
            _SOURCE_LITERALS[path] = _literal_bindings(raw, vars(module))
        for name, value in _SOURCE_LITERALS[path].items():
            require(name in vars(module) and _same_literal(vars(module)[name], value),
                    'PROGRAM_LOADED_CONSTANT_MISMATCH')
        compiled = _COMPILED_SOURCE[path]
        for item in tuple(vars(module).values()):
            function = inspect.unwrap(item) if callable(item) else item
            if not isinstance(function, types.FunctionType) or function.__module__ != module_name:
                continue
            reference = compiled.get(function.__code__.co_qualname)
            # Code-object equality compares instructions, constants and scope;
            # marshalled bytes can differ solely from string-interning references.
            require(reference is not None and function.__code__ == reference,
                    'PROGRAM_LOADED_CODE_MISMATCH')


def current_identity():
    """Pin the executed source closure, configurations and relevant runtime versions."""
    _loaded_source_guard()
    manifest = {path: sha256((ROOT / path).read_bytes()) for path in SOURCE_FILES}
    runtime = {
        'python': sys.version, 'implementation': sys.implementation.name,
        'unicode': unicodedata.unidata_version, 'numpy': np.__version__,
        'cryptography': cryptography.__version__, 'python_optimization': sys.flags.optimize,
    }
    parameters = {
        'relation': RELATION_ID, 'verifier': VERIFIER_ID,
        'numeric': NUMERIC_PROFILE, 'decision': DECISION_PROFILE, 'scope': SCOPE,
        'base_wire_parameters': PARAMETER_HASH.hex(),
        'work_profile': cell.PROFILE, 'challenge_domain': CHALLENGE_DOMAIN,
        'work_nonce': 'independent-u64-per-tile', 'tiles': [64, 64, 64, 64, 1],
        'max_batch': 64, 'contract_limit': CONTRACT_LIMIT, 'witness_limit': WITNESS_LIMIT,
    }
    return {
        'program_sha256': digest({'sources': manifest, 'runtime': runtime,
                                  'execution_parameters': parameters}),
        'parameters_sha256': digest(parameters),
        'source_manifest': manifest, 'runtime': runtime,
    }


def contract_id(raw):
    strict_json(raw, CONTRACT_LIMIT, 'CONTRACT')
    return H('useful-cell-int257-v1/contract', raw).hex()


def _state(state):
    require(type(state) is dict and set(state) ==
            {'cell_id', 'generation', 'state_root', 'model_artifact'}, 'STATE_FIELDS')
    for field in ('cell_id', 'state_root', 'model_artifact'):
        hex_value(state[field], code='STATE_' + field.upper())
    unsigned(state['generation'], 'STATE_GENERATION')
    return copy.deepcopy(state)


def _rows(rows):
    require(type(rows) is list and 1 <= len(rows) <= 64, 'BATCH_SIZE')
    fields = {'id', 'file', 'source_content_sha256', 'split', 'label', 'x'}
    for row in rows:
        require(type(row) is dict and set(row) == fields, 'INPUT_FIELDS')
        hex_value(row['id'], code='INPUT_ID')
        hex_value(row['source_content_sha256'], code='CONTENT_ID')
        require(type(row['file']) is str and 0 < len(row['file']) <= 1024 and
                not row['file'].startswith('/') and '..' not in row['file'].split('/'), 'SOURCE_PATH')
        require(row['split'] in ('consumer', 'evaluation_a', 'evaluation_b'), 'INPUT_PARTITION')
        require(type(row['label']) is int and 0 <= row['label'] < 3, 'INPUT_LABEL')
        require(type(row['x']) is list and len(row['x']) == DIM and
                all(type(v) is int and -8 <= v <= 8 for v in row['x']) and
                row['x'][-1] == 8, 'INPUT_NUMERIC')
    require(len({row['split'] for row in rows}) == 1, 'MIXED_PARTITION')
    partition_manifest(rows)  # Includes duplicate-ID rejection and complete ordered row digest.


@lru_cache(maxsize=2)
def _replayed_source(source, program_sha256):
    """Cache only actual, bounded source replay, never a caller-supplied success flag."""
    hex_value(source, 40, 'SOURCE_COMMIT')
    env = dict(os.environ)
    env.update({'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
                'PYTHONUTF8': '1', 'LC_ALL': 'C.UTF-8'})
    result = run_bounded(
        [sys.executable, str(Path(__file__).resolve()), '--replay-source', source],
        b'', timeout=30, stdout_limit=MAX_TASK_BYTES, stderr_limit=8192,
        cwd=ROOT, env=env)
    require(result.returncode == 0, 'SOURCE_REPLAY_UNAVAILABLE')
    value = strict_json(result.stdout, MAX_TASK_BYTES, 'SOURCE_REPLAY')
    require(type(value) is dict and set(value) == {'source', 'program_sha256', 'rows'} and
            value['source'] == source and value['program_sha256'] == program_sha256,
            'SOURCE_REPLAY_PROGRAM')
    require(type(value['rows']) is list and 0 < len(value['rows']) <= 32768, 'SOURCE_REPLAY_ROWS')
    # Immutable serialized data is the only cached value, so callers cannot poison it.
    return canonical(value['rows'])


def _verify_upstream(model, rows, identity):
    _rows(rows)
    source = hex_value(model['source'], 40, 'SOURCE_COMMIT')
    reproduced = json.loads(_replayed_source(source, identity['program_sha256']))
    indexed = {row['id']: row for row in reproduced}
    require(len(indexed) == len(reproduced), 'SOURCE_DUPLICATE')
    for row in rows:
        require(row['id'] in indexed and canonical(row) == canonical(indexed[row['id']]),
                'SOURCE_FEATURE_BINDING')


def _components(model, identity):
    files = identity['source_manifest']
    return {
        'artifact': artifact_id(model), 'schema': model['schema'], 'source_commit': model['source'],
        'encoder': {'version': model['feature'], 'kind': 'source-token-hash-extractor',
                    'source_sha256': files['formal/pon-nakamoto-v1/experiments/model_loop.py']},
        'organ_adapter': {'version': 'research-shared-source-router-v1',
                          'source_sha256': files['formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py']},
        'cell_head': {'version': model['schema'], 'weights_sha256':
                      digest({'base': model['base'], 'deltas': model['deltas']})},
        'router': {'version': 'integer-three-expert-router-v1', 'weights_sha256': digest(model['router'])},
        'quantizer': {'version': 'prequantized-int16-artifact-scale1024-v1',
                      'runtime_quantization': False, 'prequantization_equivalence_proven': False,
                      'source_sha256': files['formal/pon-nakamoto-v1/model_contract.py']},
    }


def _assemble(model, rows, before, *, consumer, allowed_use, candidate_artifact,
              deadline_ms, request_id, target, identity):
    require(type(model) is dict, 'MODEL_OBJECT')
    load_model_bytes(canonical(model))
    before = _state(before)
    require(before['model_artifact'] == artifact_id(model), 'STATE_MODEL')
    identity_text(consumer, 'CONSUMER')
    identity_text(allowed_use, 'ALLOWED_USE')
    hex_value(candidate_artifact, code='CANDIDATE_ARTIFACT')
    require(candidate_artifact == artifact_id(model), 'CANDIDATE_MODEL')
    unsigned(deadline_ms, 'DEADLINE')
    hex_value(request_id, code='REQUEST_ID')
    hex_value(target, code='WORK_TARGET')
    require(target != '00' * 32, 'WORK_TARGET_ZERO')
    _rows(rows)
    return {
        'schema': RELATION_ID,
        'model': _components(model, identity),
        'state': {'cell_id': before['cell_id'], 'generation': before['generation'],
                  'before_sha256': digest(before), 'transition': 'read-only-v1'},
        'inputs': {
            'source_commit': model['source'], 'upstream': 'replayed-frozen-git-source-v1',
            'partition': rows[0]['split'], 'rows_sha256': digest(rows),
            'batch_members': [{'id': r['id'], 'source': r['file'],
                               'content_sha256': r['source_content_sha256'],
                               'features_sha256': digest(r['x'])} for r in rows],
        },
        'numeric': copy.deepcopy(NUMERIC_PROFILE), 'decision': copy.deepcopy(DECISION_PROFILE),
        'output': {'mapping': list(CLASSES), 'consumer': consumer, 'allowed_use': allowed_use,
                   'candidate_artifact': candidate_artifact, 'deadline_ms': deadline_ms,
                   'request_id': request_id},
        'proof': {'relation': RELATION_ID, 'verifier': VERIFIER_ID,
                  'program_sha256': identity['program_sha256'],
                  'parameters_sha256': identity['parameters_sha256'],
                  'source_manifest_sha256': digest(identity['source_manifest']),
                  'work_profile': cell.PROFILE, 'challenge_domain': CHALLENGE_DOMAIN,
                  'target': target, 'nonce_rule': 'independent-u64-per-tile'},
        'scope': copy.deepcopy(SCOPE),
    }


def freeze_contract(model, rows, before_state, *, consumer, allowed_use,
                    candidate_artifact, deadline_ms, request_id, target):
    """Admission helper; freezing a contract itself grants no owner authority."""
    identity = current_identity()
    value = _assemble(model, rows, before_state, consumer=consumer, allowed_use=allowed_use,
                      candidate_artifact=candidate_artifact, deadline_ms=deadline_ms,
                      request_id=request_id, target=target, identity=identity)
    _verify_upstream(model, rows, identity)
    require(current_identity() == identity, 'PROGRAM_CHANGED_DURING_FREEZE')
    raw = canonical(value)
    require(len(raw) <= CONTRACT_LIMIT, 'CONTRACT_LIMIT')
    return raw


def _contract(raw):
    value = strict_json(raw, CONTRACT_LIMIT, 'CONTRACT')
    require(type(value) is dict and set(value) ==
            {'schema', 'model', 'state', 'inputs', 'numeric', 'decision', 'output', 'proof', 'scope'},
            'CONTRACT_FIELDS')
    require(value['schema'] == RELATION_ID, 'RELATION_VERSION')
    require(type(value['output']) is dict and set(value['output']) ==
            {'mapping', 'consumer', 'allowed_use', 'candidate_artifact', 'deadline_ms', 'request_id'},
            'OUTPUT_CONTRACT_FIELDS')
    require(type(value['proof']) is dict and set(value['proof']) ==
            {'relation', 'verifier', 'program_sha256', 'parameters_sha256',
             'source_manifest_sha256', 'work_profile', 'challenge_domain', 'target', 'nonce_rule'},
            'PROOF_CONTRACT_FIELDS')
    return value


def _bound_contract(raw, model, rows, before, identity):
    value = _contract(raw)
    out = value['output']
    computed = _assemble(model, rows, before, consumer=out['consumer'], allowed_use=out['allowed_use'],
                         candidate_artifact=out['candidate_artifact'], deadline_ms=out['deadline_ms'],
                         request_id=out['request_id'], target=value['proof']['target'], identity=identity)
    require(canonical(computed) == raw, 'EXECUTED_CONTRACT_MISMATCH')
    _verify_upstream(model, rows, identity)
    return value


def _challenge(raw, before, tile, nonce):
    unsigned(nonce, 'WORK_NONCE')
    return H(CHALLENGE_DOMAIN, bytes.fromhex(contract_id(raw)), bytes.fromhex(digest(before)),
             bytes.fromhex(tile['task']), u64(tile['index']), u64(nonce))


def _output(value, cid, observed):
    predictions = observed['predictions'].tolist()
    batch = len(predictions)
    return {
        'schema': RELATION_ID + '/output', 'contract_id': cid,
        'request_id': value['output']['request_id'], 'consumer': value['output']['consumer'],
        'candidate_artifact': value['output']['candidate_artifact'],
        'routes': observed['routes'].tolist(), 'logits': observed['logits'].tolist(),
        'predictions': predictions, 'labels': [CLASSES[p] for p in predictions],
        'stop': [False] * batch, 'abstain': [False] * batch,
    }


def reference_search_plan(contract_raw, before_state, tiles, batch_size, max_attempts):
    """Describe the complete diagnostic denominator, without granting work authority.

    The experiment retains this separately before starting the proof search. The
    caller must have obtained tiles and state from the frozen relation; this
    helper alone does not validate a model or a producer-supplied statement.
    """
    return {
        'schema': 'useful-cell-reference-search-plan-v1',
        'kind': 'plan', 'relation': RELATION_ID,
        'contract_id': contract_id(contract_raw),
        'before_state_sha256': digest(before_state),
        'target': _contract(contract_raw)['proof']['target'],
        'batch_size': batch_size, 'max_attempts_per_tile': max_attempts,
        'tiles': [{'index': tile['index'], 'task': tile['task'],
                   'material_sha256': sha256(tile['material'])} for tile in tiles],
    }


def prove_reference(contract_raw, model, rows, before_state, *, max_attempts=64,
                    attempt_sink=None):
    """Generate real W1 witnesses, optionally retaining every started attempt.

    The sink is diagnostic, not an acceptance oracle. It sees the plan before
    search and each nonce start before arithmetic. A failed sink aborts proving;
    callers cannot obtain a successful witness after losing evidence. No source,
    numeric, challenge, target, decision or state-transition rule is changed.
    """
    require(type(max_attempts) is int and 1 <= max_attempts <= 4096, 'SEARCH_BUDGET')
    require(attempt_sink is None or callable(attempt_sink), 'ATTEMPT_SINK')
    identity = current_identity()
    value = _bound_contract(contract_raw, model, rows, before_state, identity)
    tiles, _ = cell.build_tiles(model, rows)
    sink_failed = False

    def emit(event):
        nonlocal sink_failed
        if attempt_sink is not None:
            try:
                # A sink must not be able to rewrite the frozen plan or a result.
                attempt_sink(copy.deepcopy(event))
            except BaseException:
                sink_failed = True
                raise

    emit(reference_search_plan(contract_raw, before_state, tiles, len(rows), max_attempts))
    entries, products = [], {}
    target = bytes.fromhex(value['proof']['target'])
    try:
        for tile in tiles:
            words = list(struct.unpack('<' + 'I' * (2 * work.CELLS), tile['material']))
            for nonce in range(max_attempts):
                challenge = _challenge(contract_raw, before_state, tile, nonce)
                context = {'tile': tile['index'], 'nonce': nonce,
                           'challenge': challenge.hex()}
                emit({'kind': 'attempt-start', **context})
                wall, cpu = time.perf_counter_ns(), time.process_time_ns()
                try:
                    proof = work.prove(challenge, words[:work.CELLS], words[work.CELLS:])
                    ticket = H('ticket', challenge, proof[-32:])
                except BaseException as error:
                    emit({'kind': 'attempt-error', **context,
                          'wall_ns': time.perf_counter_ns() - wall,
                          'process_cpu_ns': time.process_time_ns() - cpu,
                          'error_type': type(error).__name__, 'error': str(error)[:1024]})
                    raise
                # These are actual attempt clocks, excluding journal I/O. The
                # driver additionally measures the whole instrumented prove call.
                elapsed_wall, elapsed_cpu = time.perf_counter_ns() - wall, time.process_time_ns() - cpu
                hit = ticket <= target
                emit({'kind': 'attempt-complete', **context, 'trace': proof[-32:].hex(),
                      'proof_sha256': sha256(proof), 'ticket': ticket.hex(), 'hit': hit,
                      'wall_ns': elapsed_wall, 'process_cpu_ns': elapsed_cpu})
                if hit:
                    break
            else:
                raise ValueError('SEARCH_EXHAUSTED')
            entries.append({'index': tile['index'], 'nonce': nonce, 'proof_hex': proof.hex()})
            products[tile['index']] = proof[4 + 2 * work.CELLS * 4:-32]
        observed = cell.consume_products(tiles, products, len(rows))
        witness = canonical({'schema': RELATION_ID + '/witness', 'model': model, 'rows': rows, 'tiles': entries})
        require(len(witness) <= WITNESS_LIMIT, 'WITNESS_LIMIT')
        require(current_identity() == identity, 'PROGRAM_CHANGED_DURING_PROVING')
        output = _output(value, contract_id(contract_raw), observed)
        emit({'kind': 'end', 'status': 'complete', 'witness_sha256': sha256(witness),
              'output_sha256': digest(output), 'after_state_sha256': digest(before_state)})
        return {'output': output, 'after_state': copy.deepcopy(before_state), 'witness': witness}
    except BaseException as error:
        if not sink_failed:
            emit({'kind': 'end', 'status': 'failed',
                  'error_type': type(error).__name__, 'error': str(error)[:1024]})
        raise


def _now(clock_ms):
    return unsigned(clock_ms(), 'CLOCK')


def _check_output_shape(output, batch):
    require(type(output) is dict and set(output) ==
            {'schema', 'contract_id', 'request_id', 'consumer', 'candidate_artifact',
             'routes', 'logits', 'predictions', 'labels', 'stop', 'abstain'}, 'OUTPUT_FIELDS')
    for key in ('schema', 'contract_id', 'request_id', 'consumer', 'candidate_artifact'):
        require(type(output[key]) is str and len(output[key]) <= 256, 'OUTPUT_IDENTITY')
    for key in ('routes', 'predictions'):
        require(type(output[key]) is list and len(output[key]) == batch and
                all(type(v) is int and 0 <= v < 3 for v in output[key]), 'OUTPUT_INDICES')
    require(type(output['logits']) is list and len(output['logits']) == batch and
            all(type(row) is list and len(row) == 3 and
                all(type(v) is int and -(1 << 63) <= v < 1 << 63 for v in row)
                for row in output['logits']), 'OUTPUT_LOGITS')
    require(type(output['labels']) is list and len(output['labels']) == batch and
            all(type(v) is str and v in CLASSES for v in output['labels']), 'OUTPUT_LABELS')
    for key in ('stop', 'abstain'):
        require(type(output[key]) is list and len(output[key]) == batch and
                all(type(v) is bool for v in output[key]), 'OUTPUT_DECISIONS')


def verify_relation(contract_raw, before_state, output, after_state, witness_raw, *,
                    expected, clock_ms=lambda: time.time_ns() // 1_000_000):
    """Verify the complete reference relation against independently retained context.

    `expected` and the clock are verifier/consumer inputs, never witness fields.
    The owner must authenticate that context and atomically apply any later use;
    this pure function does not authorize, mutate, install, settle or deduplicate.
    """
    started = _now(clock_ms)
    value = _contract(contract_raw)
    require(type(expected) is dict and set(expected) ==
            {'contract_id', 'program_sha256', 'parameters_sha256', 'before_state',
             'consumer', 'allowed_use', 'candidate_artifact'}, 'EXPECTED_CONTEXT_FIELDS')
    for key in ('contract_id', 'program_sha256', 'parameters_sha256', 'candidate_artifact'):
        hex_value(expected[key], code='EXPECTED_' + key.upper())
    require(contract_id(contract_raw) == expected['contract_id'], 'EXPECTED_CONTRACT')
    require(canonical(_state(before_state)) == canonical(_state(expected['before_state'])),
            'EXPECTED_STATE')
    require(canonical(_state(after_state)) == canonical(before_state), 'READ_ONLY_STATE')
    for key in ('consumer', 'allowed_use', 'candidate_artifact'):
        require(value['output'][key] == expected[key], 'EXPECTED_' + key.upper())
    deadline = unsigned(value['output']['deadline_ms'], 'DEADLINE')
    require(started <= deadline, 'DEADLINE_EXPIRED')
    identity = current_identity()
    require(value['proof']['program_sha256'] == expected['program_sha256'] == identity['program_sha256'],
            'FIXED_PROGRAM')
    require(value['proof']['parameters_sha256'] == expected['parameters_sha256'] == identity['parameters_sha256'],
            'FIXED_PARAMETERS')
    witness = strict_json(witness_raw, WITNESS_LIMIT, 'WITNESS')
    require(type(witness) is dict and set(witness) == {'schema', 'model', 'rows', 'tiles'} and
            witness['schema'] == RELATION_ID + '/witness', 'WITNESS_VERSION_FIELDS')
    model, rows = witness['model'], witness['rows']
    _bound_contract(contract_raw, model, rows, before_state, identity)
    _check_output_shape(output, len(rows))
    tiles, _ = cell.build_tiles(model, rows)
    entries = witness['tiles']
    require(type(entries) is list and len(entries) == len(tiles), 'WITNESS_TILE_SET')
    products = {}
    for tile, entry in zip(tiles, entries):
        require(type(entry) is dict and set(entry) == {'index', 'nonce', 'proof_hex'} and
                type(entry['index']) is int and entry['index'] == tile['index'], 'WITNESS_TILE_ORDER')
        hex_value(entry['proof_hex'], 2 * work.PROOF_BYTES, 'WITNESS_PROOF_BYTES')
        proof = bytes.fromhex(entry['proof_hex'])
        require(proof[4:4 + 2 * work.CELLS * 4] == tile['material'], 'WITNESS_MATERIAL')
        challenge = _challenge(contract_raw, before_state, tile, entry['nonce'])
        # Full scalar transcript AND product verification, never native JSON status/precheck alone.
        _, product = work.verify(challenge, bytes.fromhex(tile['task']),
                                 bytes.fromhex(value['proof']['target']), proof)
        products[tile['index']] = work.field_bytes(product)
    observed = cell.consume_products(tiles, products, len(rows))
    independent = evaluate_exact(model, [row['x'] for row in rows])
    for key in ('products', 'routes', 'logits', 'predictions'):
        require(canonical(observed[key].tolist()) == canonical(independent[key]), 'SCALAR_' + key.upper())
    require(canonical(output) == canonical(_output(value, expected['contract_id'], observed)),
            'OUTPUT_RELATION')
    require(current_identity() == identity, 'PROGRAM_CHANGED_DURING_VERIFICATION')
    finished = _now(clock_ms)
    require(started <= finished <= deadline, 'COMPLETION_DEADLINE')
    return {
        'schema': RELATION_ID + '/verification', 'contract_id': expected['contract_id'],
        'relation_valid': True, 'upstream_verified': True, 'upstream_scope': 'frozen-public-source-extractor',
        'complete_w1_transcripts_verified': len(tiles), 'integer_decision_verified': True,
        'read_only_state_verified': True, 'external_context_matched': True,
        'clock_start_ms': started, 'clock_finish_ms': finished,
        'ordinary_hepta_encoder_verified': False, 'owner_authorization_verified': False,
        'model_behavior_preserved': None, 'bf16_equivalence': None,
        'calibration_qualified': False, 'ood_qualified': False, 'old_task_retention_qualified': False,
        'succinct_proof': False, 'work_security_qualified': False,
        'production_qualified': False, 'public_reward_eligible': False,
    }


def _source_worker(source):
    hex_value(source, 40, 'SOURCE_COMMIT')
    identity = current_identity()
    rows = source_model.corpus(source)
    raw = canonical({'source': source, 'program_sha256': identity['program_sha256'], 'rows': rows})
    require(current_identity() == identity, 'SOURCE_PROGRAM_CHANGED')
    require(len(raw) <= MAX_TASK_BYTES, 'SOURCE_REPLAY_LIMIT')
    sys.stdout.buffer.write(raw)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--replay-source':
        _source_worker(sys.argv[2])
    else:
        raise SystemExit('Use the imported verifier API or experiments/useful_cell_relation_v1.py.')
