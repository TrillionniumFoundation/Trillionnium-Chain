#!/usr/bin/env python3
"""Bounded, persistent CPU inference adapter for the original Hepta read owner.

The host pins and admits the parameter bytes before starting this private worker.
This process reuses the existing model/LoRA loader, causal forward pass, and wait4
supervisor. It has no optimizer, registry, selector, authority key or journal.
The socket is private to a create-only owner directory; every use still requires
the original Hepta host's resource reservation and final-use admission.
"""
import sys
if __name__ == '__main__' and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit('NEURAL_READ_ISOLATED_ENTRY')

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import stat
import time
import types

SCHEMA = 'hepta-smollm-neural-read-worker-v2'
MAX_REQUEST = 8192
MAX_REQUESTS = 64


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'NEURAL_READ_DUPLICATE_FIELD')
        result[key] = value
    return result


def bootstrap_bytes(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'NEURAL_READ_BOOTSTRAP_FILE')
        raw = source.read(maximum + 1)
    require(0 < len(raw) <= maximum, 'NEURAL_READ_BOOTSTRAP_BOUND')
    return raw


def worker_sources():
    sources = inherited.source_pins()
    sources['llm_python_runtime_contract.py'] = runtime.file_sha(python_runtime.__file__)
    for relative in ('formal/pon-nakamoto-v1/contract_wire.py', 'config/pon/devnet-v1.json',
                     'config/pon/ledger-v1.json', 'config/pon/work-profile-v1.json', 'config/pon/model-family-v1.json'):
        path = runtime.REPOSITORY / relative
        sources[path.name] = runtime.file_sha(path)
    return sources


def _install_runtime_guard(args, pins):
    guard = python_runtime.install_import_guard(args.runtime_contract, pins)
    # Preserve the complete host-admitted set, including non-Python config pins.
    # Copy only after the original guard has validated the exact dict and bytes.
    args.runtime_source_pins = dict(pins)
    args.runtime_import_guard = guard


def _verify_runtime_ready(args):
    python_runtime.verify_loaded(args.runtime_contract, args.runtime_source_pins,
                                 args.runtime_import_guard)


def read_request(connection):
    raw = bytearray()
    while len(raw) <= MAX_REQUEST:
        part = connection.recv(min(1024, MAX_REQUEST + 1 - len(raw)))
        if not part:
            break
        raw.extend(part)
        if b'\n' in part:
            break
    require(0 < len(raw) <= MAX_REQUEST and raw.endswith(b'\n') and
                    raw.count(b'\n') == 1, 'NEURAL_READ_FRAME')
    value = json.loads(raw, object_pairs_hook=unique)
    if value == {'schema': SCHEMA, 'stop': True} and type(value.get('stop')) is bool:
        return None, hashlib.sha256(raw[:-1]).hexdigest()
    require(type(value) is dict and set(value) == {'schema', 'request_id', 'prompt'} and
        value['schema'] == 'hepta-smollm-inference-input-v1' and
        type(value['request_id']) is str and 1 <= len(value['request_id'].encode()) <= 128 and
        type(value['prompt']) is str and 1 <= len(value['prompt'].encode()) <= 2048,
        'NEURAL_READ_REQUEST')
    return value, hashlib.sha256(raw[:-1]).hexdigest()


def action_profile(value):
    require(type(value) is list and 1 <= len(value) <= 128, 'NEURAL_READ_ACTION_LIMIT')
    ids, labels = set(), set()
    for item in value:
        require(type(item) is dict and set(item) == {'action_id', 'completion'} and
            type(item['action_id']) is str and 1 <= len(item['action_id'].encode()) <= 128 and
            type(item['completion']) is str and 1 <= len(item['completion'].encode()) <= 64 and
            item['action_id'] not in ids and item['completion'] not in labels, 'NEURAL_READ_ACTION')
        ids.add(item['action_id']); labels.add(item['completion'])
    require(value == sorted(value, key=lambda item: item['action_id']), 'NEURAL_READ_ACTION_ORDER')
    return value


# This is an explicit material-provenance bridge, not an inference permission.
# The caller must independently admit the complete current source/snapshot tuple.
MATERIAL_BRIDGE_PROFILE_V1 = 'smollm2-public-v2-material-runtime-bridge-v1'
_MATERIAL_PLAN_SHA256 = '01ec1a644f37b9fc7a4c6616f589768df97f8eed7a289b5de86afadaa7ce6165'
_MATERIAL_CONTRACT_SHA256 = 'ebc8ac84999a91acb823d1bf8959a7dbc61fe20d7ba137f11affe426605d9852'
_MATERIAL_CONTRACT_ID = 'c9b06f9a029a3257801844f89acb59b5f59f6a39087335af323f274e9152992f'
_MATERIAL_RUNTIME_SHA256 = '65ccc6454befd96fa5ce1f5bdde2c56cb6cbb741cf495b8d24a758039f99f755'
_EXECUTION_RUNTIME_SHA256 = '13e4c11d51931d902483372a9a05c7180333893202ecb1d663d57a83111eccc7'


def _bridge_canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def _bridge_identity(value):
    return hashlib.sha256(_bridge_canonical(value)).hexdigest()


def _bridge_behavior(source):
    return _bridge_identity(dict(source=source, special_token_decode='skip',
                                 cleanup=False, chat_template='apply-once-no-extra-bos'))


def _bridge_operator(source, backend):
    return _bridge_identity(dict(source=source, backend=backend,
                                 matmul='highest-no-TF32-eager-attention'))


class _MaterialRuntimeBridgeV1:
    """One exact old material/current runtime pair, with no load authority.

    Both original raw material inputs are fixed independently. The current plan
    must be the complete original plan with exactly its execution-source field
    changed. This never relabels current execution as historical source.
    """
    __slots__ = ('_expected_contract', '_record')

    def __init__(self, profile, material_plan_raw, current_plan,
                 material_contract_raw, material_contract_id):
        require(profile == MATERIAL_BRIDGE_PROFILE_V1, 'NEURAL_BRIDGE_PROFILE')
        require(type(material_plan_raw) is bytes and
                0 < len(material_plan_raw) <= 64 * 1024 and
                hashlib.sha256(material_plan_raw).hexdigest() == _MATERIAL_PLAN_SHA256,
                'NEURAL_BRIDGE_MATERIAL_PLAN')
        require(type(material_contract_raw) is bytes and
                0 < len(material_contract_raw) <= 1024 * 1024 and
                hashlib.sha256(material_contract_raw).hexdigest() == _MATERIAL_CONTRACT_SHA256 and
                material_contract_id == _MATERIAL_CONTRACT_ID, 'NEURAL_BRIDGE_MATERIAL_CONTRACT')
        historical_plan = json.loads(material_plan_raw, object_pairs_hook=unique)
        historical_contract = json.loads(material_contract_raw, object_pairs_hook=unique)
        require(_bridge_canonical(historical_plan) + b'\n' == material_plan_raw and
                _bridge_canonical(historical_contract) == material_contract_raw and
                historical_plan['runtime_source'] == _MATERIAL_RUNTIME_SHA256,
                'NEURAL_BRIDGE_CANONICAL_MATERIAL')
        expected_plan = dict(historical_plan, runtime_source=_EXECUTION_RUNTIME_SHA256)
        require(type(current_plan) is dict and
                _bridge_canonical(current_plan) == _bridge_canonical(expected_plan),
                'NEURAL_BRIDGE_CURRENT_PLAN')
        require(historical_contract['tokenizer']['behavior_contract'] ==
                _bridge_behavior(_MATERIAL_RUNTIME_SHA256) and
                historical_contract['numeric']['operator_contract'] ==
                _bridge_operator(_MATERIAL_RUNTIME_SHA256, historical_plan['backend']) and
                historical_contract['registration']['target_admission'] ==
                _bridge_identity(historical_plan), 'NEURAL_BRIDGE_MATERIAL_PROVENANCE')
        # These are derived identities, not omitted comparison fields. Every
        # remaining byte of the canonical actual loaded contract must agree.
        projected = json.loads(material_contract_raw, object_pairs_hook=unique)
        projected['tokenizer']['behavior_contract'] = _bridge_behavior(_EXECUTION_RUNTIME_SHA256)
        projected['numeric']['operator_contract'] = _bridge_operator(
            _EXECUTION_RUNTIME_SHA256, current_plan['backend'])
        projected['registration']['target_admission'] = _bridge_identity(current_plan)
        self._expected_contract = _bridge_canonical(projected)
        self._record = _bridge_canonical(dict(
            schema='hepta-smollm-material-runtime-bridge-v1', profile=profile,
            historical_plan_sha256=_MATERIAL_PLAN_SHA256,
            historical_contract_sha256=_MATERIAL_CONTRACT_SHA256,
            historical_contract=_MATERIAL_CONTRACT_ID,
            historical_runtime_source=_MATERIAL_RUNTIME_SHA256,
            execution_runtime_source=_EXECUTION_RUNTIME_SHA256,
            execution_plan_sha256=_bridge_identity(current_plan),
            execution_contract_sha256=hashlib.sha256(self._expected_contract).hexdigest()))

    def verify_loaded_contract(self, actual):
        require(type(actual) is dict and _bridge_canonical(actual) == self._expected_contract,
                'NEURAL_BRIDGE_LOADED_CONTRACT')
        return json.loads(self._record, object_pairs_hook=unique)


BRIDGED_PLAN_SCHEMA_V1 = 'hepta-smollm-neural-read-plan-material-bridge-v1'
BRIDGED_READY_SCHEMA_V1 = 'hepta-smollm-neural-read-ready-material-bridge-v1'


def _bridge_source_commitment(args):
    identities = {}
    for path, digest in args.runtime_source_pins.items():
        name = Path(path).name
        runtime.require(name not in identities, 'NEURAL_BRIDGE_SOURCE_ALIAS')
        identities[name] = digest
    ordinary = set(worker_sources()) | {Path(__file__).name}
    caller = {'hepta_neural_forward_v2.py', 'hepta_neural_forward_bootstrap_v2.py'}
    runtime.require(set(identities) in (ordinary, ordinary | caller),
                    'NEURAL_BRIDGE_SOURCE_SET')
    return _bridge_identity(identities)


def _bridge_execution_sources(args):
    commitment = _bridge_source_commitment(args)
    source = str(Path(runtime.__file__).resolve())
    runtime.require(args.runtime_source_pins.get(source) == _EXECUTION_RUNTIME_SHA256 and
                    runtime.file_sha(source) == _EXECUTION_RUNTIME_SHA256,
                    'NEURAL_BRIDGE_EXECUTION_SOURCE')
    return commitment


def _read_worker_plan(args, bridged):
    python_runtime.verify_files(args.runtime_contract)
    plan = inherited.checked_json(args.plan, args.plan_sha256, 512 * 1024)
    fields = {'schema', 'runtime', 'parent', 'inherited_sources', 'worker_source',
              'actions', 'runtime_snapshot_sha256'}
    runtime.require(type(plan) is dict and
                    set(plan) == (fields | {'material_bridge'} if bridged else fields),
                    'NEURAL_READ_PLAN')
    schema = BRIDGED_PLAN_SCHEMA_V1 if bridged else SCHEMA
    runtime.require(plan['schema'] == schema and plan['inherited_sources'] == worker_sources()
        and plan['worker_source'] == runtime.file_sha(__file__) and
        plan['runtime_snapshot_sha256'] == args.runtime_snapshot_sha256, 'NEURAL_READ_SOURCE_CHANGED')
    pilot = runtime.validate_plan(plan['runtime'])
    runtime.require(pilot['backend'] == 'cpu' and pilot['threads'] <= 4, 'NEURAL_READ_CPU_ONLY')
    bridge = None
    if bridged:
        _bridge_execution_sources(args)
        value = plan['material_bridge']
        runtime.require(type(value) is dict and set(value) == {'profile', 'material_plan'} and
                        type(value['material_plan']) is str, 'NEURAL_BRIDGE_INPUT')
        parent = inherited.validate_parent(plan['parent'])
        _, parent_raw, _ = inherited.read_parent(parent)
        bridge = _MaterialRuntimeBridgeV1(value['profile'], value['material_plan'].encode(),
            pilot, parent_raw, parent['contract'])
    return plan, pilot, bridge


def preflight_material_runtime_bridge_v1(args):
    """Validate this explicit mode before a direct caller starts its client."""
    _read_worker_plan(args, True)


def worker(args):
    return _worker(args, False)


def worker_bridge_v1(args):
    return _worker(args, True)


def _worker(args, bridged):
    plan, pilot, bridge = _read_worker_plan(args, bridged)
    directory, materials = Path(args.output).resolve(), Path(args.materials).resolve()
    observer = runtime.Observer(directory, 'cpu')
    manifest, _ = observer.stage('material-verification', lambda: runtime.verify_materials(materials))
    runtime.require(runtime.identity(manifest) == pilot['snapshot'], 'NEURAL_READ_SNAPSHOT')
    imports = observer.stage('runtime-import', lambda: runtime.runtime_import(pilot))
    torch, device, *_ = imports
    model, tokenizer, shapes, _ = observer.stage('model-load',
        lambda: runtime.load_model(materials, pilot, imports))
    actual, _, _ = observer.stage('backbone-tokenizer-verification',
        lambda: runtime.make_contract(model, tokenizer, shapes, materials, manifest, pilot))
    parent = inherited.validate_parent(plan['parent'])
    contract, _, factors = observer.stage('parent-material-verification', lambda: inherited.read_parent(parent))
    if bridge is None:
        runtime.require({k: v for k, v in actual.items() if k != 'registration'} ==
                        {k: v for k, v in contract.items() if k != 'registration'}, 'NEURAL_READ_RUNTIME_BINDING')
        bridge_record = None
    else:
        bridge_record = bridge.verify_loaded_contract(actual)
    model = runtime.insert_lora(model, pilot, 'candidate', torch)
    loaded = observer.stage('actual-parent-reload', lambda: inherited.load_factors(model, contract,
        parent['contract'], factors, parent['adapter'], torch, device))
    actions = action_profile(plan['actions'])
    action_tokens = [tokenizer.encode(item['completion'], add_special_tokens=False) for item in actions]
    runtime.require(all(len(tokens) == 1 for tokens in action_tokens) and
                    len({tokens[0] for tokens in action_tokens}) == len(actions), 'NEURAL_READ_SINGLE_TOKEN_ACTIONS')
    model.eval()
    _verify_runtime_ready(args)
    # Bind a relative socket inside the already-private owner directory; this
    # avoids Unix sun_path limits on long project paths without global /tmp state.
    os.chdir(directory)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind('model.sock')
        os.chmod('model.sock', 0o600)
        server.listen(1)
        server.settimeout(60)
        ready = dict(schema=SCHEMA, actual_loaded_parent=loaded,
            file_sha256=parent['file_sha256'], contract=parent['contract'], generation=parent['generation'],
            backbone=contract['backbone']['index_root'], tokenizer=contract['tokenizer']['files_root'],
            source_pins=plan['inherited_sources'], worker_source=plan['worker_source'],
            runtime_snapshot_sha256=args.runtime_snapshot_sha256,
            actions=actions, observed_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            authority=inherited.NO_AUTHORITY)
        if bridge_record is not None:
            ready['schema'] = BRIDGED_READY_SCHEMA_V1
            ready['material_runtime_bridge'] = bridge_record
            ready['runtime_source_set_sha256'] = _bridge_source_commitment(args)
        # Publish only a complete ready observation. The host must never race a
        # partially written JSON file while deciding whether to expose reads.
        with (directory/'ready.pending').open('x', encoding='utf-8') as handle:
            json.dump(ready, handle, sort_keys=True, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        (directory/'ready.pending').rename(directory/'ready.json')
        for _ in range(MAX_REQUESTS):
            try:
                connection, _ = server.accept()
            except TimeoutError:
                break
            with connection:
                connection.settimeout(10)
                request, input_sha256 = read_request(connection)
                if request is None:
                    break
                start = time.monotonic_ns()
                # All possible action completions are frozen in the model
                # profile. No request carries its expected answer. Score their
                # actual first-token logits in one forward pass; this explicit
                # profile is not labelled as a fixed-16-token decoder receipt.
                tokens = runtime.prompt_tokens(tokenizer, request, pilot['input_tokens_max'])
                ids = torch.tensor([tokens], dtype=torch.int64, device=device)
                with torch.inference_mode():
                    mask = torch.ones_like(ids, dtype=torch.bool)
                    positions = mask.to(torch.int64).cumsum(-1)-1
                    result = model(input_ids=ids, attention_mask=mask, position_ids=positions, use_cache=False)
                    logits = result.logits[:, -1, :]
                    runtime.require(logits.dtype == torch.float32 and logits.device.type == 'cpu' and
                        torch.isfinite(logits).all().item(), 'NEURAL_READ_LOGITS')
                    scores = [round(float(logits[0, value[0]].item()) * (1 << 32)) for value in action_tokens]
                    runtime.require(all(-(1 << 63) <= score < (1 << 63) for score in scores), 'NEURAL_READ_SCORE_RANGE')
                response = dict(schema=SCHEMA, request_id=request['request_id'], input_sha256=input_sha256,
                    file_sha256=parent['file_sha256'], artifact=loaded, contract=parent['contract'],
                    profile='hepta-smollm-single-token-action-score-v1',
                    action_ids=[item['action_id'] for item in actions], scores_q32=scores,
                    input_tokens=len(tokens), logits_sha256=hashlib.sha256(runtime.tensor_bytes(logits)).hexdigest(),
                    execution_ns=time.monotonic_ns()-start,
                    observed_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                    authority=inherited.NO_AUTHORITY)
                raw = json.dumps(response, sort_keys=True, separators=(',', ':')).encode()
                runtime.require(len(raw) <= 128 * 1024, 'NEURAL_READ_RESPONSE_LIMIT')
                connection.sendall(raw+b'\n')
        (directory/'model.sock').unlink()


def serve(args):
    return _serve(args, None)


def serve_bridge_v1(args):
    raw = bootstrap_bytes(args.material_plan, 64 * 1024)
    require(args.material_plan_sha256 == _MATERIAL_PLAN_SHA256 and
            hashlib.sha256(raw).hexdigest() == _MATERIAL_PLAN_SHA256,
            'NEURAL_BRIDGE_MATERIAL_PLAN')
    return _serve(args, raw)


def _serve(args, material_plan_raw):
    runtime.require(Path(args.output).is_absolute(), 'NEURAL_READ_OUTPUT_PATH')
    runtime.require(type(args.threads) is int and 1 <= args.threads <= 4, 'NEURAL_READ_CPU_ONLY')
    parent = inherited.validate_parent(inherited.checked_json(args.parent, args.parent_sha256))
    _, parent_raw, _ = inherited.read_parent(parent)
    actions = action_profile(inherited.checked_json(args.actions, args.actions_sha256))
    manifest, _ = runtime.verify_materials(args.materials)
    plan = dict(schema=SCHEMA, runtime=runtime.experiment_plan(manifest, threads=args.threads, steps=10),
                parent=parent, actions=actions, inherited_sources=worker_sources(), worker_source=runtime.file_sha(__file__),
                runtime_snapshot_sha256=args.runtime_snapshot_sha256)
    if material_plan_raw is not None:
        _bridge_execution_sources(args)
        _MaterialRuntimeBridgeV1(MATERIAL_BRIDGE_PROFILE_V1, material_plan_raw,
            plan['runtime'], parent_raw, parent['contract'])
        plan['schema'] = BRIDGED_PLAN_SCHEMA_V1
        plan['material_bridge'] = dict(profile=MATERIAL_BRIDGE_PROFILE_V1,
                                       material_plan=material_plan_raw.decode())
    root = Path(args.output)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    plan_path = root/'worker-plan.json'
    runtime.save(plan_path, plan)
    with runtime.cooperative_supervisor_stop() as stop_request:
        command = '_worker' if material_plan_raw is None else '_worker-bridge-v1'
        result = runtime.supervise([sys.executable, '-I', '-S', '-B', '-X',
            'pycache_prefix=' + sys.pycache_prefix, str(Path(__file__).resolve()), command,
            '--materials', str(Path(args.materials).resolve()), '--output', str(root/'worker'),
            '--runtime-snapshot', str(Path(args.runtime_snapshot).resolve()),
            '--runtime-snapshot-sha256', args.runtime_snapshot_sha256,
            '--source-pins', args.source_pins, '--source-pins-sha256', args.source_pins_sha256,
            '--plan', str(plan_path), '--plan-sha256', runtime.file_sha(plan_path)], root/'worker',
            plan['runtime']['inference_budget'], stop_request=stop_request)
    runtime.require(result['outcome'] == 'success', 'NEURAL_READ_WORKER_FAILED')


def bootstrap_runtime_v2(args):
    """Apply the ordinary v2 runtime boundary to four explicit pinned inputs.

    Callers supply source_pins, source_pins_sha256, runtime_snapshot and
    runtime_snapshot_sha256. This preserves all entry and byte checks; callers
    retain their own umask, argument handling and subsequent operation checks.
    """
    global python_runtime, inherited, runtime
    require(sys.flags.isolated == 1 and sys.flags.no_site == 1, 'NEURAL_READ_ISOLATED_ENTRY')
    raw = bootstrap_bytes(args.source_pins, 128 * 1024)
    require(0 < len(raw) <= 128 * 1024 and hashlib.sha256(raw).hexdigest() == args.source_pins_sha256,
            'NEURAL_READ_SOURCE_PINS')
    pins = json.loads(raw, object_pairs_hook=unique)
    helper = Path(__file__).resolve().with_name('llm_python_runtime_contract.py')
    raw = bootstrap_bytes(helper, 2 * 1024 * 1024)
    require(len(raw) <= 2 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == pins.get(str(helper)),
            'NEURAL_READ_HELPER_PIN')
    python_runtime = types.ModuleType('llm_python_runtime_contract')
    python_runtime.__file__ = str(helper)
    sys.modules[python_runtime.__name__] = python_runtime
    exec(compile(raw, str(helper), 'exec'), python_runtime.__dict__)
    args.runtime_contract = python_runtime.load_snapshot(args.runtime_snapshot, args.runtime_snapshot_sha256)
    python_runtime.configure(args.runtime_contract)
    _install_runtime_guard(args, pins)
    import llm_runtime_pilot as runtime
    import llm_inherited_runtime as inherited


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    runner = commands.add_parser('serve')
    for name in ('materials', 'parent', 'parent-sha256', 'actions', 'actions-sha256', 'output'):
        runner.add_argument('--'+name, required=True)
    runner.add_argument('--threads', type=int, default=4)
    child = commands.add_parser('_worker')
    for name in ('materials', 'output', 'plan', 'plan-sha256'):
        child.add_argument('--'+name, required=True)
    bridge_runner = commands.add_parser('serve-bridge-v1')
    for name in ('materials', 'parent', 'parent-sha256', 'actions', 'actions-sha256', 'output',
                 'material-plan', 'material-plan-sha256'):
        bridge_runner.add_argument('--'+name, required=True)
    bridge_runner.add_argument('--threads', type=int, default=4)
    bridge_child = commands.add_parser('_worker-bridge-v1')
    for name in ('materials', 'output', 'plan', 'plan-sha256'):
        bridge_child.add_argument('--'+name, required=True)
    for command in (runner, child, bridge_runner, bridge_child):
        command.add_argument('--runtime-snapshot', required=True)
        command.add_argument('--runtime-snapshot-sha256', required=True)
        command.add_argument('--source-pins', required=True)
        command.add_argument('--source-pins-sha256', required=True)
    args = parser.parse_args()
    bootstrap_runtime_v2(args)
    if args.command == '_worker':
        worker(args)
    elif args.command == '_worker-bridge-v1':
        worker_bridge_v1(args)
    elif args.command == 'serve-bridge-v1':
        serve_bridge_v1(args)
    else:
        serve(args)


if __name__ == '__main__':
    main()
