#!/usr/bin/env python3
"""Bounded, persistent CPU inference adapter for the original Hepta read owner.

The host pins and admits the parameter bytes before starting this private worker.
This process reuses the existing model/LoRA loader, causal forward pass, and wait4
supervisor. It has no optimizer, registry, selector, authority key or journal.
The socket is private to a create-only owner directory; every use still requires
the original Hepta host's resource reservation and final-use admission.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import sys
import time

import llm_inherited_runtime as inherited
import llm_runtime_pilot as runtime

SCHEMA = 'hepta-smollm-neural-read-worker-v1'
MAX_REQUEST = 8192
MAX_REQUESTS = 64


def read_request(connection):
    raw = bytearray()
    while len(raw) <= MAX_REQUEST:
        part = connection.recv(min(1024, MAX_REQUEST + 1 - len(raw)))
        if not part:
            break
        raw.extend(part)
        if b'\n' in part:
            break
    runtime.require(0 < len(raw) <= MAX_REQUEST and raw.endswith(b'\n') and
                    raw.count(b'\n') == 1, 'NEURAL_READ_FRAME')
    value = json.loads(raw, object_pairs_hook=runtime.unique)
    if value == {'schema': SCHEMA, 'stop': True} and type(value.get('stop')) is bool:
        return None, hashlib.sha256(raw[:-1]).hexdigest()
    runtime.require(type(value) is dict and set(value) == {'schema', 'request_id', 'prompt'} and
        value['schema'] == 'hepta-smollm-inference-input-v1' and
        type(value['request_id']) is str and 1 <= len(value['request_id'].encode()) <= 128 and
        type(value['prompt']) is str and 1 <= len(value['prompt'].encode()) <= 2048,
        'NEURAL_READ_REQUEST')
    return value, hashlib.sha256(raw[:-1]).hexdigest()


def action_profile(value):
    runtime.require(type(value) is list and 1 <= len(value) <= 128, 'NEURAL_READ_ACTION_LIMIT')
    ids, labels = set(), set()
    for item in value:
        runtime.require(type(item) is dict and set(item) == {'action_id', 'completion'} and
            type(item['action_id']) is str and 1 <= len(item['action_id'].encode()) <= 128 and
            type(item['completion']) is str and 1 <= len(item['completion'].encode()) <= 64 and
            item['action_id'] not in ids and item['completion'] not in labels, 'NEURAL_READ_ACTION')
        ids.add(item['action_id']); labels.add(item['completion'])
    runtime.require(value == sorted(value, key=lambda item: item['action_id']), 'NEURAL_READ_ACTION_ORDER')
    return value


def worker(args):
    plan = inherited.checked_json(args.plan, args.plan_sha256, 512 * 1024)
    runtime.require(type(plan) is dict and set(plan) == {'schema', 'runtime', 'parent',
        'inherited_sources', 'worker_source', 'actions'}, 'NEURAL_READ_PLAN')
    runtime.require(plan['schema'] == SCHEMA and plan['inherited_sources'] == inherited.source_pins()
        and plan['worker_source'] == runtime.file_sha(__file__), 'NEURAL_READ_SOURCE_CHANGED')
    pilot = runtime.validate_plan(plan['runtime'])
    runtime.require(pilot['backend'] == 'cpu' and pilot['threads'] <= 4, 'NEURAL_READ_CPU_ONLY')
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
    runtime.require({k: v for k, v in actual.items() if k != 'registration'} ==
                    {k: v for k, v in contract.items() if k != 'registration'}, 'NEURAL_READ_RUNTIME_BINDING')
    model = runtime.insert_lora(model, pilot, 'candidate', torch)
    loaded = observer.stage('actual-parent-reload', lambda: inherited.load_factors(model, contract,
        parent['contract'], factors, parent['adapter'], torch, device))
    actions = action_profile(plan['actions'])
    action_tokens = [tokenizer.encode(item['completion'], add_special_tokens=False) for item in actions]
    runtime.require(all(len(tokens) == 1 for tokens in action_tokens) and
                    len({tokens[0] for tokens in action_tokens}) == len(actions), 'NEURAL_READ_SINGLE_TOKEN_ACTIONS')
    model.eval()
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
            actions=actions, observed_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            authority=inherited.NO_AUTHORITY)
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
    runtime.require(Path(args.output).is_absolute(), 'NEURAL_READ_OUTPUT_PATH')
    runtime.require(type(args.threads) is int and 1 <= args.threads <= 4, 'NEURAL_READ_CPU_ONLY')
    parent = inherited.validate_parent(inherited.checked_json(args.parent, args.parent_sha256))
    inherited.read_parent(parent)
    actions = action_profile(inherited.checked_json(args.actions, args.actions_sha256))
    manifest, _ = runtime.verify_materials(args.materials)
    plan = dict(schema=SCHEMA, runtime=runtime.experiment_plan(manifest, threads=args.threads, steps=10),
                parent=parent, actions=actions, inherited_sources=inherited.source_pins(), worker_source=runtime.file_sha(__file__))
    root = Path(args.output)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    plan_path = root/'worker-plan.json'
    runtime.save(plan_path, plan)
    result = runtime.supervise([sys.executable, str(Path(__file__).resolve()), '_worker',
        '--materials', str(Path(args.materials).resolve()), '--output', str(root/'worker'),
        '--plan', str(plan_path), '--plan-sha256', runtime.file_sha(plan_path)], root/'worker',
        plan['runtime']['inference_budget'])
    runtime.require(result['outcome'] == 'success', 'NEURAL_READ_WORKER_FAILED')


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
    args = parser.parse_args()
    worker(args) if args.command == '_worker' else serve(args)


if __name__ == '__main__':
    main()
