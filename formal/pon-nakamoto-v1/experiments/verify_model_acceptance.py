#!/usr/bin/env python3
"""Offline bounded ingestion of an owner-pinned model operations package.

No downloads, training, signatures, chain changes or independent acceptance.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract_wire import unique
from llm_adapter_contract import verify_target_contract, verify_run_plan, require
from model_acceptance import verify_acceptance

MAX_JSON = 2*1024*1024
MAX_MATERIAL = 16*1024*1024


def bounded_file(root, name, limit):
    require(type(name) is str and name and not Path(name).is_absolute() and
            all(part not in ('.', '..') for part in name.split('/')), 'ACCEPTANCE_INPUT_PATH')
    path = root/name
    require(path.resolve().is_relative_to(root) and path.is_file(), 'ACCEPTANCE_INPUT_PATH')
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    require(len(raw) <= limit, 'ACCEPTANCE_INPUT_LIMIT')
    return raw


def load_json(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('ACCEPTANCE_NONFINITE')))


def ingest(folder, *, preregistration_hash, plan_hash, contract_hash,
           backbone_root, tokenizer_root, owner_record):
    root = Path(folder).resolve()
    contract = verify_target_contract(bounded_file(root, 'contract.json', MAX_JSON), contract_hash,
        expected_backbone_root=backbone_root, expected_tokenizer_root=tokenizer_root)
    plan = verify_run_plan(bounded_file(root, 'plan.json', MAX_JSON), plan_hash, contract, contract_hash,
        expected_owner_record=owner_record)
    index = load_json(bounded_file(root, 'material-index.json', MAX_JSON))
    require(type(index) is dict and 1 <= len(index) <= 65536, 'ACCEPTANCE_MATERIAL_INDEX')
    remaining = MAX_MATERIAL; material = {}
    for key, name in index.items():
        raw = bounded_file(root, name, remaining)
        remaining -= len(raw); material[key] = raw
    return verify_acceptance(bounded_file(root, 'preregistration.json', MAX_JSON), preregistration_hash,
        plan, plan_hash, load_json(bounded_file(root, 'run-record.json', MAX_JSON)),
        load_json(bounded_file(root, 'receipt.json', MAX_JSON)), material)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--require-reported-gates', action='store_true',
                        help='Print assessment then exit 2 for a failed reported gate; does not grant acceptance')
    for name in ('preregistration-hash', 'plan-hash', 'contract-hash', 'backbone-root', 'tokenizer-root', 'owner-record'):
        parser.add_argument('--'+name, required=True)
    args = vars(parser.parse_args()); folder = args.pop('input')
    required = args.pop('require_reported_gates')
    report = ingest(folder, **args)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    if required and not report['reported_gates_passed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
