#!/usr/bin/env python3
"""Negative controls for the independent retained-receipt checker."""
import argparse
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', required=True, type=Path)
parser.add_argument('--receipt', required=True, type=Path)
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('checker', root / 'verify_incentive_split_receipt.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
positive = checker.verify(args.repo, args.receipt)
receipt = json.loads(args.receipt.read_text())

def tamper_signature(value):
    raw = bytearray.fromhex(value['split']['signed_commands'][0]['transactions'][0])
    raw[-1] ^= 1
    value['split']['signed_commands'][0]['transactions'][0] = raw.hex()

def tamper_complete_model(value):
    raw = bytearray.fromhex(value['split']['bundle_model_hex'])
    raw[-1] ^= 1
    value['split']['bundle_model_hex'] = raw.hex()

def tamper_claim(value):
    claims = value['split']['claims']
    claims[next(iter(claims))] += 1

def tamper_source_reservation(value):
    source = value['split']['known_alias_source']
    value['split']['source_budgets'][source] -= 1

def tamper_account(value):
    value['split']['alias_accounts_final'][0]['balance'] += 1

def remove_reveal(value):
    value['split']['signed_commands'][2]['transactions'].pop()

observations = []
with tempfile.TemporaryDirectory(prefix='trnm-v4-split-controls-') as temporary:
    for mutate in [tamper_signature, tamper_complete_model, tamper_claim,
                   tamper_source_reservation, tamper_account, remove_reveal]:
        candidate = deepcopy(receipt)
        mutate(candidate)
        path = Path(temporary) / (mutate.__name__ + '.json')
        path.write_text(json.dumps(candidate))
        try:
            checker.verify(args.repo, path)
        except Exception as error:
            observations.append({'mutation': mutate.__name__, 'rejected': True,
                                 'exception': type(error).__name__, 'reason': str(error)})
        else:
            raise AssertionError('mutation unexpectedly accepted: ' + mutate.__name__)
print(json.dumps({'schema': 'v4-split-independent-checker-negative-controls-v1',
                  'positive_receipt_sha256': positive['receipt_sha256'],
                  'controls': observations, 'all_rejected': True}, sort_keys=True, indent=2))
