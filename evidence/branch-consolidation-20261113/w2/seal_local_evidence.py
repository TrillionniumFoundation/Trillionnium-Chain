#!/usr/bin/env python3
"""Verify retained W2 audit rows and original command logs; run no Git/test/build."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def main():
    ledger = read('tip-ledger.json')
    source = read('source-variants.snapshot.json')
    documents = read('document-variants.snapshot.json')
    index = read('validation-index.json')
    assert len(ledger['tips']) == 24
    assert len(source['variants']) == 95
    assert len(documents) == 33
    assert {v['id'] for v in source['variants']} == set(range(95))
    expected_heads = {t['sha'] for t in source['cohort'] + source['additional_transferred_cohort']}
    assert {t['original_head'] for t in ledger['tips']} == expected_heads
    for tip in ledger['tips']:
        expected = {v['id'] for v in source['variants'] if tip['original_head'] in v['tips']}
        assert set(tip['source_variant_ids']) == expected, tip['original_head']
    for v in source['variants']:
        assert re.fullmatch(r'[0-9a-f]{40}', v['branch_blob'])
    for row in documents:
        assert re.fullmatch(r'[0-9a-f]{40}', row['blob'])
        assert re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
    python_methods = go_functions = 0
    for expected in index['receipts']:
        receipt = read(expected['path'])
        raw = (ROOT / expected['log']).read_bytes()
        assert receipt['status'] == 'command_succeeded' and receipt['exit_code'] == 0
        assert receipt['before'] == receipt['after']
        assert receipt['before']['tracked_worktree_verified']
        assert receipt['before']['tested_commit'] == expected['tested_commit']
        assert len(raw) == receipt['log_bytes']
        assert hashlib.sha256(raw).hexdigest() == receipt['log_sha256']
        text = raw.decode()
        counts = expected['counts']
        if counts.get('python_methods'):
            assert re.search(r'Ran ' + str(counts['python_methods']) + r' tests? in ', text)
            assert '\nOK\n' in text
            assert 'skipped=' not in text
            python_methods += counts['python_methods']
        if counts.get('go_functions'):
            assert len(re.findall(r'^=== RUN   Test', text, flags=re.M)) == counts['go_functions']
            assert len(re.findall(r'^--- PASS: Test', text, flags=re.M)) == counts['go_functions']
            go_functions += counts['go_functions']
    parity = read(index['parity_report'])
    assert parity['count'] == len(parity['cases']) == 10
    assert [x['seed'] for x in parity['cases']] == list(range(10))
    assert all(x['full_bytes_equal'] and x['valid_go_verifier'] and x['valid_python_verifier']
               for x in parity['cases'])
    assert python_methods == 35 and go_functions == 2
    print(json.dumps({'schema': 'trnm-w2-local-evidence-seal-v1', 'result': 'PASS',
                      'tips': 24, 'source_variants': 95, 'document_variants': 33,
                      'receipts': 3, 'python_methods': 35, 'go_functions': 2,
                      'full_byte_cases': 10, 'git_build_or_tests_executed': False,
                      'original_head_ancestry_checked': False}, sort_keys=True))


if __name__ == '__main__':
    main()
