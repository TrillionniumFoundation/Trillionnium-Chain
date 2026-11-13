#!/usr/bin/env python3
"""Check the actual filtered libtest run against its same-commit catalog."""
import hashlib
import json
from pathlib import Path
import re
import sys

directory = Path(sys.argv[1])
names = ('cell-finalized-control-catalog', 'cell-finalized-controls')
receipts = [json.loads((directory / (name + '.json')).read_text()) for name in names]
logs = [(directory / (name + '.log')).read_bytes() for name in names]
for receipt, log in zip(receipts, logs):
    assert receipt['status'] == 'command_succeeded' and receipt['exit_code'] == 0
    assert hashlib.sha256(log).hexdigest() == receipt['log_sha256']
    assert len(log) == receipt['log_bytes']
    assert receipt['before'] == receipt['after']
    assert receipt['before']['tracked_worktree_verified'] is True
assert receipts[0]['before'] == receipts[1]['before']
catalog = re.findall(r'^([A-Za-z0-9_:]+): test$', logs[0].decode(), re.M)
assert catalog and len(set(catalog)) == len(catalog)
filters = receipts[1]['argv'][receipts[1]['argv'].index('--') + 1:]
filters = [value for value in filters if not value.startswith('--')]
assert filters
expected = sorted(name for name in catalog if any(value in name for value in filters))
assert len(expected) == 46
actual = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ok$', logs[1].decode(), re.M)
assert len(actual) == len(set(actual)) == 46
assert sorted(actual) == expected
assert re.findall(r'^running ([0-9]+) tests$', logs[1].decode(), re.M) == ['46']
summary = re.findall(r'^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in ([0-9.]+)s$', logs[1].decode(), re.M)
assert len(summary) == 1
assert tuple(map(int, summary[0][:5])) == (46, 0, 0, 0, len(catalog)-46)
result = dict(schema='trnm-cell-native-test-roster-check-v1', status='PASS',
    tested_commit=receipts[1]['before']['tested_commit'], tested_tree=receipts[1]['before']['tested_tree'],
    catalog_tests=len(catalog), selected_tests=len(expected), filters=filters,
    expected_test_names=expected, executed_test_names=sorted(actual),
    source_catalog_receipt=names[0]+'.json', source_execution_receipt=names[1]+'.json',
    scope='native catalog and harness transcript identity; no independent runtime/production oracle',
    whole_chain_pq_qualified=False, production_activation=False)
(directory/'cell-finalized-test-roster.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({k:result[k] for k in ('status','tested_commit','catalog_tests','selected_tests')}))
