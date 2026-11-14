#!/usr/bin/env python3
"""Use the original source preparer for an explicit new environment generation."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback

ROOT = Path('/home/qq/work/chain-bt-owner-convergence-20261112-4a0b')
CONTROL = Path(str(ROOT) + '-control')
BASE = Path(str(ROOT) + '-validation')
OUT = BASE / 'private-runtime02-inputs'
PROJECTION = BASE / 'private-runtime02-projection'
NEW = Path('/home/qq/work/chain-bt-4a0b-runtime02')
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TREE = 'a897ba4c74897a05ceb364f098b1bfe32c850213'
SOURCE_SHA = 'fb6fe559317f7c3cd6ef504581b89e7d8229a7c700d3c71b61099a32d443cec9'
AUDIT_SHA = '59f49b99968bb41e6fa44c0cf59a18f08a5fce36bedb3fd5fcafec7487edfce6'
PREPARER_SHA = '4b919011b673a3a0ab738628b3c21ee7328a8a66ec86985f5843c5f4429a5ccc'
WRAPPER_SHA = 'd6540d88b88341c94a2be72fc76b16261f0607e1fd9c2a98ed9096aa913435f4'
PROJECTION_TOOL_SHA = '5b4f4d4f7a0dcde9bcba6221fc4c8fd7b92f1be05c1fd706fa0545b496c2caba'
PYTHON_SHA = '23bc148d2b48964b621c5561ff2b81c1d9c7b717967a7491efbf12f4304882b5'
SNAPSHOT_LOGICAL = 'runtime/runtime-snapshot.json'
DOMAIN = b'trnm.bt.private-runtime-projection.operation.v1\x00'
os.umask(0o077)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + chr(10)).encode()


def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def read_pinned(path, checksum):
    raw = Path(path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == checksum
    return raw


def identity():
    value = {key: subprocess.check_output(['/usr/bin/git', *args], cwd=ROOT, text=True).strip()
             for key, args in {'head': ['rev-parse', 'HEAD'], 'tree': ['rev-parse', 'HEAD^{tree}'],
                               'status': ['status', '--porcelain', '--untracked-files=all']}.items()}
    assert value == {'head': HEAD, 'tree': TREE, 'status': ''}
    return value


def measure(path, checksum):
    path = Path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 512 * 1024**2
        count = 0; digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''):
            count += len(block); assert count <= before.st_size; digest.update(block)
        after = os.fstat(stream.fileno())
    assert count == before.st_size and digest.hexdigest() == checksum
    assert all(getattr(before, key) == getattr(after, key) for key in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    return count


def main():
    assert len(sys.argv) == 1 and not OUT.exists()
    started = time.monotonic()
    original_path = CONTROL / 'source-inputs.native-v2.json'
    audit_path = CONTROL / 'source-inputs.native-v2.verification.json'
    original = json.loads(read_pinned(original_path, SOURCE_SHA))
    original_audit = json.loads(read_pinned(audit_path, AUDIT_SHA))
    projection_raw = (PROJECTION / 'summary.json').read_bytes()
    projection = json.loads(projection_raw)
    assert projection['completed'] is True and projection['passed'] is True
    assert projection['source'] == HEAD and projection['source_and_original_input_unchanged'] is True
    assert projection['observer_sha256'] == PROJECTION_TOOL_SHA
    assert projection['full_sealed_runtime_import_admission_performed'] is False
    assert projection['native_operation_started'] is False
    snapshot_path = Path(projection['snapshot']['path'])
    snapshot_sha = projection['snapshot']['sha256']
    assert snapshot_path == PROJECTION / 'runtime-snapshot.projected.v2.json'
    snapshot_raw = read_pinned(snapshot_path, snapshot_sha)
    assert snapshot_sha == projection['expected_projection_sha256']
    assert snapshot_raw == (PROJECTION / 'expected-projection.json').read_bytes()
    private_python = NEW / 'python/bin/python3.12'
    assert projection['python'] == {'path': str(private_python), 'sha256': PYTHON_SHA}
    assert sha(private_python) == PYTHON_SHA
    assert not Path(original['output']).exists() and not Path(original['output'] + '-wrapper').exists()
    preparer = ROOT / 'scripts/prepare_cell_sealed_research_v1.py'
    read_pinned(preparer, PREPARER_SHA)
    wrapper_raw = read_pinned(CONTROL / 'run_model.py', WRAPPER_SHA)
    before = identity()
    OUT.mkdir(mode=0o700)
    report = {'schema': 'trnm.bt-private-runtime-env2-input-preparation.v1', 'source': HEAD,
              'before_identity': before, 'observer_sha256': sha(Path(__file__)),
              'original_preparer_sha256': PREPARER_SHA, 'previous_source_sha256': SOURCE_SHA,
              'projection_summary_sha256': hashlib.sha256(projection_raw).hexdigest(),
              'environment_generation': 2, 'model_generation': original['parent']['generation'],
              'source_model_parent_preserved': False, 'independent_31_inputs_verified': False,
              'full_sealed_runtime_import_admission_performed': False,
              'native_operation_started': False, 'model_loaded': False, 'model_executed': False,
              'original_hepta_owner_used': False, 'hepta_final_use': False,
              'production_activation': False, 'model_efficacy_qualified': False, 'passed': False}
    try:
        preimage = DOMAIN + bytes.fromhex(HEAD) + bytes.fromhex(SOURCE_SHA) + bytes.fromhex(snapshot_sha) + (2).to_bytes(8, 'big')
        operation = hashlib.sha256(preimage).hexdigest()
        old_c3_path = ROOT / 'evidence/cell-storage-four-gates-20261111/current/model/fresh-input.json'
        old_c3 = json.loads(read_pinned(old_c3_path, 'cfeb462afd142ba0c2dd29f722216161346810038e19c0ac1815b12f4828d107'))
        previous_operations = {original['operation'], old_c3['source']['operation']}
        assert operation not in previous_operations and operation != '00' * 32
        output = BASE / ('real-native-env2-' + operation[:16] + '-attempt01')
        assert not output.exists() and not Path(str(output) + '-wrapper').exists()
        assert output.parent.resolve(strict=True) == output.parent
        base = Path(original['model']['base/model.safetensors']['path']).parent
        adapter = Path(original['model']['adapter/artifact.safetensors']['path']).parent
        assert base.resolve(strict=True) == base and adapter.resolve(strict=True) == adapter
        parent = dict(original['parent'], schema='hepta-smollm-parent-material-v1', directory=str(adapter))
        parent_path = OUT / 'derived-parent-preparer-envelope.json'
        requests_path = OUT / 'derived-original-requests.json'
        write(parent_path, encoded(parent)); write(requests_path, encoded(original['requests']))
        plan_rows = [(logical, item) for logical, item in original['environment'].items()
                     if item['sha256'] == '01ec1a644f37b9fc7a4c6616f589768df97f8eed7a289b5de86afadaa7ce6165']
        assert len(plan_rows) == 1
        plan_logical, plan = plan_rows[0]
        unused = OUT / 'unused-original-preparer-bytecode'
        assert not unused.exists()
        prepared_path = OUT / 'prepared-source-v1.json'
        argv = [str(private_python), '-S', '-B', '-X', 'pycache_prefix=' + str(unused), str(preparer),
                '--repo', str(ROOT), '--materials', str(base), '--parent', str(parent_path),
                '--parent-sha256', sha(parent_path), '--python', str(private_python), '--python-sha256', PYTHON_SHA,
                '--runtime-snapshot', str(snapshot_path), '--runtime-snapshot-sha256', snapshot_sha,
                '--requests', str(requests_path), '--requests-sha256', sha(requests_path),
                '--operation', operation, '--output', str(output), '--manifest', str(prepared_path),
                '--material-profile', original['material_profile'], '--material-plan', plan['path'],
                '--material-plan-sha256', plan['sha256'], '--seconds', str(original['seconds']),
                '--max-snapshot-bytes', str(original['max_snapshot_bytes']),
                '--runtime-rss-bytes', str(original['runtime_rss_bytes']), '--threads', str(original['threads']),
                '--environment-generation', '2']
        report['preparer_argv'] = argv
        report['preparer_environment'] = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': str(BASE / 'tmp')}
        with (OUT / 'original-preparer.stdout').open('xb') as stdout, (OUT / 'original-preparer.stderr').open('xb') as stderr:
            child = subprocess.run(argv, cwd=ROOT, env=report['preparer_environment'], stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, timeout=180)
        report['preparer_exit_code'] = child.returncode
        assert child.returncode == 0 and not unused.exists()
        original_receipt = json.loads((OUT / 'original-preparer.stdout').read_bytes())
        assert original_receipt['manifest'] == str(prepared_path)
        assert original_receipt['sha256'] == sha(prepared_path)
        assert original_receipt['manifest_count'] == 30
        assert original_receipt['native_executed'] is False and original_receipt['model_executed'] is False
        assert all(value is False for value in original_receipt['authority'].values())
        prepared = json.loads(prepared_path.read_bytes())
        assert prepared['schema'] == 'trnm.cell-sealed-research-source.v1'
        final = copy.deepcopy(prepared)
        final['schema'] = original['schema']
        final['snapshot'] = copy.deepcopy(original['snapshot'])
        final['network'] = copy.deepcopy(original['network'])
        expected = copy.deepcopy(original)
        expected.update(operation=operation, output=str(output), environment_generation=2,
                        python={'path': str(private_python), 'sha256': PYTHON_SHA})
        for logical, item in expected['environment'].items():
            if logical == SNAPSHOT_LOGICAL:
                item.update(path=str(snapshot_path), sha256=snapshot_sha)
            elif logical != plan_logical:
                item['path'] = str(ROOT / logical)
        assert final == expected, 'original preparer output exceeded the declared identity/path changes'
        source_path = OUT / 'source-inputs.native-v2-env2.json'
        source_raw = encoded(final); source_sha = hashlib.sha256(source_raw).hexdigest()
        write(source_path, source_raw)
        audit = copy.deepcopy(original_audit)
        audit.update(operation=operation, source_sha256=source_sha, previous_source_sha256=SOURCE_SHA,
                     same_independent_bytes=False, model_material_pins_unchanged=True,
                     remaining_environment_member_hashes_unchanged=True, python_original_sha256_preserved=True,
                     migration_kind='new-environment-generation-private-runtime-projection',
                     old_snapshot_sha256=original['environment'][SNAPSHOT_LOGICAL]['sha256'],
                     projected_snapshot_sha256=snapshot_sha, environment_generation=2,
                     model_generation=original['parent']['generation'])
        assert len(audit['inputs']) == 31
        changed = []
        for row in audit['inputs']:
            category, logical = row['category'], row['logical']
            item = final['python'] if category == 'python' else final[category][logical]
            prior = original['python'] if category == 'python' else original[category][logical]
            row['previous_path'] = row['selected_path']
            assert row['previous_path'] == prior['path'] and row['sha256'] == prior['sha256']
            row['selected_path'] = item['path']
            if item['sha256'] != prior['sha256']:
                assert (category, logical) == ('environment', SNAPSHOT_LOGICAL)
                changed.append([category, logical])
                row['previous_sha256'] = row['sha256']; row['previous_size'] = row['size']
                row['sha256'] = snapshot_sha; row['size'] = len(snapshot_raw)
            assert measure(row['selected_path'], row['sha256']) == row['size']
        assert changed == [['environment', SNAPSHOT_LOGICAL]]
        new_audit_path = OUT / 'source-inputs.native-v2-env2.verification.json'
        audit_raw = encoded(audit); write(new_audit_path, audit_raw)
        module = ast.parse(wrapper_raw)
        nodes = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name in ('sha', 'check', 'inputs')]
        assert len(nodes) == 3
        scope = {'hashlib': hashlib, 'Path': Path, 'stat': stat}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(CONTROL / 'run_model.py'), 'exec'), scope)
        actual_inputs = scope['inputs'](final, audit)
        payload = [row for row in actual_inputs if row['category'] != 'python']
        total = sum(row['size'] for row in payload)
        chunks = sum((row['size'] + 4194303) // 4194304 for row in payload)
        assert len(payload) == 30 and total == 272530091 + len(snapshot_raw)
        assert total <= original['max_snapshot_bytes'] and chunks <= 128
        assert total == original_receipt['payload_bytes']
        write(OUT / 'actual-input-readback.json', encoded(actual_inputs))
        report.update(operation=operation, operation_domain=DOMAIN.decode('ascii'),
                      operation_preimage_hex=preimage.hex(), known_prior_operations=sorted(previous_operations),
                      output=str(output), source_input={'path': str(source_path), 'bytes': len(source_raw), 'sha256': source_sha},
                      input_audit={'path': str(new_audit_path), 'bytes': len(audit_raw), 'sha256': hashlib.sha256(audit_raw).hexdigest()},
                      snapshot={'path': str(snapshot_path), 'bytes': len(snapshot_raw), 'sha256': snapshot_sha},
                      python=final['python'], payload_files=30, independent_inputs=31, payload_bytes=total,
                      actual_chunks=chunks, historical_95_chunk_roster_preserved=(chunks == 95),
                      model_generation=final['parent']['generation'], source_model_parent_preserved=True,
                      independent_31_inputs_verified=True, original_wrapper_input_function_verified=True,
                      derived_parent_envelope={'path': str(parent_path), 'sha256': sha(parent_path), 'historical_original_file_claim': False},
                      derived_requests={'path': str(requests_path), 'sha256': sha(requests_path), 'original_values_unchanged': True},
                      original_preparer_receipt=original_receipt, passed=True)
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['traceback'] = traceback.format_exc(); report['passed'] = False
    finally:
        try:
            report['after_identity'] = identity(); assert report['after_identity'] == before
            assert sha(original_path) == SOURCE_SHA and sha(audit_path) == AUDIT_SHA
            assert sha(preparer) == PREPARER_SHA and sha(CONTROL / 'run_model.py') == WRAPPER_SHA
            assert sha(snapshot_path) == snapshot_sha and sha(private_python) == PYTHON_SHA
            assert not Path(original['output']).exists() and not Path(original['output'] + '-wrapper').exists()
            if 'output' in report:
                assert not Path(report['output']).exists() and not Path(report['output'] + '-wrapper').exists()
            report['source_and_pins_unchanged'] = True
        except BaseException as error:
            report['end_error'] = type(error).__name__ + ': ' + str(error); report['passed'] = False
        report['completed'] = True; report['elapsed_seconds'] = time.monotonic() - started
        write(OUT / 'preparation-success.json', encoded(report))
        print(json.dumps({'completed': True, 'passed': report['passed'], 'output': str(OUT),
                          'source_input': report.get('source_input'), 'operation': report.get('operation'),
                          'payload_bytes': report.get('payload_bytes'), 'actual_chunks': report.get('actual_chunks'),
                          'native_operation_started': False}, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
