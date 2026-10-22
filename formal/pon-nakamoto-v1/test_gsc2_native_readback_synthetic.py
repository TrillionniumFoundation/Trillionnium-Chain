#!/usr/bin/env python3
"""Synthetic reader negative controls, never native execution or consensus proof.

The fixture has no signed transactions and a dummy PNW1 byte string. It is only
a small SQLite/current-root/framing input for the independent reader.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile

import check_gsc2_native_readback as reader
import gsc2_independent_vectors
from gsc2_independent_vectors import archive, encode, h, state_root


def fixture(directory, source):
    (directory / 'store').mkdir()
    context = {'network': '01' * 32, 'parameters': '02' * 32, 'genesis': '03' * 32}
    owners = [bytes(32), bytes([255]) * 32]
    accounts = [(owners[0], 0, 7), (owners[1], 17, 9)]
    working = {'meta:issued': 17}
    commitment = dict(network=context['network'], parameters=context['parameters'],
                      account_root=archive(accounts).hex(), account_count=2, account_balance=17,
                      maximum_permanent_accounts=1000000, working_root=state_root(working).hex(),
                      working_count=1, maximum_working_keys=65536, escrow_balance=0,
                      reward_balance=0, issued=17)
    encoded = encode(commitment)
    root = h('native-permanent-account-state-v2', encoded)
    header = bytearray(318)
    header[:6] = b'PNH1\x01\x00'
    header[6:38] = bytes.fromhex(context['network'])
    header[38:70] = bytes.fromhex(context['parameters'])
    header[70:102] = bytes.fromhex(context['genesis'])
    header[102:110] = (1).to_bytes(8, 'little')
    header[182:214] = reader.sequence_root('transactions', [])
    header[214:246] = root
    packet = bytes(header) + b'\x00\x00PNW1' + bytes(49184)
    tip = h('block', bytes(header), packet[-32:])
    schema = reader.schema_from_source(source)
    state = dict(working)
    state.update({'account:' + owner.hex(): {'balance': balance, 'nonce': nonce}
                  for owner, balance, nonce in accounts})
    with sqlite3.connect(directory / 'store/native.sqlite') as db:
        db.executescript(reader.ddl_from_source(source))
        db.executemany('INSERT INTO metadata(key,value) VALUES (?,?)',
                       [('schema', schema), ('parameters', bytes.fromhex(context['parameters'])),
                        ('genesis', bytes.fromhex(context['genesis']))])
        db.execute('INSERT INTO blocks VALUES (?,?,?,?,?,?)',
                   (tip, bytes.fromhex(context['genesis']), 1, bytes(63) + b'\x01', packet, root))
        db.execute('INSERT INTO active VALUES (1,?,?,?)', (tip, 1, 1))
        db.executemany('INSERT INTO kv VALUES (?,?,?)',
                       [(1, key, reader.canonical(value)) for key, value in state.items()])
    serde = {key: list(bytes.fromhex(value)) if key in reader.COMMIT_HASH_FIELDS else value
             for key, value in commitment.items()}
    observation = dict(schema='pon-native-growth-reference-observation-v2', **context,
                       tip=tip.hex(), generation=1, height=1, state_root=root.hex(),
                       permanent_accounts=2, working_keys=1, maximum_permanent_accounts=1000000,
                       maximum_working_keys=65536, complete_state_required=True,
                       bounded_witness_qualified=False, production_activation=False,
                       required_permanent_accounts=2, required_working_keys=1)
    snapshot = dict(tip=tip.hex(), generation=1, state_root=root.hex())
    receipt = dict(schema=reader.SCHEMA, database='store/native.sqlite',
                   state_backend='growth-complete-state-reference-v2', bounded_witness_qualified=False,
                   production_activation=False, git_head_at_execution='0' * 40,
                   git_tree_at_execution='0' * 40, git_reported_clean_at_execution=False,
                   context=context, storage_schema=schema.hex(), commitment=serde,
                   encoded_commitment=encoded.hex(), before_reopen=snapshot.copy(), after_reopen=snapshot.copy(),
                   observation=observation, initial_accounts=2, created_by_signed_transfers=0,
                   sender_nonces=[0, 0, 0, 0], blocks=1, active_permanent_accounts=2)
    write_receipt(directory, receipt)


def write_receipt(directory, receipt):
    (directory / 'native.json').write_text(json.dumps(receipt, sort_keys=True))


def receipt_mutation(directory, mutation):
    receipt = json.loads((directory / 'native.json').read_text())
    mutation(receipt)
    write_receipt(directory, receipt)


def sql_mutation(directory, sql, args=()):
    with sqlite3.connect(directory / 'store/native.sqlite') as db:
        db.execute(sql, args)


def kv(directory, owner, raw):
    sql_mutation(directory, 'UPDATE kv SET value=? WHERE key=?', (raw, 'account:' + owner * 32))


def restoring_wal(database, source):
    connection = sqlite3.connect(database)
    assert connection.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
    connection.execute('PRAGMA wal_autocheckpoint=0')
    # The main DB alone has an invalid schema context. Only the committed
    # WAL restores it, so an immutable reader that ignores WAL cannot pass.
    connection.execute("UPDATE metadata SET value=? WHERE key='schema'", (bytes(32),))
    connection.commit()
    assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
    connection.execute("UPDATE metadata SET value=? WHERE key='schema'", (reader.schema_from_source(source),))
    connection.commit()
    return connection


def wal_controls(base, source):
    results = []
    for initially_empty in (False, True):
        directory = base / ('empty-wal' if initially_empty else 'absent-wal')
        directory.mkdir()
        fixture(directory, source)
        database = directory / 'store/native.sqlite'
        connection = sqlite3.connect(database)
        assert connection.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
        connection.close()
        wal = Path(str(database) + '-wal')
        assert not wal.exists()
        if initially_empty:
            wal.write_bytes(b'')
        before = reader.file_identities(database)
        result = reader.readback(directory, source, 2)
        assert result['result'] == 'PASS' and set(result['database_files']) == {database.name}
        assert reader.file_identities(database) == before
        assert wal.exists() and wal.stat().st_size == 0
        results.append({'case': directory.name, 'result': 'PASS'})

    directory = base / 'committed-wal'
    directory.mkdir()
    fixture(directory, source)
    database = directory / 'store/native.sqlite'
    wal = Path(str(database) + '-wal')
    connection = restoring_wal(database, source)
    try:
        assert wal.stat().st_size > 0
        before = reader.file_identities(database)
        result = reader.readback(directory, source, 2)
        assert result['result'] == 'PASS' and wal.name in result['database_files']
        assert reader.file_identities(database) == before
        assert result['database_files'][wal.name]['sha256'] == reader.sha(wal)
        results.append({'case': directory.name, 'result': 'PASS'})
        connection.execute('UPDATE kv SET value=? WHERE key=?',
                           (b'{"balance":0,"nonce":8}', 'account:' + '00' * 32))
        connection.commit()
        try:
            reader.readback(directory, source, 2)
        except ValueError as error:
            assert str(error) == 'actual commitment hash field mismatch: account_root'
        else:
            raise AssertionError('reader ignored the committed WAL nonce mutation')
        results.append({'case': 'wal-only-nonce-mutation-rejected', 'result': 'PASS'})
    finally:
        connection.close()

    # Every positive length is data to pin, including malformed/header-only WAL.
    baseline = reader.file_identities(database)
    for payload in (b'x', b'W' * 32, b'W' * 64):
        wal.write_bytes(payload)
        changed = reader.file_identities(database)
        assert changed != baseline and changed[wal.name]['bytes'] == len(payload)
        wal.write_bytes(b'')
        assert reader.file_identities(database) == baseline
        wal.unlink()
        assert reader.file_identities(database) == baseline
    results.append({'case': 'nonempty-wal-pinned-at-every-length', 'result': 'PASS'})
    empty_target = directory / 'empty-target'
    empty_target.write_bytes(b'')
    for target in (empty_target, directory / 'missing-target'):
        wal.symlink_to(target.resolve())
        try:
            reader.file_identities(database)
        except ValueError as error:
            assert str(error) == 'regular database/WAL files required'
        else:
            raise AssertionError('reader accepted an empty or dangling WAL symlink')
        wal.unlink()
    results.append({'case': 'empty-and-dangling-wal-symlinks-rejected', 'result': 'PASS'})
    for name in ('database', 'receipt', 'wal-appears', 'wal-byte', 'wal-unlink'):
        directory = base / ('changed-' + name)
        directory.mkdir()
        fixture(directory, source)
        target = {'database': directory / 'store/native.sqlite',
                  'receipt': directory / 'native.json',
                  'wal-appears': directory / 'store/native.sqlite-wal',
                  'wal-byte': directory / 'store/native.sqlite-wal',
                  'wal-unlink': directory / 'store/native.sqlite-wal'}[name]
        writer = restoring_wal(directory / 'store/native.sqlite', source) if name in ('wal-byte', 'wal-unlink') else None
        original = reader.sparse_root
        mutated = False

        def mutate_at_math(*args):
            nonlocal mutated
            if not mutated:
                if name == 'wal-unlink':
                    target.unlink()
                elif name == 'wal-byte':
                    with target.open('r+b') as stream:
                        stream.seek(-1, 2)
                        byte = stream.read(1)
                        stream.seek(-1, 2)
                        stream.write(bytes([byte[0] ^ 1]))
                else:
                    with target.open('ab') as stream:
                        stream.write(b' ')
                mutated = True
            return original(*args)

        reader.sparse_root = mutate_at_math
        try:
            try:
                reader.readback(directory, source, 2)
            except (ValueError, sqlite3.Error):
                assert mutated
            else:
                raise AssertionError('reader accepted changed ' + name)
        finally:
            reader.sparse_root = original
            if writer is not None:
                writer.close()
        results.append({'case': 'during-readback-' + name + '-rejected', 'result': 'PASS'})
    return results


def run(source):
    fixed = reader.load((source / 'tests/vectors/pon/native-growth-reference-v2.json').read_bytes())
    assert fixed == gsc2_independent_vectors.result, 'fixed GSC2 vectors differ from independent derivation'
    changes = [
        ('actual_account_nonce', lambda p: kv(p, '00', b'{"balance":0,"nonce":8}')),
        ('actual_account_amount', lambda p: kv(p, 'ff', b'{"balance":18,"nonce":9}')),
        ('actual_state_noncanonical', lambda p: kv(p, '00', b'{"balance": 0,"nonce":7}')),
        ('actual_state_duplicate_json_key', lambda p: kv(p, '00', b'{"balance":0,"nonce":7,"nonce":7}')),
        ('actual_state_bool_nonce', lambda p: kv(p, '00', b'{"balance":0,"nonce":true}')),
        ('actual_state_integer_overflow', lambda p: kv(p, '00', b'{"balance":0,"nonce":18446744073709551616}')),
        ('actual_state_sql_text_type', lambda p: sql_mutation(p, "UPDATE kv SET value='17' WHERE key='meta:issued'")),
        ('actual_block_root', lambda p: sql_mutation(p, 'UPDATE blocks SET state_root=?', (bytes(32),))),
        ('actual_parameters_context', lambda p: sql_mutation(p, "UPDATE metadata SET value=? WHERE key='parameters'", (bytes(32),))),
        ('actual_schema_extra_trigger', lambda p: sql_mutation(p, 'CREATE TRIGGER injected AFTER INSERT ON kv BEGIN SELECT 1; END')),
        ('actual_schema_missing_index', lambda p: sql_mutation(p, 'DROP INDEX work_order')),
        ('actual_schema_same_count_different_index', lambda p: replace_index(p)),
        ('receipt_network_context', lambda p: receipt_mutation(p, lambda r: r['context'].__setitem__('network', 'ff' * 32))),
        ('receipt_encoded_commitment', lambda p: receipt_mutation(p, lambda r: r.__setitem__('encoded_commitment', '00' * 196))),
        ('receipt_bool_count', lambda p: receipt_mutation(p, lambda r: r['commitment'].__setitem__('account_count', True))),
        ('receipt_hash_bool_element', lambda p: receipt_mutation(p, lambda r: r['commitment']['network'].__setitem__(0, True))),
        ('receipt_observation_flag', lambda p: receipt_mutation(p, lambda r: r['observation'].__setitem__('bounded_witness_qualified', True))),
        ('receipt_production_flag', lambda p: receipt_mutation(p, lambda r: r.__setitem__('production_activation', True))),
        ('receipt_cold_reopen_tip', lambda p: receipt_mutation(p, lambda r: r['after_reopen'].__setitem__('tip', 'ff' * 32))),
        ('receipt_observation_count', lambda p: receipt_mutation(p, lambda r: r['observation'].__setitem__('permanent_accounts', 3))),
        ('receipt_duplicate_json_key', lambda p: (p / 'native.json').write_text(
            (p / 'native.json').read_text()[:-1] + ',"schema":"' + reader.SCHEMA + '"}')),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='gsc2-reader-synthetic-') as temporary:
        base = Path(temporary)
        baseline = base / 'baseline'
        baseline.mkdir()
        fixture(baseline, source)
        result = reader.readback(baseline, source, 2)
        assert result['result'] == 'PASS'
        assert result['scope']['reader_executes_native_code'] is False
        assert result['scope']['actual_sqlite_schema_matches_source_ddl'] is True
        wal_results = wal_controls(base, source)
        for index, (name, mutate) in enumerate(changes):
            directory = base / str(index)
            directory.mkdir()
            fixture(directory, source)
            mutate(directory)
            try:
                reader.readback(directory, source, 2)
            except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError, sqlite3.Error) as error:
                results.append({'case': name, 'result': 'REJECT', 'reason': str(error)})
            else:
                raise AssertionError('reader accepted synthetic mutation: ' + name)
    return {'schema': 'independent-gsc2-reader-synthetic-negative-controls-v1', 'result': 'PASS',
            'baseline_inputs': 1, 'rejected_mutations': len(results), 'cases': results,
            'wal_controls': wal_results,
            'scope': 'Synthetic SQLite/current-root/framing input only; no signed transactions, dummy PNW1, '
                     'no native execution, consensus validity, actual growth or durability qualification'}


def replace_index(directory):
    with sqlite3.connect(directory / 'store/native.sqlite') as db:
        db.execute('DROP INDEX work_order')
        db.execute('CREATE INDEX work_order ON blocks(height,id)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    print(json.dumps(run(parser.parse_args().source_root), indent=2, sort_keys=True))
