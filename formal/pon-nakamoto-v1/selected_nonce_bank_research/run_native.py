#!/usr/bin/env python3
"""Fresh full frozen selected-local native verification, never W1/Node admission."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import argparse
import json
import subprocess

BASE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path,
                        default=BASE/'native_selected/target/release/selected-event-native-research')
    parser.add_argument('--expected-binary-sha256', required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    digest = sha256(binary.read_bytes()).hexdigest()
    if digest != args.expected_binary_sha256:
        raise ValueError('NATIVE_BINARY_PIN')
    manifest = json.loads((BASE/'SOURCE_PINS.json').read_text())
    source_hashes = {}
    for name, record in manifest['files'].items():
        if name.startswith('native_selected/'):
            got = sha256((BASE/name).read_bytes()).hexdigest()
            if got != record['sha256']:
                raise ValueError('NATIVE_SOURCE_PIN:'+name)
            source_hashes[name] = got
    expected = BASE/'upstream/reference/real_lottery_hit_p_1_64.expected.bin'
    out = BASE/'results/native_acceptance'
    out.mkdir(exist_ok=False)
    cases = []
    audit = json.loads((BASE/'results/full_range_audit/result.json').read_text())
    rows = json.loads((BASE/'results/native_expected_rows.json').read_text())
    by_nonce = {row['nonce']:row for row in rows}
    for nonce in audit['accepted_nonces']:
        cases.append((f'audit-{nonce}', BASE/f'results/full_range_audit/accepted_witnesses/nonce-{nonce}.bin',
                      'ACCEPT_SELECTED_EVENT_ONLY', None, by_nonce[nonce]))
    campaign = json.loads((BASE/'results/campaign_result.json').read_text())
    for strategy in campaign['strategies']:
        nonce = strategy['winner_nonce']
        if nonce is not None:
            cases.append((strategy['name'], BASE/f"results/{strategy['name']}/witnesses/nonce-{nonce}.bin",
                          'ACCEPT_SELECTED_EVENT_ONLY', None, by_nonce[nonce]))
    first = (BASE/f"results/full_range_audit/accepted_witnesses/nonce-{audit['accepted_nonces'][0]}.bin").read_bytes()
    coordinate = bytearray(first)
    coordinate[8] ^= 1
    coordinate_path = out/'wrong_selected_coordinate.bin'
    coordinate_path.write_bytes(coordinate)
    cases.append(('wrong_selected_coordinate', coordinate_path, 'REJECT', 'SELECTED_COORD', None))
    block = bytearray(first)
    value = int.from_bytes(block[11:15], 'little')
    block[11:15] = ((value+1) % 4294967291).to_bytes(4, 'little')
    block_path = out/'wrong_original_input.bin'
    block_path.write_bytes(block)
    cases.append(('wrong_original_input', block_path, 'REJECT', 'MERKLE', None))
    results = []
    for name, witness, status, error, row in cases:
        invocation = [str(binary), 'verify', str(expected), str(witness)]
        ran = subprocess.run(invocation, capture_output=True, text=True, check=False, timeout=30)
        (out/(name+'.stdout.json')).write_text(ran.stdout)
        (out/(name+'.stderr.log')).write_text(ran.stderr)
        if ran.returncode != 0:
            raise ValueError('NATIVE_EXIT:'+name+':'+str(ran.returncode))
        observation = json.loads(ran.stdout)
        verdict = observation['result']
        if verdict['status'] != status or (error is not None and verdict['error'] != error):
            raise ValueError('NATIVE_VERDICT:'+name)
        if row is not None:
            assert verdict['event_id'] == row['event']
            assert verdict['ticket'] == row['ticket']
            assert sha256(witness.read_bytes()).hexdigest() == row['witness_sha256']
            # Acceptance must have reached both noisy and useful arithmetic.
            assert observation['counts']['scalar_multiplications'] == 2048
        results.append({'name':name, 'witness_file':str(witness.relative_to(BASE)),
                        'witness_sha256':sha256(witness.read_bytes()).hexdigest(),
                        'exit_code':ran.returncode,'status':verdict['status'],
                        'error':verdict.get('error'), 'counts':observation['counts'],
                        'stdout_sha256':sha256(ran.stdout.encode()).hexdigest()})
    if sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError('BINARY_CHANGED_DURING_RUN')
    environment = {}
    for name, command in [('rustc',['rustc','-Vv']),('cargo',['cargo','--version']),
                           ('observed_git_head',['git','rev-parse','HEAD'])]:
        ran = subprocess.run(command,cwd=BASE,capture_output=True,text=True,check=False)
        environment[name] = {'exit_code':ran.returncode, 'stdout':ran.stdout,'stderr':ran.stderr}
    record = {'schema':'selected-nonce-bank-native-acceptance-r4-v1',
              'generated_utc':datetime.now(timezone.utc).isoformat(),
              'binary_path':str(binary),'binary_sha256':digest,'native_source_sha256':source_hashes,
              'expected_sha256':sha256(expected.read_bytes()).hexdigest(),
              'observed_environment':environment,
              'observed_git_head_is_not_a_claim_that_new_directory_was_committed':True,
              'accepted_invocations':sum(r['status']=='ACCEPT_SELECTED_EVENT_ONLY' for r in results),
              'negative_controls':sum(r['status']=='REJECT' for r in results),
              'unique_accepted_witnesses':len({r['witness_sha256'] for r in results if r['status']=='ACCEPT_SELECTED_EVENT_ONLY'}),
              'results':results,
              'qualification':'COMPLETE_SELECTED_LOCAL_NATIVE_RELATION_ONLY_NOT_W1_NOT_STARK_NOT_NODE'}
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ('accepted_invocations','negative_controls','unique_accepted_witnesses','binary_sha256')}))


if __name__ == '__main__':
    main()
