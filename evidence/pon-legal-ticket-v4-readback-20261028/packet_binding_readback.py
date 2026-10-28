#!/usr/bin/env python3
"""Bind existing positive packet bytes to their original observed identities.

This is a pure archive reader. It does not run W1, perform Node admission,
construct invalid work, search tickets, or repeat the hosted experiment.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'source/scripts/ci'))
from check_legal_ticket_cost_v3 import read_rows


def tagged(tag, *parts):
    digest = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in parts:
        digest.update(len(part).to_bytes(4, 'little'))
        digest.update(part)
    return digest.digest()


def main():
    arch, url, expected_size, expected_sha, artifact = sys.argv[1:]
    root = ROOT / arch
    expected_size = int(expected_size)
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(expected_size+1)
    assert len(raw) == expected_size and hashlib.sha256(raw).hexdigest() == expected_sha
    z = zipfile.ZipFile(io.BytesIO(raw))
    rows, _, _ = read_rows(root/'cost/stdout.jsonl.gz')
    archive = json.loads((root/'archive-member-readback.json').read_text())
    expected_members = {x['name']:x for x in archive['member_records']}
    assert set(z.namelist()) == set(expected_members) and len(z.namelist()) == len(expected_members)
    checked = []
    identities = {}
    for cohort in rows[1:-1]:
        seed = bytes.fromhex(cohort['native_template_header'])
        target = bytes.fromhex(cohort['target'])
        won = {t['packet_id']:t for s in cohort['searches'] for t in s['trials'] if t['target_hit']}
        for packet in cohort['retained_packets']:
            trial = won[packet['id']]
            name = 'packets/'+packet['file']
            data = z.read(name)
            assert len(data) == 49508 == packet['bytes'] == expected_members[name]['bytes']
            assert hashlib.sha256(data).hexdigest() == packet['sha256'] == expected_members[name]['sha256']
            header, count, proof = data[:318], data[318:320], data[320:]
            assert header[:6] == b'PNH1\x01\x00' and count == b'\0\0'
            assert len(proof) == 49188 and proof[:4] == b'PNW1'
            assert header[:310] == seed[:310] and int.from_bytes(header[310:318], 'little') == trial['nonce']
            assert header[70:102].hex() == cohort['parent'] and header[118:150] == target
            assert header[278:310].hex() == cohort['task']
            challenge = tagged(b'challenge', header)
            ticket = tagged(b'ticket', challenge, proof[-32:])
            packet_id = tagged(b'block', header, proof[-32:]).hex()
            assert challenge.hex() == trial['challenge'] and hashlib.sha256(proof).hexdigest() == trial['proof_sha256']
            assert ticket.hex() == trial['ticket'] and ticket <= target and packet_id == packet['id']
            current = dict(packet_sha256=packet['sha256'], proof_sha256=trial['proof_sha256'], challenge=trial['challenge'], ticket=trial['ticket'])
            assert packet_id not in identities or identities[packet_id] == current
            identities[packet_id] = current
            checked.append(dict(file=name, packet_id=packet_id, **current))
    assert len(checked) == 762 and len(identities) == 127
    pieces = []
    for index, offset in enumerate(range(0, len(raw), 4*1024*1024)):
        part = raw[offset:offset+4*1024*1024]
        pieces.append(dict(index=index, offset=offset, bytes=len(part), sha256=hashlib.sha256(part).hexdigest(),
                           git_blob_sha1=hashlib.sha1(('blob '+str(len(part))+'\0').encode()+part).hexdigest()))
    result = dict(schema='legal-ticket-v4-positive-packet-byte-binding-v1', architecture=arch,
        artifact_id=int(artifact), archive_bytes=len(raw), archive_sha256=expected_sha,
        positive_packet_files_checked=762, unique_packet_ids=127, packet_length=49508,
        header_bytes=318, transaction_count=0, original_w1_proof_bytes=49188,
        all_original_packet_header_challenge_proof_hash_ticket_and_id_bindings_pass=True,
        copied_field_and_hash_identity_checks_only=True,
        native_admission_or_work_relation_reexecuted=False,
        failed_attempt_proof_bytes_available=False,
        archive_saved_locally=False, archive_4mib_parts_for_future_durable_publication=pieces,
        original_packet_fields=checked,
        scope='Read original admitted positive bytes, derive original public hash identities and compare to raw successful run. Full matrix/work and native-state acceptance remain the original hosted Node execution, not this byte reader.')
    (root/'positive-packet-binding.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('architecture','positive_packet_files_checked','unique_packet_ids','all_original_packet_header_challenge_proof_hash_ticket_and_id_bindings_pass','native_admission_or_work_relation_reexecuted')}))


if __name__ == '__main__':
    main()
