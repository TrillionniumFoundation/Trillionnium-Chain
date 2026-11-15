#!/usr/bin/env python3
"""Source-bound constructive oracle observations; bounded JSON, no flat gate dump.

Reproduction keeps native-sized macro interpretation distinct from reduced-shape
leaf-gate execution. Optional historical native packets remain external evidence,
never a claim that this campaign ran a native node or quantum hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))
sys.path.insert(0, str(ROOT / "scripts"))
import work_oracle
from w1_quantum_oracle import FixedTemplate, OracleProgram, Shape, SOURCE_FILES, canonical, h_bytes

SCHEMA = "trnm-w1-constructive-oracle-campaign-v1"
FILES = SOURCE_FILES + (
    "formal/pon-nakamoto-v1/test_w1_quantum_oracle.py",
    "formal/pon-nakamoto-v1/experiments/w1_quantum_oracle_campaign.py",
    "formal/pon-nakamoto-v1/quantum_oracle_resources.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/reference.py",
    "formal/pon-nakamoto-v1/vectors/header.bin",
    "formal/pon-nakamoto-v1/vectors/work.bin",
    "scripts/pon_daa_schedule_reader.py",
)
ASSERTIONS = {
    "constructive_upper_bound_for_declared_fixed_context_only": True,
    "native_sized_run_is_macro_semantics_not_leaf_gate_execution": True,
    "reduced_gate_controls_are_not_native_parameter_runs": True,
    "quantum_hardware_executed": False,
    "native_node_executed_by_campaign": False,
    "quantum_cost_lower_bound_or_optimality_proved": False,
    "physical_hardware_calibrated": False,
    "mining_security_qualified": False,
    "production_activation": False,
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_load(raw):
    if type(raw) is not bytes or len(raw) > 2_000_000:
        raise ValueError("JSON_BOUND")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("NONFINITE_JSON:" + value)
    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            reject(value)
        return result
    def bounded(value):
        result = int(value)
        if not -(1 << 256) < result < (1 << 256):
            raise ValueError("JSON_INTEGER_BOUND")
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject,
                      parse_float=finite, parse_int=bounded)


def read(path, limit=2_000_000):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("INPUT_FILE_BOUND")
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("INPUT_FILE_CHANGED_BOUND")
    return data


def write_atomic(path, data):
    if type(data) is not bytes or len(data) > 2_000_000 or path.exists():
        raise ValueError("OUTPUT_BOUND_OR_ALREADY_EXISTS")
    temporary = path.with_suffix(path.suffix + '.partial')
    with temporary.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def committed_inventory(head, hashes):
    if type(head) is not str or not re.fullmatch('[0-9a-f]{40}', head):
        raise ValueError("SOURCE_HEAD")
    kind = subprocess.run(['git', 'cat-file', '-t', head], cwd=ROOT, capture_output=True, text=True)
    if kind.returncode or kind.stdout.strip() != 'commit':
        raise ValueError("SOURCE_HEAD")
    uncommitted = []
    for name in FILES:
        value = subprocess.run(['git', 'show', head + ':' + name], cwd=ROOT, capture_output=True)
        if value.returncode or digest(value.stdout) != hashes[name]:
            uncommitted.append(name)
    return uncommitted


def source_record():
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    hashes = {name: digest((ROOT / name).read_bytes()) for name in FILES}
    uncommitted = committed_inventory(head, hashes)
    return {"git_head": head, "source_sha256": hashes, "uncommitted_source_files": uncommitted,
            "all_sources_committed_at_head": not uncommitted}


def validate_source(record):
    if type(record) is not dict or set(record) != {'git_head', 'source_sha256', 'uncommitted_source_files', 'all_sources_committed_at_head'}:
        raise ValueError("SOURCE_SCHEMA")
    hashes = {name: digest((ROOT / name).read_bytes()) for name in FILES}
    if record['source_sha256'] != hashes:
        raise ValueError("SOURCE_HASH")
    expected = committed_inventory(record['git_head'], hashes)
    if record['uncommitted_source_files'] != expected or record['all_sources_committed_at_head'] is not (not expected):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")


def retained_template(profile="PNH1"):
    header, proof = read(FORMAL / 'vectors/header.bin'), read(FORMAL / 'vectors/work.bin')
    values = struct.unpack('<' + 'I' * 8192, proof[4:4 + 32768])
    if profile == 'PGH2':
        header = b'PGH2' + header + bytes([71]) * 32
    elif profile != 'PNH1':
        raise ValueError("PROFILE")
    return FixedTemplate.from_header(header, values[:4096], values[4096:])


def reduced_template():
    a, b = (2,), (3,)
    task = digest(h_bytes(b'task', struct.pack('<I', 2), struct.pack('<I', 3)))
    header = (b'PNH1\x01\0' + b''.join(bytes([i]) * 32 for i in (1, 2, 3))
              + struct.pack('<QQ', 7, 11) + bytes([255]) * 32
              + b''.join(bytes([i]) * 32 for i in range(5, 9)) + bytes.fromhex(task) + bytes(8))
    return FixedTemplate.from_header(header, a, b, 16, Shape(1, 1, 4, 1))


def exhaustion_nonce(template):
    # Independently search a reduced-width fixture for an actual bounded SHA
    # stream with no accepted word, rather than replacing noise with fake data.
    for nonce in range(65536):
        challenge = hashlib.sha256(h_bytes(template.challenge_tag, template.header_for(nonce))).digest()
        for label in range(4):
            noise = hashlib.sha256(h_bytes(b'noise', challenge, bytes([label]), bytes(4))).digest()
            if all((word[0] & 15) >= 11 for word in struct.iter_unpack('<I', noise)):
                return nonce
    raise ValueError("REDUCED_EXHAUSTION_FIXTURE_NOT_FOUND")


def historical_native_control(receipt_path, raw_dir):
    """Use existing reader grammar on ONE admitted retained native packet.

    Does not rerun its original 85-observation native campaign or reassert its
    historical process/source provenance. Original receipt and bytes are pinned.
    """
    import pon_daa_schedule_reader as reader
    receipt_raw = read(receipt_path)
    receipt = strict_load(receipt_raw)
    raw_report = reader.read_bounded(raw_dir / 'daa-bounds.json', 2 * 1024 * 1024)
    wanted = receipt['independent_reader']['report_sha256']
    if digest(raw_report) != wanted:
        raise ValueError("HISTORICAL_REPORT_DIGEST")
    report = reader.load_report(raw_report)
    if report['schema'] != 'pon-native-daa-bounds-v1':
        raise ValueError("HISTORICAL_SCHEMA")
    rows = [(i, row) for i, row in enumerate(report['records'])
            if row.get('complete_native_work_verification') is True and row.get('admission', {}).get('kind') == 'admitted']
    if not rows:
        raise ValueError("NO_HISTORICAL_ADMITTED_FIXTURE")
    index, row = rows[0]
    identifier = reader.hexadecimal(row['id'], 32)
    filename = 'packets/' + identifier.hex() + '.pnk'
    if row['packet_file'] != filename or (raw_dir / 'packets').is_symlink():
        raise ValueError("HISTORICAL_PACKET_PATH")
    packet = reader.read_bounded(raw_dir / filename, reader.PACKET_BYTES)
    if len(packet) != reader.PACKET_BYTES or packet[318:320] != bytes(2) or digest(packet) != row['packet_sha256']:
        raise ValueError("HISTORICAL_PACKET_BYTES")
    header, proof = packet[:318], packet[320:]
    if header.hex() != row['header_hex'] or digest(proof) != row['proof_sha256'] or proof[-32:].hex() != row['trace']:
        raise ValueError("HISTORICAL_STATEMENT_BYTES")
    decoded = reader.wire.header_decode(header)
    if decoded['nonce'] != row['nonce'] or reader.wire.header_encode(decoded) != header:
        raise ValueError("HISTORICAL_HEADER")
    challenge = reader.wire.H('challenge', header)
    ticket, _ = work_oracle.verify(challenge, decoded['work_task'], decoded['target'], proof)
    if reader.wire.H('block', header, proof[-32:]) != identifier:
        raise ValueError("HISTORICAL_BLOCK_ID")
    values = struct.unpack('<' + 'I' * 8192, proof[4:4 + 32768])
    template = FixedTemplate.from_header(header, values[:4096], values[4096:])
    metadata = {"receipt_sha256": digest(receipt_raw), "report_sha256": wanted,
                "historical_native_source_commit": receipt['native_source_commit'],
                "packet_sha256": digest(packet), "proof_sha256": digest(proof), "block_id": row['id'],
                "row_index": index, "nonce": row['nonce'], "trace": row['trace'], "ticket": ticket.hex(),
                "historical_native_admission_observed": True,
                "current_native_execution": False, "current_python_full_relation_rechecked": True,
                "original_85_observation_campaign_rerun": False}
    return template, metadata


def case_definitions(native_receipt=None, native_raw_dir=None):
    if (native_receipt is None) != (native_raw_dir is None):
        raise ValueError("PAIRED_HISTORICAL_INPUTS")
    original_header = read(FORMAL / 'vectors/header.bin')
    nonce = int.from_bytes(original_header[310:318], 'little')
    reduced = reduced_template()
    cases = [('retained-pnh1', retained_template(), nonce, 'macro'),
             ('pgh2-witness-bound', retained_template('PGH2'), nonce, 'macro'),
             ('reduced-gate-success', reduced, 0, 'gates'),
             ('reduced-gate-noise-exhaustion', reduced, exhaustion_nonce(reduced), 'gates')]
    historical = None
    if native_receipt is not None:
        template, historical = historical_native_control(native_receipt, native_raw_dir)
        cases.append(('historically-admitted-pnh1', template, historical['nonce'], 'macro'))
    return cases, historical


def observe(name, template, nonce, mode):
    started = time.monotonic()
    program = OracleProgram(template)
    resources = program.resources()
    observed = program.execute(nonce, mode=mode)
    if template.shape.native:
        challenge = hashlib.sha256(h_bytes(template.challenge_tag, template.header_for(nonce))).digest()
        _, trace = work_oracle.evaluate(challenge, template.a, template.b)
        ticket = hashlib.sha256(h_bytes(b'ticket', challenge, trace)).hexdigest()
        if observed['challenge'] != challenge.hex() or observed['trace'] != trace.hex() or observed['ticket'] != ticket:
            raise ValueError("INDEPENDENT_NATIVE_SHAPE_SCALAR_DIFFERENTIAL")
    if name == 'retained-pnh1' and observed['trace'] != read(FORMAL / 'vectors/work.bin')[-32:].hex():
        raise ValueError("RETAINED_PROOF_DIFFERENTIAL")
    if name == 'reduced-gate-noise-exhaustion' and (observed['winner'] or all(observed['noise_complete'])):
        raise ValueError("EXHAUSTION_NOT_EXERCISED")
    return {"name": name, "nonce": nonce, "execution_mode": mode, "resources": resources,
            "observation": observed, "classical_build_and_check_wall_seconds": time.monotonic() - started}


def run_campaign(out, native_receipt=None, native_raw_dir=None):
    source = source_record()
    cases, historical = case_definitions(native_receipt, native_raw_dir)
    out.mkdir(parents=True, exist_ok=False)
    records = []
    for case in cases:
        records.append(observe(*case))
    if historical is not None:
        actual = records[-1]['observation']
        if any(actual[key] != historical[key] for key in ('trace', 'ticket')) or not actual['winner']:
            raise ValueError("HISTORICAL_NATIVE_PACKET_DIFFERENTIAL")
    if source['source_sha256'] != {name: digest((ROOT / name).read_bytes()) for name in FILES}:
        raise ValueError("SOURCE_CHANGED_DURING_OBSERVATION")
    report = {"schema": SCHEMA, "source": source, "assertions": ASSERTIONS, "records": records,
              "historical_native_control": historical,
              "historical_input_locations": None if historical is None else {
                  "receipt": str(native_receipt.resolve()), "raw_dir": str(native_raw_dir.resolve())},
              "storage_scope": "compact JSON and hashes; leaf netlists reconstructed in memory; no expanded native-sized gate list"}
    encoded = canonical(report) + b'\n'
    write_atomic(out / 'report.json', encoded)
    write_atomic(out / 'manifest.json', canonical({"schema": SCHEMA + '-manifest', "report_sha256": digest(encoded)}) + b'\n')
    return {"result": "CONSTRUCTIVE_UPPER_BOUND_AND_SCOPED_EXECUTION_OBSERVED", "cases": len(records),
            "macro_cases": sum(r['execution_mode'] == 'macro' for r in records),
            "reduced_gate_cases": sum(r['execution_mode'] == 'gates' for r in records),
            "report_sha256": digest(encoded), "bytes": len(encoded), "security_qualified": False}


def verify_campaign(out, native_receipt=None, native_raw_dir=None):
    if out.is_symlink() or not out.is_dir() or {p.name for p in out.iterdir()} != {'report.json', 'manifest.json'}:
        raise ValueError("CAMPAIGN_INVENTORY")
    raw = read(out / 'report.json')
    report, manifest = strict_load(raw), strict_load(read(out / 'manifest.json'))
    if type(report) is not dict or set(report) != {
            'schema', 'source', 'assertions', 'records', 'historical_native_control',
            'historical_input_locations', 'storage_scope'}:
        raise ValueError("CAMPAIGN_SCHEMA")
    if manifest != {'schema': SCHEMA + '-manifest', 'report_sha256': digest(raw)} or report.get('schema') != SCHEMA:
        raise ValueError("CAMPAIGN_MANIFEST")
    if canonical(report.get('assertions')) != canonical(ASSERTIONS):
        raise ValueError("QUALIFICATION_SUBSTITUTION")
    validate_source(report.get('source'))
    locations = report.get('historical_input_locations')
    if locations is not None and (type(locations) is not dict or set(locations) != {'receipt', 'raw_dir'}
                                  or any(type(value) is not str for value in locations.values())):
        raise ValueError("HISTORICAL_LOCATION_SCHEMA")
    if locations is not None and native_receipt is None and native_raw_dir is None:
        native_receipt, native_raw_dir = Path(locations['receipt']), Path(locations['raw_dir'])
    cases, historical = case_definitions(native_receipt, native_raw_dir)
    if canonical(historical) != canonical(report.get('historical_native_control')) or type(report.get('records')) is not list or len(report['records']) != len(cases):
        raise ValueError("CASE_INVENTORY_OR_HISTORICAL_SUBSTITUTION")
    for case, recorded in zip(cases, report['records']):
        if type(recorded) is not dict or set(recorded) != {
                'name', 'nonce', 'execution_mode', 'resources', 'observation',
                'classical_build_and_check_wall_seconds'}:
            raise ValueError("CASE_SCHEMA")
        seconds = recorded.get('classical_build_and_check_wall_seconds')
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError("CLASSICAL_TIMING")
        replay = observe(*case)
        for key in ('name', 'nonce', 'execution_mode', 'resources', 'observation'):
            if canonical(recorded.get(key)) != canonical(replay[key]):
                raise ValueError("CONSTRUCTIVE_REPLAY_MISMATCH:" + key)
    validate_source(report['source'])
    return {"result": "CONSTRUCTIVE_SOURCE_BOUND_REPLAY_PASS", "cases": len(cases),
            "current_native_execution": False, "quantum_hardware_executed": False, "security_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--out', type=Path)
    action.add_argument('--verify', type=Path)
    parser.add_argument('--native-receipt', type=Path)
    parser.add_argument('--native-raw-dir', type=Path)
    args = parser.parse_args()
    result = (verify_campaign(args.verify, args.native_receipt, args.native_raw_dir) if args.verify else
              run_campaign(args.out, args.native_receipt, args.native_raw_dir))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
