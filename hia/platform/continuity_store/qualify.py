"""Actual physical qualification of the finite installed continuity owner."""
from __future__ import annotations

import argparse
import itertools
import json
import lzma
from pathlib import Path
import struct

from hia.platform.build import new_output, write_json, sha256
from hia.platform.continuity_store.build import Build, file_identity
from hia.platform.continuity_store.cases import cases, capacity_cases, material
from hia.platform.continuity_store.native_io import run
from hia.platform.continuity_store.context_qualification import qualify_context
from hia.platform.continuity_store.reference import configuration
from hia.platform.typed_store.cases import BLOCK, SLOT, MAX, kv, delta
from hia.tests.test_state_root import reference as root_reference

ROOT = Path(__file__).resolve().parents[3]

import hashlib
import json
from pathlib import Path
import resource
import time

def memory_observation():
    result = {
        "monotonic_ns": time.monotonic_ns(),
        "self_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "unit": "KiB on the required Linux qualification host",
    }
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, value, unit = line.split()
                if unit != "kB":
                    raise ValueError("Unexpected Linux proc memory unit")
                result[key.rstrip(":").lower() + "_kib"] = int(value)
    except FileNotFoundError:
        result["proc_status"] = "unavailable"
    return result

def _write_all(stream, raw):
    offset = 0
    while offset < len(raw):
        size = stream.write(raw[offset:])
        if size is None or size <= 0:
            raise OSError("Evidence journal short write")
        offset += size

class EvidenceJournal:
    """One immutable-in-order JSON record at a time, with no retained records."""
    def __init__(self, path):
        self.path = Path(path)
        self.path.open("xb").close()
        self.count = 0
        self.bytes = 0
        self.digest = hashlib.sha256()
        self.failed = False

    def __len__(self):
        return self.count

    def append(self, record):
        if self.failed:
            raise ValueError("Evidence journal already has an incomplete record")
        start = self.bytes
        record_digest = hashlib.sha256()
        size = 0
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        try:
            with self.path.open("ab") as destination:
                for part in encoder.iterencode(record):
                    raw = part.encode("utf-8")
                    _write_all(destination, raw)
                    record_digest.update(raw)
                    self.digest.update(raw)
                    size += len(raw)
                _write_all(destination, b"\n")
                record_digest.update(b"\n")
                self.digest.update(b"\n")
                size += 1
                destination.flush()
            if self.path.stat().st_size != start + size:
                raise ValueError("Evidence journal extent changed")
        except BaseException:
            self.failed = True
            raise
        self.bytes += size
        self.count += 1
        return {"path": str(self.path), "record": self.count - 1,
                "offset": start, "bytes": size,
                "sha256": record_digest.hexdigest()}

    def identity(self):
        if self.failed:
            raise ValueError("Evidence journal is incomplete")
        return {"path": str(self.path), "records": self.count,
                "bytes": self.bytes, "sha256": self.digest.hexdigest()}

    def write_array_object(self, output, metadata, *, key="cases"):
        """Stream the exact persisted records into a conventional JSON array.

        Recomputing the entire journal identity during this copy detects missing,
        extra, truncated or changed records. A failure leaves an explicitly partial
        output and cannot produce a successful qualification report.
        """
        if self.failed or key in metadata:
            raise ValueError("Invalid evidence journal finalization")
        if self.path.stat().st_size != self.bytes:
            raise ValueError("Evidence journal final extent differs")
        header = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        if not header.endswith(b"}"):
            raise ValueError("Evidence metadata is not an object")
        digest = hashlib.sha256()
        count = size = 0
        with Path(output).open("xb") as destination:
            _write_all(destination, header[:-1])
            if len(metadata):
                _write_all(destination, b",")
            _write_all(destination, json.dumps(key).encode() + b":[")
            with self.path.open("rb") as source:
                for line in source:
                    if not line.endswith(b"\n"):
                        raise ValueError("Evidence journal has a truncated record")
                    digest.update(line)
                    size += len(line)
                    if count:
                        _write_all(destination, b",")
                    _write_all(destination, line[:-1])
                    count += 1
            if (count, size, digest.hexdigest()) != (
                    self.count, self.bytes, self.digest.hexdigest()):
                raise ValueError("Evidence journal changed before finalization")
            _write_all(destination, b"]}\n")

class ControlJournal(list):
    """Small in-memory summaries plus the complete on-disk controls."""
    def __init__(self, path):
        super().__init__()
        self.journal = EvidenceJournal(path)

    def append(self, control):
        receipt = self.journal.append(control)
        summary = {key: value for key, value in control.items() if key != "actual"}
        actual = control.get("actual")
        if isinstance(actual, dict):
            summary["actual"] = {key: value for key, value in actual.items()
                                 if key not in {"output_hex", "output_before_hex"}}
        elif "actual" in control:
            summary["actual"] = actual
        summary["complete_record"] = receipt
        super().append(summary)

    def extend(self, controls):
        for control in controls:
            self.append(control)


def need(condition, message):
    if not condition:
        raise ValueError(message)

def safe(row):
    return not row['timed_out'] and not row['gate_errors'] and row['inputs_unchanged']

def semantic_case(executable, directory, case):
    actual = run(executable, directory, kv(case.before), delta(case.changes), variant=case.variant,
        height=case.height, detach=case.detach, root=case.root, profile=case.profile,
        cancel=case.cancel, cancel_class=case.cancel_class, token=case.token, timeout=120)
    progresses = case.progress()
    checks = {'process': safe(actual), 'code': actual['exit'] == case.code,
        'progress': actual['progress_records'] == progresses}
    receipt = actual.get('receipt')
    if case.code == 0:
        expected = kv(case.result)
        root = root_reference(case.result)[1] if case.root else bytes(32)
        wanted = {'kind': 2 if case.root else 1, 'count': len(case.result), 'output_bytes': len(expected),
            'delta_count': len(case.changes), 'progresses': len(progresses), 'block_hex': BLOCK.hex(),
            'slot': SLOT, 'root_hex': root.hex(), 'reserved': 0,
            'continuity': case.capacity, 'context': configuration(case.variant)['context']}
        checks.update(output=actual.get('output_hex') == expected.hex(), receipt=receipt == wanted,
            no_stderr=not actual['stderr_hex'])
        result_hex = actual.get('output_hex')
        root_hex = root.hex() if case.root else None
        capacity = receipt.get('continuity') if receipt else None
        context = receipt.get('context') if receipt else None
    else:
        checks.update(no_receipt=not actual['stdout_hex'], no_staging=actual['output_bytes'] == 0,
            diagnostic=len(actual.get('diagnostic', [])) == 7 and actual['diagnostic'][0] == case.code
                and actual['diagnostic'][3] == len(progresses) and actual['diagnostic'][6] == 0)
        if case.code == 80:
            checks['callback_identity'] = actual['diagnostic'][4:6] == [case.cancel_class, case.token]
        result_hex, root_hex, capacity, context = None, None, None, None
    return {'name': case.name, 'status': 'PASS' if all(checks.values()) else 'FAIL',
        'checks': checks, 'actual': actual}, {'name': case.name, 'code': actual['exit'],
        'progresses': len(actual['progress_records']), 'result_hex': result_hex,
        'root_hex': root_hex, 'capacity': capacity, 'context': context}

def physical(executable, output, controls):
    base = kv(material({}))
    no_changes = delta(())
    def check(name, options, predicate):
        actual = run(executable, output / name, base, no_changes, **options)
        ok = predicate(actual)
        controls.append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'actual': actual})
        need(ok, 'Physical continuity control differs: ' + name)
        return actual
    def refused(row, code):
        return safe(row) and row['exit'] == code and not row['stdout_hex'] and row['output_bytes'] == 0
    for name, code in [('unsealed-base', 65), ('unsealed-delta', 65), ('output-mode', 65), ('output-link', 65),
            ('output-nonempty', 65), ('output-append', 65), ('output-readonly', 65), ('output-alias-base', 65),
            ('output-locked', 67), ('gw-output-alias', 65), ('gr-output-alias', 65), ('gw-base-alias', 65),
            ('gr-delta-alias', 65), ('gw-read-end', 65), ('gr-write-end', 65), ('gate-self-loop', 65),
            ('gw-separate-regular', 65), ('gr-separate-regular', 65), ('gate-rdwr-fifo', 65), ('gate-opath-fifo', 65)]:
        check('cap-' + name, {'capability': name}, lambda row, code=code: safe(row) and row['exit'] == code
            and not row['progress_records'] and not row['stdout_hex'] and row['output_hex'] == row['output_before_hex'])
    for cut in range(32):
        check('prefix-cut-' + str(cut), {'bootstrap_mutator': lambda raw, cut=cut: raw[:cut]},
            lambda row: refused(row, 64) and not row['progress_records'])
    for name, mutate, code in (
            ('unknown-context', lambda raw: raw[:8] + struct.pack('<Q', 4) + raw[16:], 69),
            ('bad-prefix-magic', lambda raw: b'NOTCONF1' + raw[8:], 64),
            ('prefix-reserved', lambda raw: raw[:24] + struct.pack('<Q', 1) + raw[32:], 64),
            ('context-profile-mismatch', lambda raw: raw[:8] + struct.pack('<Q', 2) + raw[16:], 69)):
        check(name, {'bootstrap_mutator': mutate}, lambda row, code=code: refused(row, code)
            and not row['progress_records'])
    check('growth-root-unimplemented', {'variant': 2, 'profile': 1, 'root': True},
        lambda row: refused(row, 69) and not row['progress_records'])
    for point in (6, 7):
        for cls in (1, 2, 3, 4):
            check(f'cancel-boundary-{point}-{cls}', {'cancel': point, 'cancel_class': cls, 'token': MAX - cls},
                lambda row, cls=cls: refused(row, 80) and row['diagnostic'][4:6] == [cls, MAX - cls])
        killed = check('sigkill-' + str(point), {'kill': point}, lambda row: safe(row)
            and row['exit'] == -9 and not row['stdout_hex'])
        restarted = check('restart-' + str(point), {}, lambda row: safe(row) and row['exit'] == 0
            and row['output_hex'] == base.hex() and not row['stderr_hex'])
        cold = run(executable, output / ('cold-' + str(point)), Path(restarted['output_path']), no_changes)
        ok = safe(cold) and cold['exit'] == 0 and cold['output_hex'] == base.hex()
        ok = ok and cold['receipt']['root_hex'] == restarted['receipt']['root_hex']
        controls.append({'name': 'cold-' + str(point), 'status': 'PASS' if ok else 'FAIL', 'actual': cold})
        need(ok, 'Fresh process complete State/continuity/root reread differs')
    check('owned-controller-stop', {'kill': 6, 'stop_file': output / 'owned-stop'},
        lambda row: safe(row) and row['exit'] == -9 and row['controller_stop_requested']
            and row['controller_stop'][0]['signal_outcome'] == 'sent' and not row['stdout_hex'])
    check('real-efbig', {'file_limit': 41}, lambda row: refused(row, 70)
        and row['diagnostic'][6] == 0)
    check('lost-receipt', {'lose_receipt': True}, lambda row: safe(row) and row['exit'] == 70
        and not row['stdout_hex'] and row['output_hex'] == base.hex())

def main():
    if not __debug__:
        raise RuntimeError('Optimized qualification is not supported')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = new_output(args.output)
    controls = ControlJournal(output / 'control-records.jsonl')
    comparisons = EvidenceJournal(output / 'comparison-records.jsonl')
    memory = [dict(phase='start', **memory_observation())]
    scope = {'schema': 'trnm.hia.continuity-staging-qualification.v1',
        'finite_installed_configurations': 4, 'original_rust': 'NOT_RUN',
        'all_original_non_pq_configurations_covered': False, 'pq_config_and_anchor_qualified': False,
        'public_capacity_with_progress_qualified': False, 'namespace_commit_ack_authority': False,
        'complete_node': False, 'gsc2_root': False, 'physical_power_loss': False,
        'same_uid_continuous_attacker': False, 'cold_means_fresh_process_not_cache_eviction': True}
    build_receipt = None
    try:
        build = Build(output / 'build', ROOT)
        executable, build_receipt = build.build()
        memory.append(dict(phase='native-build', **memory_observation()))
        contexts = qualify_context(build, output / 'context', controls)
        memory.append(dict(phase='native-context', **memory_observation()))
        selected = itertools.chain(cases(), capacity_cases())
        semantic = output / 'semantic'
        semantic.mkdir(mode=0o700)
        corpus_path = output / 'corpus.jsonl'
        with corpus_path.open('w') as corpus:
            for index, case in enumerate(selected):
                corpus.write(json.dumps(case.corpus(), separators=(',', ':')) + '\n')
                control, comparison = semantic_case(executable, semantic / f'{index:04}-{case.name}', case)
                controls.append(control)
                write_json(output / 'running-controls.json', {'controls': controls})
                need(control['status'] == 'PASS', 'Native continuity semantic mismatch: '
                    + case.name + ' ' + json.dumps(control['checks']))
                comparisons.append(comparison)
                memory.append(dict(phase='semantic', case=case.name, **memory_observation()))
        physical_output = output / 'physical'
        physical_output.mkdir(mode=0o700)
        physical(executable, physical_output, controls)
        memory.append(dict(phase='physical', **memory_observation()))
        build.check_sources()
        bundle = {'schema': 'trnm.hia.native-continuity-staging-comparison.v1', 'status': 'PASS',
            'build': build_receipt, 'corpus': file_identity(corpus_path), 'contexts': contexts}
        need(len(comparisons) == 572 and len(controls) == 659, 'Complete qualification case count differs')
        comparisons.write_array_object(output / 'native-comparison.json', bundle)
        archives = {}
        for name in ('corpus.jsonl', 'control-records.jsonl', 'comparison-records.jsonl'):
            source_path, archived = output / name, output / (name + '.xz')
            with source_path.open('rb') as source, lzma.open(archived, 'wb', preset=1) as destination:
                while block := source.read(1 << 20):
                    destination.write(block)
            archives[name] = {'raw': file_identity(source_path), 'archive': file_identity(archived)}
        memory.append(dict(phase='archive-complete', **memory_observation()))
        report = dict(scope, status='NATIVE_PASS_ORIGINAL_NOT_RUN', controls=controls,
            semantic_cases=len(comparisons), control_count=len(controls), build=build_receipt,
            corpus=bundle['corpus'], source_inputs_stable=True, contexts=contexts,
            control_journal=controls.journal.identity(), comparison_journal=comparisons.identity(),
            archives=archives, controller_memory=memory)
        write_json(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'controls': len(controls),
            'semantic': len(comparisons), 'report': str(output / 'report.json')}))
        return 0
    except BaseException as error:
        write_json(output / 'report.json', dict(scope, status='FAIL', error=repr(error),
            controls=controls, build=build_receipt, controller_memory=memory))
        raise

if __name__ == '__main__':
    raise SystemExit(main())
