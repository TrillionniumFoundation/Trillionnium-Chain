"""Seven native Research payloads against the actual retained public Rust crate."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_research_external_key import build_original

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/research_protocol/payload.hepta"
REFERENCE = ROOT / "hia/tests/rust_research_payload_reference.rs"
MAX = (1 << 64) - 1
NAMES = ['', 'ResearchCommandV1', 'ResearchObjectKind', 'ContributionRole',
         'LicenseScope', 'ChallengeReason', 'ClaimResolutionDecision', 'score_bps',
         'share_bps', 'commitment_id', 'match_id', 'challenge_id', 'event_root',
         'roster_root', 'ruleset_hash', 'dataset_hash', 'archive_hash', 'event_count',
         'evaluation_id', 'match_evidence_ref', 'submission_hash', 'rubric_hash',
         'evaluation_hash', 'reproduction_hash', 'receipt_id', 'evaluation_ref',
         'contributors', 'contributor', 'accepted_work_units', 'contribution_hash',
         'policy_hash', 'claim_id', 'workload_receipt_ref', 'evidence_refs',
         'evidence_ref', 'artifact_hash', 'claim_scope_hash', 'claimants', 'claimant',
         'declaration_id', 'claim_ref', 'licensor', 'additional_terms_hash',
         'challenger', 'evidence_hash', 'resolution_id', 'challenge_ref', 'resolution_hash']
TYPES = ['match_evidence_commitment', 'evaluation_commitment', 'issue_workload_receipt',
         'create_research_claim', 'declare_license', 'challenge_research_claim',
         'resolve_research_claim']
KINDS = ['match_evidence', 'evaluation_commitment', 'workload_receipt', 'research_claim',
         'license_declaration', 'claim_challenge', 'claim_resolution']


def key(n):
    return list(n.to_bytes(32, 'big'))


def ref(kind, n=1, version=1):
    return dict(kind=KINDS[kind-1], key=key(n), object_version=version)


def shares(n=2):
    return [dict(contributor=key(i+1), share_bps=10000//n+(i < 10000 % n))
            for i in range(n)] if n else []


def fixtures():
    payloads = [
        dict(commitment_id=key(1), match_id=key(2), challenge_id=key(3), event_root=key(4),
             roster_root=key(5), ruleset_hash=key(6), dataset_hash=key(7), archive_hash=key(8),
             event_count=1, completed_at_unix_s=1),
        dict(evaluation_id=key(9), match_evidence_ref=ref(1), submission_hash=key(10),
             rubric_hash=key(11), evaluation_hash=key(12), reproduction_hash=None,
             score_bps=6500, accepted=True, completed_at_unix_s=1),
        dict(receipt_id=key(13), evaluation_ref=ref(2), contributors=[
            dict(contributor=key(1), role='researcher', accepted_work_units=3, contribution_hash=key(14)),
            dict(contributor=key(2), role='evaluator', accepted_work_units=5, contribution_hash=key(15))],
             total_accepted_work_units=8, policy_hash=key(16), issued_at_unix_s=1),
        dict(claim_id=key(17), workload_receipt_ref=ref(3), evidence_refs=[ref(1), ref(2)],
             artifact_hash=key(18), claim_scope_hash=key(19), claimants=shares(), created_at_unix_s=1),
        dict(declaration_id=key(20), claim_ref=ref(4), licensor=key(21), scope='artifact',
             spdx_expression='MIT OR Apache-2.0', additional_terms_hash=None, effective_at_unix_s=1),
        dict(challenge_id=key(22), claim_ref=ref(4), challenger=key(23), reason='authorship',
             evidence_hash=key(24), opened_at_unix_s=1),
        dict(resolution_id=key(25), challenge_ref=ref(6), decision='amend_contributor_shares',
             resolution_hash=key(26), amended_claimants=shares(), decided_at_unix_s=1),
    ]
    return [dict(type=t, payload=p) for t, p in zip(TYPES, payloads)]


def typed(command, op=2):
    return {'op': op, 'command': copy.deepcopy(command)}


def header(op, kind, data):
    return b'RTP1' + bytes((op, 0, 0, 0)) + struct.pack('<QQ', kind, 0) + data


def uint(value):
    if value < 24:
        return bytes((value,))
    for cap, tag, width in ((256, 24, 1), (65536, 25, 2), (1 << 32, 26, 4), (1 << 64, 27, 8)):
        if value < cap:
            return bytes((tag,)) + value.to_bytes(width, 'big')
    raise ValueError(value)


def spans(data):
    """Independent fixture walker; expected decisions still come from Rust."""
    out = []

    def one(pos):
        start = pos
        first = data[pos]
        pos += 1
        major, additional = first >> 5, first & 31
        if major == 7:
            out.append((start, pos, major, additional))
            return pos
        if additional < 24:
            value = additional
        else:
            width = {24: 1, 25: 2, 26: 4, 27: 8}[additional]
            value = int.from_bytes(data[pos:pos+width], 'big')
            pos += width
        out.append((start, pos, major, value))
        if major in (2, 3):
            return pos + value
        if major == 4:
            for _ in range(value):
                pos = one(pos)
        return pos

    if one(0) != len(data):
        raise AssertionError('original fixture has unconsumed bytes')
    return out


class ResearchPayloadNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='trnm-research-payload-')
        try:
            _, cls.original = build_original(cls.directory.name)
            dependencies = cls.original['dependency_sha256']
            crate = [Path(p) for p, h in dependencies.items()
                     if h == cls.original['crate_sha256'] and Path(p).name == 'libtrnm_research_protocol.rlib']
            serde = [Path(p) for p in dependencies if Path(p).name.startswith('libserde_json-')]
            if len(crate) != 1 or len(serde) != 1:
                raise AssertionError('Actual original/serde artifact is missing or ambiguous')
            cls.oracle = Path(cls.directory.name) / 'research-payload-original'
            args = ['rustc', '--edition=2021', '--deny=warnings', str(REFERENCE), '-o', str(cls.oracle),
                    '--extern', 'trnm_research_protocol=' + str(crate[0]),
                    '--extern', 'serde_json=' + str(serde[0])]
            for p in sorted({Path(p).parent for p in dependencies}):
                args += ['-L', 'dependency=' + str(p)]
            built = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
            if built.returncode:
                raise AssertionError('Original public payload adapter failed:\n' + built.stderr)
            cls.original['payload_adapter_sha256'] = hashlib.sha256(cls.oracle.read_bytes()).hexdigest()
            cls.module = NativeModule(SOURCE, byte_exports=('f0',))
            cls.compared = cls.abi = 0
            cls.codes = set()
            cls.base = cls.reference([typed(c, 1) for c in fixtures()])
        except BaseException:
            cls.directory.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        print(json.dumps({'schema': 'trnm.hia.research-payload-observation.v1',
                          'original_native_pairs': cls.compared, 'abi_controls': cls.abi,
                          'observed_returns': sorted(cls.codes), 'original': cls.original,
                          'native': {'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                     'artifact_sha256': cls.module.artifact_sha256,
                                     'compiler_sha256': cls.module.receipt['compiler_sha256']}}))
        cls.module.close()
        cls.directory.cleanup()

    @classmethod
    def reference(cls, rows):
        process = subprocess.run([str(cls.oracle)], input=''.join(json.dumps(r) + '\n' for r in rows),
                                 capture_output=True, text=True, timeout=30)
        if process.returncode:
            raise AssertionError(process.stderr)
        out = [json.loads(line) for line in process.stdout.splitlines()]
        if len(out) != len(rows):
            raise AssertionError('Original adapter did not complete every input')
        return out

    def compare(self, rows):
        for start in range(0, len(rows), 12):
            batch = rows[start:start+12]
            originals = self.reference(batch)
            calls, expected, scratch_sizes = [], [], []
            for request, result in zip(batch, originals):
                op = request['op']
                data = bytes.fromhex(request['cbor'] if op == 3 else result['flat_input'])
                kind = 0 if op == 3 else TYPES.index(request['command']['type'])+1
                raw = header(op, kind, data)
                size = 128 + 3*len(data) + 512
                want = bytearray(b'\xa5' * size)
                want[:128] = bytes(128)
                if result['code']:
                    struct.pack_into('<QQQ', want, 32, NAMES.index(result['name']), result['detail1'], result['detail2'])
                else:
                    cb, flat = bytes.fromhex(result['canonical']), bytes.fromhex(result['flat'])
                    name = result['command_type'].encode()
                    self.assertEqual(cb[3:], bytes.fromhex(result['payload']))
                    self.assertEqual(bytes.fromhex(result['object_ref']), b'\x84\x01'+uint(result['kind'])+b'\x58\x20'+bytes.fromhex(result['key'])+b'\x01')
                    struct.pack_into('<8Q', want, 0, len(cb), len(flat), result['kind'], len(name), 0, 0, 0, result['object_version'])
                    want[64:96] = bytes.fromhex(result['key'])
                    want[96:96+len(name)] = name
                    want[128:128+len(cb)+len(flat)] = cb+flat
                scratch = 2560+16*len(data)
                scratch_sizes.append(scratch)
                calls.append(('f0', [raw, b'\xa5'*size, b'\x5a'*(scratch+29)]))
                expected.append(bytes(want))
            actual = self.module.call_many(calls, timeout=60)
            for req, call, original, want, size, got in zip(batch, calls, originals, expected, scratch_sizes, actual):
                got.require_returned()
                with self.subTest(op=req['op'], kind=req.get('command', {}).get('type'), prefix=call[1][0][:64].hex()):
                    self.assertEqual(got.value, original['code'], original)
                    self.assertEqual(got.arguments[0], call[1][0])
                    self.assertEqual(got.arguments[1], want)
                    self.assertEqual(got.arguments[2][size:], b'\x5a'*29)
                type(self).compared += 1
                type(self).codes.add(got.value)

    def test_seven_payloads_encode_validate_decode_and_numeric_boundaries(self):
        commands = fixtures()
        rows = []
        values = (0, 1, 23, 24, 255, 256, 65535, 65536, (1 << 32)-1, 1 << 32, MAX)
        for c in commands:
            rows += [typed(c, 1), typed(c, 2)]
            for field, value in c['payload'].items():
                if type(value) is int:
                    for n in values:
                        if field == 'score_bps' and n > 65535:
                            continue
                        changed = copy.deepcopy(c)
                        changed['payload'][field] = n
                        rows += [typed(changed, 1), typed(changed, 2)]
        self.compare(rows)
        encoded = self.reference([r for r in rows if r['op'] == 1])
        self.compare([{'op': 3, 'cbor': r['canonical']} for r in encoded])

    def test_zero_fields_reference_kinds_and_multiple_error_precedence(self):
        rows = []
        for c in fixtures():
            fields = []
            for name, value in c['payload'].items():
                if isinstance(value, list) and len(value) == 32:
                    fields.append((name, [0]*32))
                elif isinstance(value, dict) and 'object_version' in value:
                    for kind in range(1, 8):
                        changed = copy.deepcopy(c)
                        changed['payload'][name] = ref(kind, 1, 1)
                        rows.append(typed(changed))
                    for bad in (ref(7, 0, 0), ref(7, 1, 0), ref(7, 0, 1)):
                        fields.append((name, bad))
            for index, (name, bad) in enumerate(fields):
                changed = copy.deepcopy(c)
                changed['payload'][name] = bad
                rows += [typed(changed), typed(changed, 1)]
                for next_name, next_bad in fields[index+1:]:
                    both = copy.deepcopy(changed)
                    both['payload'][next_name] = next_bad
                    rows.append(typed(both))
        self.compare(rows)

    def test_accounting_ordering_limits_overflow_and_exact_totals(self):
        rows = []
        for n in (0, 1, 2, 3, 64, 127, 128, 129):
            c = fixtures()[2]
            c['payload']['contributors'] = [dict(contributor=key(i+1), role='researcher',
                accepted_work_units=1, contribution_hash=key(i+1)) for i in range(n)]
            c['payload']['total_accepted_work_units'] = n
            rows += [typed(c), typed(c, 1)]
            for total in (0, n+1, MAX):
                bad = copy.deepcopy(c)
                bad['payload']['total_accepted_work_units'] = total
                rows.append(typed(bad))
            for index in (3, 6):
                c = fixtures()[index]
                c['payload']['claimants' if index == 3 else 'amended_claimants'] = shares(n)
                rows += [typed(c), typed(c, 1)]
        for units in ((MAX, 1), (MAX-1, 1), (1, 0), (0, MAX)):
            c = fixtures()[2]
            for row, amount in zip(c['payload']['contributors'], units):
                row['accepted_work_units'] = amount
            c['payload']['total_accepted_work_units'] = sum(units) & MAX
            rows.append(typed(c))
        for collection, index in (('contributors', 2), ('claimants', 3), ('amended_claimants', 6)):
            for mode in ('reverse', 'duplicate', 'zero-key', 'bad-value', 'bad-digest'):
                c = fixtures()[index]
                items = c['payload'][collection]
                if mode == 'reverse':
                    items.reverse()
                elif mode == 'duplicate':
                    items[1]['contributor'] = items[0]['contributor']
                elif mode == 'zero-key':
                    items[1]['contributor'] = key(0)
                elif mode == 'bad-value':
                    items[1]['accepted_work_units' if index == 2 else 'share_bps'] = 0
                elif index == 2:
                    items[1]['contribution_hash'] = key(0)
                rows.append(typed(c))
        for value in (0, 1, 9999, 10000, 10001, 65535):
            c = fixtures()[3]
            c['payload']['claimants'][1]['share_bps'] = value
            rows.append(typed(c))
        for n in (0, 1, 64, 65):
            c = fixtures()[3]
            c['payload']['evidence_refs'] = [ref(1, i+1) for i in range(n)]
            rows += [typed(c), typed(c, 1)]
        for items in ([ref(1, 1), ref(1, 1, 2)], [ref(1, 1, 2), ref(1, 1)],
                      [ref(2), ref(1)], [ref(1), ref(1)], [ref(1, 0)], [ref(3)],
                      [ref(1, 1, 0)], [ref(1, 2), ref(1, 1)]):
            c = fixtures()[3]
            c['payload']['evidence_refs'] = items
            rows.append(typed(c))
        self.compare(rows)
        encoded = self.reference([r for r in rows if r['op'] == 1])
        self.compare([{'op': 3, 'cbor': r['canonical']} for r in encoded])

    def test_optional_hashes_spdx_evaluation_and_resolution_rules(self):
        rows = []
        for index, field in ((1, 'reproduction_hash'), (4, 'additional_terms_hash')):
            for value in (None, key(0), key(1), [255]*32):
                c = fixtures()[index]
                c['payload'][field] = value
                rows += [typed(c), typed(c, 1)]
        for score in (0, 1, 10000, 10001, 65535):
            for accepted in (False, True):
                c = fixtures()[1]
                c['payload'].update(score_bps=score, accepted=accepted)
                rows.append(typed(c))
        expressions = ['', 'MIT', ' MIT', 'MIT ', 'MIT  OR GPL', 'MIT\tOR GPL',
                       'a'*128, 'a'*129, 'é', '研究', '\u00a0MIT', 'MIT\n', 'MIT\0']
        expressions += ['A'+chr(i)+'B' for i in range(128)]
        for expression in expressions:
            c = fixtures()[4]
            c['payload']['spdx_expression'] = expression
            rows += [typed(c), typed(c, 1)]
        for decision in ('uphold', 'reject', 'amend_contributor_shares', 'require_license_amendment'):
            for n in (0, 1, 2, 129):
                c = fixtures()[6]
                c['payload'].update(decision=decision, amended_claimants=shares(n))
                rows += [typed(c), typed(c, 1)]
        self.compare(rows)
        encoded = self.reference([r for r in rows if r['op'] == 1])
        self.compare([{'op': 3, 'cbor': r['canonical']} for r in encoded])

    def test_canonical_truncation_reserved_forms_lengths_and_discriminants(self):
        rows = []
        for fixture in self.base:
            raw = bytes.fromhex(fixture['canonical'])
            variants = [raw[:p] for p in range(len(raw))]
            variants += [bytes((b,))+raw[1:] for b in range(256)]
            variants += [raw+tail for tail in (b'\0', b'\xff', b'\x80', raw)]
            for begin, end, major, value in spans(raw):
                if major == 0:
                    for v in (0, 1, 2, 7, 8, 65535, 65536, MAX):
                        variants.append(raw[:begin]+uint(v)+raw[end:])
                    if value < 24:
                        variants.append(raw[:begin]+bytes((24, value))+raw[end:])
                elif major in (2, 3, 4):
                    for v in (0, 1, 31, 32, 33, 64, 65, 128, 129, MAX):
                        h = bytearray(uint(v));h[0] |= major << 5
                        variants.append(raw[:begin]+h+raw[end:])
                    for reserved in range(28, 32):
                        variants.append(raw[:begin]+bytes(((major << 5)|reserved,))+raw[end:])
            rows.extend({'op': 3, 'cbor': r.hex()} for r in variants)
        self.compare(rows)

    def test_random_canonical_mutations_and_full_width_typed_values(self):
        rng = random.Random(0x72545031)
        rows = []
        for _ in range(512):
            raw = bytearray.fromhex(rng.choice(self.base)['canonical'])
            for _ in range(rng.randrange(1, 5)):
                raw[rng.randrange(len(raw))] = rng.randrange(256)
            rows.append({'op': 3, 'cbor': raw.hex()})
        for _ in range(128):
            c = copy.deepcopy(rng.choice(fixtures()))
            for field, value in c['payload'].items():
                if type(value) is int:
                    c['payload'][field] = rng.getrandbits(16 if field == 'score_bps' else 64)
                elif isinstance(value, list) and len(value) == 32:
                    c['payload'][field] = list(rng.randbytes(32))
            rows += [typed(c, 1), typed(c)]
        self.compare(rows)

    def test_borrowed_frame_capacity_and_typed_shape_refusals(self):
        fixture = self.base[0]
        flat = bytes.fromhex(fixture['flat_input'])
        raw = header(1, 1, flat)
        required = 2560+16*len(flat)
        cases = []
        for n in (0, 1, 23):
            cases.append((raw[:n], 2048, required+29, 65))
        for p in (0, 3, 5, 7, 16, 23):
            changed = bytearray(raw);changed[p] ^= 1
            cases.append((bytes(changed), 2048, required+29, 65))
        for n in (0, 1, 127):
            cases.append((raw, n, required+29, 64))
        for n in (0, 1, required-1):
            cases.append((raw, 2048, n, 64))
        for p in (0, 1, len(flat)-1):
            data = flat[:p]
            cases.append((header(1, 1, data), 2048, 2560+16*len(data)+29, 65))
        cases.append((header(1, 1, flat+b'\0'), 2048, required+16+29, 65))
        cases.append((raw, 128, required+29, 64))
        for wire, out, scratch, code in cases:
            result = self.module.call_many([('f0', [wire, b'\xa5'*out, b'\x5a'*scratch])], timeout=15)[0]
            result.require_returned()
            self.assertEqual(result.value, code)
            self.assertEqual(result.arguments[0], wire)
            self.assertEqual(result.arguments[1], b'\xa5'*out)
            type(self).abi += 1
