"""Observe the public Candidate DSO; original execution is a separate process."""
from collections import Counter
from pathlib import Path
import argparse
import ctypes as C
import gzip
import hashlib
import json
import lzma
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_candidate.qualification.api import Result, Scalar, View, buffer, load
from hia.platform.pq_candidate.qualification.cases import PARTITIONS, selected


class Observation:
    def __init__(self, image, digest, cases, partition, output):
        assert not sys.flags.optimize
        assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
        self.library, self.functions = load(image)
        self.output = output.absolute()
        self.output.mkdir()
        self.started = time.monotonic()
        self.report = {'status': 'FAIL', 'image_sha256': digest, 'partition': partition,
            'native_calls': 0, 'cases': 0, 'fresh_original_process_executed': False,
            'scope': 'actual native observations; separate original comparison required'}
        self.rows = selected(json.loads(lzma.decompress(cases.read_bytes())), partition)
        self.counts, self.live = Counter(), set()
        self.case = 'initial'
        self.calls = gzip.open(self.output / 'native-calls.jsonl.gz', 'xb', compresslevel=1)
        self.values = gzip.open(self.output / 'native-values.jsonl.gz', 'xb', compresslevel=1)

    def call(self, name, *arguments):
        value = self.functions[name](*arguments)
        self.counts[name] += 1
        self.report['native_calls'] += 1
        row = {'sequence': self.report['native_calls'], 'case': self.case, 'function': name}
        if isinstance(value, Result):
            row.update(status=value.status, has_value=bool(value.value))
        elif isinstance(value, Scalar):
            row.update(status=value.status, value=value.value)
        elif isinstance(value, View):
            raw = C.string_at(value.data, value.size) if value.data else b''
            row.update(has_data=bool(value.data), size=value.size, sha256=hashlib.sha256(raw).hexdigest())
        else:
            row['value'] = value
        self.calls.write((json.dumps(row, sort_keys=True) + '\n').encode())
        return value

    def own(self, value, kind=None):
        assert value.status == 0 and value.value, (self.case, value.status)
        assert value.value not in self.live
        self.live.add(value.value)
        actual = self.call('kind', value.value)
        assert kind is None or kind == actual, (self.case, kind, actual)
        return value.value

    def drop(self, owner):
        assert owner in self.live and self.call('drop', owner) == 0
        self.live.remove(owner)

    def view(self, name, owner):
        value = self.call(name, owner)
        assert value.data, (self.case, name)
        return C.string_at(value.data, value.size)

    def scalar(self, name, owner):
        value = self.call(name, owner)
        assert value.status == 0, (self.case, name, value.status)
        return value.value

    def name(self, algorithm):
        handle = self.own(self.call('algorithm_name', algorithm), 103)
        text = self.view('algorithm_name_bytes', handle).decode()
        self.drop(handle)
        return text

    def error(self, handle):
        if self.call('kind', handle) != 255:
            return None
        code = self.call('value_code', handle)
        expected = self.call('value_expected', handle)
        actual = self.call('value_actual', handle)
        text = self.own(self.call('error_display', handle), 105)
        display = self.view('value_bytes', text).decode()
        self.drop(text)
        return {'code': code, 'expected': expected, 'actual': actual, 'display': display}

    def execute(self, request):
        op = request['op']
        if op == 'error_display':
            value = self.own(self.call('candidate_error_display', request['code'],
                request['expected'], request['actual']), 105)
            return {'display': self.view('value_bytes', value).decode()}
        algorithm = request['parameter']
        if op == 'info':
            all_owner = self.own(self.call('algorithm_all'), 104)
            all_parameters = self.view('algorithm_all_bytes', all_owner)
            return {'name': self.name(algorithm),
                'public_key_bytes': self.scalar('algorithm_public_key_bytes', algorithm),
                'signature_bytes': self.scalar('algorithm_signature_bytes', algorithm),
                'nist_category': self.scalar('algorithm_nist_category', algorithm),
                'all': [self.name(parameter) for parameter in all_parameters]}
        if op in ('keygen', 'sign'):
            raw_seed = bytes.fromhex(request['seed'])
            seed_buffer = buffer(raw_seed)
            seed = self.own(self.call('seed_copy', seed_buffer, len(raw_seed)), 1)
            assert seed_buffer.raw[:len(raw_seed)] == raw_seed
            key = self.own(self.call('signing_from_owned_seed', algorithm, seed))
            self.live.remove(seed)
            error = self.error(key)
            if error:
                return error
            assert self.call('kind', key) == 2
            assert self.scalar('signing_algorithm', key) == algorithm
            row = {'code': 0, 'name': self.name(self.scalar('signing_algorithm', key)),
                'pk': self.view('signing_public_key', key).hex()}
            if op == 'keygen':
                return row
            raw_message = bytes.fromhex(request['message'])
            message_buffer = buffer(raw_message)
            signature = self.own(self.call('sign', key, message_buffer, len(raw_message)))
            assert message_buffer.raw[:len(raw_message)] == raw_message
            error = self.error(signature)
            if error:
                return error
            assert self.call('kind', signature) == 101
            row['signature'] = self.view('signature_bytes', signature).hex()
            assert self.view('value_bytes', signature).hex() == row['signature']
            return row
        assert op == 'verify'
        public, message, signature = (bytes.fromhex(request[field]) for field in ('pk', 'message', 'signature'))
        public_buffer, message_buffer, signature_buffer = map(buffer, (public, message, signature))
        key = self.own(self.call('verifier_from_pinned_raw', algorithm, public_buffer, len(public)))
        assert public_buffer.raw[:len(public)] == public
        error = self.error(key)
        if error:
            return error
        assert self.call('kind', key) == 3
        assert self.scalar('verifier_algorithm', key) == algorithm
        assert self.view('verifier_public_key', key) == public
        observed = self.own(self.call('verify', key, message_buffer, len(message), signature_buffer, len(signature)))
        assert message_buffer.raw[:len(message)] == message and signature_buffer.raw[:len(signature)] == signature
        error = self.error(observed)
        if error:
            return error
        assert self.call('kind', observed) == 102
        return {'code': self.call('value_code', observed), 'expected': self.call('value_expected', observed),
            'actual': self.call('value_actual', observed),
            'name': self.name(self.scalar('verifier_algorithm', key)),
            'pk': self.view('verifier_public_key', key).hex()}

    def run(self):
        try:
            for row in self.rows:
                assert not self.live
                self.case = row['label']
                try:
                    result = self.execute(row['original'])
                    self.values.write((json.dumps({'label': self.case, 'result': result}, sort_keys=True) + '\n').encode())
                    self.report['cases'] += 1
                finally:
                    for owner in tuple(self.live):
                        self.drop(owner)
            assert self.report['cases'] == len(self.rows) and not self.live
            self.report['status'] = 'PASS'
        except BaseException:
            self.report['traceback'] = traceback.format_exc()
            raise
        finally:
            self.calls.close()
            self.values.close()
            self.report.update(seconds=time.monotonic() - self.started,
                remaining_live_owners=len(self.live), function_counts=dict(sorted(self.counts.items())))
            (self.output / 'report.json').write_text(json.dumps(self.report, sort_keys=True, indent=2) + '\n')
        return self.report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--partition', choices=PARTITIONS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = Observation(args.image, args.image_sha256, args.cases, args.partition, args.output).run()
    print(json.dumps(value, sort_keys=True))
