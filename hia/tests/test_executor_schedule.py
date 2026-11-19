"""Real native seven-strategy scheduler, independent sets/graph reference.

The legacy model is a source-derived expectation, not a substitute for running
the unchanged Rust library.  The optional original-Rust qualification executes
that library separately and records its own status.  Only the explicit reader
high-water correction differs in the repaired reference used by native tests.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, replace
import base64
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import time
import unittest

from hia.tests.native_support import NativeModule

SOURCE = Path(__file__).resolve().parents[1] / 'src/executor/schedule.hepta'
U64 = (1 << 64) - 1


def float_bits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]


def float_value(value):
    return struct.unpack('<d', struct.pack('<Q', value))[0]


@dataclass(frozen=True)
class Tx:
    identity: int
    reads: tuple = ()
    writes: tuple = ()
    payload: bytes = b''


def tx(identity, reads=(), writes=(), payload=b'', version=1):
    return Tx(identity, tuple((key, version) for key in reads),
              tuple((key, version) for key in writes), payload)


@dataclass(frozen=True)
class Config:
    flags: int = 6
    buckets: int = 8
    minimum_batch: int = 512
    sample: int = 2048
    window: int = 0
    seed: int = 0
    threshold: int = float_bits(.22)
    margin: int = float_bits(.04)
    minimum_hot: int = float_bits(.0075)
    minimum_gain: int = float_bits(.01)

    def words(self):
        return [self.flags, self.buckets, self.minimum_batch, self.sample,
                self.window, self.seed, self.threshold, self.margin,
                self.minimum_hot, self.minimum_gain]


def frame(txs, strategy=0, config=Config(), operation=0):
    words = [operation, strategy, len(txs), *config.words(), 0, 0]
    result = bytearray(b'EXSCH001' + struct.pack('<15Q', *words))
    for item in txs:
        result.extend(struct.pack('<4Q', item.identity, len(item.reads),
                                  len(item.writes), len(item.payload)))
        for key, version in item.reads + item.writes:
            result.extend(struct.pack('<QQ', key, version))
        result.extend(item.payload)
    return bytes(result)


def sizes(txs, operation=0):
    references = sum(len(item.reads) + len(item.writes) for item in txs)
    return (264 + 16 * len(txs) if operation == 0 else 256,
            4096 + 168 * len(txs) + 72 * references)


def domains(txs):
    result = []
    for item in txs:
        versions = {}
        for key, version in item.reads + item.writes:
            if key in versions and versions[key] != version:
                raise ValueError('original public entry must reject version skew')
            versions[key] = version
        result.append(({key for key, _ in item.reads},
                       {key for key, _ in item.writes}))
    return result


def adaptive_key(reads, writes):
    if not reads and not writes:
        return None
    ordered_r, ordered_w = sorted(reads), sorted(writes)
    if not writes:
        return (ordered_r[0], ordered_r[1] if len(ordered_r) > 1 else 0)
    if not reads:
        return (ordered_w[0], ordered_w[1] if len(ordered_w) > 1 else 0)
    union = sorted(reads | writes)
    primary = union[0]
    remaining_r = [key for key in ordered_r if key != primary]
    remaining_w = [key for key in ordered_w if key != primary]
    if primary == 0 or (primary in reads and primary in writes
                        and (len(remaining_r) <= 1 or len(remaining_w) <= 1)):
        secondary = union[1] if len(union) > 1 else 0
    elif primary == ordered_w[0]:
        secondary = (remaining_w or remaining_r or [0])[0]
    else:
        secondary = ordered_w[0]
    if ordered_w[0] == primary:
        secondary = 0
    return primary, secondary


def adaptive_reference(txs, config=Config(), access=None):
    access = domains(txs) if access is None else access
    count = len(txs)
    thresholds = [config.threshold, config.margin,
                  config.minimum_hot, config.minimum_gain]
    def answer(use, reason, sample, ratio=0., share=0., gain=0.):
        return [int(use), reason, sample, float_bits(ratio), thresholds[0],
                thresholds[1], float_bits(share), thresholds[2],
                float_bits(gain), thresholds[3]]
    if count < config.minimum_batch:
        return answer(False, 1, count)
    sample = min(count, config.sample)
    indices = (range(count) if sample == count else
               [min(U64, i * (count - 1)) // (sample - 1)
                if sample > 1 else 0 for i in range(sample)])
    histogram = Counter()
    previous = None
    previous_index = None
    hits = pairs = observed = 0
    for index in indices:
        if index == previous_index:
            continue
        previous_index = index
        key = adaptive_key(*access[index])
        if key is None:
            previous = None
            continue
        histogram[key] += 1
        observed += 1
        if previous is not None:
            pairs += 1
            hits += previous == key
        previous = key
    if not pairs or not observed:
        return answer(False, 2, sample)
    ratio = float(hits) / float(pairs)
    share = float(max(histogram.values())) / float(observed)
    gain = ratio * share
    threshold, margin, minimum_hot, minimum_gain = map(float_value, thresholds)
    use = ratio >= threshold + margin and share >= minimum_hot and gain >= minimum_gain
    reason = (3 if use else 4 if share < minimum_hot else
              5 if gain < minimum_gain else 6)
    return answer(use, reason, sample, ratio, share, gain)


def order_reference(txs, access, strategy, config):
    order = list(range(len(txs)))
    if strategy == 1:
        return sorted(order, key=lambda i: (-len(access[i][0] | access[i][1]), txs[i].identity))
    if strategy in (2, 3):
        return sorted(order, key=lambda i: ((-1 if strategy == 2 else 1) * len(access[i][1]),
                                           -len(access[i][0]), txs[i].identity))
    if strategy != 4 or len(txs) < 4 or not any(r or w for r, w in access):
        return order
    count = min(config.buckets, len(txs))
    def hint(pair):
        keys = sorted(pair[0] | pair[1])
        mixed = keys[0] if keys else 0
        if len(keys) > 1:
            mixed ^= ((keys[1] << 7) | (keys[1] >> 57)) & U64
        return mixed % count
    hints = [hint(pair) for pair in access]
    buckets = [deque() for _ in range(count)]
    for index, bucket in enumerate(hints):
        buckets[bucket].append(index)
    signaled = {bucket for bucket, (reads, writes) in zip(hints, access) if reads or writes}
    active = [index for index, bucket in enumerate(buckets) if bucket]
    if len(active) <= 1 or len(signaled) <= 1 or len(active) == len(txs):
        return order
    first = hints[0]
    shallow = min(map(len, (buckets[index] for index in active)))
    if max(map(len, buckets)) >= min(U64, 2 * shallow):
        start = min((index for index in active if len(buckets[index]) == shallow),
                    key=lambda index: (min((index-first) % count, (first-index) % count),
                                       (first-index) % count, index))
    else:
        start = first
    result = []
    while any(buckets):
        for index in [(start + step) % count for step in range(count)]:
            if buckets[index]:
                result.append(buckets[index].popleft())
        start = (start + 1) % count
    return result


def schedule_reference(txs, strategy=0, config=Config(), repaired=True, operation=0):
    """Independent container model; repaired toggles exactly reader max update."""
    access = domains(txs)
    decision = [0] * 10
    selected = strategy
    if operation == 1:
        (ar, aw), (br, bw) = access
        return {'groups': [], 'group_count': int(bool(aw & (br | bw) or ar & bw)),
                'selected': strategy, 'profile': [0]*17, 'decision': decision}
    if operation == 2 or (strategy == 5 and txs):
        decision = adaptive_reference(txs, config, access)
        if operation == 0:
            selected = 4 if decision[0] else 0
    if operation == 2:
        return {'groups': [], 'group_count': 0, 'selected': strategy,
                'profile': [0]*17, 'decision': decision}
    order = order_reference(txs, access, selected, config)
    groups = []
    readers, writers = {}, {}
    # All ten counters are output in their public Rust field order.
    checks = hits = scanned = fallback = 0
    ww_checks = ww_hits = wr_checks = wr_hits = rw_checks = rw_hits = 0
    group_reads, group_writes = [], []
    cursor = config.seed
    free = not any(reads or writes for reads, writes in access)
    deep = selected == 6 and bool(config.flags & 1)
    skip = bool(config.flags & 2)
    rr = bool(config.flags & 4)
    for index in order:
        all_reads, write_keys = access[index]
        read_keys = all_reads - write_keys
        dependencies = ([writers[key] for key in read_keys if key in writers] +
                        [writers[key] for key in write_keys if key in writers] +
                        [readers[key] for key in write_keys if key in readers])
        minimum = max((group + 1 for group in dependencies), default=0)
        if free:
            target = 0
        elif not deep:
            checks += len(read_keys) + 2 * len(write_keys)
            hits += len(dependencies)
            target = minimum
        else:
            span = max(0, len(groups)-minimum)
            target = minimum if skip and not read_keys and not write_keys and span else None
            start = cursor % span if rr and span > 1 else 0
            for step in range(span):
                if target is not None or (config.window and step >= config.window):
                    break
                candidate = minimum + ((start+step) % span)
                scanned += 1
                if not skip or write_keys:
                    checks += 1
                    ww_checks += 1
                    if write_keys & group_writes[candidate]:
                        hits += 1
                        ww_hits += 1
                        continue
                    checks += 1
                    wr_checks += 1
                    if write_keys & group_reads[candidate]:
                        hits += 1
                        wr_hits += 1
                        continue
                if not skip or read_keys:
                    checks += 1
                    rw_checks += 1
                    if read_keys & group_writes[candidate]:
                        hits += 1
                        rw_hits += 1
                        continue
                target = candidate
            if target is None:
                fallback += span > 0
                target = len(groups)
            if rr and span > 1:
                cursor = (cursor + 1) & U64
        while len(groups) <= target:
            groups.append([])
            group_reads.append(set())
            group_writes.append(set())
        groups[target].append(index)
        group_reads[target].update(read_keys)
        group_writes[target].update(write_keys)
        for key in read_keys:
            readers[key] = max(readers.get(key, 0), target) if repaired else target
        for key in write_keys:
            writers[key] = target
    totals = Counter(key for reads, writes in access for key in reads | writes)
    sum_keys = sum(totals.values())
    n, count = len(txs), len(groups)
    profile = [n, count, n, max(map(len, groups), default=0), min(map(len, groups), default=0),
               float_bits(float(n)/float(count) if count else 0.),
               float_bits(float(max(totals.values()))/float(sum_keys) if sum_keys else 0.),
               checks, hits, scanned, fallback,
               ww_checks, ww_hits, wr_checks, wr_hits, rw_checks, rw_hits]
    return {'groups': groups, 'group_count': count, 'selected': selected,
            'profile': profile, 'decision': decision}


def graph_violations(txs, groups):
    """Pairwise graph uses original raw references, not the scheduling maps."""
    violations = []
    for group_index, group in enumerate(groups):
        for first, second in itertools.combinations(group, 2):
            a, b = txs[first], txs[second]
            ar, aw = {r[0] for r in a.reads}, {r[0] for r in a.writes}
            br, bw = {r[0] for r in b.reads}, {r[0] for r in b.writes}
            keys = (aw & bw) | (aw & br) | (ar & bw)
            if keys:
                violations.append((group_index, first, second, sorted(keys)))
    return violations


def decoded_output(raw, count, operation):
    words = list(struct.unpack('<32Q', raw[:256]))
    if words[0] != int.from_bytes(b'EXSCOUT1', 'little') or words[1] != operation or words[2] != count:
        raise AssertionError('wrong native frame identity')
    groups = []
    written = 256
    if operation == 0:
        amount = words[3]
        written = 264 + 8 * (count + amount)
        offsets = struct.unpack_from('<' + 'Q' * (amount+1), raw, 256)
        if offsets[0] != 0 or offsets[-1] != count or sorted(offsets) != list(offsets):
            raise AssertionError('invalid native group offsets')
        items = struct.unpack_from('<' + 'Q' * count, raw, 264+8*amount)
        groups = [list(items[start:end]) for start, end in zip(offsets, offsets[1:])]
    return {'groups': groups, 'group_count': words[3], 'selected': words[4],
            'profile': words[5:22], 'decision': words[22:32]}, written


def original_counterexample():
    return [tx(1, writes=[2]), tx(2, reads=[1, 2]),
            tx(3, reads=[1]), tx(4, writes=[1])]


RAW_WORKER = r'''
import base64, ctypes, fcntl, hashlib, json, os, resource, sys, time
request = json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
binary = open(request['path'], 'rb').read()
if hashlib.sha256(binary).hexdigest() != request['sha256']:
    raise ValueError('native artifact changed')
fd = os.memfd_create('executor-schedule-native', os.MFD_ALLOW_SEALING)
try:
    position = 0
    while position < len(binary):
        amount = os.write(fd, binary[position:])
        if amount <= 0:
            raise OSError('short artifact write')
        position += amount
    fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    if fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034)) != 15:
        raise ValueError('artifact not sealed')
    library = ctypes.CDLL('/proc/self/fd/' + str(fd))
finally:
    os.close(fd)
function = library.f0
function.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
function.restype = ctypes.c_uint64
def arena(size, residue, fill):
    if not 0 <= size <= 8 << 20:
        raise ValueError('development extent bound')
    allocation = ctypes.create_string_buffer(size + 64)
    ctypes.memset(ctypes.addressof(allocation), fill, ctypes.sizeof(allocation))
    offset = 16 + ((residue - ctypes.addressof(allocation)) % 8)
    return allocation, offset, size, ctypes.addressof(allocation) + offset
def content(item):
    return item[0].raw[item[1]:item[1]+item[2]]
def guards(item):
    return item[0].raw[:item[1]], item[0].raw[item[1]+item[2]:]
answers = []
for sequence in request['sequences']:
    rows = sequence['rows']
    raw_rows = [base64.b64decode(row['raw'], validate=True) for row in rows]
    a = arena(max(map(len, raw_rows)), sequence['residues'][0], 0x69)
    o = arena(max(row['output'] for row in rows) + 31, sequence['residues'][1], 0xa7)
    s = arena(max(row['scratch'] for row in rows) + 37, sequence['residues'][2], 0xc4)
    extents = sorted((item[3], item[3]+item[2]) for item in (a,o,s))
    if any(right > end for (_,right),(end,_) in zip(extents,extents[1:])):
        raise ValueError('borrowed memory overlaps')
    addresses = [item[3] for item in (a,o,s)]
    for raw,row in zip(raw_rows,rows):
        ctypes.memmove(a[3], raw, len(raw))
        ctypes.memset(o[3], 0xa7, o[2])
        before = [content(item) for item in (a,o,s)]
        before_guards = [guards(item) for item in (a,o,s)]
        started = time.monotonic_ns()
        packed = function(a[3],len(raw),o[3],row['output'],s[3],row['scratch'])
        elapsed = time.monotonic_ns()-started
        after = [content(item) for item in (a,o,s)]
        answers.append({'value':packed & 0xffffffff, 'abi_status':packed >> 32,
            'addresses':addresses,'residues':[value % 8 for value in addresses],
            'output':after[1][:row['output']].hex(), 'elapsed_ns':elapsed,
            'input_unchanged':before[0] == after[0],
            'output_outside_borrow_unchanged':before[1][row['output']:] == after[1][row['output']:],
            'scratch_unchanged':before[2] == after[2],
            'scratch_outside_used_unchanged':before[2][row['used']:] == after[2][row['used']:],
            'scratch_outside_borrow_unchanged':before[2][row['scratch']:] == after[2][row['scratch']:],
            'guards_unchanged':before_guards == [guards(item) for item in (a,o,s)]})
print(json.dumps({'sha256':hashlib.sha256(binary).hexdigest(),'answers':answers,
                  'compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]}))
'''


class ExecutorScheduleNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        cls.native = NativeModule(SOURCE, byte_exports=('f0',))
        cls.addClassCleanup(cls.native.close)
        cls.invocations = 0
        cls.intentional_differences = []

    @classmethod
    def tearDownClass(cls):
        destination = os.environ.get('HIA_EXECUTOR_OBSERVATIONS')
        if destination:
            record = {'schema': 'trnm.hia.executor-development-observations.v1',
                      'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                      'artifact_sha256': cls.native.artifact_sha256,
                      'build_receipt': cls.native.receipt,
                      'native_invocations': cls.invocations,
                      'raw_extent_observation': getattr(cls, 'raw_extent_observation', None),
                      'wall_seconds': time.monotonic()-cls.started,
                      'intentional_legacy_differences': cls.intentional_differences,
                      'legacy_rust_execution': 'NOT_RUN_BY_THIS_SUITE',
                      'whole_executor_crate_native': False,
                      'ordinary_node_dependency': False,
                      'whole_chain_native': False}
            Path(destination).write_text(json.dumps(record, indent=2)+'\n')

    def check_cases(self, rows):
        # Each row: (transactions, strategy, effective config, operation).
        for offset in range(0, len(rows), 64):
            batch = rows[offset:offset+64]
            calls = []
            for txs, strategy, config, operation in batch:
                output, scratch = sizes(txs, operation)
                calls.append(('f0', [frame(txs, strategy, config, operation),
                                      bytes([0xA7]) * (output+19),
                                      bytes([0xC4]) * (scratch+23)]))
            results = self.native.call_many(calls, timeout=60)
            type(self).invocations += len(calls)
            for row, call, result in zip(batch, calls, results):
                txs, strategy, config, operation = row
                result.require_returned()
                self.assertEqual(result.value, 0, (strategy, config, txs))
                expected = schedule_reference(txs, strategy, config, True, operation)
                actual, written = decoded_output(result.arguments[1], len(txs), operation)
                self.assertEqual(actual, expected, (strategy, config, txs))
                self.assertEqual(result.arguments[0], call[1][0])
                self.assertEqual(result.arguments[1][written:], call[1][1][written:])
                self.assertEqual(result.arguments[2][sizes(txs, operation)[1]:], bytes([0xC4])*23)
                if operation == 0:
                    self.assertEqual(sorted(itertools.chain.from_iterable(actual['groups'])), list(range(len(txs))))
                    self.assertEqual(graph_violations(txs, actual['groups']), [])
                    old = schedule_reference(txs, strategy, config, False)
                    if old != expected:
                        # Retain compact case identity and full old/new result: no
                        # failed original behavior is silently treated as equivalent.
                        type(self).intentional_differences.append({
                            'input_sha256': hashlib.sha256(call[1][0]).hexdigest(),
                            'count': len(txs), 'strategy': strategy,
                            'config_words': config.words(),
                            'legacy_source_derived': old, 'native_repaired': actual,
                            'legacy_conflicts': graph_violations(txs, old['groups'])})

    def test_explicit_reader_regression_and_seven_strategies(self):
        cases = original_counterexample()
        repaired = schedule_reference(cases)
        # Exact pre-fix counterexample; this is source-derived until Rust CI runs.
        self.assertEqual(repaired['groups'], [[0, 2], [1], [3]])
        original = schedule_reference(cases, repaired=False)
        self.assertEqual(original['groups'], [[0, 2], [1, 3]])
        self.assertEqual(graph_violations(cases, original['groups']), [(1, 1, 3, [1])])
        rows = [(cases, strategy, Config(), 0) for strategy in range(7)]
        rows += [(cases, 6, replace(Config(), flags=flags, seed=seed, window=window), 0)
                 for flags in (1, 3, 5, 7) for seed in (0, 1, U64) for window in (0, 1, 4096)]
        self.check_cases(rows)

    def test_empty_payload_identity_ties_and_object_domain_edges(self):
        samples = [[], [tx(0)], [tx(U64), tx(0), tx(U64), tx(0)],
                   [tx(7, [0, 0], [0, 0], b'\0\xffsame'),
                    tx(7, [U64], [1 << 63], b'\0\xffsame'),
                    tx(7, [0], [U64], b'other'), tx(0, [1 << 63], [], b'')],
                   [tx(i % 3, [i % 7] * 3, [i % 5] * 4, bytes([i]), version=(i * 17) & U64)
                    for i in range(20)]]
        self.check_cases([(items, strategy, Config(), 0) for items in samples for strategy in range(7)])
        # Across transactions a version is not the conflict identity.
        pairs = [[tx(1, [0], version=0), tx(1, [0], version=U64)],
                 [tx(1, [0], version=0), tx(1, [], [0], version=U64)],
                 [tx(1, [], [U64]), tx(1, [], [U64])],
                 [tx(1, [], [U64]), tx(1, [1 << 63])],
                 [tx(1), tx(1)]]
        self.check_cases([(items, 0, Config(), 1) for items in pairs])

    def test_exhaustive_four_transaction_access_graphs(self):
        # Both valid key 0 and a second key, pure/mixed/keyless/echo domains.
        choices = [tx(0), tx(0, [0]), tx(0, [], [0]), tx(0, [1]),
                   tx(0, [], [1]), tx(0, [0, 1]), tx(0, [0], [1]), tx(0, [0], [0])]
        rows = []
        for ordinal, indices in enumerate(itertools.product(range(len(choices)), repeat=4)):
            items = [replace(choices[value], identity=(position+ordinal) % 3)
                     for position, value in enumerate(indices)]
            strategy = ordinal % 7
            flags = (1, 3, 5, 7)[ordinal % 4] if strategy == 6 else 6
            config = replace(Config(), flags=flags, seed=U64-ordinal, window=(0, 1, 2)[ordinal % 3])
            rows.append((items, strategy, config, 0))
        self.check_cases(rows)

    def test_random_full_strategy_configs_and_duplicate_references(self):
        rng = random.Random(0xEC5C001)
        keys = [0, 1, 2, 3, 4, 5, 7, 8, 31, 1 << 32, 1 << 63, U64]
        rows = []
        for iteration in range(180):
            items = []
            for index in range(rng.randrange(1, 80)):
                reads = [rng.choice(keys) for _ in range(rng.randrange(7))]
                writes = [rng.choice(keys) for _ in range(rng.randrange(7))]
                items.append(tx(rng.choice([0, 1, U64, index]), reads, writes,
                                rng.randbytes(rng.randrange(17)), version=rng.getrandbits(64)))
            config = replace(Config(), flags=rng.randrange(8), buckets=rng.randrange(4, 65),
                             minimum_batch=64, sample=rng.choice([64, 65, 511, 2048]),
                             window=rng.choice([0, 1, 2, 17, 4096]), seed=rng.getrandbits(64))
            rows.extend((items, strategy, config, 0) for strategy in range(7))
        self.check_cases(rows)

    def test_hot_bucket_full_fanout_sparse_ties_and_unsigned_rotation(self):
        rows = []
        for buckets in range(4, 65):
            samples = [[tx(i, [key]) for i, key in enumerate([3]*5 + [1, 5, 2, 2, 2, 2])],
                       [tx(i, [], [key]) for i, key in enumerate([U64, 1<<63, 0, 1<<32]*7)],
                       [tx(i, [U64, 0, 1<<63], [2]) for i in range(4)] + [tx(9)]*3,
                       [tx(i, [i]) for i in range(buckets)],
                       [tx(i, [1]) if i % 2 else tx(i) for i in range(8)]]
            rows.extend((items, 4, replace(Config(), buckets=buckets), 0) for items in samples)
        self.check_cases(rows)

    def test_adaptive_reasons_mixed_keys_and_exact_float_boundaries(self):
        base = replace(Config(), minimum_batch=64, sample=64)
        none = [tx(i) for i in range(64)]
        hot = [tx(i, [1]) for i in range(64)]
        alternating = [tx(i, [i % 2]) for i in range(64)]
        broken = [tx(i, [1]) if i % 2 else tx(i) for i in range(64)]
        mixed = [tx(i, [0, 1, 2], [0, 3, 4]) if i % 3 == 0 else
                 tx(i, [5, 7], [5, 6]) if i % 3 == 1 else tx(i, [2, 6], [5, 8]) for i in range(64)]
        samples = [[], hot[:63], none, hot, alternating, broken, mixed]
        configs = [base, replace(base, threshold=float_bits(1.), margin=0),
                   replace(base, threshold=0, margin=0, minimum_hot=0, minimum_gain=0),
                   replace(base, threshold=1 << 63, margin=1 << 63,
                           minimum_hot=1 << 63, minimum_gain=1 << 63),
                   replace(base, threshold=1, margin=(1 << 52)-1,
                           minimum_hot=1, minimum_gain=1),
                   replace(base, minimum_hot=float_bits(.75)),
                   replace(base, minimum_gain=float_bits(.9))]
        rows = [(items, 5, config, operation) for items in samples for config in configs
                for operation in (0, 2)]
        # Threshold equality and its adjacent binary64 values, including addition
        # of a tiny positive subnormal that must round away at a normal boundary.
        streak = [tx(i, [1 if i < 49 else i]) for i in range(64)]
        measure = adaptive_reference(streak, base)
        for field, value in [('threshold', measure[3]), ('minimum_hot', measure[6]),
                             ('minimum_gain', measure[8])]:
            for adjacent in (value-1, value, value+1):
                for margin in (0, 1):
                    config = replace(base, threshold=0, margin=margin, minimum_hot=0, minimum_gain=0)
                    config = replace(config, **{field: adjacent})
                    rows.append((streak, 5, config, 2))
        self.check_cases(rows)

    def test_adaptive_sampling_includes_both_endpoints_and_2048_sample(self):
        samples = []
        for count, sample in [(65, 64), (2049, 2048), (4097, 64), (4097, 2048)]:
            items = [tx(i, [1 if i > count//3 else (i % 19)+2]) for i in range(count)]
            items[0] = tx(0, [U64])
            items[-1] = tx(U64, [0])
            samples.append((items, 5, replace(Config(), minimum_batch=64, sample=sample), 2))
        self.check_cases(samples)

    def test_deep_wide_group_span_and_maximum_adaptive_batch_floor(self):
        # Thousands of dependency groups exercise full-width RR indices rather
        # than reducing the original behavior to toy batches or a small cap.
        chain = [tx(i,writes=[0]) for i in range(4100)] + [tx(4100,reads=[U64]),tx(4101)]
        self.check_cases([(chain,6,replace(Config(),flags=flags,seed=seed,window=window),0)
                          for flags,seed,window in [(1,0,0),(3,0,4096),(5,4096,1),(7,U64,4096)]])
        samples = []
        for count in (4095,4096,4097):
            items = [tx(i,reads=[i%17]) for i in range(count)]
            samples.append((items,5,replace(Config(),minimum_batch=4096,sample=64),2))
        self.check_cases(samples)

    def test_wire_config_and_version_refusals_keep_output_atomic(self):
        valid_txs = [tx(1, [0], [1], b'opaque')]
        good = frame(valid_txs)
        outsize, scratchsize = sizes(valid_txs)
        def alter(offset, value, raw=good):
            result = bytearray(raw)
            struct.pack_into('<Q', result, offset, value)
            return bytes(result)
        malformed = [(good[:length], 1, True) for length in (0, 7, 127, 128, 159, len(good)-1)]
        malformed += [(b'badmagic'+good[8:], 2, True), (good+b'x', 1, True)]
        for offset, value in [(8, 3), (16, 7), (32, 8), (40, 3), (40, 65), (48, 63),
                              (48, 4097), (56, 63), (56, 2049), (64, 4097), (112, 1), (120, 1),
                              (80, float_bits(-1.)), (88, 0x7ff0000000000000),
                              (96, 0x7ff8000000000000), (104, float_bits(1.)+1)]:
            malformed.append((alter(offset, value), 3, True))
        for offset in (24, 136, 144, 152):
            malformed.append((alter(offset, U64), 1, True))
        malformed.append((frame(valid_txs, operation=1), 3, True))
        skew = [Tx(1, ((0, 0), (0, 1)), (), b''),
                Tx(1, (), ((U64, 0), (U64, U64)), b''),
                Tx(1, ((1, 1),), ((1, 2),), b'')]
        for item in skew:
            for strategy in range(7):
                malformed.append((frame([item], strategy), 5, False))
        calls = [('f0', [raw, bytes([0xA7])*outsize, bytes([0xC4])*(scratchsize+1000)])
                 for raw, _, _ in malformed]
        calls.extend([('f0', [good, bytes([0xA7])*(outsize-1), bytes([0xC4])*scratchsize]),
                      ('f0', [good, bytes([0xA7])*outsize, bytes([0xC4])*(scratchsize-1)])])
        codes = [code for _, code, _ in malformed] + [100, 100]
        untouched = [clean for _, _, clean in malformed] + [True, True]
        results = self.native.call_many(calls)
        type(self).invocations += len(calls)
        for call, result, code, clean in zip(calls, results, codes, untouched):
            result.require_returned()
            self.assertEqual(result.value, code, call[1][0].hex())
            self.assertEqual(result.arguments[:2], call[1][:2])
            if clean:
                self.assertEqual(result.arguments[2], call[1][2])

    def test_raw_unaligned_reused_arena_and_beyond_runner_megabyte(self):
        # The shared runner's 1 MiB private-buffer bound is not a product limit.
        large = [tx(index, writes=[index % 17], payload=b'\xff') for index in range(8192)]
        rows = []
        def add(items, *, short=False, bad_magic=False):
            output, scratch = sizes(items)
            raw = frame(items)
            if bad_magic:
                raw = b'badmagic'+raw[8:]
            rows.append({'raw':base64.b64encode(raw).decode(), 'output':output,
                         'scratch':scratch-int(short), 'used':scratch,
                         'code':100 if short else 2 if bad_magic else 0,
                         'expected':schedule_reference(items) if not (short or bad_magic) else None,
                         'count':len(items)})
        add(large)
        add(large, short=True)
        add(original_counterexample())
        add([], bad_magic=True)
        add([])
        sequence = {'residues':[1,3,5], 'rows':[{key:value for key,value in row.items()
                                              if key not in {'expected'}} for row in rows]}
        request = {'path':str(self.native.library), 'sha256':self.native.artifact_sha256,
                   'sequences':[sequence]}
        completed = subprocess.run([sys.executable,'-I','-S','-B','-c',RAW_WORKER],
            input=json.dumps(request),capture_output=True,text=True,timeout=40,check=False)
        self.assertEqual(completed.returncode,0,completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed['sha256'],self.native.artifact_sha256)
        self.assertEqual(observed['compiler_modules_loaded'],[])
        self.assertEqual(len(observed['answers']),len(rows))
        type(self).invocations += len(rows)
        addresses = observed['answers'][0]['addresses']
        self.assertGreater(rows[0]['scratch'],1 << 20)
        for row,answer in zip(rows,observed['answers']):
            self.assertEqual(answer['addresses'],addresses)
            self.assertEqual(answer['residues'],[1,3,5])
            self.assertEqual(answer['abi_status'],0)
            self.assertEqual(answer['value'],row['code'])
            for field in ('input_unchanged','output_outside_borrow_unchanged',
                          'scratch_outside_used_unchanged','scratch_outside_borrow_unchanged',
                          'guards_unchanged'):
                self.assertTrue(answer[field],field)
            output = bytes.fromhex(answer['output'])
            if row['code']:
                self.assertEqual(output,bytes([0xa7])*row['output'])
                self.assertTrue(answer['scratch_unchanged'])
            else:
                actual,written = decoded_output(output,row['count'],0)
                self.assertEqual(actual,row['expected'])
                self.assertEqual(output[written:],bytes([0xa7])*(len(output)-written))
        self.assertEqual(graph_violations(large,rows[0]['expected']['groups']),[])
        type(self).raw_extent_observation = {'count':8192, 'scratch_bytes':rows[0]['scratch'],
            'native_wall_ns':observed['answers'][0]['elapsed_ns'],
            'pointer_residues':[1,3,5], 'cpu_budget_seconds':30,'wall_budget_seconds':40,
            'service_qualification':False}


if __name__ == '__main__':
    unittest.main()
