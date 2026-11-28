"""Deterministic authenticated test WALs and observation-only AVL assertions."""
from pathlib import Path
import hashlib
import mmap
import random
import struct
word = lambda *items: struct.pack('<' + 'Q' * len(items), *items)
big = lambda value: struct.pack('>Q', value)
NS = bytes([1])*32 + bytes([3])*32 + bytes([4])*32 + bytes([5])*32 + word(7)
NS_HASH = hashlib.sha256(b'trnm.portable-g3.payload-replay.namespace.v1' + NS[:32] + big(7) + NS[32:128]).digest()

def record(index, previous, *, remote=None, direction=1, session=None, generation=1, sequence=0):
    raw = bytearray(380)
    raw[:8] = b'TRNPRW01'
    raw[8] = 1
    raw[9] = int(remote is not None)
    raw[12:20] = big(index)
    raw[20:52] = NS_HASH
    raw[52:84] = NS[:32]
    raw[124:132] = big(7)
    raw[132:228] = NS[32:128]
    raw[316:348] = previous
    if remote is not None:
        raw[84:116] = remote
        raw[116] = direction
        raw[228:260] = session or bytes([7]) * 32
        raw[260:268] = big(generation)
        raw[268:276] = big(sequence)
        raw[276] = 1
        raw[280:284] = struct.pack('>I', index % (8 * 1024 * 1024 + 1))
        raw[284:316] = hashlib.sha256(b'avl-fixture-fingerprint' + big(index)).digest()
    raw[348:] = hashlib.sha256(b'trnm.portable-g3.payload-replay.record.v1'
                               + big(348) + raw[:348]).digest()
    return bytes(raw)

def remote_key(number):
    assert number > 0
    # A long identical prefix exercises comparisons that hash routing can hide.
    return bytes(24) + big(number)

def inspect_tree(work_path, input_path):
    summaries = []
    with work_path.open('rb') as work_file, input_path.open('rb') as input_file:
        with mmap.mmap(work_file.fileno(), 0, access=mmap.ACCESS_READ) as work, \
                mmap.mmap(input_file.fileno(), 0, access=mmap.ACCESS_READ) as source:
            wal_bytes = len(source) - 144
            count = wal_bytes // 380
            assert len(work) == 8192 + wal_bytes + count * 128
            assert work[8192:8192 + wal_bytes] == source[144:]
            u64 = lambda offset: struct.unpack_from('<Q', work, offset)[0]
            assert u64(1544) == count
            assert work[2048:2184] == source[8:144]

            def key(record_at, mode):
                assert 8192 + 380 <= record_at < 8192 + wal_bytes
                assert (record_at - 8192) % 380 == 0
                common = bytes(work[record_at + 84:record_at + 117])
                offset, size = ((0, 0), (228, 32), (260, 16), (228, 88))[mode]
                return common + bytes(work[record_at + offset:record_at + offset + size])

            for mode in range(4):
                expected = {}
                for index in range(1, count):
                    record_at = 8192 + 380 * index
                    value = key(record_at, mode)
                    if mode == 0:
                        expected[value] = record_at
                    else:
                        expected.setdefault(value, record_at)
                nodes = u64(1760 + mode * 8)
                root = u64(1728 + mode * 8)
                base = u64(1552 + mode * 8)
                assert base == 8192 + wal_bytes + mode * count * 32
                assert nodes == len(expected) and 0 <= nodes < count
                visited = set()

                def walk(node, lower=None, upper=None):
                    if node == 0:
                        return 0
                    assert base <= node < base + nodes * 32 and (node - base) % 32 == 0
                    assert node not in visited
                    visited.add(node)
                    record_at, left, right, height = struct.unpack_from('<4Q', work, node)
                    value = key(record_at, mode)
                    assert (lower is None or lower < value) and (upper is None or value < upper)
                    assert expected.pop(value) == record_at
                    left_height = walk(left, lower, value)
                    right_height = walk(right, value, upper)
                    assert height == 1 + max(left_height, right_height)
                    assert abs(left_height - right_height) <= 1 and height <= 64
                    return height

                height = walk(root)
                assert not expected and len(visited) == nodes
                assert visited == set(range(base, base + nodes * 32, 32))
                assert not any(work[base + nodes * 32:base + count * 32])
                summaries.append({'mode': mode, 'nodes': nodes, 'height': height})
            return {'records': count, 'trees': summaries,
                    'summary_hex': work[6144:6216].hex(), 'whole_tree_invariants': True}


def names(large):
    answer = ['genesis-only','one-key','sorted','reverse','zigzag','permuted',
              'interleaved-generations','duplicate-sequence','reused-session','capacity-79','capacity-zero']
    if large:
        answer += ['maximal-aligned-sorted','exact-64m-truncated','over-64m','namespace-before-size']
    return answer

def specification(name, large):
    assert name in names(large)
    return {'name':name, 'output_size':79 if name=='capacity-79' else 0 if name=='capacity-zero' else 256,
            'observe_index':name in ['genesis-only','one-key','sorted','reverse','zigzag','permuted',
                                     'interleaved-generations','maximal-aligned-sorted']}

def blocks(name, large):
    assert name in names(large)
    ns = bytes(32)+NS[32:] if name=='namespace-before-size' else NS
    yield word(1)+ns
    count=4095 if large else 63
    ordered=list(range(1,count+1))
    if name=='genesis-only':frames=iter(())
    elif name in ['one-key','capacity-79','capacity-zero']:
        frames=iter([{'remote':remote_key(1)}])
    elif name in ['sorted','reverse','zigzag','permuted']:
        if name=='reverse':ordered.reverse()
        elif name=='permuted':random.Random(0x48494141564c).shuffle(ordered)
        elif name=='zigzag':
            ordered=[]
            for i in range((count+1)//2):
                ordered.append(i+1)
                if i+1<count-i:ordered.append(count-i)
        assert len(ordered)==len(set(ordered))==count
        frames=({'remote':remote_key(i)} for i in ordered)
    elif name=='interleaved-generations':
        frames=({'remote':remote_key(peer),'direction':direction,'session':bytes([generation+10])*32,
                 'generation':generation,'sequence':sequence}
                for generation in range(1,5) for sequence in range(5)
                for peer in range(1,33) for direction in (1,2))
    elif name=='duplicate-sequence':frames=iter([{'remote':remote_key(1)},{'remote':remote_key(1)}])
    elif name=='reused-session':
        frames=({'remote':remote_key(1),'generation':generation,
                 'session':bytes([7 if generation in (1,5) else generation+10])*32}
                for generation in range(1,6))
    else:frames=({'remote':remote_key(i)} for i in range(1,(64<<20)//380))
    previous=record(0,bytes(32));yield previous
    for number,frame in enumerate(frames,1):
        previous=record(number,previous[348:],**frame);yield previous
    if name in ['exact-64m-truncated','over-64m','namespace-before-size']:
        yield bytes((64<<20)%380 + (name!='exact-64m-truncated'))
