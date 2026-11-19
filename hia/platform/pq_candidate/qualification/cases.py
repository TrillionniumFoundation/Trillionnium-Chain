"""Deterministic test data for the original Candidate API, never a PQ runtime."""
import hashlib


PARAMETERS = (65, 87)
SEEDS = (bytes(32), bytes([1]) * 32, bytes([31]) * 32, bytes([255]) * 32, bytes(range(32)))
LENGTHS = (0, 1, 2, 63, 64, 65, 135, 136, 137, 175, 176, 255, 256, 4096, 65535, 65536)
MODE_MESSAGE = b'TRNM/Test/PQCandidate/v1\0exact message'
PARTITIONS = ('methods', 'verify-65', 'verify-87')


def message(size):
    block = bytes(range(251))
    return block * (size // len(block)) + block[:size % len(block)]


def fixture_requests():
    rows = []
    for parameter in PARAMETERS:
        for index, seed in enumerate(SEEDS):
            rows.append({'label': f'key-{parameter}-{index}', 'request': {
                'op': 'keygen', 'parameter': parameter, 'seed': seed.hex()}})
        for size in LENGTHS:
            rows.append({'label': f'sign-{parameter}-{size}', 'request': {
                'op': 'sign', 'parameter': parameter, 'seed': SEEDS[2].hex(),
                'message': message(size).hex()}})
        for index in (0, 1, 3, 4):
            rows.append({'label': f'sign-seed-{parameter}-{index}', 'request': {
                'op': 'sign', 'parameter': parameter, 'seed': SEEDS[index].hex(),
                'message': MODE_MESSAGE.hex()}})
        rows.append({'label': f'math-key-{parameter}', 'request': {
            'op': 'keygen_math', 'parameter': parameter, 'seed': (bytes([38]) * 32).hex()}})
    return rows


def fixture_map(rows, observed):
    assert len(rows) == len(observed) and len({row['label'] for row in rows}) == len(rows)
    assert all(value['code'] == 0 for value in observed)
    return {row['label']: value for row, value in zip(rows, observed)}


def mode_requests(first):
    rows = []
    digest = hashlib.sha512(MODE_MESSAGE).digest()
    framed = bytes([1, 0]) + bytes.fromhex('0609608648016503040203') + digest
    for parameter in PARAMETERS:
        key = first[f'math-key-{parameter}']
        for mode, profile, body, context in (
                ('context', 1, MODE_MESSAGE, b'different FIPS context'),
                ('context-255', 1, MODE_MESSAGE, bytes(range(255))),
                ('internal', 2, MODE_MESSAGE, b''),
                ('prehash', 2, framed, b''),
                ('raw-mu', 3, digest, b'')):
            rows.append({'label': f'mode-{parameter}-{mode}', 'request': {
                'op': 'sign_math', 'parameter': parameter, 'sk': key['sk'],
                'rnd': bytes(32).hex(), 'profile': profile,
                'message': body.hex(), 'context': context.hex()}})
        rows.append({'label': f'mode-{parameter}-digest-message', 'request': {
            'op': 'sign', 'parameter': parameter, 'seed': (bytes([38]) * 32).hex(),
            'message': digest.hex()}})
    return rows


def mode_validation_requests(first, rows, second):
    requests = []
    for row in rows:
        request = row['request']
        parameter = request['parameter']
        requests.append({'op': 'verify_math', 'parameter': parameter,
            'pk': first[f'math-key-{parameter}']['pk'],
            'signature': second[row['label']]['signature'],
            'message': request['message'], 'context': request.get('context', ''),
            'profile': request.get('profile', 1)})
    return requests


def corpus(first_values, mode_values):
    initial = fixture_requests()
    first = fixture_map(initial, first_values)
    modes = mode_requests(first)
    second = fixture_map(modes, mode_values)
    rows = []

    def add(label, request):
        partition = ('verify-' + str(request['parameter'])) if request['op'] == 'verify' else 'methods'
        rows.append({'label': label, 'partition': partition, 'original': request})

    for parameter in PARAMETERS:
        add(f'info-{parameter}', {'op': 'info', 'parameter': parameter})
    amounts = (0, 1, 9, 10, 99, 100, 65535, 65536, 65537, (1 << 32) - 1,
               1 << 32, (1 << 63) - 1, 1 << 63, (1 << 64) - 1)
    for code in range(2, 9):
        for index, actual in enumerate(amounts):
            expected = amounts[-index - 1]
            add(f'error-{code}-{index}', {'op': 'error_display', 'code': code,
                'expected': expected, 'actual': actual})
    for row in initial:
        if not row['label'].startswith('math-key-'):
            add(row['label'], row['request'])
    for parameter in PARAMETERS:
        public = bytes.fromhex(first[f'key-{parameter}-2']['pk'])
        base_message = message(176)
        signature = bytes.fromhex(first[f'sign-{parameter}-176']['signature'])
        pk_size, signature_size = len(public), len(signature)

        def verify(label, pk=public, msg=base_message, sig=signature):
            add(f'{parameter}-{label}', {'op': 'verify', 'parameter': parameter,
                'pk': pk.hex(), 'message': msg.hex(), 'signature': sig.hex()})

        for size in LENGTHS:
            verify(f'valid-{size}', msg=message(size), sig=bytes.fromhex(first[f'sign-{parameter}-{size}']['signature']))
        for index in (0, 1, 3, 4):
            verify(f'wrong-key-{index}', pk=bytes.fromhex(first[f'key-{parameter}-{index}']['pk']))
        for index, pk in enumerate((bytes(pk_size), bytes([255]) * pk_size, message(pk_size))):
            verify(f'raw-public-pattern-{index}', pk=pk)
        other_pk = 2592 if parameter == 65 else 1952
        for size in (0, 1, 31, 32, pk_size - 1, pk_size + 1, other_pk, 1048577):
            for mixed in (False, True):
                verify(f'public-length-{size}-{int(mixed)}', pk=message(size),
                    msg=message(65537) if mixed else base_message, sig=b'' if mixed else signature)
        other_signature = 4627 if parameter == 65 else 3309
        for size in (0, 1, 31, 32, signature_size - 1, signature_size + 1, other_signature, 1048577):
            verify(f'signature-length-{size}', sig=message(size))
        for size in (65537, 1048577, 2097153):
            for suffix, sig in (('valid-signature', signature), ('empty-signature', b''),
                                ('malformed-signature', bytes(signature_size))):
                verify(f'oversize-{size}-{suffix}', msg=message(size), sig=sig)
            add(f'{parameter}-oversize-sign-{size}', {'op': 'sign', 'parameter': parameter,
                'seed': SEEDS[2].hex(), 'message': message(size).hex()})
        for size in (0, 1, 175, 177, 65536):
            verify(f'wrong-message-{size}', msg=message(size))
        verify('wrong-message-one-bit', msg=bytes([base_message[0] ^ 1]) + base_message[1:])
        verify('empty-signature-bytes', sig=bytes(signature_size))
        verify('ff-signature-bytes', sig=bytes([255]) * signature_size)
        challenge, polynomials, omega, count = (48, 5, 55, 6) if parameter == 65 else (64, 7, 75, 8)
        for at in range(challenge):
            for mask in (1, 128, 255):
                changed = bytearray(signature)
                changed[at] ^= mask
                verify(f'challenge-{at}-{mask}', sig=changed)
        for polynomial in range(polynomials):
            start = challenge + polynomial * 640
            for offset in (0, 1, 2, 3, 639):
                for mask in (1, 128, 255):
                    changed = bytearray(signature)
                    changed[start + offset] ^= mask
                    verify(f'z-{polynomial}-{offset}-{mask}', sig=changed)
            for fill in (0, 255):
                changed = bytearray(signature)
                changed[start:start + 640] = bytes([fill]) * 640
                verify(f'z-whole-{polynomial}-{fill}', sig=changed)
        hints = challenge + polynomials * 640
        for at in range(count):
            for invalid in (omega + 1, 255):
                changed = bytearray(signature)
                changed[hints + omega + at] = invalid
                verify(f'hint-cut-{at}-{invalid}', sig=changed)
        for at in range(1, count):
            changed = bytearray(signature)
            changed[hints:] = bytes(omega + count)
            changed[hints + omega + at - 1] = 2
            changed[hints + omega + at] = 1
            verify(f'hint-decreasing-{at}', sig=changed)
        for name, active, cuts in (
                ('none', b'', [0] * count),
                ('first-zero', b'\0', [1] * count),
                ('duplicate-in-poly', b'\x01\x01', [2] * count),
                ('descending-in-poly', b'\x02\x01', [2] * count),
                ('same-index-different-poly', b'\x01\x01', [1] + [2] * (count - 1)),
                ('last-index', b'\xff', [1] * count)):
            changed = bytearray(signature)
            changed[hints:] = active + bytes(omega - len(active)) + bytes(cuts)
            verify('hint-' + name, sig=changed)
        for at in (0, omega - 1):
            changed = bytearray(signature)
            changed[hints:] = bytes(omega + count)
            changed[hints + at] = 1
            verify(f'hint-nonzero-padding-{at}', sig=changed)
        for row in modes:
            if row['request']['parameter'] == parameter:
                verify(row['label'], pk=bytes.fromhex(first[f'math-key-{parameter}']['pk']),
                    msg=MODE_MESSAGE, sig=bytes.fromhex(second[row['label']]['signature']))
    assert len({row['label'] for row in rows}) == len(rows)
    assert set(row['partition'] for row in rows) == set(PARTITIONS)
    return rows


def selected(rows, partition):
    assert partition in PARTITIONS
    assert len({row['label'] for row in rows}) == len(rows)
    return [row for row in rows if row['partition'] == partition]
