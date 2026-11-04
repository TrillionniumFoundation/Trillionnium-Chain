#!/usr/bin/env python3
"""P2 CPU-only proxy: exact V3 ticket SHA256 search on synthetic Cookie IDs.

No signed cookie, native V3 service, GPU, real network or independent adversary.
All misses, capped searches, measured process CPU and actual wall time remain
in the report. This tool changes no W1, V3 policy or consensus authority.
"""
import argparse
import hashlib
import json
import platform
import struct
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'formal/pon-nakamoto-v1'))
from contract_wire import H

SCHEMA = 'trnm-v3-cookie-cost-cpu-proxy-v1'


def attempt(cookie, nonce, bits):
    if len(cookie) != 32 or type(nonce) is not int or not 0 <= nonce < (1 << 64) or not 8 <= bits <= 20:
        raise ValueError('profile')
    value = H('public-ticket-v3', cookie, struct.pack('<Q', nonce))
    return int.from_bytes(value[:4], 'big') >> (32 - bits) == 0


def sample(bits, seed, max_attempts):
    cookie = H('synthetic-v3-cookie-id-p2-cpu-only', struct.pack('<Q', seed))
    before_wall, before_cpu = time.perf_counter_ns(), time.process_time_ns()
    winner = None
    attempts = 0
    for nonce in range(max_attempts):
        attempts += 1
        if attempt(cookie, nonce, bits):
            winner = nonce
            break
    cpu_ns = time.process_time_ns() - before_cpu
    wall_ns = time.perf_counter_ns() - before_wall
    return dict(
        bits=bits, cookie_digest_sha256=hashlib.sha256(cookie).hexdigest(),
        attempts=attempts, max_attempts=max_attempts, winning_nonce=winner,
        status='WINNER' if winner is not None else 'CAPPED',
        calling_process_cpu_ns=cpu_ns, wall_ns=wall_ns,
        hash_search_cpu_includes_loop=True,
        expected_trials_under_uniform_assumption=1 << bits,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bits', type=int, nargs='+', default=[8, 12, 16])
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--max-attempts', type=int, default=262144)
    parser.add_argument('--out')
    options = parser.parse_args()
    if (not 1 <= options.samples <= 8 or not 1 <= options.max_attempts <= 1 << 22
            or len(options.bits) != len(set(options.bits))
            or any(not 8 <= bits <= 20 for bits in options.bits)):
        raise SystemExit('bounded sample/attempt/bits profile required')
    rows = [sample(bits, seed + 1, options.max_attempts)
            for bits in options.bits for seed in range(options.samples)]
    report = dict(
        schema=SCHEMA, source='Python equivalent framing; synthetic Cookie ID only',
        platform=platform.platform(), actual_signed_cookie=False,
        actual_native_v3_service=False, measured_gpu_hash_rate=None,
        full_w1_receiver_cpu_measured_by_this_probe=False,
        independent_attacker=False, protocol_change=False,
        production_activation=False, rows=rows,
    )
    output = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if options.out:
        with open(options.out, 'x', encoding='utf-8') as destination:
            destination.write(output)
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
