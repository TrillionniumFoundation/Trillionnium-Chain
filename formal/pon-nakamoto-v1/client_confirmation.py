"""Bounded history delivery and receiver-verified confirmation at existing Ledger owners.

This is a full-verifying reference client, not a succinct light client or public node.
Remote chainwork, confirmation flags, clocks and snapshots are never accepted as facts.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import struct
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from typing import BinaryIO

from contract_wire import H, NETWORK, PARAMETER_HASH, PARAMS, WORK_PROFILE, canonical, header_decode, sequence_root, unique
from ledger import GENESIS, Ledger, require

MAX_PAGE_BYTES = PARAMS['max_p2p_frame_bytes']
MAX_PAGE_BLOCKS = 16
PAGE_FIELDS = {'schema', 'network', 'parameters', 'genesis', 'tip', 'after',
               'blocks', 'next_after', 'complete'}
BLOCK_FIELDS = {'header', 'transactions', 'proof'}


def digest(value: str) -> bytes:
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'DIGEST')
    return bytes.fromhex(value)


def unpack_body(body: bytes) -> list[bytes]:
    """Decode the existing stored body grammar with exact length/count limits."""
    require(isinstance(body, bytes) and 2 <= len(body) <= PARAMS['max_block_bytes'], 'BODY')
    count = struct.unpack_from('<H', body)[0]
    require(count <= PARAMS['max_transactions'], 'BODY')
    offset, rows = 2, []
    for _ in range(count):
        require(offset + 2 <= len(body), 'BODY')
        size = struct.unpack_from('<H', body, offset)[0]
        offset += 2
        require(159 <= size <= PARAMS['max_transaction_bytes'] and offset + size <= len(body), 'BODY')
        rows.append(body[offset:offset + size])
        offset += size
    require(offset == len(body), 'BODY')
    return rows


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def _unb64(value: str, maximum: int) -> bytes:
    require(isinstance(value, str) and len(value) <= 4 * ((maximum + 2) // 3), 'ENCODED_LIMIT')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise ValueError('BASE64') from error
    require(len(raw) <= maximum and _b64(raw) == value, 'BASE64')
    return raw


def _page(tip: bytes, after: bytes, blocks: list[dict], next_after: bytes) -> bytes:
    return canonical({'schema': 'pon-history-page-v1', 'network': NETWORK.hex(),
                      'parameters': PARAMETER_HASH.hex(), 'genesis': GENESIS.hex(),
                      'tip': tip.hex(), 'after': after.hex(), 'blocks': blocks,
                      'next_after': next_after.hex(), 'complete': next_after == tip})


def history_pages(source: Ledger, tip: bytes, after: bytes = GENESIS, *,
                  blocks_per_page: int = MAX_PAGE_BLOCKS,
                  progress: Callable[[str, int], None] | None = None) -> Iterator[bytes]:
    """Pin a verified branch, spool its ancestry once, emit bounded untrusted pages.

    The cursor is a block identity, not a height or an authority token. Cancellation
    closes the spool. No source SQL writes, snapshots or peer work totals are exported.
    """
    require(type(blocks_per_page) is int and 1 <= blocks_per_page <= MAX_PAGE_BLOCKS, 'PAGE_LIMIT')
    require(isinstance(tip, bytes) and len(tip) == 32 and isinstance(after, bytes) and len(after) == 32, 'DIGEST')
    source.ready()
    source.block(after)
    with tempfile.SpooledTemporaryFile(max_size=8192, mode='w+b') as ancestry:
        current, count = tip, 0
        while current != after:
            row = source.block(current)
            require(row[0] is not None, 'CURSOR_NOT_ANCESTOR')
            require(source.block(row[0])[1] + 1 == row[1], 'HEIGHT')
            ancestry.write(current)
            current, count = row[0], count + 1
            if progress and count % 256 == 0:
                progress('ancestry', count)
        if not count:
            yield _page(tip, after, [], after)
            return
        rows, cursor, last = [], after, after
        for index in range(count):
            ancestry.seek(32 * (count - index - 1))
            bid = ancestry.read(32)
            require(len(bid) == 32, 'ANCESTRY_IO')
            row = source.block(bid)
            item = {'header': _b64(row[3]), 'transactions': [_b64(tx) for tx in unpack_body(row[4])],
                    'proof': _b64(row[5])}
            proposed = _page(tip, cursor, rows + [item], bid)
            if rows and (len(rows) == blocks_per_page or len(proposed) > MAX_PAGE_BYTES):
                yield _page(tip, cursor, rows, last)
                cursor, rows = last, []
            rows.append(item)
            require(len(_page(tip, cursor, rows, bid)) <= MAX_PAGE_BYTES, 'PAGE_BYTES')
            last = bid
            if progress:
                progress('export', index + 1)
        yield _page(tip, cursor, rows, last)


def decode_page(raw: bytes, expected_tip: bytes, after: bytes) -> tuple[list[tuple], bytes, bool]:
    """All bounded grammar and continuation checks precede any work verification."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PAGE_BYTES, 'PAGE_BYTES')
    try:
        page = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError('PAGE_JSON') from error
    require(isinstance(page, dict) and set(page) == PAGE_FIELDS, 'PAGE_FIELDS')
    require(page['schema'] == 'pon-history-page-v1', 'PAGE_SCHEMA')
    require(page['network'] == NETWORK.hex() and page['parameters'] == PARAMETER_HASH.hex()
            and page['genesis'] == GENESIS.hex(), 'NETWORK')
    require(digest(page['tip']) == expected_tip and digest(page['after']) == after, 'PAGE_CONTEXT')
    require(type(page['complete']) is bool, 'PAGE_COMPLETE')
    require(isinstance(page['blocks'], list) and len(page['blocks']) <= MAX_PAGE_BLOCKS, 'PAGE_LIMIT')
    records, current = [], after
    for item in page['blocks']:
        require(isinstance(item, dict) and set(item) == BLOCK_FIELDS, 'BLOCK_FIELDS')
        hb = _unb64(item['header'], 318)
        header = header_decode(hb)
        require(header['parent'] == current, 'PAGE_ORDER')
        require(isinstance(item['transactions'], list)
                and len(item['transactions']) <= PARAMS['max_transactions'], 'BODY')
        txs = [_unb64(tx, PARAMS['max_transaction_bytes']) for tx in item['transactions']]
        proof = _unb64(item['proof'], WORK_PROFILE['proof_bytes'])
        require(len(proof) == WORK_PROFILE['proof_bytes'], 'WORK_LENGTH')
        current = H('block', hb, proof[-32:])
        records.append((hb, txs, proof, current))
    require(records or after == expected_tip, 'PAGE_NO_PROGRESS')
    require(digest(page['next_after']) == current and page['complete'] == (current == expected_tip), 'PAGE_CONTINUATION')
    return records, current, page['complete']


def receive_page(receiver: Ledger, raw: bytes, *, expected_tip: bytes, after: bytes,
                 observed_now: int, progress: Callable[[str, int], None] | None = None) -> dict:
    """Reuse the receiver's normal admission and persistence, never a second store.

    A failed/cancelled page may leave a valid prefix in immutable block storage. No
    failed block is persisted; the requested target activates only after completion.
    A later ordinary recovery can legitimately select that fully verified prefix.
    """
    require(type(observed_now) is int and 0 <= observed_now < 2**64, 'CLOCK')
    records, next_after, complete = decode_page(raw, expected_tip, after)
    receiver.ready()
    receiver.block(after)  # must already be locally verified, never imported as a snapshot
    for index, (hb, txs, proof, expected) in enumerate(records):
        if progress:
            progress('before_admit', index)
        actual = receiver.admit(hb, txs, proof, observed_now)
        require(actual == expected, 'BLOCK_ID')
        if progress:
            progress('admitted', index + 1)
    if complete:
        receiver.activate(expected_tip)  # strictly greater locally derived work only
    active, generation = receiver.active()
    return {'next_after': next_after.hex(), 'complete': complete, 'verified_blocks': len(records),
            'local_tip': active.hex(), 'local_generation': generation,
            'requested_tip_active': active == expected_tip}


def confirmation(receiver: Ledger, transaction: bytes, included_block: bytes, *,
                 observed_now: int | None = None) -> dict:
    """Calculate transaction membership, active ancestry, depth and work locally.

    The observed chain is not proof of global freshness or eclipse resistance. This
    return value is neither irreversible finality nor a local execution permission.
    """
    require(isinstance(transaction, bytes) and len(transaction) == 32
            and isinstance(included_block, bytes) and len(included_block) == 32, 'DIGEST')
    clock_scope = 'local-wall-clock' if observed_now is None else 'explicit-logical-test-clock'
    observed_now = int(time.time()) if observed_now is None else observed_now
    require(type(observed_now) is int and 0 <= observed_now < 2**64, 'CLOCK')
    receiver.ready()
    tip, generation, _ = receiver.read_active()
    if tip != GENESIS:
        require(header_decode(receiver.block(tip)[3])['timestamp'] <= observed_now + PARAMS['future_skew_seconds'], 'TIME_DEFERRED')
    included = receiver.block(included_block)
    require(included[3] is not None, 'NO_TRANSACTION')
    body = unpack_body(included[4])
    require(sequence_root('transactions', body) == header_decode(included[3])['transactions'], 'ROOT')
    indexes = [i for i, tx in enumerate(body) if H('tx-id', tx) == transaction]
    require(len(indexes) == 1, 'NO_TRANSACTION')
    current = tip
    while receiver.block(current)[1] > included[1]:
        row = receiver.block(current)
        require(row[0] is not None and receiver.block(row[0])[1] + 1 == row[1], 'HEIGHT')
        current = row[0]
    on_chain = current == included_block
    tip_row = receiver.block(tip)
    depth = tip_row[1] - included[1] if on_chain else None
    delta = int.from_bytes(tip_row[2], 'big') - int.from_bytes(included[2], 'big') if on_chain else None
    target = int.from_bytes(header_decode(included[3])['target'], 'big')
    required = (2**256 // (target + 1)) * PARAMS['confirmation_work_multiplier']
    confirmed = on_chain and depth >= PARAMS['confirmation_depth'] and delta >= required
    require(receiver.active() == (tip, generation), 'STALE_VIEW')
    return {'network': NETWORK.hex(), 'parameters': PARAMETER_HASH.hex(), 'genesis': GENESIS.hex(),
            'transaction': transaction.hex(), 'transaction_index': indexes[0],
            'included_block': included_block.hex(), 'observed_tip': tip.hex(),
            'included_height': included[1], 'observed_height': tip_row[1],
            'active_generation': generation, 'depth': depth,
            'observed_now': observed_now, 'clock_scope': clock_scope,
            'cumulative_work_delta': str(delta) if delta is not None else None,
            'required_work_delta': str(required),
            'status': 'confirmed' if confirmed else ('included' if on_chain else 'reorged'),
            'scope': 'locally-full-verified-observation-not-global-freshness',
            'finalized': False, 'execution_authority': False}


def receive_stream(receiver: Ledger, stream: BinaryIO, *, expected_tip: bytes,
                   after: bytes, observed_now: int) -> dict:
    """NDJSON is only a bounded offline transport. EOF before target is not success."""
    result = None
    while True:
        line = stream.readline(MAX_PAGE_BYTES + 2)
        if not line:
            break
        require(line.endswith(b'\n') and len(line) <= MAX_PAGE_BYTES + 1, 'PAGE_BYTES')
        require(result is None or not result['complete'], 'TRAILING_PAGE')
        result = receive_page(receiver, line[:-1], expected_tip=expected_tip, after=after,
                              observed_now=observed_now)
        after = bytes.fromhex(result['next_after'])
    require(result is not None and result['complete'], 'INCOMPLETE_HISTORY')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['export', 'receive', 'confirm'])
    parser.add_argument('--store', required=True)
    parser.add_argument('--tip')
    parser.add_argument('--after', default=GENESIS.hex())
    parser.add_argument('--transaction')
    parser.add_argument('--included-block')
    parser.add_argument('--logical-now', type=int, help='explicit test clock; not a live confirmation')
    args = parser.parse_args()
    ledger = Ledger(args.store)
    try:
        ledger.recover()
        if args.command == 'export':
            for page in history_pages(ledger, digest(args.tip), digest(args.after)):
                sys.stdout.buffer.write(page + b'\n')
        elif args.command == 'receive':
            result = receive_stream(ledger, sys.stdin.buffer, expected_tip=digest(args.tip),
                                    after=digest(args.after), observed_now=args.logical_now
                                    if args.logical_now is not None else int(time.time()))
            result['clock_scope'] = 'explicit-logical-test-clock' if args.logical_now is not None else 'local-wall-clock'
            print(json.dumps(result, sort_keys=True))
        else:
            print(json.dumps(confirmation(ledger, digest(args.transaction), digest(args.included_block),
                                          observed_now=args.logical_now), sort_keys=True))
    finally:
        ledger.close()


if __name__ == '__main__':
    main()
