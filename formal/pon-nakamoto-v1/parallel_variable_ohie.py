"""A bounded OHIE research state machine with an explicit text interpretation.

Source: Wang et al., arXiv:2105.02927v2, Sections 2/4.2/6.3 and Appendix G.
This profile uses Section 4.2's max(rank + difficulty, trailing.next_rank),
not Appendix G Algorithm 7's different conditional increment. Its integer
target encoding, full parent-vector transport, timestamp checks, finite limits
and configurable confirmation lag are stated premises. It is neither native
PoN, Fast DAA 2026, nor a security theorem (classical or quantum).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from fractions import Fraction
import hashlib
import heapq
import json
import math
import re
import time
from typing import Any


PROFILE_NAME = "parallel-variable-ohie-2021-text-profile"
DOMAIN = b"trnm-research-ohie-text-v1\0"
SOURCE = {
    "url": "https://arxiv.org/html/2105.02927v2",
    "version": "arXiv:2105.02927v2, 2021-05-10",
    "retrieved_utc_date": "2026-11-04",
    "retrieved_html_sha256": "4e1382a5515758c482e2e23fab8c04c936d7174e59cfeaabf1257a072ba36337",
    "license": "CC BY 4.0",
    "scope": "retrieved full arXiv HTML; not the final ACM PDF",
}
ASSUMPTIONS = {
    "schema": "trnm-ohie-text-profile-assumptions-v1",
    "source": SOURCE,
    "rank_interpretation": "Section 4.2 max(rank + difficulty, trailing.next_rank)",
    "appendix_rank_discrepancy": "Algorithm 7 line 20 differs when rank < trailing.next_rank < rank + difficulty",
    "environment_window_discrepancy": "Section 6 uses epoch length Phi; Appendix D prints chain count m in the analogous window",
    "target": "integer exclusive threshold 1 <= T <= 2^k; ticket < T, unlike native inclusive ticket <= target",
    "retarget": "last completed pivot epoch; floor(T * elapsed / (epoch_blocks * target_block_rounds)); ceil(T/tau) lower clamp; min(2^k,T*tau) upper clamp",
    "difficulty": "exact rational 2^k/T; checked numerator/denominator width; not native integer/u512 chainwork",
    "ties": "equal cumulative difficulty keeps the currently selected tip",
    "sortition": "one common Merkle commitment to all ordered parents before hashing; low log2(m) bits of the truncated hash select the chain",
    "sortition_correlation": "hash < T and chain id use the same ticket; chain probabilities need not be equal when T is not divisible by m",
    "parent_transport": "full ordered parent vector transmitted and checked; not the paper's two membership-proof bandwidth encoding",
    "pivot_rule": "nonpivot reference cumulative work cannot decrease; a heavier different pivot fork is allowed, as in source M2",
    "trailing": "honest templates choose maximal next_rank among committed tips; admission checks the named valid dependency, not the sender's unknowable local view",
    "timestamp": "integer round; strictly after selected parent and pivot parent; not earlier than any committed parent or trailing dependency; future imports deferred",
    "confirmation": "per-chain timestamp prefix at now - configured lag; minimum next_rank across all chains; rank then chain-id ordering",
    "confirmation_lag": "explicit empirical input; no claim that it satisfies ell + 2 Delta in the paper",
    "ledger": "synthetic unit tokens with named genesis inputs; ordered input consumption and duplicate rejection; no signatures or native execution",
    "queries": "real SHA256 truncated to k bits with deterministic seeded nonce schedules; synthetic query budgets, not measured W1 costs",
    "round_order": "deliver then mine; each miner's per-round queries use one frozen template; delivery delay at least one round",
    "private_strategy": "isolated private DAG ignores public imports for mining; can withhold all blocks until a configured release",
    "network": "bounded complete dependency bundles and fixed delay; no bandwidth/eclipsing model",
    "source_experiment_scope": "the paper's Section 7 simulator modeled mining only; this model separately implements its declared ledger profile",
    "proof_scope": "classical query-budget theorem assumptions are not established or inherited by observations",
    "native_w1_verified": False,
    "quantum_oracle_modeled": False,
    "security_theorem": False,
    "fast_daa_2026_implemented": False,
    "production_activation": False,
    "release_ready": False,
    "receipt_scope": "source-consistent replay, not authenticated execution attestation",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def uint(value: int, name: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(name)
    return value


def identifier(value: str, name: str, maximum: int = 80) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9:_-]{1," + str(maximum) + r"}", value):
        raise ValueError(name)
    return value


def hash_id(value: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("HASH_ID")
    return value


def rational(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def checked(value: Fraction, bits: int) -> Fraction:
    if value < 0 or max(value.numerator.bit_length(), value.denominator.bit_length()) > bits:
        raise OverflowError("RATIONAL_ARITHMETIC_BOUND")
    return value


def next_rank(rank: Fraction, difficulty: Fraction, trailing: Fraction, bits: int = 512) -> Fraction:
    if rank < 0 or difficulty <= 0 or trailing < 0:
        raise ValueError("RANK_ARGUMENTS")
    return checked(max(rank + difficulty, trailing), bits)


@dataclass(frozen=True)
class Profile:
    chains: int = 4
    hash_bits: int = 12
    initial_target: int = 1024
    epoch_blocks: int = 8
    target_block_rounds: int = 4
    damping_factor: int = 4
    confirmation_lag_rounds: int = 12
    arithmetic_bits: int = 512
    max_block_transactions: int = 16
    genesis_tokens: tuple[str, ...] = ("gen:0", "gen:1")

    def validate(self) -> None:
        uint(self.chains, "CHAINS", 16, 2)
        if self.chains & (self.chains - 1):
            raise ValueError("CHAINS_POWER_OF_TWO")
        uint(self.hash_bits, "HASH_BITS", 256, 8)
        uint(self.initial_target, "INITIAL_TARGET", 1 << self.hash_bits, 1)
        uint(self.epoch_blocks, "EPOCH_BLOCKS", 4096, 2)
        uint(self.target_block_rounds, "TARGET_BLOCK_ROUNDS", 100_000, 1)
        uint(self.damping_factor, "DAMPING_FACTOR", 16, 1)
        uint(self.confirmation_lag_rounds, "CONFIRMATION_LAG", 100_000, 1)
        uint(self.arithmetic_bits, "ARITHMETIC_BITS", 4096, self.hash_bits + 1)
        uint(self.max_block_transactions, "BLOCK_TRANSACTIONS", 64, 1)
        if type(self.genesis_tokens) is not tuple or not 1 <= len(self.genesis_tokens) <= 64:
            raise ValueError("GENESIS_TOKENS")
        if len(set(self.genesis_tokens)) != len(self.genesis_tokens):
            raise ValueError("DUPLICATE_GENESIS_TOKEN")
        for token in self.genesis_tokens:
            identifier(token, "GENESIS_TOKEN")
            if not token.startswith("gen:"):
                raise ValueError("GENESIS_TOKEN_NAMESPACE")

    @property
    def identity(self) -> str:
        self.validate()
        return hashlib.sha256(DOMAIN + canonical({"profile": PROFILE_NAME, "parameters": asdict(self),
                                                   "interpretation": ASSUMPTIONS})).hexdigest()


@dataclass(frozen=True)
class Limits:
    max_blocks: int = 2048
    max_pending_blocks: int = 2048
    max_mempool: int = 128

    def validate(self, chains: int) -> None:
        uint(self.max_blocks, "MAX_BLOCKS", 10_000, chains + 1)
        uint(self.max_pending_blocks, "MAX_PENDING_BLOCKS", 10_000, 1)
        uint(self.max_mempool, "MAX_MEMPOOL", 1024, 1)


class ModelLimit(RuntimeError):
    """An observed finite budget ended; never interpreted as protocol success."""


@dataclass(frozen=True)
class Transaction:
    label: str
    spends: str

    def validate(self) -> None:
        identifier(self.label, "TRANSACTION_LABEL", 40)
        identifier(self.spends, "TRANSACTION_INPUT")
        if not (self.spends.startswith("gen:") or re.fullmatch(r"tx:[0-9a-f]{64}", self.spends)):
            raise ValueError("TRANSACTION_INPUT_NAMESPACE")

    @property
    def txid(self) -> str:
        self.validate()
        return "tx:" + hashlib.sha256(DOMAIN + b"unit-token\0" + canonical(asdict(self))).hexdigest()


def parent_commitment(parents: tuple[str, ...]) -> str:
    if type(parents) is not tuple or not 2 <= len(parents) <= 16 or len(parents) & (len(parents) - 1):
        raise ValueError("PARENT_VECTOR")
    nodes = [hashlib.sha256(DOMAIN + b"parent-leaf\0" + i.to_bytes(2, "big")
                           + bytes.fromhex(hash_id(parent))).digest() for i, parent in enumerate(parents)]
    while len(nodes) > 1:
        nodes = [hashlib.sha256(DOMAIN + b"parent-node\0" + nodes[i] + nodes[i + 1]).digest()
                 for i in range(0, len(nodes), 2)]
    return nodes[0].hex()


def sortition_counts(target: int, chains: int) -> tuple[int, ...]:
    """Exact finite winning-ticket counts, including T < m starvation."""
    uint(target, "TARGET", 1 << 256, 1)
    uint(chains, "CHAINS", 16, 2)
    if chains & (chains - 1):
        raise ValueError("CHAINS_POWER_OF_TWO")
    return tuple(0 if target <= chain else (target - 1 - chain) // chains + 1 for chain in range(chains))


@dataclass(frozen=True)
class Template:
    profile: str
    parents: tuple[str, ...]
    trailing: str
    timestamp: int
    target: int
    miner: str
    transactions: tuple[Transaction, ...] = ()


@dataclass(frozen=True)
class Block:
    profile: str
    parents: tuple[str, ...]
    commitment: str
    trailing: str
    timestamp: int
    target: int
    miner: str
    transactions: tuple[Transaction, ...]
    nonce: int
    chain: int
    block_id: str

    def header(self) -> dict:
        # The chain is derived AFTER the hash, and the parent vector is bound by
        # its root. Neither is a free pre-query choice of winning chain.
        return {"profile": self.profile, "parent_commitment": self.commitment,
                "trailing": self.trailing, "timestamp": self.timestamp, "target": self.target,
                "miner": self.miner, "transactions": [asdict(tx) for tx in self.transactions],
                "nonce": self.nonce}

    def digest(self) -> str:
        return hashlib.sha256(DOMAIN + b"header\0" + canonical(self.header())).hexdigest()

    def ticket(self, bits: int) -> int:
        return int(self.block_id, 16) >> (256 - bits)

    def dependencies(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.parents, self.trailing)))

    def as_dict(self) -> dict:
        return asdict(self)


def candidate(template: Template, nonce: int, profile: Profile) -> Block:
    uint(nonce, "NONCE", (1 << 64) - 1)
    provisional = Block(template.profile, template.parents, parent_commitment(template.parents),
                        template.trailing, template.timestamp, template.target, template.miner,
                        template.transactions, nonce, 0, "0" * 64)
    digest = provisional.digest()
    ticket = int(digest, 16) >> (256 - profile.hash_bits)
    return Block(template.profile, template.parents, provisional.commitment, template.trailing,
                 template.timestamp, template.target, template.miner, template.transactions,
                 nonce, ticket & (profile.chains - 1), digest)


def block_from_dict(value: dict) -> Block:
    keys = set(Block.__dataclass_fields__)
    if type(value) is not dict or set(value) != keys:
        raise ValueError("BLOCK_FIELDS")
    if type(value["parents"]) is not list or type(value["transactions"]) is not list:
        raise ValueError("BLOCK_ARRAY_FIELDS")
    txs = []
    for tx in value["transactions"]:
        if type(tx) is not dict or set(tx) != {"label", "spends"}:
            raise ValueError("TRANSACTION_FIELDS")
        txs.append(Transaction(**tx))
    return Block(**{**value, "parents": tuple(value["parents"]), "transactions": tuple(txs)})


@dataclass(frozen=True)
class Record:
    profile: str
    block_id: str
    chain: int
    parent: str | None
    pivot: str
    height: int
    timestamp: int
    target: int
    credit: Fraction
    chainwork: Fraction
    rank: Fraction
    next_rank: Fraction
    block: Block | None = None


def heavier(candidate_record: Record, current: Record) -> bool:
    if candidate_record.profile != current.profile or candidate_record.chain != current.chain:
        raise ValueError("INCOMPATIBLE_CHAIN_COMPARISON")
    return candidate_record.chainwork > current.chainwork


@dataclass(frozen=True)
class Admission:
    status: str
    reason: str
    block_id: str


@dataclass(frozen=True)
class Ledger:
    profile: str
    round: int
    confirmation_bar: Fraction
    partial_tips: tuple[str, ...]
    blocks: tuple[str, ...]
    transactions: tuple[str, ...]
    labels: tuple[str, ...]
    skipped: tuple[tuple[str, str], ...]
    unspent: tuple[str, ...]

    def as_dict(self) -> dict:
        return {**asdict(self), "confirmation_bar": rational(self.confirmation_bar)}


class State:
    """One receiver's admitted DAG, pending dependencies, tips and ordered ledger."""

    def __init__(self, profile: Profile = Profile(), limits: Limits = Limits()):
        profile.validate()
        limits.validate(profile.chains)
        self.profile, self.limits, self.identity = profile, limits, profile.identity
        self.now = 0
        self.records: dict[str, Record] = {}
        self.pending: dict[str, Block] = {}
        self.mempool: dict[str, Transaction] = {}
        self.accepted_history: list[tuple[int, str]] = []
        self.metrics = {key: 0 for key in (
            "accepted", "duplicate", "rejected", "deferred", "resolved_pending", "rejected_pending", "adoptions",
            "chain_reorgs", "removed_chain_blocks", "maximum_chain_reorg")}
        self.rejection_reasons: dict[str, int] = {}
        genesis = tuple(hashlib.sha256(DOMAIN + b"genesis\0" + bytes.fromhex(self.identity)
                                       + i.to_bytes(2, "big")).hexdigest() for i in range(profile.chains))
        for chain, block_id in enumerate(genesis):
            self.records[block_id] = Record(self.identity, block_id, chain, None, genesis[0], 0, 0,
                                             profile.initial_target, Fraction(0), Fraction(0),
                                             Fraction(0), Fraction(1))
        self.genesis = genesis
        self.tips = list(genesis)

    def add_transaction(self, tx: Transaction) -> None:
        if type(tx) is not Transaction:
            raise ValueError("TRANSACTION_TYPE")
        tx.validate()
        if tx.txid not in self.mempool and len(self.mempool) >= self.limits.max_mempool:
            raise ModelLimit("MEMPOOL_LIMIT")
        self.mempool[tx.txid] = tx

    def path(self, block_id: str) -> list[Record]:
        if block_id not in self.records:
            raise ValueError("UNKNOWN_PATH_TIP")
        path = []
        while True:
            record = self.records[block_id]
            path.append(record)
            if record.parent is None:
                return list(reversed(path))
            block_id = record.parent
            if len(path) > self.limits.max_blocks:
                raise ValueError("ANCESTRY_BOUND")

    def required_target(self, pivot: str) -> int:
        if pivot not in self.records or self.records[pivot].chain != 0:
            raise ValueError("PIVOT_REFERENCE")
        parent = self.records[pivot]
        if parent.height == 0:
            return self.profile.initial_target
        if parent.height % self.profile.epoch_blocks:
            return parent.target
        start = parent
        for _ in range(self.profile.epoch_blocks):
            if start.parent is None:
                raise ValueError("PIVOT_EPOCH_ANCESTRY")
            start = self.records[start.parent]
        elapsed = parent.timestamp - start.timestamp
        if elapsed <= 0:
            raise ValueError("PIVOT_EPOCH_DURATION")
        denominator = self.profile.epoch_blocks * self.profile.target_block_rounds
        raw = parent.target * elapsed // denominator
        lower = (parent.target + self.profile.damping_factor - 1) // self.profile.damping_factor
        upper = min(1 << self.profile.hash_bits, parent.target * self.profile.damping_factor)
        return max(lower, min(upper, raw))

    def template(self, timestamp: int, miner: str, transactions: tuple[Transaction, ...] | None = None) -> Template:
        uint(timestamp, "TIMESTAMP", 1_000_000, 1)
        identifier(miner, "MINER", 40)
        parents = tuple(self.tips)
        trailing = max(parents, key=lambda tip: self.records[tip].next_rank)
        if timestamp <= max(self.records[parent].timestamp for parent in parents):
            raise ValueError("TEMPLATE_NOT_AFTER_PARENTS")
        if transactions is None:
            applied = set(self.ledger().transactions)
            transactions = tuple(tx for txid, tx in self.mempool.items() if txid not in applied)
            transactions = transactions[:self.profile.max_block_transactions]
        return Template(self.identity, parents, trailing, timestamp, self.required_target(parents[0]),
                        miner, transactions)

    def _shape(self, block: Block) -> None:
        if type(block) is not Block:
            raise ValueError("BLOCK_TYPE")
        if block.profile != self.identity:
            raise ValueError("PROFILE_MISMATCH")
        hash_id(block.block_id)
        hash_id(block.trailing)
        hash_id(block.commitment)
        uint(block.chain, "CHAIN_ID", self.profile.chains - 1)
        uint(block.timestamp, "TIMESTAMP", 1_000_000, 1)
        uint(block.nonce, "NONCE", (1 << 64) - 1)
        uint(block.target, "TARGET", 1 << self.profile.hash_bits, 1)
        identifier(block.miner, "MINER", 40)
        if type(block.parents) is not tuple or len(block.parents) != self.profile.chains:
            raise ValueError("PARENT_VECTOR")
        if block.commitment != parent_commitment(block.parents):
            raise ValueError("PARENT_COMMITMENT")
        if block.block_id in block.dependencies():
            raise ValueError("SELF_REFERENCE")
        if type(block.transactions) is not tuple or len(block.transactions) > self.profile.max_block_transactions:
            raise ValueError("TRANSACTION_COUNT")
        for tx in block.transactions:
            if type(tx) is not Transaction:
                raise ValueError("TRANSACTION_TYPE")
            tx.validate()
        if block.digest() != block.block_id:
            raise ValueError("HEADER_HASH")
        ticket = block.ticket(self.profile.hash_bits)
        if block.chain != ticket & (self.profile.chains - 1):
            raise ValueError("CHAIN_SORTITION")
        if ticket >= block.target:
            raise ValueError("POW_THRESHOLD")

    def _derive(self, block: Block) -> Record:
        parents = [self.records[parent] for parent in block.parents]
        if any(parent.chain != index or parent.profile != self.identity for index, parent in enumerate(parents)):
            raise ValueError("PARENT_CHAIN")
        parent, pivot = parents[block.chain], parents[0]
        trailing = self.records[block.trailing]
        if trailing.profile != self.identity:
            raise ValueError("TRAILING_PROFILE")
        if block.target != self.required_target(pivot.block_id):
            raise ValueError("REQUIRED_TARGET")
        if block.timestamp <= max(parent.timestamp, pivot.timestamp):
            raise ValueError("PARENT_TIMESTAMP")
        if block.timestamp < max([record.timestamp for record in parents] + [trailing.timestamp]):
            raise ValueError("DEPENDENCY_TIMESTAMP")
        if block.chain and pivot.chainwork < self.records[parent.pivot].chainwork:
            raise ValueError("PIVOT_WORK_DECREASE")
        credit = checked(Fraction(1 << self.profile.hash_bits, block.target), self.profile.arithmetic_bits)
        chainwork = checked(parent.chainwork + credit, self.profile.arithmetic_bits)
        rank = parent.next_rank
        next_value = next_rank(rank, credit, trailing.next_rank, self.profile.arithmetic_bits)
        return Record(self.identity, block.block_id, block.chain, parent.block_id, pivot.block_id,
                      parent.height + 1, block.timestamp, block.target, credit, chainwork, rank, next_value, block)

    def _reject(self, block: Block, reason: str) -> Admission:
        self.metrics["rejected"] += 1
        self.rejection_reasons[reason] = self.rejection_reasons.get(reason, 0) + 1
        return Admission("REJECTED", reason, getattr(block, "block_id", ""))

    def _accept(self, block: Block, pending: bool = False) -> Admission:
        try:
            record = self._derive(block)
        except (ValueError, OverflowError) as error:
            return self._reject(block, str(error))
        if len(self.records) >= self.limits.max_blocks:
            raise ModelLimit("BLOCK_STORAGE_LIMIT")
        old = self.records[self.tips[block.chain]]
        self.records[block.block_id] = record
        self.metrics["accepted"] += 1
        self.accepted_history.append((self.now, block.block_id))
        if pending:
            self.metrics["resolved_pending"] += 1
        if heavier(record, old):
            old_path = self.path(old.block_id)
            new_ids = {entry.block_id for entry in self.path(record.block_id)}
            removed = 0
            for entry in reversed(old_path):
                if entry.block_id in new_ids:
                    break
                removed += 1
            self.metrics["adoptions"] += 1
            if removed:
                self.metrics["chain_reorgs"] += 1
                self.metrics["removed_chain_blocks"] += removed
                self.metrics["maximum_chain_reorg"] = max(self.metrics["maximum_chain_reorg"], removed)
            self.tips[block.chain] = block.block_id
        return Admission("ACCEPTED", "VALID_PROFILE_BLOCK", block.block_id)

    def _drain(self) -> None:
        # An admitted block can unlock a future/missing-parent dependency chain.
        # The bound is the finite pending inventory, not an unbounded retry loop.
        while True:
            ready = [block for block in self.pending.values() if block.timestamp <= self.now
                     and all(parent in self.records for parent in block.dependencies())]
            if not ready:
                return
            for block in sorted(ready, key=lambda item: (item.timestamp, item.block_id)):
                result = self._accept(block, pending=True)
                del self.pending[block.block_id]
                if result.status == "REJECTED":
                    self.metrics["rejected_pending"] += 1
                if result.status not in ("ACCEPTED", "REJECTED"):
                    raise AssertionError("PENDING_ADMISSION_RESULT")

    def advance(self, now: int) -> None:
        uint(now, "ROUND", 1_000_000)
        if now < self.now:
            raise ValueError("ROUND_REWIND")
        self.now = now
        self._drain()

    def receive(self, block: Block, now: int) -> Admission:
        self.advance(now)
        try:
            self._shape(block)
        except (ValueError, TypeError, OverflowError) as error:
            return self._reject(block, str(error))
        if block.block_id in self.records:
            self.metrics["duplicate"] += 1
            return Admission("KNOWN", "ALREADY_ADMITTED", block.block_id)
        missing = any(parent not in self.records for parent in block.dependencies())
        if missing or block.timestamp > now:
            if block.block_id not in self.pending:
                if len(self.pending) >= self.limits.max_pending_blocks:
                    raise ModelLimit("PENDING_BLOCK_LIMIT")
                self.pending[block.block_id] = block
                self.metrics["deferred"] += 1
            return Admission("DEFERRED", "MISSING_DEPENDENCY" if missing else "FUTURE_TIMESTAMP", block.block_id)
        result = self._accept(block)
        self.pending.pop(block.block_id, None)
        self._drain()
        return result

    def receive_bundle(self, blocks: tuple[Block, ...], now: int) -> list[Admission]:
        if type(blocks) is not tuple or len(blocks) > self.limits.max_blocks:
            raise ValueError("BUNDLE_BOUND")
        for block in blocks:
            if type(block) is not Block:
                raise ValueError("BLOCK_TYPE")
            if type(block.parents) is not tuple or len(block.parents) != self.profile.chains:
                raise ValueError("PARENT_VECTOR")
            hash_id(block.block_id)
            for parent in block.dependencies():
                hash_id(parent)
        # Reject malformed graph envelopes before any member mutates the view.
        order = topological_blocks(blocks)
        for block in order:
            self._shape(block)
        return [self.receive(block, now) for block in order]

    def ledger(self) -> Ledger:
        cutoff = self.now - self.profile.confirmation_lag_rounds
        partial = [[entry for entry in self.path(tip) if entry.height == 0 or entry.timestamp <= cutoff]
                   for tip in self.tips]
        partial_tips = tuple(chain[-1].block_id for chain in partial)
        bar = min(chain[-1].next_rank for chain in partial)
        fully_confirmed = [entry for chain in partial for entry in chain if entry.height and entry.rank < bar]
        fully_confirmed.sort(key=lambda entry: (entry.rank, entry.chain, entry.block_id))
        applied: set[str] = set()
        unspent = set(self.profile.genesis_tokens)
        txids, labels, skipped = [], [], []
        for entry in fully_confirmed:
            assert entry.block is not None
            for tx in entry.block.transactions:
                txid = tx.txid
                if txid in applied:
                    skipped.append((txid, "DUPLICATE_TRANSACTION"))
                elif tx.spends not in unspent:
                    skipped.append((txid, "INPUT_NOT_UNSPENT"))
                else:
                    unspent.remove(tx.spends)
                    unspent.add(txid)
                    applied.add(txid)
                    txids.append(txid)
                    labels.append(tx.label)
        return Ledger(self.identity, self.now, bar, partial_tips,
                      tuple(entry.block_id for entry in fully_confirmed), tuple(txids), tuple(labels),
                      tuple(skipped), tuple(sorted(unspent)))


def topological_blocks(blocks: tuple[Block, ...]) -> list[Block]:
    by_id: dict[str, Block] = {}
    positions: dict[str, int] = {}
    for index, block in enumerate(blocks):
        if type(block) is not Block:
            raise ValueError("BLOCK_TYPE")
        hash_id(block.block_id)
        if block.block_id in by_id:
            if block != by_id[block.block_id]:
                raise ValueError("CONFLICTING_BLOCK_ENVELOPE")
            continue
        by_id[block.block_id] = block
        positions[block.block_id] = index
    children: dict[str, list[str]] = {block_id: [] for block_id in by_id}
    indegree = {block_id: 0 for block_id in by_id}
    for block_id, block in by_id.items():
        for parent in block.dependencies():
            hash_id(parent)
            if parent in by_id:
                children[parent].append(block_id)
                indegree[block_id] += 1
    ready = [(positions[block_id], block_id) for block_id, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    result = []
    while ready:
        _, block_id = heapq.heappop(ready)
        result.append(by_id[block_id])
        for child in children[block_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(ready, (positions[child], child))
    if len(result) != len(by_id):
        raise ValueError("CYCLIC_BUNDLE")
    return result


@dataclass(frozen=True)
class BudgetPhase:
    at_round: int
    queries_per_miner: tuple[int, ...]


@dataclass(frozen=True)
class Scenario:
    name: str = "honest_m4"
    seed: int = 7101
    profile: Profile = field(default_factory=Profile)
    rounds: int = 200
    queries_per_miner: tuple[int, ...] = (2, 2)
    delay_rounds: int = 1
    probe_arrival_round: int = 2
    budget_phases: tuple[BudgetPhase, ...] = ()
    private_miner: int | None = None
    private_release_round: int | None = None
    private_censors_probe: bool = True
    diagnostic_discard_chain: int | None = None
    max_blocks: int = 1500
    max_queries: int = 100_000
    max_events: int = 30_000
    max_pending_deliveries: int = 10_000
    max_trace_rows: int = 30_002
    cpu_limit_seconds: float = 20.0

    def validate(self) -> None:
        identifier(self.name, "SCENARIO_NAME", 80)
        uint(self.seed, "SEED", (1 << 64) - 1)
        if type(self.profile) is not Profile:
            raise ValueError("PROFILE_TYPE")
        self.profile.validate()
        uint(self.rounds, "ROUNDS", 4096, 1)
        self._budgets(self.queries_per_miner)
        uint(self.delay_rounds, "DELAY_ROUNDS", 64, 1)
        uint(self.probe_arrival_round, "PROBE_ARRIVAL", self.rounds, 1)
        if type(self.budget_phases) is not tuple or len(self.budget_phases) > 32:
            raise ValueError("BUDGET_PHASES")
        previous = 0
        for phase in self.budget_phases:
            if type(phase) is not BudgetPhase:
                raise ValueError("BUDGET_PHASE_TYPE")
            uint(phase.at_round, "BUDGET_PHASE_ROUND", self.rounds, previous + 1)
            self._budgets(phase.queries_per_miner)
            if len(phase.queries_per_miner) != len(self.queries_per_miner):
                raise ValueError("BUDGET_PHASE_MINERS")
            previous = phase.at_round
        if self.private_miner is not None:
            uint(self.private_miner, "PRIVATE_MINER", len(self.queries_per_miner) - 1)
        if self.private_release_round is not None:
            uint(self.private_release_round, "PRIVATE_RELEASE", self.rounds, 1)
            if self.private_miner is None:
                raise ValueError("RELEASE_WITHOUT_PRIVATE_MINER")
        if type(self.private_censors_probe) is not bool:
            raise ValueError("PRIVATE_CENSOR_FLAG")
        if self.diagnostic_discard_chain is not None:
            uint(self.diagnostic_discard_chain, "DISCARD_CHAIN", self.profile.chains - 1)
        for name, cap, lower in (("max_blocks", 8000, 1), ("max_queries", 1_000_000, 1),
                                 ("max_events", 200_000, 1), ("max_pending_deliveries", 20_000, 1),
                                 ("max_trace_rows", 200_002, 2)):
            uint(getattr(self, name), name.upper(), cap, lower)
        if type(self.cpu_limit_seconds) not in (int, float) or not math.isfinite(self.cpu_limit_seconds) or not 0.001 <= self.cpu_limit_seconds <= 60:
            raise ValueError("CPU_LIMIT")

    @staticmethod
    def _budgets(values: tuple[int, ...]) -> None:
        if type(values) is not tuple or not 1 <= len(values) <= 8:
            raise ValueError("QUERY_BUDGETS")
        for value in values:
            uint(value, "QUERY_BUDGET", 512)

    def budgets(self, now: int) -> tuple[int, ...]:
        result = self.queries_per_miner
        for phase in self.budget_phases:
            if phase.at_round > now:
                break
            result = phase.queries_per_miner
        return result


def common_prefix_length(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    count = 0
    for a, b in zip(left, right):
        if a != b:
            break
        count += 1
    return count


class Simulation:
    def __init__(self, scenario: Scenario, cpu_clock=time.process_time):
        scenario.validate()
        self.case, self.profile = scenario, scenario.profile
        limits = Limits(max_blocks=scenario.max_blocks + scenario.profile.chains,
                        max_pending_blocks=scenario.max_blocks)
        self.miners = [f"m{i}" for i in range(len(scenario.queries_per_miner))]
        self.nodes = {name: State(self.profile, limits) for name in [*self.miners, "observer"]}
        self.private = None if scenario.private_miner is None else self.miners[scenario.private_miner]
        self.blocks: dict[str, Block] = {}
        self.pending: list[tuple[int, int, str, int, tuple[str, ...]]] = []
        self.private_roots: list[str] = []
        self.unscheduled_roots: list[str] = []
        self.sequence, self.now, self.completed_rounds, self.events, self.queries = 0, 0, 0, 0, 0
        self.termination = "horizon"
        self.minimum_queried_target: int | None = None
        self.queries_with_unreachable_chains = 0
        self.queries_with_unequal_sortition_counts = 0
        self.cpu_clock, self.cpu_started = cpu_clock, cpu_clock()
        self.probe = Transaction("public_probe", self.profile.genesis_tokens[0])
        self.stats = {miner: {key: 0 for key in ("queries", "winning_candidates", "accepted_blocks",
                                               "discarded_winners", "profile_rejected_winners", "ignored_public_deliveries")}
                      for miner in self.miners}
        self.nonces = {miner: int.from_bytes(hashlib.sha256(canonical([scenario.seed, miner])).digest()[:6], "big")
                       for miner in self.miners}
        self.trace: list[dict] = []
        self.observations = {name: {"previous_ledger": (), "block_prefix_reversals": 0,
                                   "maximum_removed_ledger_blocks": 0, "previous_probe": False,
                                   "probe_first_confirmed_round": None, "probe_confirmation_reversals": 0}
                             for name in self.nodes}
        self.honest_ledger_divergence_observations = 0
        self._log("start", profile=self.profile.identity, source=SOURCE, schema="trnm-ohie-text-trace-v1")

    def _log(self, kind: str, **data: Any) -> None:
        if len(self.trace) >= self.case.max_trace_rows:
            raise AssertionError("TRACE_RESERVATION")
        self.trace.append({"row": len(self.trace), "round": self.now, "kind": kind, **data})

    def _step(self) -> None:
        if self.events >= self.case.max_events:
            raise ModelLimit("event_limit")
        # Keep one row for the finish record even at the exact boundary.
        if len(self.trace) >= self.case.max_trace_rows - 1:
            raise ModelLimit("trace_limit")
        if self.cpu_clock() - self.cpu_started >= self.case.cpu_limit_seconds:
            raise ModelLimit("cpu_limit")
        self.events += 1

    def closure(self, roots: tuple[str, ...]) -> tuple[Block, ...]:
        selected: dict[str, Block] = {}
        stack = list(roots)
        genesis = set(self.nodes["observer"].genesis)
        while stack:
            block_id = stack.pop()
            if block_id in genesis or block_id in selected:
                continue
            if block_id not in self.blocks:
                raise ValueError("UNKNOWN_BUNDLE_DEPENDENCY")
            block = self.blocks[block_id]
            selected[block_id] = block
            stack.extend(block.dependencies())
            if len(selected) > self.case.max_blocks:
                raise ModelLimit("bundle_limit")
        return tuple(topological_blocks(tuple(selected.values())))

    def _broadcast(self, roots: tuple[str, ...], sender: str) -> bool:
        recipients = [name for name in self.nodes if name != sender]
        if len(self.pending) + len(recipients) > self.case.max_pending_deliveries:
            self.unscheduled_roots.extend(roots)
            return False
        for recipient in recipients:
            self.sequence += 1
            heapq.heappush(self.pending, (self.now + self.case.delay_rounds, self.sequence,
                                         recipient, self.now, roots))
        return True

    def _observe(self, name: str) -> None:
        ledger = self.nodes[name].ledger()
        observation = self.observations[name]
        old = observation["previous_ledger"]
        removed = len(old) - common_prefix_length(old, ledger.blocks)
        if removed:
            observation["block_prefix_reversals"] += 1
            observation["maximum_removed_ledger_blocks"] = max(observation["maximum_removed_ledger_blocks"], removed)
        observation["previous_ledger"] = ledger.blocks
        confirmed = self.probe.txid in ledger.transactions
        if confirmed and observation["probe_first_confirmed_round"] is None:
            observation["probe_first_confirmed_round"] = self.now
        if observation["previous_probe"] and not confirmed:
            observation["probe_confirmation_reversals"] += 1
        observation["previous_probe"] = confirmed

    def _deliver(self, event: tuple[int, int, str, int, tuple[str, ...]]) -> None:
        _, _, recipient, sent, roots = event
        if recipient == self.private:
            self.stats[recipient]["ignored_public_deliveries"] += 1
            self._log("delivery", recipient=recipient, sent_round=sent, roots=roots,
                      ignored_by_private_strategy=True, accepted=[])
            return
        node = self.nodes[recipient]
        before = len(node.accepted_history)
        result = node.receive_bundle(self.closure(roots), self.now)
        if any(item.status == "REJECTED" for item in result):
            raise AssertionError("GENERATED_BUNDLE_REJECTED")
        accepted = [block_id for _, block_id in node.accepted_history[before:]]
        self._observe(recipient)
        self._log("delivery", recipient=recipient, sent_round=sent, roots=roots,
                  ignored_by_private_strategy=False, accepted=accepted, tips=tuple(node.tips),
                  probe_confirmed=self.observations[recipient]["previous_probe"])

    def _mine(self, miner: str, template: Template) -> None:
        if self.queries >= self.case.max_queries:
            raise ModelLimit("query_limit")
        if len(self.blocks) >= self.case.max_blocks:
            raise ModelLimit("block_limit")
        self._step()
        nonce = self.nonces[miner]
        self.nonces[miner] += 1
        self.queries += 1
        self.minimum_queried_target = template.target if self.minimum_queried_target is None else min(self.minimum_queried_target, template.target)
        self.queries_with_unreachable_chains += template.target < self.profile.chains
        self.queries_with_unequal_sortition_counts += bool(template.target % self.profile.chains)
        stats = self.stats[miner]
        stats["queries"] += 1
        block = candidate(template, nonce, self.profile)
        ticket = block.ticket(self.profile.hash_bits)
        won = ticket < template.target
        row: dict[str, Any] = {"miner": miner, "nonce": nonce, "ticket": ticket,
                               "target": template.target, "chain": block.chain, "won": won}
        limit = None
        if won:
            stats["winning_candidates"] += 1
            row["block"] = block.as_dict()
            if block.chain == self.case.diagnostic_discard_chain:
                stats["discarded_winners"] += 1
                row["disposition"] = "diagnostic_discard"
            else:
                result = self.nodes[miner].receive(block, self.now)
                if result.status != "ACCEPTED":
                    stats["profile_rejected_winners"] += 1
                    row["disposition"] = "rejected_by_profile"
                    row["reason"] = result.reason
                    limit = "profile_arithmetic_or_validation_limit"
                else:
                    self.blocks[block.block_id] = block
                    stats["accepted_blocks"] += 1
                    self._observe(miner)
                    held = miner == self.private and (self.case.private_release_round is None
                                                      or self.now < self.case.private_release_round)
                    row["disposition"] = "private_withheld" if held else "published"
                    if held:
                        self.private_roots.append(block.block_id)
                    elif not self._broadcast((block.block_id,), miner):
                        row["disposition"] = "publication_censored_by_limit"
                        limit = "pending_delivery_limit"
        self._log("query", **row)
        if limit:
            raise ModelLimit(limit)

    def run(self) -> tuple[dict, list[dict]]:
        try:
            for now in range(1, self.case.rounds + 1):
                if self.cpu_clock() - self.cpu_started >= self.case.cpu_limit_seconds:
                    raise ModelLimit("cpu_limit")
                self.now = now
                for node in self.nodes.values():
                    node.advance(now)
                if now == self.case.probe_arrival_round:
                    self._step()
                    for name, node in self.nodes.items():
                        if name != self.private or not self.case.private_censors_probe:
                            node.add_transaction(self.probe)
                    self._log("probe_arrival", transaction=asdict(self.probe))
                if self.private and now == self.case.private_release_round:
                    self._step()
                    roots = tuple(self.private_roots)
                    scheduled = not roots or self._broadcast(roots, self.private)
                    self._log("private_release", miner=self.private, roots=roots, scheduled=scheduled)
                    if not scheduled:
                        raise ModelLimit("pending_delivery_limit")
                    self.private_roots.clear()
                while self.pending and self.pending[0][0] <= now:
                    self._step()
                    self._deliver(heapq.heappop(self.pending))
                templates = {name: node.template(now, name) for name, node in self.nodes.items() if name in self.miners}
                for miner, count in zip(self.miners, self.case.budgets(now)):
                    for _ in range(count):
                        self._mine(miner, templates[miner])
                for name in self.nodes:
                    self._observe(name)
                ledgers = [node.ledger().blocks for name, node in self.nodes.items() if name != self.private]
                for index, left in enumerate(ledgers):
                    for right in ledgers[index + 1:]:
                        if common_prefix_length(left, right) < min(len(left), len(right)):
                            self.honest_ledger_divergence_observations += 1
                self.completed_rounds = now
        except ModelLimit as error:
            self.termination = str(error)
        for name in self.nodes:
            self._observe(name)
        summary = self.summary()
        self._log("finish", termination=self.termination, observed_round=self.now,
                  complete_rounds=self.completed_rounds, queries=self.queries,
                  pending_deliveries=len(self.pending), private_blocks_still_withheld=len(self.private_roots))
        summary["trace_rows"] = len(self.trace)
        return summary, self.trace

    def summary(self) -> dict:
        views = {}
        for name, node in self.nodes.items():
            ledger = node.ledger()
            selected = [entry for tip in node.tips for entry in node.path(tip) if entry.height]
            work_by_miner: dict[str, Fraction] = {}
            for entry in selected:
                assert entry.block is not None
                owner = entry.block.miner
                work_by_miner[owner] = work_by_miner.get(owner, Fraction(0)) + entry.credit
            observation = {key: value for key, value in self.observations[name].items() if not key.startswith("previous_")}
            views[name] = {"tips": list(node.tips), "heights": [node.records[tip].height for tip in node.tips],
                           "chainwork": [rational(node.records[tip].chainwork) for tip in node.tips],
                           "selected_blocks": len(selected), "fully_confirmed_blocks": len(ledger.blocks),
                           "selected_work_by_claimed_miner": {miner: rational(work) for miner, work in sorted(work_by_miner.items())},
                           "ledger": ledger.as_dict(), "admission": dict(node.metrics),
                           "rejection_reasons": dict(node.rejection_reasons),
                           "pending_dependency_or_future_blocks": len(node.pending),
                           "probe_confirmed_at_end": self.probe.txid in ledger.transactions,
                           "probe_unconfirmed_at_observation_end": self.probe.txid not in ledger.transactions,
                           **observation}
        scheduled_queries = sum(sum(self.case.budgets(now)) for now in range(1, self.case.rounds + 1))
        return {"schema": "trnm-ohie-text-summary-v1", "profile_name": PROFILE_NAME,
                "profile_identity": self.profile.identity, "termination": self.termination,
                "observed_round": self.now, "completed_rounds": self.completed_rounds,
                "horizon_completed": self.termination == "horizon", "events": self.events,
                "queries_executed": self.queries, "queries_scheduled_over_horizon": scheduled_queries,
                "queries_not_executed": scheduled_queries - self.queries,
                "minimum_queried_target": self.minimum_queried_target,
                "winning_ticket_counts_at_minimum_target": None if self.minimum_queried_target is None else sortition_counts(self.minimum_queried_target, self.profile.chains),
                "queries_with_unreachable_chains": self.queries_with_unreachable_chains,
                "queries_with_unequal_sortition_counts": self.queries_with_unequal_sortition_counts,
                "created_blocks": len(self.blocks), "miner_accounting": self.stats,
                "pending_deliveries_censored": len(self.pending),
                "private_blocks_still_withheld": len(self.private_roots),
                "publication_roots_censored": list(self.unscheduled_roots),
                "honest_ledger_divergence_sample_count": self.honest_ledger_divergence_observations,
                "diagnostic_sortition_discard_enabled": self.case.diagnostic_discard_chain is not None,
                "views": views, "security_theorem": False, "quantum_oracle_modeled": False,
                "native_w1_verified": False, "fast_daa_2026_implemented": False, "release_ready": False}


def run_scenario(scenario: Scenario) -> tuple[dict, list[dict]]:
    return Simulation(scenario).run()


def standard_scenarios() -> tuple[Scenario, ...]:
    return (
        Scenario("honest_m2", profile=Profile(chains=2, target_block_rounds=2)),
        Scenario("honest_m4"),
        Scenario("delayed_m4", delay_rounds=4),
        Scenario("participation_drop_m4", budget_phases=(BudgetPhase(70, (1, 0)),)),
        Scenario("private_release_m4", queries_per_miner=(2, 2, 1), private_miner=2,
                 private_release_round=90),
        Scenario("withheld_chain_diagnostic", diagnostic_discard_chain=1),
    )
