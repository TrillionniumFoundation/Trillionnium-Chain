"""Non-authoritative executable examples for PCC1. Python 3.10+, stdlib only.

NOT a production consensus engine, signature verifier, storage adapter, network
simulator or complete model checker. Inputs stand for already authenticated facts;
JSON snapshots below are test comparisons, NEVER protocol signing preimages.
"""
from copy import deepcopy
from dataclasses import dataclass, asdict
from functools import wraps
import json

MAX_U128 = (1 << 128) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, maximum=MAX_U128):
    require(type(value) is int and 0 <= value <= maximum, "invalid unsigned integer")
    return value


def threshold(weights):
    require(bool(weights), "empty validator set")
    total = 0
    for identity, weight in weights.items():
        require(isinstance(identity, str) and bool(identity), "invalid identity")
        require(uint(weight) > 0, "zero weight")
        total = uint(total + weight)
    uint(2 * total)  # Match the frozen checked-u128 arithmetic contract.
    return (2 * total) // 3 + 1


def check_quorum(weights, signers):
    q = threshold(weights)
    require(tuple(sorted(set(signers))) == tuple(signers), "noncanonical or duplicate signers")
    require(all(s in weights for s in signers), "unknown signer")
    require(sum(weights[s] for s in signers) >= q, "insufficient weight")


@dataclass(frozen=True)
class Context:
    genesis: str
    chain: str
    protocol: int
    epoch: int
    validator_set: str
    parameters: str


@dataclass(frozen=True)
class CertifiedHeader:
    context: Context
    block: str
    parent: str
    height: int
    view: int
    qc_digest: str
    justify_digest: str
    signers: tuple


def check_finality_shape(kind, headers, context, weights, target):
    """Relationship check ONLY. Does not authenticate signatures or execution."""
    require(kind == "poco-three-chain-v0", "wrong proof class")
    require(len(headers) == 3, "three certified headers required")
    require(headers[0].block == target, "wrong finality target")
    for header in headers:
        require(header.context == context, "context mismatch")
        require(uint(header.height) > 0 and uint(header.view) > 0, "synthetic anchor is not a QC")
        require(bool(header.block) and bool(header.qc_digest), "missing identity")
        check_quorum(weights, header.signers)
    for parent, child in zip(headers, headers[1:]):
        require(child.parent == parent.block, "broken parent link")
        require(child.height == parent.height + 1, "noncontiguous height")
        require(child.view > parent.view, "nonincreasing view")
        require(child.justify_digest == parent.qc_digest, "different QC signer subset/digest")


class SigningTrace:
    """Crash/readback boundary example, not a full consensus decision procedure."""
    stages = ("IntentDurable", "SignatureRecorded", "VotePublished")

    def __init__(self, context):
        self.context = context
        self.records = {}
        self.last_voted_view = 0
        self.finalized_height = 0
        self.generation = 1

    def decide(self, kind, view, digest):
        require(kind in ("vote", "timeout"), "unknown signing kind")
        require(uint(view) > 0 and bool(digest), "invalid intent")
        key = (kind, view)
        if key in self.records:
            require(self.records[key][0] == digest, "equivocation")
            return key
        if kind == "vote":
            require(view > self.last_voted_view, "watermark regression")
        self.records[key] = (digest, "IntentDurable")
        if kind == "vote":
            self.last_voted_view = view
        return key

    def advance(self, key, digest, generation, stage):
        require(generation == self.generation, "stale recovery generation")
        require(key in self.records and self.records[key][0] == digest, "wrong receipt binding")
        require(stage in self.stages, "wrong stage")
        old = self.stages.index(self.records[key][1])
        new = self.stages.index(stage)
        require(new in (old, old + 1), "skipped or regressed stage")
        self.records[key] = (digest, stage)

    def reopen(self):
        clone = deepcopy(self)
        clone.generation += 1
        return clone


def atomic(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        old = deepcopy(self.__dict__)
        try:
            result = method(self, *args, **kwargs)
            self.invariants()
            return result
        except Exception:
            self.__dict__ = old
            raise
    return wrapped


@dataclass
class Task:
    owner: str
    lane: int
    nonce: int
    funds: int
    work: tuple  # verify work, retained bytes, challenge work
    deadline: int
    retain_until: int
    profile: str
    phase: str = "Running"
    accepted: bool = False
    ready_at: int = 0
    outcome: str = ""
    retention_released: bool = False


class ResourceLedger:
    """Finalized-transition arithmetic abstraction; not authorization/AI verification.

    admit/resolve inputs represent successful deterministic authorization/profile
    checks outside this model. Omitted checks cannot be inferred from a passing test.
    Historical task records are retained for replay examples; they are NOT active
    task slots. This dictionary is not a production pruning or bounded-storage design.
    """
    def __init__(self, funds=100, caps=(100, 100, 100), max_tasks=16, service_cap=2):
        uint(funds)
        require(len(caps) == 3 and all(uint(c) > 0 for c in caps), "bad resource caps")
        require(uint(max_tasks) > 0 and uint(service_cap) > 0, "zero progress budget")
        self.initial = funds
        self.available = funds
        self.escrow = 0
        self.paid = 0
        self.refunded = 0  # Saturating diagnostic lower bound, NOT an asset.
        self.refund_counter_saturated = False
        self.caps = tuple(caps)
        self.max_tasks = max_tasks
        self.service_cap = service_cap
        self.reserved = [0, 0, 0]
        self.height = 0
        self.tasks = {}
        self.next_nonce = {}

    def active_task_count(self):
        return sum(1 for task in self.tasks.values()
                   if task.phase != "Settled" or not task.retention_released)

    def snapshot(self):
        return json.dumps({
            "height": self.height, "available": self.available, "escrow": self.escrow,
            "paid": self.paid, "refunded": self.refunded, "reserved": self.reserved,
            "refund_counter_saturated": self.refund_counter_saturated,
            "tasks": {k: asdict(v) for k, v in sorted(self.tasks.items())},
            "nonces": sorted((owner, lane, n) for (owner, lane), n in self.next_nonce.items()),
        }, sort_keys=True)

    def invariants(self):
        require(self.initial == self.available + self.escrow + self.paid, "asset conservation")
        require(self.escrow == sum(t.funds for t in self.tasks.values() if t.phase != "Settled"), "escrow mismatch")
        require(self.active_task_count() <= self.max_tasks, "active task slot overcommit")
        expected = [0, 0, 0]
        for task in self.tasks.values():
            for i in (0, 2):
                expected[i] += task.work[i] if task.phase != "Settled" else 0
            expected[1] += task.work[1] if not task.retention_released else 0
        require(expected == self.reserved, "resource accounting mismatch")
        require(all(0 <= n <= c for n, c in zip(expected, self.caps)), "resource overcommit")
        require(all(uint(n) == n for n in (self.available, self.escrow, self.paid, self.refunded)), "amount range")
        require(type(self.refund_counter_saturated) is bool, "invalid diagnostic flag")
        require(not self.refund_counter_saturated or self.refunded == MAX_U128, "diagnostic flag mismatch")

    @atomic
    def admit(self, task_id, owner, lane, nonce, funds, work, deadline, retain_until, profile):
        require(task_id not in self.tasks, "duplicate task identity")
        require(bool(task_id) and bool(owner) and bool(profile), "missing binding")
        uint(lane, 65535)
        require(nonce == self.next_nonce.get((owner, lane), 1), "nonce mismatch")
        uint(nonce)
        require(uint(funds) > 0 and funds <= self.available, "insufficient escrow")
        require(len(work) == 3 and all(uint(x) > 0 for x in work), "zero or malformed reservation")
        require(uint(deadline) > self.height, "deadline is not in future")
        require(uint(retain_until) > deadline, "invalid retention horizon")
        require(self.active_task_count() < self.max_tasks, "task cap")
        require(all(a + b <= c for a, b, c in zip(self.reserved, work, self.caps)), "aggregate resource cap")
        self.tasks[task_id] = Task(owner, lane, nonce, funds, tuple(work), deadline, retain_until, profile)
        self.next_nonce[(owner, lane)] = uint(nonce + 1)
        self.available -= funds
        self.escrow += funds
        self.reserved = [a + b for a, b in zip(self.reserved, work)]

    @atomic
    def resolve(self, task_id, profile, accepted):
        task = self.tasks[task_id]
        require(task.phase == "Running", "wrong result predecessor")
        require(profile == task.profile and type(accepted) is bool, "wrong profile/outcome")
        require(self.height <= task.deadline, "late result")
        task.phase = "Ready"
        task.ready_at = self.height
        task.accepted = accepted
        task.outcome = "verified" if accepted else "rejected"

    @atomic
    def settle(self, task_id):
        task = self.tasks[task_id]
        if task.phase == "Settled":
            return  # Exact retry cannot pay twice.
        require(task.phase in ("Ready", "Expired"), "unresolved task")
        self.escrow -= task.funds
        if task.accepted:
            self.paid += task.funds
        else:
            self.available += task.funds
            # Recycled principal can produce unbounded lifetime refund volume.
            # A diagnostic overflow must never roll back required block service.
            self.refund_counter_saturated |= task.funds > MAX_U128 - self.refunded
            self.refunded = min(MAX_U128, self.refunded + task.funds)
        for i in (0, 2):
            self.reserved[i] -= task.work[i]
        task.phase = "Settled"

    @atomic
    def begin_block(self, height):
        require(uint(height) == self.height + 1, "noncontiguous block")
        self.height = height
        due = sorted((t.deadline, key) for key, t in self.tasks.items()
                     if t.phase == "Running" and t.deadline < height)
        for _, key in due[:self.service_cap]:
            self.tasks[key].phase = "Expired"
            self.tasks[key].ready_at = height
            self.tasks[key].outcome = "timeout-not-fraud"
        ready = sorted((t.ready_at, key) for key, t in self.tasks.items() if t.phase in ("Ready", "Expired"))
        for _, key in ready[:self.service_cap]:
            self.settle(key)
        retained = sorted((t.retain_until, key) for key, t in self.tasks.items()
                          if t.phase == "Settled" and not t.retention_released and t.retain_until < height)
        for _, key in retained[:self.service_cap]:
            task = self.tasks[key]
            self.reserved[1] -= task.work[1]
            task.retention_released = True
