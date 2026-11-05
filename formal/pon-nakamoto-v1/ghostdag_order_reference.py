"""Bounded, uniform-work GHOSTDAG Algorithm 1 ordering research kernel.

Independently implemented from Sompolinsky, Wyborski and Zohar, PHANTOM
GHOSTDAG (2021-11-10), Algorithm 1. This is a complete-graph ordering function,
not a miner, a live admission/confirmation protocol, Kaspa, or native PoN.
Canonical hash-shaped IDs are supplied labels: no header hash, work proof,
transaction, signature, difficulty adjustment or network premise is verified.

The paper specifies lowest-hash ties between equally scoring tips. Its freedom
to choose a deterministic anticone topological order is fixed here to Kahn's
algorithm, choosing the lowest hash among currently ready vertices. All blocks,
including red blocks, appear in the returned order. Every block has exactly one
unit of synthetic work; other work profiles are explicitly unsupported.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import heapq
import json
import re


PROFILE = "ghostdag-algorithm1-uniform-work-v1"
DOMAIN = b"trnm-research-ghostdag-order-v1\0"
SOURCE = {
    "url": "https://www.avivz.net/pubs/2021/phantom_ghostdag.pdf",
    "revision": "2021-11-10",
    "section": "Algorithm 1; Sections 2.4.1 and 3.2",
}
ASSUMPTIONS = {
    "schema": "trnm-ghostdag-order-scope-v1",
    "profile": PROFILE,
    "source": SOURCE,
    "input": "complete finite DAG; one genesis; lowercase 256-bit hash-shaped labels",
    "work": "exactly one synthetic unit per block, including genesis",
    "score": "number of blue blocks in the strict past; genesis has score zero",
    "selected_tip": "highest strict-past blue score, then lowest hash",
    "merge_order": "lowest hash among ready vertices in the selected-tip anticone",
    "blue_admission": "candidate and every existing blue must remain within k blue anticones",
    "red_order": "red vertices remain in the topological output",
    "budget": "finite graph, edges, cached entries and deterministic operation units; no partial result",
    "operation_units": "logical loop/heap/bitset work, with bitset work charged per 64-bit word; not CPU cycles",
    "header_hashes_verified": False,
    "native_w1_verified": False,
    "pq_verified": False,
    "variable_difficulty_supported": False,
    "kaspa_implementation_equivalence": False,
    "confirmation_protocol_implemented": False,
    "security_theorem": False,
    "production_activation": False,
    "release_ready": False,
}


class GraphError(ValueError):
    """Malformed graph or an unsupported input profile."""


class ModelLimit(RuntimeError):
    """A finite research budget was exceeded; there is no successful result."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _uint(value: int, name: str, maximum: int, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GraphError(name)


def _hash_id(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise GraphError("BLOCK_ID")


@dataclass(frozen=True)
class Limits:
    max_blocks: int = 256
    max_parents: int = 64
    max_edges: int = 8192
    max_cached_entries: int = 131072
    max_operations: int = 2_000_000

    def validate(self) -> None:
        _uint(self.max_blocks, "MAX_BLOCKS", 2048, 1)
        _uint(self.max_parents, "MAX_PARENTS", 2048, 1)
        _uint(self.max_edges, "MAX_EDGES", 262144)
        _uint(self.max_cached_entries, "MAX_CACHED_ENTRIES", 2_000_000)
        _uint(self.max_operations, "MAX_OPERATIONS", 100_000_000)


@dataclass(frozen=True)
class Block:
    block_id: str
    parents: tuple[str, ...]
    work: int = 1


def block_from_dict(value: dict) -> Block:
    """Strict research encoding; no implicit conversion of a native header."""
    if type(value) is not dict or set(value) != {"block_id", "parents", "work"}:
        raise GraphError("BLOCK_SCHEMA")
    if type(value["parents"]) is not list or len(value["parents"]) > 2048:
        raise GraphError("PARENT_VECTOR")
    _hash_id(value["block_id"])
    for parent in value["parents"]:
        _hash_id(parent)
    if type(value["work"]) is not int or value["work"] != 1:
        raise GraphError("UNSUPPORTED_WORK")
    if len(set(value["parents"])) != len(value["parents"]):
        raise GraphError("DUPLICATE_PARENT")
    return Block(value["block_id"], tuple(value["parents"]), value["work"])


@dataclass(frozen=True)
class BlockScore:
    block_id: str
    blue_score: int
    selected_parent: str | None


@dataclass(frozen=True)
class Statistics:
    blocks: int
    edges: int
    depth: int
    operations: int
    cached_entries: int


@dataclass(frozen=True)
class Ordering:
    profile: str
    k: int
    graph_sha256: str
    genesis: str
    selected_tip: str
    blue: tuple[str, ...]
    red: tuple[str, ...]
    order: tuple[str, ...]
    scores: tuple[BlockScore, ...]
    blue_anticone_sizes: tuple[tuple[str, int], ...]
    statistics: Statistics

    def decision(self) -> dict:
        """Deterministic graph decision, excluding implementation work counters."""
        value = asdict(self)
        del value["statistics"]
        return value

    @property
    def decision_sha256(self) -> str:
        return hashlib.sha256(DOMAIN + b"decision\0" + canonical(self.decision())).hexdigest()


class _Budget:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.operations = 0
        self.cached_entries = 0

    def step(self, amount: int = 1) -> None:
        if amount > self.limits.max_operations - self.operations:
            raise ModelLimit("OPERATION_BUDGET")
        self.operations += amount

    def retain(self, amount: int) -> None:
        if amount > self.limits.max_cached_entries - self.cached_entries:
            raise ModelLimit("CACHED_ENTRY_BUDGET")
        self.cached_entries += amount


@dataclass
class _Context:
    blue: int
    order: tuple[int, ...]
    counts: dict[int, int]
    selected: int | None


class _Graph:
    def __init__(self, blocks: list[Block] | tuple[Block, ...], limits: Limits,
                 budget: _Budget):
        if type(blocks) not in (list, tuple):
            raise GraphError("BLOCK_VECTOR")
        if not blocks:
            raise GraphError("EMPTY_GRAPH")
        if len(blocks) > limits.max_blocks:
            raise ModelLimit("BLOCK_BUDGET")
        budget.step(len(blocks))
        by_id: dict[str, Block] = {}
        edges = 0
        for block in blocks:
            budget.step()
            if type(block) is not Block:
                raise GraphError("BLOCK_TYPE")
            _hash_id(block.block_id)
            if block.block_id in by_id:
                raise GraphError("DUPLICATE_BLOCK")
            if type(block.work) is not int or block.work != 1:
                raise GraphError("UNSUPPORTED_WORK")
            if type(block.parents) is not tuple:
                raise GraphError("PARENT_VECTOR")
            if len(block.parents) > limits.max_parents:
                raise ModelLimit("PARENT_BUDGET")
            edges += len(block.parents)
            if edges > limits.max_edges:
                raise ModelLimit("EDGE_BUDGET")
            budget.step(len(block.parents))
            for parent in block.parents:
                _hash_id(parent)
                if parent == block.block_id:
                    raise GraphError("SELF_PARENT")
            if len(set(block.parents)) != len(block.parents):
                raise GraphError("DUPLICATE_PARENT")
            by_id[block.block_id] = block
        # Sorting the canonical fixed-width IDs also provides the minimum-hash
        # heap key; no arrival-position or parent-vector tie-break is retained.
        budget.step(len(blocks) * max(1, len(blocks).bit_length()))
        self.ids = tuple(sorted(by_id))
        index = {block_id: i for i, block_id in enumerate(self.ids)}
        self.parents: list[tuple[int, ...]] = []
        for block_id in self.ids:
            block = by_id[block_id]
            budget.step(len(block.parents) + 1)
            if any(parent not in index for parent in block.parents):
                raise GraphError("MISSING_PARENT")
            self.parents.append(tuple(sorted(index[parent] for parent in block.parents)))
        roots = [i for i, parents in enumerate(self.parents) if not parents]
        if len(roots) != 1:
            raise GraphError("SINGLE_GENESIS_REQUIRED")
        self.genesis = roots[0]
        n = len(self.ids)
        self.words = (n + 63) // 64
        self.children: list[list[int]] = [[] for _ in range(n)]
        self.parent_masks = [0] * n
        for child, parents in enumerate(self.parents):
            for parent in parents:
                budget.step(self.words + 1)
                self.children[parent].append(child)
                self.parent_masks[child] |= 1 << parent
        self.topological = self.topological_subset((1 << n) - 1, budget)
        self.ancestors = [0] * n
        self.descendants = [0] * n
        depths = [0] * n
        for child in self.topological:
            for parent in self.parents[child]:
                budget.step(self.words + 1)
                self.ancestors[child] |= self.ancestors[parent] | (1 << parent)
                depths[child] = max(depths[child], depths[parent] + 1)
            if child != self.genesis and not self.ancestors[child] & (1 << self.genesis):
                raise GraphError("GENESIS_CLOSURE")
        for child in reversed(self.topological):
            for parent in self.parents[child]:
                budget.step(self.words)
                self.descendants[parent] |= self.descendants[child] | (1 << child)
        self.anticones = []
        full = (1 << n) - 1
        for i in range(n):
            budget.step(self.words)
            self.anticones.append(full & ~(self.ancestors[i] | self.descendants[i] | (1 << i)))
        self.edges = edges
        self.depth = max(depths)
        budget.step(n + edges)
        self.digest = hashlib.sha256(DOMAIN + b"graph\0" + canonical([
            {"block_id": block_id, "parents": sorted(by_id[block_id].parents), "work": 1}
            for block_id in self.ids
        ])).hexdigest()

    def topological_subset(self, mask: int, budget: _Budget) -> tuple[int, ...]:
        """Kahn/min-hash traversal; parents outside this subset are already ready."""
        indegree: dict[int, int] = {}
        ready: list[int] = []
        todo = mask
        while todo:
            budget.step(self.words + 1)
            bit = todo & -todo
            todo ^= bit
            i = bit.bit_length() - 1
            indegree[i] = (self.parent_masks[i] & mask).bit_count()
            if not indegree[i]:
                ready.append(i)
        heapq.heapify(ready)
        ordered: list[int] = []
        while ready:
            budget.step(max(1, len(indegree).bit_length()))
            i = heapq.heappop(ready)
            ordered.append(i)
            for child in self.children[i]:
                budget.step()
                if child not in indegree:
                    continue
                indegree[child] -= 1
                if not indegree[child]:
                    budget.step(max(1, len(indegree).bit_length()))
                    heapq.heappush(ready, child)
        if len(ordered) != len(indegree):
            raise GraphError("CYCLE")
        return tuple(ordered)

    def tips(self, candidates: tuple[int, ...], budget: _Budget) -> tuple[int, ...]:
        """Discard redundant ancestor references, retaining actual induced tips."""
        past_of_candidates = 0
        for candidate in candidates:
            budget.step(self.words)
            past_of_candidates |= self.ancestors[candidate]
        budget.step(len(candidates) * self.words)
        return tuple(i for i in candidates if not past_of_candidates & (1 << i))


def order_dag(blocks: list[Block] | tuple[Block, ...], k: int, *,
              limits: Limits = Limits(), profile: str = PROFILE) -> Ordering:
    """Return the whole finite ordering, or reject; never grant admission/finality.

    Complete past summaries are memoized in topological order rather than using
    Python recursion. The input is not mutated. Limits reject even an otherwise
    valid graph and never return a partial order or a partially colored graph.
    """
    if type(profile) is not str or profile != PROFILE:
        raise GraphError("UNSUPPORTED_PROFILE")
    if type(limits) is not Limits:
        raise GraphError("LIMITS_TYPE")
    limits.validate()
    _uint(k, "K", 2048)
    budget = _Budget(limits)
    graph = _Graph(blocks, limits, budget)
    n = len(graph.ids)
    cached: list[_Context | None] = [None] * n

    def assemble(mask: int, tips: tuple[int, ...]) -> _Context:
        budget.step(len(tips))
        if not tips:
            raise AssertionError("NONEMPTY_CONTEXT_WITHOUT_TIPS")
        # The index order is exactly the ascending fixed-width hash order.
        selected = min(tips, key=lambda i: (-cached[i].blue.bit_count(), i))
        base = cached[selected]
        if base is None:
            raise AssertionError("UNREADY_PAST")
        budget.retain(len(base.order) + len(base.counts) + 2)
        budget.step(len(base.order) + len(base.counts) + graph.words)
        blue = base.blue | (1 << selected)
        counts = base.counts.copy()
        counts[selected] = 0
        ordered = list(base.order) + [selected]
        merge = mask & ~(graph.ancestors[selected] | (1 << selected))
        for candidate in graph.topological_subset(merge, budget):
            budget.step(graph.words)
            incomparable = blue & graph.anticones[candidate]
            candidate_count = incomparable.bit_count()
            allowed = candidate_count <= k
            affected: list[int] = []
            if allowed:
                todo = incomparable
                while todo:
                    budget.step(graph.words)
                    bit = todo & -todo
                    todo ^= bit
                    other = bit.bit_length() - 1
                    affected.append(other)
                    if counts[other] >= k:
                        allowed = False
                        break
            if allowed:
                budget.retain(1)
                budget.step(len(affected) + graph.words)
                blue |= 1 << candidate
                counts[candidate] = candidate_count
                for other in affected:
                    counts[other] += 1
            budget.retain(1)
            budget.step()
            ordered.append(candidate)
        if len(ordered) != mask.bit_count():
            raise AssertionError("INCOMPLETE_ORDER")
        return _Context(blue, tuple(ordered), counts, selected)

    for i in graph.topological:
        budget.step()
        if i == graph.genesis:
            cached[i] = _Context(0, (), {}, None)
        else:
            cached[i] = assemble(graph.ancestors[i], graph.tips(graph.parents[i], budget))
    tips = tuple(i for i, children in enumerate(graph.children) if not children)
    result = assemble((1 << n) - 1, tips)
    budget.step(n * graph.words)
    blue = tuple(graph.ids[i] for i in range(n) if result.blue & (1 << i))
    red = tuple(graph.ids[i] for i in range(n) if not result.blue & (1 << i))
    scores = tuple(BlockScore(graph.ids[i], cached[i].blue.bit_count(),
                              None if cached[i].selected is None else graph.ids[cached[i].selected])
                   for i in range(n))
    return Ordering(PROFILE, k, graph.digest, graph.ids[graph.genesis],
                    graph.ids[result.selected], blue, red,
                    tuple(graph.ids[i] for i in result.order), scores,
                    tuple((graph.ids[i], result.counts[i]) for i in sorted(result.counts)),
                    Statistics(n, graph.edges, graph.depth, budget.operations, budget.cached_entries))
