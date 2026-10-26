"""Research-only indexed fork-local ASERT oracle; input blocks are ASSUMED valid.

No W1 proof is verified here. The index models the native bounded jump lookup
cost/ordering, not the native SQLite WAL, packet authentication or consensus.
"""
from dataclasses import dataclass
from hashlib import sha256

from daa_research_oracle import asert_target

GENESIS = sha256(b"pon-index-genesis").digest()
NETWORK = sha256(b"pon-index-network").digest()
PARAMETERS = sha256(b"pon-index-parameters").digest()
POW_LIMIT = (1 << 250) - 1
ANCHOR_TARGET = 1 << 220


@dataclass(frozen=True)
class Block:
    identity: bytes
    parent: bytes
    height: int
    timestamp: int
    target: int
    network: bytes = NETWORK
    parameters: bytes = PARAMETERS


def identity(parent: bytes, height: int, timestamp: int, target: int,
             network: bytes = NETWORK, parameters: bytes = PARAMETERS) -> bytes:
    return sha256(b"index-only-not-W1" + network + parameters + parent
                  + height.to_bytes(8, "little")
                  + timestamp.to_bytes(8, "little")
                  + target.to_bytes(32, "big")).digest()


class ValidatedInputIndex:
    """Research simulation. Call append ONLY after an independent W1 verifier."""
    def __init__(self):
        self.headers = {GENESIS: Block(GENESIS, bytes(32), 0, 0, ANCHOR_TARGET)}
        self.jumps = {GENESIS: []}

    def append(self, parent: bytes, timestamp: int, target: int = ANCHOR_TARGET) -> bytes:
        if parent not in self.headers:
            raise ValueError("PARENT_UNAVAILABLE")
        height = self.headers[parent].height + 1
        name = identity(parent, height, timestamp, target)
        if name in self.headers:
            raise ValueError("DUPLICATE")
        jumps = [parent]
        while len(jumps) < 63:
            prior = jumps[-1]
            if len(self.jumps[prior]) < len(jumps):
                break
            jumps.append(self.jumps[prior][len(jumps) - 1])
        self.headers[name] = Block(name, parent, height, timestamp, target)
        self.jumps[name] = jumps
        return name

    def _check(self, name: bytes):
        if name == GENESIS:
            return
        h = self.headers.get(name)
        if (h is None or h.network != NETWORK or h.parameters != PARAMETERS
                or h.identity != identity(h.parent, h.height, h.timestamp, h.target)):
            raise ValueError("INDEX_HEADER_CORRUPT")
        if h.parent not in self.headers or self.headers[h.parent].height + 1 != h.height:
            raise ValueError("INDEX_PARENT_CORRUPT")

    def _jump(self, name: bytes, k: int) -> bytes:
        self._check(name)
        jumps = self.jumps[name]
        if k >= len(jumps):
            raise ValueError("INDEX_MISSING")
        found = jumps[k]
        if k == 0:
            if found != self.headers[name].parent:
                raise ValueError("INDEX_PARENT_CORRUPT")
        else:
            left = jumps[k - 1]
            self._check(left)
            if k-1 >= len(self.jumps[left]) or found != self.jumps[left][k-1]:
                raise ValueError("INDEX_STRUCTURE_CORRUPT")
        self._check(found)
        if self.headers[found].height != self.headers[name].height - (1 << k):
            raise ValueError("INDEX_HEIGHT_CORRUPT")
        return found

    def heights(self, tip: bytes, requested_desc: list[int], budget: int = 1024):
        if not 1 <= len(requested_desc) <= 24 or not 3 <= budget <= 1024:
            raise ValueError("INDEX_REQUEST")
        current = tip
        self._check(current)
        height = self.headers[current].height
        cost = 2
        output = {}
        for expected in requested_desc:
            if type(expected) is not int or expected < 0 or expected > height:
                raise ValueError("INDEX_HEIGHT")
            if output and expected >= next(reversed(output)):
                raise ValueError("INDEX_ORDER")
            difference = height - expected
            for k in range(62, -1, -1):
                if difference & (1 << k):
                    cost += 12  # conservative model cost, not actual SQL telemetry
                    if cost > budget:
                        raise ValueError("INDEX_BUDGET")
                    current = self._jump(current, k)
            cost += 2
            if cost > budget:
                raise ValueError("INDEX_BUDGET")
            if self.headers[current].height != expected:
                raise ValueError("INDEX_HEIGHT")
            output[expected] = current
            height = expected
        return output, cost

    def asert_shadow(self, tip: bytes, activation_height: int, median: bool):
        height = self.headers[tip].height
        if not 0 < activation_height <= height:
            raise ValueError("INDEX_ACTIVATION")
        heights = {activation_height}
        for end in (height, activation_height - 1):
            heights.update(range(max(0, end - 10), end + 1))
        names, cost = self.heights(tip, sorted(heights, reverse=True))
        times = {h: self.headers[name].timestamp for h, name in names.items()}
        def clock(end):
            if not median:
                return times[end]
            sample = sorted(times[i] for i in range(max(0, end - 10), end + 1))
            return sample[len(sample) // 2]
        target = asert_target(self.headers[names[activation_height]].target,
                              clock(activation_height - 1), clock(height),
                              activation_height, height + 1, 10, 7200, POW_LIMIT)
        return target, cost, names[activation_height]
