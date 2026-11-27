"""Sealed public Engine used only by the finite read-only SQLite replay fixtures."""
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import struct

from hia.platform.service_settlement.qualification.native import PublicEngine
from hia.platform.state_import_sqlite.qualification_host import sealed_library


class _Calls:
    public_dispatch_wall_ns = 0

    def __init__(self):
        self.applies = 0

    @staticmethod
    def blob(data):
        return len(data)

    def record(self, item):
        if item["function"] == "engine_apply":
            self.applies += 1


@dataclass
class FixtureReplay:
    engine: PublicEngine
    calls: _Calls
    same_block: bool = False
    variable_rows: int = 0
    parent: int | None = None
    trust: bytes | None = None
    last_parent_root: bytes | None = None

    @classmethod
    def open(cls, stack, build, digest, *, same_block=False, variable_rows=0):
        build = Path(build)
        meta = json.loads((build / "build.json").read_bytes())
        if meta["artifact"]["sha256"] != digest:
            raise ValueError("Unexpected Settlement Engine identity")
        calls = _Calls()
        image = stack.enter_context(sealed_library(build / "settlement-engine.so", digest))
        engine = PublicEngine(build, calls, observed_image=(image._name, meta["artifact"]))
        session = cls(engine, calls, same_block, variable_rows)
        stack.callback(session.close)
        return session

    def close(self):
        for pointer in tuple(self.engine.live):
            self.engine.drop(pointer)

    def preview_genesis_receipt(self, trust, expected_root, height, command):
        """One private prospective call; no original execution context or receipt is supplied."""
        if self.parent is not None or self.calls.applies or not 112 <= len(command) <= 8192 or command[0]:
            raise ValueError("One exact genesis AdmitReceipt prospective command is required")
        self.parent = self.engine.owned("engine_new", body=trust)
        return self._prospective_receipt(trust, expected_root, height, command, 0)

    def preview_replayed_receipt(self, expected_root, height, command):
        if (self.parent is None or self.variable_rows != 1 or self.calls.applies != 1
                or not 112 <= len(command) <= 8192 or command[0]):
            raise ValueError("Exactly one held original AdmitReceipt predecessor is required")
        return self._prospective_receipt(self.trust, expected_root, height, command, 1)

    def preview_replayed_rollup(self, expected_root, height, command):
        if (self.parent is None or self.variable_rows != 1 or self.calls.applies != 1
                or not 112 <= len(command) <= 8192 or command[0] != 1):
            raise ValueError("Rollup preview requires one actual immutable admitted predecessor")
        return self._prospective_receipt(self.trust, expected_root, height, command, 1, include_state=True)

    @contextmanager
    def prepare_mixed_preview(self, trust, expected_root):
        """Yield ordered detached successors without replacing the audited parent."""
        if self.parent is None or self.variable_rows != 1 or self.calls.applies != 1 or trust != self.trust:
            raise ValueError("Missing the exact verified durable parent")
        parent = self.parent
        engine = self.engine
        if (engine.kind(parent) != 1 or engine.view("engine_trust", parent) != trust
                or engine.view("engine_state_root", parent) != expected_root
                or engine.scalar("engine_history_count", parent) != 1):
            raise ValueError("Held native parent changed")
        initial = parent
        succ = []
        next_root = expected_root

        def step(kind, height, command):
            nonlocal parent, next_root
            expected = (24, 25)
            pending = len(succ)
            if pending >= len(expected) or kind != expected[pending]:
                raise ValueError("Unsupported genuine mixed prospective order")
            if not 112 <= len(command) <= 8192 or command[0] != kind-24:
                raise ValueError("Wrong bounded canonical batch command")
            op = engine.owned("operation_id", body=command)
            try:
                if engine.kind(op) != 2:
                    return None
                identity = engine.view("bytes_view", op)
            finally:
                engine.drop(op)
            child = engine.owned("engine_apply", parent, body=command, height=height)
            succ.append(child)
            if (engine.kind(child) != 1 or engine.scalar("engine_history_count", child) != pending + 2
                    or engine.scalar("engine_history_count", initial) != 1
                    or engine.view("engine_state_root", parent) != next_root):
                return None
            root = engine.view("engine_state_root", child)
            if (len(identity), len(root)) != (32, 32):
                raise ValueError("Wrong observed ID or next root size")
            typed = engine.view("engine_state", child) if kind == 25 else b""
            if kind == 25 and not 111 <= len(typed) <= 16384:
                return None
            result = next_root, identity, root, typed
            parent, next_root = child, root
            return result

        try:
            yield step
        finally:
            for ptr in reversed(succ):
                engine.drop(ptr)

    def _prospective_receipt(self, trust, expected_root, height, command, prior_count, *, include_state=False):
        if (self.engine.kind(self.parent) != 1
                or self.engine.view("engine_trust", self.parent) != trust
                or self.engine.scalar("engine_history_count", self.parent) != prior_count):
            return None
        parent_root = self.engine.view("engine_state_root", self.parent)
        if len(parent_root) != 32 or parent_root != expected_root:
            return None
        op = self.engine.owned("operation_id", body=command)
        try:
            if self.engine.kind(op) != 2:
                return None
            identity = self.engine.view("bytes_view", op)
        finally:
            self.engine.drop(op)
        successor = self.engine.owned("engine_apply", self.parent, body=command, height=height)
        try:
            if (self.engine.kind(successor) != 1
                    or self.engine.scalar("engine_history_count", successor) != prior_count + 1
                    or self.engine.scalar("engine_history_count", self.parent) != prior_count
                    or self.engine.view("engine_state_root", self.parent) != parent_root):
                return None
            root = self.engine.view("engine_state_root", successor)
            if (len(parent_root), len(identity), len(root), self.calls.applies) != (32, 32, 32, prior_count + 1):
                raise ValueError("Sealed Engine returned a malformed prospective result")
            if include_state:
                state = self.engine.view("engine_state", successor)
                if not 111 <= len(state) <= 16384:
                    return None
                return parent_root, identity, root, state
            return parent_root, identity, root
        finally:
            self.engine.drop(successor)

    def apply(self, request):
        before = self.calls.applies
        if self.variable_rows:
            if not 40 <= len(request) <= 20642:
                raise ValueError("Wrong bounded variable replay input")
            seq, trust_n, execution_n, command_n, height = struct.unpack_from("<5Q", request)
            if (not 1 <= seq <= self.variable_rows or seq != before + 1 or not 74 <= trust_n <= 8160
                    or not 154 <= execution_n <= 4250 or not 1 <= command_n <= 8192
                    or len(request) != 40 + trust_n + execution_n + command_n):
                raise ValueError("Invalid length-delimited variable replay request")
            boundary = 40 + trust_n
            ending = boundary + execution_n
            trust, execution, command = request[40:boundary], request[boundary:ending], request[ending:]
            variable_kinds = ((0, 1) if self.same_block else (0,)*self.variable_rows
                              if self.variable_rows > 4 else (0, 0, 1, 2)[:self.variable_rows])
            if self.same_block and self.variable_rows != 2:
                raise ValueError("Same-block replay has two actual operations")
            if (command[0] != variable_kinds[seq - 1]
                    or struct.unpack_from("<Q", execution, execution_n - 40)[0] != height):
                raise ValueError("Wrong actual variable replay kind or coordinates")
        else:
            widths = (1921, 2811) if self.same_block else (1921, 1953, 3742, 1293)
            if len(request) not in widths:
                raise ValueError("Wrong bounded replay input")
            seq, = struct.unpack_from("<Q", request)
            if not 1 <= seq <= len(widths) or seq != before + 1 or len(request) != widths[seq - 1]:
                raise ValueError("Noncontiguous sealed Engine request")
            trust, execution, command = request[8:890], request[890:1053], request[1053:]
            kinds = (0, 1) if self.same_block else (0, 0, 1, 2)
            if command[0] != kinds[seq - 1]:
                raise ValueError("Request does not follow the admitted receipt/rollup/settle profile")
            height, = struct.unpack_from("<Q", execution, 123)
        if self.parent is None:
            if seq != 1:
                raise ValueError("Missing private immutable predecessor")
            self.parent = self.engine.owned("engine_new", body=trust)
            self.trust = trust
        if (self.trust != trust or self.engine.kind(self.parent) != 1
                or self.engine.scalar("engine_history_count", self.parent) != seq - 1
                or self.engine.view("engine_trust", self.parent) != trust):
            return b""

        validated = self.engine.owned("engine_validate_execution", self.parent, body=execution)
        try:
            if (self.engine.kind(validated), self.engine.view("bytes_view", validated)) != (4, b""):
                return b""
        finally:
            self.engine.drop(validated)
        identity = self.engine.owned("operation_id", body=command)
        try:
            if self.engine.kind(identity) != 2:
                return b""
            operation_id = self.engine.view("bytes_view", identity)
        finally:
            self.engine.drop(identity)
        self.last_parent_root = self.engine.view("engine_state_root", self.parent)
        if len(self.last_parent_root) != 32:
            return b""
        successor = self.engine.owned("engine_apply", self.parent, body=command, height=height)
        try:
            if self.engine.kind(successor) != 1:
                return b""
            count = self.engine.scalar("engine_history_count", successor)
            if self.engine.scalar("engine_history_count", self.parent) != seq - 1:
                return b""
            root = self.engine.view("engine_state_root", successor)
            copied = self.engine.owned("engine_state_copy", successor)
            try:
                if self.engine.kind(copied) != 3:
                    return b""
                state = self.engine.view("bytes_view", copied)
                expected_state = (1196, 2172) if self.same_block else (1196, 2145, 3185, 4870)
                state_extent = (111 <= len(state) <= 16384 if self.variable_rows
                                else len(state) == expected_state[seq - 1])
                if (len(operation_id), len(root)) != (32, 32) or not state_extent:
                    return b""
                if state != self.engine.view("engine_state", successor):
                    return b""
            finally:
                self.engine.drop(copied)
            if self.calls.applies != seq:
                return b""
            reply = struct.pack("<Q", count) + operation_id + root + state
            self.engine.drop(self.parent)
            self.parent, successor = successor, None
            return reply
        finally:
            if successor is not None:
                self.engine.drop(successor)
