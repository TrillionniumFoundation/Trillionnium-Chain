"""Sealed public Engine used only by the finite read-only SQLite replay fixtures."""
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
    parent: int | None = None
    trust: bytes | None = None

    @classmethod
    def open(cls, stack, build, digest):
        build = Path(build)
        meta = json.loads((build / "build.json").read_bytes())
        if meta["artifact"]["sha256"] != digest:
            raise ValueError("Unexpected Settlement Engine identity")
        calls = _Calls()
        image = stack.enter_context(sealed_library(build / "settlement-engine.so", digest))
        engine = PublicEngine(build, calls, observed_image=(image._name, meta["artifact"]))
        session = cls(engine, calls)
        stack.callback(session.close)
        return session

    def close(self):
        for pointer in tuple(self.engine.live):
            self.engine.drop(pointer)

    def apply(self, request):
        widths = (1921, 1953, 3742, 1293)
        if len(request) not in widths:
            raise ValueError("Wrong bounded replay input")
        before = self.calls.applies
        seq, = struct.unpack_from("<Q", request)
        if seq not in (1, 2, 3, 4) or seq != before + 1 or len(request) != widths[seq - 1]:
            raise ValueError("Noncontiguous sealed Engine request")
        trust, execution, command = request[8:890], request[890:1053], request[1053:]
        if command[0] != (0, 0, 1, 2)[seq - 1]:
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
                if (len(operation_id), len(root), len(state)) != (32, 32, (1196, 2145, 3185, 4870)[seq - 1]):
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
