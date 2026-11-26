"""Sealed public Engine for the one-row read-only SQLite fixture, not a Store owner."""
from contextlib import ExitStack
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


def apply_first_fixture(build, digest, request):
    if len(request) != 1913:
        raise ValueError("Wrong bounded replay input")
    build = Path(build)
    meta = json.loads((build / "build.json").read_bytes())
    if meta["artifact"]["sha256"] != digest:
        raise ValueError("Unexpected Settlement Engine identity")
    trust, execution, command = request[:882], request[882:1045], request[1045:]
    if command[0] != 0:
        raise ValueError("First replay witness only admits an AdmitReceipt")
    height, = struct.unpack_from("<Q", execution, 123)
    seen = _Calls()
    with sealed_library(build / "settlement-engine.so", digest) as sealed:
        engine = PublicEngine(build, seen, observed_image=(sealed._name, meta["artifact"]))
        with ExitStack() as stack:
            def owned(*args, **kwargs):
                token = engine.owned(*args, **kwargs)
                stack.callback(engine.drop, token)
                return token

            parent = owned("engine_new", body=trust)
            if engine.kind(parent) != 1 or engine.scalar("engine_history_count", parent) != 0:
                return 0, b""
            if engine.view("engine_trust", parent) != trust:
                return 0, b""
            proven = owned("engine_validate_execution", parent, body=execution)
            if (engine.kind(proven), engine.view("bytes_view", proven)) != (4, b""):
                return 0, b""
            identity = owned("operation_id", body=command)
            if engine.kind(identity) != 2:
                return 0, b""
            operation_id = engine.view("bytes_view", identity)
            successor = owned("engine_apply", parent, body=command, height=height)
            if engine.kind(successor) != 1:
                return seen.applies, b""
            count = engine.scalar("engine_history_count", successor)
            if engine.scalar("engine_history_count", parent) != 0:
                return seen.applies, b""
            root = engine.view("engine_state_root", successor)
            copied = owned("engine_state_copy", successor)
            if engine.kind(copied) != 3:
                return seen.applies, b""
            state = engine.view("bytes_view", copied)
            if (len(operation_id), len(root), len(state)) != (32, 32, 1196):
                return seen.applies, b""
            if state != engine.view("engine_state", successor):
                return seen.applies, b""
        if engine.live or seen.applies != 1:
            raise ValueError("Native witness did not reap all private Engine owners")
        return seen.applies, struct.pack("<Q", count) + operation_id + root + state
