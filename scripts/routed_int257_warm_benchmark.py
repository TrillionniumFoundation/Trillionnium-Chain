"""Optional, source-bound warm ABI comparison. Not an acceptance test."""
from __future__ import annotations

import argparse
import contextlib
import ctypes
from dataclasses import dataclass
import fcntl
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from hia.tests import test_routed_int257_direct as direct
from hia.tests import test_routed_int257_grouped as grouped
from hia.tests import test_routed_int257_ordinary as ordinary
from hia.tests.native_support import NativeModule
from hia.tools import toolchain

ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ("direct", "selfhost")
LANES = ("direct", "grouped")
HARNESSES = tuple(
    Path(module.__file__).resolve().relative_to(ROOT).as_posix()
    for module in (direct, grouped, ordinary, toolchain, sys.modules[NativeModule.__module__])
) + (
    "scripts/routed_int257_warm_benchmark.py",
    "hia/tests/routed_int257_direct_derivation.py",
    "hia/toolchain.lock.json", "hia/qualification/compiler-binding.json",
)
TOKEN = re.compile(r"[a-f0-9]{64}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(root, *args):
    # The repository may be sparse, but measurement never fetches missing objects.
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
    return subprocess.run(["git", "-C", str(root), *args], env=env, check=True,
                          capture_output=True, timeout=10).stdout


class Source:
    def __init__(self, root):
        self.root = root
        self.head = git(root, "rev-parse", "--verify", "HEAD").decode().strip()
        self.tree = git(root, "rev-parse", "--verify", self.head + "^{tree}").decode().strip()
        self.inputs = {}
        self.check_head()

    def check_head(self):
        current = git(self.root, "rev-parse", "--verify", "HEAD").decode().strip()
        require(current == self.head, "Chain HEAD changed during benchmark")

    def exact(self, name, expected=None):
        path = Path(name)
        require(not path.is_absolute() and path.as_posix() == name and ".." not in path.parts,
                "noncanonical source path")
        require(not any((self.root / p).is_symlink() for p in (path, *path.parents))
                and (self.root / path).is_file(), "missing or linked benchmark input: " + name)
        current = (self.root / path).read_bytes()
        if name not in self.inputs:
            recorded = git(self.root, "cat-file", "blob", self.head + ":" + name)
            require(recorded == current, "worktree input differs from committed source: " + name)
            self.inputs[name] = sha(recorded)
        actual = sha(current)
        require(actual == self.inputs[name] and (expected is None or actual == expected),
                "build/source input mismatch: " + name)

    def validate(self):
        self.check_head()
        for name in self.inputs:
            self.exact(name)
        self.check_head()


def unique_object(items):
    obj = {}
    for key, value in items:
        require(key not in obj, "duplicate ELF pin key")
        obj[key] = value
    return obj


def elf_pins(raw):
    pins = json.loads(raw, object_pairs_hook=unique_object)
    require(type(pins) is dict and set(pins) == set(BACKENDS), "need both exact backend pin maps")
    for backend in BACKENDS:
        row = pins[backend]
        require(type(row) is dict and set(row) == set(LANES)
                and all(type(x) is str and TOKEN.fullmatch(x) for x in row.values())
                and len(set(row.values())) == 2, "need distinct exact Direct and Grouped ELF pins")
    require(len({x for row in pins.values() for x in row.values()}) == 4,
            "each image must have its own ELF identity")
    return pins


@dataclass(frozen=True)
class Workload:
    n: int
    distribution: str
    routes: tuple[int, ...]
    frame: bytes


def panel():
    dim = ordinary.DIM
    model = [((i*13+i//dim*11) % 29)-14 for i in range(ordinary.PARAMS)]
    model[3*dim:6*dim] = [0]*(3*dim)
    for j in range(3):
        model[(3+j)*dim+j] = 19
    for n in (1, 8, 32, 64):
        choices = [("one", (1,)*n)]
        if n > 1:
            choices += [
                ("balanced", tuple(i % 3 for i in range(n))),
                ("skew", tuple(2 if i == n-1 else 1 if i == n//2 else 0 for i in range(n))),
            ]
        for label, routes in choices:
            rows = [ordinary.features((j, 8), (3+k % 251, -8+k % 17),
                                      (255, (3*k) % 17-8)) for k, j in enumerate(routes)]
            yield Workload(n, label, routes, ordinary.frame(model, rows))


def output_extent(n):
    return direct.HEADER.size + (direct.ROW.size + 1) * n


def exact_product(case, left, right):
    require(left == right and len(left) == output_extent(case.n), "Product bytes differ")
    useful, padded, live, rows, bins = direct.parse(left, case.n)
    members = [tuple(i for i, j in enumerate(case.routes) if j == x) for x in range(3)]
    require((useful, padded, live) == (1542 * case.n, 0, sum(map(bool, members)))
            and bins == members and tuple(row[3] for row in rows) == case.routes,
            "Product does not express the predeclared fixture routes")
    return sha(left)


class Buffers:
    def __init__(self, function, frame, size, work):
        self.function = function
        self.i = ctypes.create_string_buffer(frame, len(frame))
        self.o = ctypes.create_string_buffer(size)
        self.a = ctypes.create_string_buffer(work)
        self.args = (ctypes.cast(self.i, ctypes.c_void_p), len(frame),
                     ctypes.cast(self.o, ctypes.c_void_p), size,
                     ctypes.cast(self.a, ctypes.c_void_p), work)

    def call(self):
        return self.function(*self.args)


def repeat(call, count):
    for _ in range(count):
        if call():
            raise ValueError("native ABI call refused inside a warm block")


def block(call, count, clock=time.perf_counter_ns):
    start = clock()
    repeat(call, count)
    elapsed = clock() - start
    require(elapsed > 0, "nonpositive monotonic interval")
    return elapsed


def run_blocks(left, right, count, pairs, first, clock=time.perf_counter_ns):
    # Even number of pairs: equal A/B and B/A starts.
    require(type(count) is int and 9 <= count <= 2000
            and type(pairs) is int and 2 <= pairs <= 40 and pairs % 2 == 0
            and first in LANES, "invalid bounded measurement policy")
    calls = dict(zip(LANES, (left, right), strict=True))
    order = LANES if first == "direct" else LANES[::-1]
    rows = []
    for i in range(pairs):
        pair = order if i % 2 == 0 else order[::-1]
        measured = {name + "_ns": block(calls[name], count, clock) for name in pair}
        rows.append({"order": pair, **measured})
    return rows


@contextlib.contextmanager
def sealed_image(raw):
    with os.fdopen(os.memfd_create("trnm-int257-warm", os.MFD_ALLOW_SEALING), "w+b") as image:
        image.write(raw)
        image.flush()
        fd = image.fileno()
        # Linux UAPI commands and mask, also used by the stock HIA compiler
        # driver. Some Python builds do not expose these Linux constants.
        add = getattr(fcntl, "F_ADD_SEALS", 1033)
        get = getattr(fcntl, "F_GET_SEALS", 1034)
        seals = 0x0f  # SEAL, SHRINK, GROW, WRITE
        fcntl.fcntl(fd, add, seals)
        require(fcntl.fcntl(fd, get) == seals, "ELF capture not immutable")
        yield fd


@contextlib.contextmanager
def load_pinned(kernel, expected):
    raw = kernel.library.read_bytes()
    require(sha(raw) == kernel.artifact_sha256 == expected, "ELF differs from its independent pin")
    # dlopen the bytes actually hashed, not a path that might later point elsewhere.
    with sealed_image(raw) as fd:
        library = ctypes.CDLL("/proc/self/fd/" + str(fd))
        function = library.f0
        function.argtypes = (ctypes.c_void_p, ctypes.c_uint64) * 3
        function.restype = ctypes.c_uint64  # Existing stock borrowed-buffer ABI.
        yield function
        require(sha(kernel.library.read_bytes()) == expected, "built ELF changed during benchmark")


def snapshot_compiler():
    _, pin = toolchain.pinned_toolchain()
    binding = json.loads((ROOT / "hia/qualification/compiler-binding.json").read_bytes())
    path = os.environ.get("HIA_NATIVE_COMPILER")
    require(bool(path), "set HIA_NATIVE_COMPILER")
    compiler = Path(path).resolve(strict=True)
    actual = sha(compiler.read_bytes())
    require(pin["revision"] == binding["toolchain_revision"]
            and actual == binding["compiler_sha256"] == os.environ.get("HIA_NATIVE_COMPILER_SHA256"),
            "native compiler differs from the repository's qualification binding")
    return pin["revision"], actual


def run(pins, pairs):
    require(2 <= pairs <= 40 and pairs % 2 == 0, "use an even number of pairs (2..40)")
    affinity = sorted(os.sched_getaffinity(0))
    require(len(affinity) == 1, "run on one allowed logical CPU with taskset")
    source = Source(ROOT)
    for path in HARNESSES:
        source.exact(path)
    compiler = snapshot_compiler()
    results, built = [], {}
    # Hold all mappings for the entire run; fd names cannot alias an earlier dlopen.
    with contextlib.ExitStack() as stack:
        functions = {}
        for backend in BACKENDS:
            for lane, entry in zip(LANES, (direct.SOURCE, grouped.SOURCE), strict=True):
                kernel = stack.enter_context(NativeModule(entry, byte_exports=("f0",),
                                                           backend=backend))
                lineage = kernel.receipt["chain_migration"]
                require(lineage["toolchain_revision"] == compiler[0] and lineage["backend"] == backend,
                        "native toolchain receipt mismatch")
                for item in lineage["inputs"]:
                    source.exact("hia/" + item["path"], item["sha256"])
                functions[backend, lane] = stack.enter_context(load_pinned(kernel, pins[backend][lane]))
                built.setdefault(backend, {})[lane] = {
                    "elf_sha256": kernel.artifact_sha256,
                    "composed_source_sha256": lineage["composed_source_sha256"],
                    "core_sha256": lineage["core_sha256"],
                }
        source.validate()
        cases = list(panel())
        gc_active = gc.isenabled()
        gc.disable()
        try:
            for k, backend in enumerate(BACKENDS):
                for index, case in enumerate(cases):
                    left, right = [
                        Buffers(functions[backend, lane], case.frame, output_extent(case.n), work)
                        for lane, work in zip(LANES, (direct.WORK, grouped.WORK), strict=True)
                    ]
                    repeat(left.call, 1)
                    repeat(right.call, 1)
                    product = left.o.raw
                    result_sha = exact_product(case, product, right.o.raw)
                    first = LANES[(index + k) % 2]
                    warm = dict(zip(LANES, (left.call, right.call), strict=True))
                    # Load, buffer allocation, initial validation, warmup, and
                    # calibration are outside recorded measurement intervals.
                    work_order = LANES if first == "direct" else LANES[::-1]
                    for lane in work_order:
                        repeat(warm[lane], 35)
                    upper = max(block(warm[lane], 9) for lane in work_order)
                    count = max(9, min(2000, 8_000_000 * 9 // upper))
                    measured = run_blocks(left.call, right.call, count, pairs, first)
                    require(left.i.raw == right.i.raw == case.frame and left.o.raw == right.o.raw == product,
                            "input or full Product changed during timing")
                    results.append({
                        "backend": backend, "rows": case.n, "distribution": case.distribution,
                        "routes": [case.routes.count(j) for j in range(3)],
                        "frame_sha256": sha(case.frame), "product_sha256": result_sha,
                        "repeats_per_block": count, "blocks": measured,
                    })
        finally:
            if gc_active:
                gc.enable()
    left, right = results[:len(cases)], results[len(cases):]
    projection = lambda row: (row["frame_sha256"], row["product_sha256"])
    require(list(map(projection, left)) == list(map(projection, right)),
            "stock emitter Product bytes differ")
    require(snapshot_compiler() == compiler, "compiler identity changed")
    source.validate()
    require(sorted(os.sched_getaffinity(0)) == affinity, "CPU affinity changed")
    return {
        "schema": "trnm.hia.int257-warm-abi-benchmark.v1",
        "scope": "offline diagnostic: complete warm f0 call including Python/ctypes overhead",
        "source": {"commit": source.head, "tree": source.tree, "inputs_sha256": source.inputs},
        "toolchain": {"revision": compiler[0], "compiler_sha256": compiler[1], "images": built},
        "host": {"affinity": affinity, "python": sys.version.split()[0], "clock": "perf_counter_ns"},
        "pairs": pairs,
        "rows": results,
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--elf-pins", type=Path, required=True, help="Independent 4-ELF JSON SHA-256 pins")
    cli.add_argument("--pairs", type=int, default=16, help="even blocks per workload/backend: 2..40")
    args = cli.parse_args()
    try:
        with args.elf_pins.open("rb") as stream:
            raw = stream.read(4097)
        require(len(raw) <= 4096, "ELF pins document exceeds 4096 bytes")
        pins = elf_pins(raw)
        print(json.dumps(run(pins, args.pairs), sort_keys=True, allow_nan=False))
    except (KeyError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        cli.exit(1, f"benchmark refused: {error}\n")


if __name__ == "__main__":
    main()
