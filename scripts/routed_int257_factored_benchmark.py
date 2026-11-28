"""Optional source-bound comparison of complete warm Direct/Grouped/Factored f0."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import gc
import itertools
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from hia.tests import test_routed_int257_factored as factored
from scripts import routed_int257_warm_benchmark as warm

LANES = ("direct", "grouped", "factored")
ORDERS = tuple(itertools.permutations(LANES))
RANKS = (1, 2, 4, 8)
DIM = warm.ordinary.DIM
CORE = struct.Struct("<6qBB")
COUNTS = struct.Struct("<5Q")
HARNESSES = warm.HARNESSES + (
    "scripts/routed_int257_factored_benchmark.py",
    "hia/tests/test_routed_int257_factored.py",
    "hia/tests/test_routed_int257_factor_preparation.py",
)
require = warm.require


def elf_pins(raw):
    pins = json.loads(raw, object_pairs_hook=warm.unique_object)
    require(type(pins) is dict and set(pins) == set(warm.BACKENDS), "need both exact backend pin maps")
    for backend in warm.BACKENDS:
        row = pins[backend]
        require(type(row) is dict and set(row) == set(LANES)
                and all(type(x) is str and warm.TOKEN.fullmatch(x) for x in row.values()),
                "need all three exact ELF pins on each backend")
    require(len({x for row in pins.values() for x in row.values()}) == 6,
            "each image must have its own ELF identity")
    return pins


def fixed_model_and_factors(rank):
    require(rank in RANKS, "rank outside the fixed fixture panel")
    base = [(i * 13 + i // DIM * 11) % 29 - 14 for i in range(3 * DIM)]
    router = [19 if k == r else 0 for r in range(3) for k in range(DIM)]
    matrices = base + router
    blocks = []
    for expert in range(3):
        down = [(expert * 7 + 3 * j) % 17 - 8 for j in range(DIM)]
        multipliers = [9 + expert * 3 + r for r in range(3)]
        matrices += [m * x for m in multipliers for x in down]
        block = struct.pack("<IIII", rank, rank, rank, rank)
        for m in multipliers:
            terms = [1] * (rank - 1) + [m - rank + 1]
            block += struct.pack("<8i", *terms, *([0] * (8-rank)))
        block += struct.pack("<257i", *down) * rank + bytes((8-rank)*DIM*4)
        blocks.append(block)
    dense = struct.pack("<3855i", *matrices)
    complete = bytes(range(32)) + dense + b"".join(blocks)
    require(len(complete) == 40460, "factor frame extent")
    return dense, complete


@dataclass(frozen=True)
class Workload:
    count: int
    distribution: str
    routes: tuple[int, ...]
    rank: int
    dense: bytes
    factored: bytes


def panel():
    models = {rank: fixed_model_and_factors(rank) for rank in RANKS}
    require(len({x[0] for x in models.values()}) == 1, "ranks changed the dense model")
    for fixture in warm.panel():
        tail = fixture.frame[15424:]
        count = struct.pack("<I", fixture.n)
        for rank, (dense, complete) in models.items():
            yield Workload(fixture.n, fixture.distribution, fixture.routes, rank,
                           count+dense+tail, complete+count+tail)


def normalize_factored(data, n):
    extent = warm.output_extent(n)
    require(len(data) == extent + COUNTS.size, "Factored result extent")
    # Canonical comparison is the pre-existing Direct/Grouped order:
    # [logits i64*3, route/prediction u8*2, router outputs i64*3].
    rows = bytearray(data[:48])
    for j in range(n):
        a, b, c, x, y, z, route, pred = CORE.unpack_from(data, 48+CORE.size*j)
        rows += warm.direct.ROW.pack(x, y, z, route, pred, a, b, c)
    rows += data[48+CORE.size*n:extent]
    return bytes(rows)


def exact_results(case, outputs):
    n = case.count
    factored_raw = outputs["factored"]
    normalized = normalize_factored(factored_raw,n)
    matched = warm.exact_product(warm.Workload(n,case.distribution,case.routes,case.dense),
                                 outputs["direct"],outputs["grouped"])
    require(normalized == outputs["direct"], "Factored Product differs")
    counts = COUNTS.unpack_from(factored_raw,len(normalized))
    expected = (771*n,771*n,260*n*case.rank,3*n,1542*n+260*n*case.rank)
    require(counts == expected, "Factored diagnostic counts differ")
    return matched, counts


def run_blocks(calls, count, cycles, shift, measure=warm.block):
    require(set(calls) == set(LANES) and type(count) is int and 9 <= count <= 2000
            and type(cycles) is int and 1 <= cycles <= 6 and 0 <= shift < len(ORDERS),
            "invalid bounded three-way measurement policy")
    ordering = ORDERS[shift:]+ORDERS[:shift]
    blocks = []
    for _ in range(cycles):
        for order in ordering:
            blocks.append({"order": order,
                           **{name+"_ns": measure(calls[name],count) for name in order}})
    return blocks


def benchmark(pins, cycles):
    require(1 <= cycles <= 6, "use 1..6 cycles of six distinct orders")
    affinity = sorted(os.sched_getaffinity(0))
    require(len(affinity) == 1, "run on one allowed logical CPU with taskset")
    root = warm.ROOT
    source = warm.Source(root)
    for path in HARNESSES:
        source.exact(path)
    compiler = warm.snapshot_compiler()
    results, built = [], {}
    fixtures = list(panel())
    with ExitStack() as stack:
        functions = {}
        for backend in warm.BACKENDS:
            for lane, entry in zip(LANES, (warm.direct.SOURCE,warm.grouped.SOURCE,factored.SOURCE),strict=True):
                kernel = stack.enter_context(warm.NativeModule(entry,byte_exports=("f0",),backend=backend))
                lineage = kernel.receipt["chain_migration"]
                require(lineage["toolchain_revision"] == compiler[0] and lineage["backend"] == backend,
                        "native toolchain receipt mismatch")
                for item in lineage["inputs"]:
                    source.exact("hia/"+item["path"],item["sha256"])
                functions[backend,lane] = stack.enter_context(warm.load_pinned(kernel,pins[backend][lane]))
                built.setdefault(backend,{})[lane] = {
                    "elf_sha256": kernel.artifact_sha256,
                    "composed_source_sha256": lineage["composed_source_sha256"],
                    "core_sha256": lineage["core_sha256"],
                }
        source.validate()
        gc_active = gc.isenabled()
        gc.disable()
        try:
            for k, backend in enumerate(warm.BACKENDS):
                for index, case in enumerate(fixtures):
                    n = case.count
                    extent = warm.output_extent(n)
                    frames = dict(zip(LANES,(case.dense,case.dense,case.factored),strict=True))
                    extents = (extent,extent,extent+COUNTS.size)
                    work = (warm.direct.WORK,warm.grouped.WORK,264+50*n)
                    buffers = {lane: warm.Buffers(functions[backend,lane],frames[lane],l,cap)
                               for lane,l,cap in zip(LANES,extents,work,strict=True)}
                    calls = {lane: value.call for lane,value in buffers.items()}
                    shift = (index+k) % len(ORDERS)
                    order = ORDERS[shift]
                    for lane in order:
                        warm.repeat(calls[lane],1)
                    before = {lane: value.o.raw for lane,value in buffers.items()}
                    product, counters = exact_results(case,before)
                    for lane in order:
                        warm.repeat(calls[lane],19)
                    upper = max(warm.block(calls[lane],9) for lane in order)
                    count = max(9,min(2000,8_000_000*9//upper))
                    blocks = run_blocks(calls,count,cycles,shift)
                    for lane in LANES:
                        require(buffers[lane].i.raw == frames[lane] and buffers[lane].o.raw == before[lane],
                                "input or result changed during timing")
                    results.append({
                        "backend":backend, "rows":n, "distribution":case.distribution, "rank":case.rank,
                        "routes":[case.routes.count(i) for i in range(3)],
                        "dense_frame_sha256":warm.sha(case.dense), "factored_frame_sha256":warm.sha(case.factored),
                        "product_sha256":product, "factored_result_sha256":warm.sha(before["factored"]),
                        "factored_diagnostic_counts":counters,
                        "repeats_per_block":count, "blocks":blocks,
                    })
        finally:
            if gc_active:
                gc.enable()
    require(len(results) == 2*len(fixtures), "missing measurement rows")
    compare = lambda row: tuple(row[x] for x in (
        "dense_frame_sha256","factored_frame_sha256","product_sha256","factored_result_sha256"))
    require(list(map(compare,results[:len(fixtures)])) == list(map(compare,results[len(fixtures):])),
            "stock emitter Product or Factored result bytes differ")
    require(warm.snapshot_compiler() == compiler, "compiler identity changed")
    source.validate()
    require(sorted(os.sched_getaffinity(0)) == affinity, "CPU affinity changed")
    return {
        "schema":"trnm.hia.int257-factored-warm-abi-benchmark.v1",
        "scope":"complete warm f0 including status and actual fresh immutable same-frame BxA check on every Factored call",
        "source":{"commit":source.head,"tree":source.tree,"inputs_sha256":source.inputs},
        "toolchain":{"revision":compiler[0],"compiler_sha256":compiler[1],"images":built},
        "host":{"affinity":affinity,"python":sys.version.split()[0],"clock":"perf_counter_ns"},
        "cycles":cycles,"rows":results,
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--elf-pins",type=Path,required=True,help="Independent six-ELF JSON SHA-256 pins")
    cli.add_argument("--cycles",type=int,default=1,help="all six lane orders per cycle; 1..6")
    args = cli.parse_args()
    try:
        with args.elf_pins.open("rb") as f:
            raw = f.read(4097)
        require(len(raw) <= 4096,"ELF pins document exceeds 4096 bytes")
        print(json.dumps(benchmark(elf_pins(raw),args.cycles),sort_keys=True,allow_nan=False))
    except (KeyError,OSError,RuntimeError,ValueError,subprocess.SubprocessError) as error:
        cli.exit(1,f"benchmark refused: {error}\n")


if __name__ == "__main__":
    main()
