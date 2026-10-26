"""Independent C++/Python ASERT fixed-point differential campaign (research only).

No W1 proofs, signatures, native Rust execution, active-chain oracle, or production
approval. Compare every complete output/error; keep invalid cases in denominators.
The existing Python source is the Git-exact oracle on the selected PR head.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import tempfile

from daa_research_oracle import asert_target

U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
SOURCE = Path(__file__).with_name("daa_cpp_oracle.cpp")
FROZEN_512_SHA = "6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97"


@dataclass(frozen=True)
class Case:
    anchor_target: int
    pow_limit: int
    anchor_parent_time: int
    parent_time: int
    anchor_height: int
    candidate_height: int
    spacing: int
    half_life: int

    def wire(self) -> str:
        return (f"{self.anchor_target:064x} {self.pow_limit:064x} "
                f"{self.anchor_parent_time} {self.parent_time} {self.anchor_height} "
                f"{self.candidate_height} {self.spacing} {self.half_life}")

    def python_result(self) -> str:
        try:
            value = asert_target(self.anchor_target, self.anchor_parent_time,
                                 self.parent_time, self.anchor_height, self.candidate_height,
                                 self.spacing, self.half_life, self.pow_limit)
            return f"{value:064x}"
        except ValueError as error:
            return "ERR_RANGE" if "overflows i128" in str(error) else "ERR_PARAMETERS"


def xorshift_512() -> list[Case]:
    """Exact deterministic Rust daa_extreme_vectors 512-case stream."""
    state = 0x62B7_F30A_C985_1D4E

    def next_u64() -> int:
        nonlocal state
        state ^= (state << 13) & U64
        state ^= state >> 7
        state ^= (state << 17) & U64
        state &= U64
        return state

    out: list[Case] = []
    for i in range(512):
        height = 2 + next_u64() % 1000
        anchor_time = 1_000_000 + next_u64() % 100_000
        deviation = next_u64() % 100_000 - 50_000
        parent_time = (anchor_time + (height - 1) * 10 + deviation) & U64
        if i % 17 == 0:
            parent_time = U64
        if i % 19 == 0:
            parent_time = 0
        half_life = (3600, 7200, 14400, 28800, 1)[i % 5]
        out.append(Case(1 << 220, (1 << 240) - 1, anchor_time, parent_time,
                        1, height, 10, half_life))
    return out


def adversarial_cases(seed: int = 20261026, count: int = 2048) -> list[Case]:
    if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= U64:
        raise ValueError("seed")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 3072:
        raise ValueError("count")
    rng = random.Random(seed)
    result: list[Case] = []
    limits = (1, (1 << 128) - 1, (1 << 240) - 1, U256)
    for i in range(count):
        cap = rng.choice(limits)
        anchor = rng.choice((1, cap, min(cap, 1 << 220), rng.randint(1, cap)))
        prev = rng.choice((0, 1, 1_000_000, U64, rng.getrandbits(64)))
        current = rng.choice((0, 1, 1_000_000, U64, rng.getrandbits(64)))
        ah = rng.choice((1, 2, 50, U64 - 20, rng.randint(1, U64 - 1)))
        ch = min(U64, ah + rng.choice((0, 1, 2, 16, 1000, U64)))
        spacing = rng.choice((0, 1, 10, 600, (1 << 62), U64))
        half = rng.choice((0, 1, 2, 3600, 7200, 14400, 28800, U64))
        if i % 31 == 0:
            # Native i128 ideal-span overflow.
            ah, ch, spacing = 1, U64, U64
        elif i % 31 == 1:
            # Ideal fits i128, but radix-scaled deviation does not.
            ah, ch, spacing = 1, U64, 1 << 62
        elif i % 31 == 2:
            # Extreme positive saturation.
            ah, ch, spacing, prev, current, half = 1, 2, 10, 0, U64, 1
        elif i % 31 == 3:
            # Extreme negative saturation.
            ah, ch, spacing, prev, current, half = 1, 2, 10, U64, 0, 1
        elif i % 31 == 4:
            # Boundary that uses signed floor vs truncation.
            ah, ch, spacing, prev, current, half = 1, 2, 10, 10_001, 10_000, 3600
        result.append(Case(anchor, cap, prev, current, ah, ch, spacing, half))
    return result


def compile_oracle(destination: Path, source: Path = SOURCE, compiler: str = "g++") -> None:
    executable = shutil.which(compiler)
    if not executable:
        raise RuntimeError("missing C++17 compiler")
    subprocess.run([executable, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", str(source), "-o", str(destination)],
                   check=True, capture_output=True, text=True, timeout=90)


def run_cpp(binary: Path, lines: list[str]) -> list[str]:
    if not lines or len(lines) > 4096:
        raise ValueError("case count")
    result = subprocess.run([str(binary)], input="\n".join(lines) + "\n", text=True,
                            capture_output=True, timeout=45, check=True)
    values = result.stdout.splitlines()
    if len(values) != len(lines):
        raise AssertionError("C++ record output count mismatch")
    return values


def compare(binary: Path, cases: list[Case]) -> dict:
    actual = run_cpp(binary, [c.wire() for c in cases])
    expected = [c.python_result() for c in cases]
    mismatch = [(i, a, b) for i, (a, b) in enumerate(zip(actual, expected)) if a != b]
    if mismatch:
        raise AssertionError(f"C++/Python mismatch first={mismatch[:5]}")
    checksum = hashlib.sha256("\n".join(actual).encode()).hexdigest()
    return {"cases": len(cases), "matches": len(cases), "mismatches": 0,
            "accepted": sum(v not in ("ERR_PARAMETERS", "ERR_RANGE") for v in actual),
            "rejected_parameters": actual.count("ERR_PARAMETERS"),
            "rejected_ranges": actual.count("ERR_RANGE"), "line_digest": checksum}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261026)
    parser.add_argument("--cases", type=int, default=2048)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output path must not exist (create-only)")
    with tempfile.TemporaryDirectory() as temp:
        binary = Path(temp) / "daa_asert_cpp_reference"
        compile_oracle(binary)
        fixed = xorshift_512()
        fixed_status = compare(binary, fixed)
        digest = hashlib.sha256(b"".join(bytes.fromhex(c.python_result()) for c in fixed)).hexdigest()
        if digest != FROZEN_512_SHA:
            raise AssertionError(f"frozen Rust 512 vector digest differs: {digest}")
        random_status = compare(binary, adversarial_cases(args.seed, args.cases))
    report = {"schema": "trnm-asert-cpp-independent-math-v1",
              "non_activated": True, "native_w1_proofs": 0,
              "distinct_independent_operators": 0,
              "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              "python_sha256": hashlib.sha256(Path(__file__).with_name("daa_research_oracle.py").read_bytes()).hexdigest(),
              "fixed_512_sha256": digest, "fixed": fixed_status, "adversarial": random_status,
              "seed": args.seed, "replay": "python3 daa_cpp_differential.py --output NEW_PATH"}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": "PASS", "output": str(args.output),
                      "fixed": fixed_status["cases"], "adversarial": random_status["cases"]}))


if __name__ == "__main__":
    main()
