#!/usr/bin/env python3
"""Execute the verbatim pinned upstream soundness calculator on actual segments.

This is a numerical model report, not a proof verifier or a PQ qualification.
The small Rust harness supplies only field/tap descriptors to the unmodified
upstream formula source; it implements no cryptographic HAL or proof backend.
No full Cargo prover build is needed. A successful real verifier must separately
authenticate the receipt whose declared segment dimensions are read here.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import urllib.request

from observations import read_single_result

COMMIT = "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9"
SOURCES = {
    "risc0/zkp/src/prove/soundness.rs": "6d814ec839d0f4b33f275cdfa2d382f4ce455957b1ec7932d9bc717ccf732921",
    "risc0/circuit/rv32im/src/zirgen/taps.rs": "b423f7bd396cd4a7ea25c326ba077dca7f96dd144fd8e44d9474bfb2489818d2",
    "risc0/zkp/src/lib.rs": "107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d",
    "risc0/core/src/field/baby_bear.rs": "df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3",
    "risc0/zkp/src/adapter.rs": "1d1aca1dd7cc4c12477e0d887a3edfa0825b822efee671170ec667c7dd65ca1d",
    "risc0/zkp/src/prove/prover.rs": "bf63f227fe515dfa8b1edce90b6475a33369fb44fe66c5784a1d70d5947c4368",
    "LICENSE": "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594",
}


class Cursor:
    def __init__(self, data):
        self.data = memoryview(data)
        self.position = 0

    def take(self, count):
        if count < 0 or count > len(self.data) - self.position:
            raise ValueError("truncated receipt metadata")
        value = self.data[self.position:self.position + count]
        self.position += count
        return value

    def word(self):
        return struct.unpack("<I", self.take(4))[0]

    def length(self, cap):
        value = struct.unpack("<Q", self.take(8))[0]
        if value > cap:
            raise ValueError("receipt metadata budget")
        return value

    def maybe_fixed(self, opened_size):
        variant = self.word()
        if variant not in (0, 1):
            raise ValueError("unknown MaybePruned variant")
        self.take(opened_size if variant == 0 else 32)

    def output(self):
        variant = self.word()
        if variant == 1:
            self.take(32)
            return
        if variant != 0:
            raise ValueError("unknown output variant")
        some = self.take(1)[0]
        if some == 0:
            return
        if some != 1:
            raise ValueError("invalid output option")
        variant = self.word()
        if variant == 0:
            self.take(self.length(228))
        elif variant == 1:
            self.take(32)
        else:
            raise ValueError("unknown journal variant")
        variant = self.word()
        if variant == 0:
            self.length(0)
        elif variant == 1:
            self.take(32)
        else:
            raise ValueError("unknown assumptions variant")


def dimensions(data):
    cursor = Cursor(data)
    if cursor.word() != 0:
        raise ValueError("only the separately verified Composite profile is supported")
    count = cursor.length(2048)
    histogram = Counter()
    for index in range(count):
        words = cursor.length(262144)
        if words < 92:
            raise ValueError("short seal")
        seal = cursor.take(words * 4)
        if struct.unpack_from("<I", seal, 0)[0] != 2:
            raise ValueError("unknown seal version")
        po2 = struct.unpack_from("<I", seal, 91 * 4)[0]
        if not 13 <= po2 <= 20:
            raise ValueError("outside the research proof dimension budget")
        histogram[po2] += 1
        if cursor.word() != index:
            raise ValueError("noncanonical segment index")
        if bytes(cursor.take(cursor.length(9))) != b"poseidon2":
            raise ValueError("unrecognized proof commitment hash")
        cursor.take(32)
        cursor.maybe_fixed(36)
        cursor.maybe_fixed(36)
        exit_code = cursor.word()
        if exit_code in (0, 1):
            cursor.take(4)
        elif exit_code not in (2, 3):
            raise ValueError("unknown exit code")
        variant = cursor.word()
        if variant == 0:
            if cursor.take(1)[0] != 0:
                raise ValueError("unsupported input opening")
        elif variant == 1:
            cursor.take(32)
        else:
            raise ValueError("unknown input variant")
        cursor.output()
    cursor.length(0)
    cursor.take(32)
    if cursor.length(228) != 228:
        raise ValueError("incorrect outer journal length")
    cursor.take(228 + 32)
    if cursor.position != len(data) or not histogram:
        raise ValueError("noncanonical receipt length")
    return histogram


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    model_input = parser.add_mutually_exclusive_group(required=True)
    model_input.add_argument("--receipt", type=Path)
    model_input.add_argument("--execution-observation", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--upstream-source", type=Path)
    args = parser.parse_args()
    if args.receipt:
        if args.receipt.stat().st_size > 128 * 1024 * 1024:
            raise SystemExit("receipt exceeds the explicit research byte budget")
        data = args.receipt.read_bytes()
        histogram = dimensions(data)
        identity = {"model_input_kind": "receipt_metadata",
                    "receipt_sha256": hashlib.sha256(data).hexdigest()}
    else:
        execution = read_single_result(args.execution_observation, "pon-w1-risc0-research-v1", "execute")
        if execution["cryptographic_proof_verified"] is not False or execution["guest_matches_native"] is not True:
            raise ValueError("expected the explicit execution-only result")
        histogram = Counter({int(po2): count for po2, count in execution["actual_segment_po2_histogram"].items()})
        if sum(histogram.values()) != execution["segments"]:
            raise ValueError("execution segment count mismatch")
        identity = {"model_input_kind": "execution_only_metadata",
                    "execution_observation_sha256": hashlib.sha256(args.execution_observation.read_bytes()).hexdigest(),
                    "image_id": execution["image_id"],
                    "no_completed_proof_is_established": True}
    if not histogram or sum(histogram.values()) > 2048:
        raise ValueError("segment count budget")
    if any(not 13 <= po2 <= 20 or type(count) is not int or count <= 0 for po2, count in histogram.items()):
        raise ValueError("invalid segment dimensions")
    if sum((1 << po2) * count for po2, count in histogram.items()) > 256 * 1024 * 1024:
        raise ValueError("total segment dimension budget")
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    contents = {}
    for name, expected in SOURCES.items():
        if args.upstream_source:
            raw = (args.upstream_source / name).read_bytes()
        else:
            url = f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/{name}"
            with urllib.request.urlopen(url, timeout=60) as response:
                raw = response.read(2 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"unreviewed upstream calculator source: {name}")
        target = out / "upstream" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        contents[name] = raw.decode()
    taps = contents["risc0/circuit/rv32im/src/zirgen/taps.rs"]
    tap_offsets = [int(re.search(r"offset:\s*(\d+)", body).group(1))
                   for body in re.findall(r"TapData\s*\{(.*?)\}", taps, re.S)]
    def integers(field):
        return [int(value) for value in re.search(field + r":\s*&\[([^\]]+)\]", taps).group(1).split(",") if value.strip()]
    group_begin = integers("group_begin")
    groups = [tap_offsets[group_begin[index + 1] - 1] + 1 for index in range(3)]
    combo_begin = integers("combo_begin")
    combos = [end - start for start, end in zip(combo_begin, combo_begin[1:])]
    assert groups == [103, 1, 211] and combos == [1, 2, 6, 5]
    # These constants are checked against the exact source, not caller-selected.
    lib = contents["risc0/zkp/src/lib.rs"]
    assert "pub const QUERIES: usize = 50;" in lib and "pub const INV_RATE: usize = 4;" in lib
    assert "const FRI_FOLD_PO2: usize = 4;" in lib
    assert "pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;" in lib
    assert "const FRI_MIN_DEGREE: usize = 256;" in lib
    field = contents["risc0/core/src/field/baby_bear.rs"]
    assert "pub const P: u32 = 15 * (1 << 27) + 1;" in field
    assert "const EXT_SIZE: usize = 4;" in field
    adapter = contents["risc0/zkp/src/adapter.rs"]
    for name, index in [("ACCUM", 0), ("CODE", 1), ("DATA", 2)]:
        assert f"pub const REGISTER_GROUP_{name}: usize = {index};" in adapter
    prover = contents["risc0/zkp/src/prove/prover.rs"]
    assert '.alloc_elem("final_poly_coeffs", self.cycles * ext_size)' in prover
    assert 'super::soundness::toy_model_security::<H>(self.taps, final_poly_coeffs.size())' in prover
    bounds = Path(__file__).resolve().parent / "host/src/receipt_bounds.rs"
    bounds_sha256 = hashlib.sha256(bounds.read_bytes()).hexdigest()
    if bounds_sha256 != "e4b5bea658dc06649e0b0c69f09bf3407d4eb64b73f382aac3be2a24da8d2d37":
        raise ValueError("research receipt budgets changed; review the allowed-dimension report")
    calculator = out / "upstream/risc0/zkp/src/prove/soundness.rs"
    harness = '''// Numerical descriptor harness only; not a cryptographic HAL or proof system.
extern crate self as risc0_core;
pub mod field {
    pub mod baby_bear { pub const P:u32=15*(1<<27)+1; }
    pub trait ExtElem { const EXT_SIZE:usize; }
}
pub mod adapter { pub const REGISTER_GROUP_ACCUM:usize=0; pub const REGISTER_GROUP_CODE:usize=1; pub const REGISTER_GROUP_DATA:usize=2; }
pub mod hal { pub trait Hal { type ExtElem:crate::field::ExtElem; } }
pub mod taps {
    pub struct TapSet { pub groups:[usize;3], pub combo_sizes:Vec<usize> }
    pub struct Combo(usize);
    impl Combo { pub fn size(&self)->usize { self.0 } }
    impl TapSet {
        pub fn group_size(&self,index:usize)->usize { self.groups[index] }
        pub fn combos(&self)->impl Iterator<Item=Combo>+'_ { self.combo_sizes.iter().map(|&n|Combo(n)) }
    }
}
pub const FRI_FOLD:usize=16; pub const FRI_MIN_DEGREE:usize=256; pub const INV_RATE:usize=4; pub const QUERIES:usize=50;
struct ExtensionDegree; impl field::ExtElem for ExtensionDegree { const EXT_SIZE:usize=4; }
struct CalculatorParameters; impl hal::Hal for CalculatorParameters { type ExtElem=ExtensionDegree; }
#[path=CALCULATOR_PATH] mod calculator;
fn main() {
    let taps=taps::TapSet { groups:GROUPS, combo_sizes:vec!COMBOS };
    for argument in std::env::args().skip(1) {
        let po2:u32=argument.parse().unwrap(); assert!((13..=24).contains(&po2));
        let coefficients=(1usize<<po2)*4;
        let toy=calculator::toy_model_security::<CalculatorParameters>(&taps,coefficients);
        let proven=calculator::proven::<CalculatorParameters>(&taps,coefficients);
        let strict=calculator::conjectured_strict::<CalculatorParameters>(&taps,coefficients);
        println!("{{\\"po2\\":{},\\"toy_model_bits\\":{},\\"proven_list_decoding_bits\\":{},\\"conjectured_strict_bits\\":{}}}",po2,toy,proven,strict);
    }
}
'''.replace("CALCULATOR_PATH", json.dumps(str(calculator))).replace("GROUPS", repr(groups)).replace("COMBOS", repr(combos))
    source = out / "calculator-harness.rs"
    source.write_text(harness)
    executable = out / "calculator-harness"
    compile_command = [str(args.rustc.resolve()), "--edition=2021", "-O", "-C", "debuginfo=0", str(source), "-o", str(executable)]
    compiled = subprocess.run(compile_command, capture_output=True, text=True, timeout=60)
    (out / "compile.stdout.log").write_text(compiled.stdout)
    (out / "compile.stderr.log").write_text(compiled.stderr)
    compiled.check_returncode()
    sizes = sorted(set(histogram) | set(range(13, 21)) | {24})
    executed = subprocess.run([str(executable), *map(str, sizes)], capture_output=True, text=True, check=True, timeout=30)
    (out / "calculator.stdout.jsonl").write_text(executed.stdout)
    estimates = {value["po2"]: value for value in map(json.loads, executed.stdout.splitlines())}
    combined = {}
    superset_bound = {}
    for model in ["toy_model_bits", "proven_list_decoding_bits", "conjectured_strict_bits"]:
        error = sum(count * 2**(-estimates[po2][model]) for po2, count in histogram.items())
        combined[model] = -math.log2(error)
        superset_bound[model] = min(estimates[po2][model] for po2 in range(13, 21)) - math.log2(2048)
    report = {
        "schema": "pon-w1-upstream-soundness-formula-observation-v1",
        **identity,
        "receipt_was_not_cryptographically_verified_by_this_calculator": True,
        "source_commit": COMMIT, "source_sha256": SOURCES,
        "upstream_rust_formulas_executed_verbatim": True,
        "descriptor_harness_is_not_a_proof_backend": True,
        "calculator_arithmetic": "upstream f32, then float64 union-bound summation; numerical estimate, not a machine-checked real bound",
        "parameters": {"group_widths_accum_code_data": groups, "biggest_combo": max(combos),
                       "field_prime": 2013265921, "extension_degree": 4, "queries": 50,
                       "expansion": 4, "folding_factor": 16, "final_degree": 256,
                       "maximum_constraint_degree": 5,
                       "degree_scope": "hardcoded assumption in upstream calculator, with an upstream FIXME; not independently derived here"},
        "actual_segment_po2_histogram": histogram,
        "per_segment_estimates": list(estimates.values()),
        "conservative_sum_of_segment_error_estimates_bits": combined,
        "accepted_research_profile": {"host_bounds_source_sha256": bounds_sha256,
                                      "po2_min": 13, "po2_max": 20, "maximum_segments": 2048,
                                      "maximum_padded_cycles": 268435456, "maximum_receipt_bytes": 134217728},
        "conservative_superset_of_accepted_profile_bits": superset_bound,
        "superset_scope": "min of the conditional per-segment numerical estimates over po2=13..20, minus log2(2048). Deliberately ignores the joint cycle/byte limits and makes no claim this worst combination is feasible or is an attack.",
        "composition_scope": "union bound conditional on the upstream per-segment model; not a complete FS, adaptive-query, hash or QROM proof",
        "pq128_qualified": False, "consensus_authority": False,
    }
    (out / "soundness-observation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
