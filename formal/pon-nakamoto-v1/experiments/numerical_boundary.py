"""Isolated numeric/operator research; no W1 profile or training change.

The optional rustc probe executes an exact source slice of the existing private
checkpoint quantizer. It does not compile or qualify the whole Rust crate,
checkpoint material policy, FP8/Pearl, a learning trajectory, or a cost bound.
Operator inputs are transformed committed maintenance matrices, never described
as a real neural checkpoint or activation capture.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
if str(FORMAL) not in sys.path:
    sys.path.insert(0, str(FORMAL))
import contract_wire as wire
import work_oracle as work

QUANTIZER = ROOT / "trillionnium/crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs"
SCALES = ((8, 2), (8, 4), (8, 6), (10, 2), (10, 4), (10, 6),
          (14, 2), (14, 4), (14, 6))
TOKEN_COUNTS = (1, 2, 8, 16, 32, 64)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fraction_pair(value):
    value = Fraction(value)
    return [str(value.numerator), str(value.denominator)]


def ieee_fraction(bits, mantissa):
    """Decode a BF16 or FP32 bit pattern to an exact rational, without floats."""
    if mantissa not in (7, 23) or type(bits) is not int or not 0 <= bits < 1 << (mantissa + 9):
        raise ValueError("IEEE_ENCODING")
    exponent = (bits >> mantissa) & 255
    if exponent == 255:
        raise ValueError("NONFINITE")
    fraction = bits & ((1 << mantissa) - 1)
    significand = fraction if exponent == 0 else fraction | (1 << mantissa)
    power = (1 if exponent == 0 else exponent) - 127 - mantissa
    magnitude = Fraction(significand) * Fraction(2) ** power
    return -magnitude if bits >> (mantissa + 8) else magnitude


def quantize_reference(bits, mantissa, scale, clip):
    """Independent Fraction nearest/even oracle for a bounded research profile."""
    if type(scale) is not int or not -32 <= scale <= 32 or type(clip) is not int or not 0 < clip < 1 << 31:
        raise ValueError("RESEARCH_QUANTIZATION_PARAMETERS")
    scaled = ieee_fraction(bits, mantissa) * Fraction(2) ** scale
    whole, remainder = divmod(abs(scaled.numerator), scaled.denominator)
    rounded = whole + int(2 * remainder > scaled.denominator or
                          (2 * remainder == scaled.denominator and whole % 2 == 1))
    clipped = rounded > clip
    value = min(rounded, clip)
    return (-value if scaled < 0 else value), clipped


def fp32_bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def fp32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def quantizer_cases():
    patterns = {
        7: {0, 0x8000, 1, 0x8001, 0x007f, 0x0080, 0x8080, 0x3f00, 0x3f80,
            0x4000, 0xc000, 0x7f7f, 0xff7f, 0x7f80, 0xff80, 0x7fc1, 0x7f81},
        23: {0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x00800000,
             0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fc00001, 0x7f800001},
    }
    for value in (0.03125, 0.09375, 0.15625, 0.21875, 8.03125, 8.09375, -0.03125, -8.09375):
        bits = fp32_bits(value)
        patterns[23].update((bits - 1, bits, bits + 1))
    for index in range(96):
        block = hashlib.sha256(b"TRNM-NUMERIC-RESEARCH-CASES-v1" + index.to_bytes(4, "little")).digest()
        patterns[7].add(int.from_bytes(block[:2], "little"))
        patterns[23].add(int.from_bytes(block[2:6], "little"))
    rows = []
    for mantissa in (7, 23):
        configurations = ((14, 32767), (8, 32767), (10, 32767)) if mantissa == 7 else ((4, 128), (2, 128), (6, 128))
        for scale, clip in configurations:
            for bits in sorted(patterns[mantissa]):
                try:
                    value, clipped = quantize_reference(bits, mantissa, scale, clip)
                    result = {"value": value, "clipped": clipped}
                except ValueError as error:
                    result = {"error": str(error)}
                rows.append({"bits": bits, "mantissa": mantissa, "scale": scale, "clip": clip,
                             "default_private_primitive_parameters": (mantissa, scale, clip) in ((7, 14, 32767), (23, 4, 128)),
                             "expected": result})
    return rows


def extract_function(source, name):
    marker = "fn " + name + "("
    require(source.count(marker) == 1, "source slice is not unique: " + name)
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    require(depth == 0, "unterminated source slice")
    return source[start:end]


def native_quantizer_probe(rustc, directory, cases):
    rustc, directory = Path(rustc), Path(directory)
    require(rustc.is_absolute() and rustc.is_file(), "explicit absolute rustc required")
    directory.mkdir(parents=True, exist_ok=False)
    source_bytes = QUANTIZER.read_bytes()
    source = source_bytes.decode("utf-8")
    slices = {name: extract_function(source, name) for name in ("require", "quantize")}
    wrapper = """
use std::io::{self, Read};
type MaterialResult<T> = std::result::Result<T, &'static str>;
SOURCE_FUNCTIONS
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().take(524289).read_to_string(&mut input)?;
    if input.len() > 524288 { return Err("PROBE_INPUT_LIMIT".into()); }
    for line in input.lines() {
        let p: Vec<_> = line.split_whitespace().collect();
        if p.len() != 4 { return Err("PROBE_FIELDS".into()); }
        match quantize(p[0].parse()?, p[1].parse()?, p[2].parse()?, p[3].parse()?) {
            Ok((v, clipped)) => println!("{}\\t{}", v, clipped),
            Err(error) => println!("ERR\\t{}", error),
        }
    }
    Ok(())
}
""".replace("SOURCE_FUNCTIONS", "\n".join(slices.values()))
    src, binary = directory / "source-slice.rs", directory / "source-slice"
    src.write_text(wrapper)
    version = subprocess.run([str(rustc), "-Vv"], capture_output=True, text=True, timeout=15, check=True)
    (directory / "rustc-version.txt").write_text(version.stdout)
    build = subprocess.run([str(rustc), str(src), "--crate-name", "checkpoint_quantizer_source_slice",
                            "--edition=2021", "-C", "opt-level=1", "-o", str(binary)],
                           capture_output=True, text=True, timeout=60, check=False)
    (directory / "compile.stdout").write_text(build.stdout)
    (directory / "compile.stderr").write_text(build.stderr)
    require(build.returncode == 0, "source-slice compilation failed; raw failure preserved")
    input_text = "".join(f"{r['bits']} {r['mantissa']} {r['scale']} {r['clip']}\n" for r in cases)
    (directory / "probe.stdin").write_text(input_text)
    execution = subprocess.run([str(binary)], input=input_text, capture_output=True,
                               text=True, timeout=30, check=False)
    (directory / "probe.stdout").write_text(execution.stdout)
    (directory / "probe.stderr").write_text(execution.stderr)
    require(execution.returncode == 0, "source-slice execution failed; raw failure preserved")
    output = execution.stdout.splitlines()
    require(len(output) == len(cases), "source-slice result count")
    differences = []
    for index, (row, line) in enumerate(zip(cases, output)):
        fields = line.split("\t")
        require(len(fields) == 2, "source-slice output fields")
        if fields[0] == "ERR":
            actual = {"error": fields[1]}
        else:
            require(fields[1] in ("true", "false"), "source-slice output boolean")
            actual = {"value": int(fields[0]), "clipped": fields[1] == "true"}
        if actual != row["expected"]:
            differences.append({"index": index, "case": row, "actual": actual})
    report = {"status": "executed", "scope": "exact-original-private-primitive-source-slice-only",
              "source_file": str(QUANTIZER.relative_to(ROOT)), "source_sha256": sha(source_bytes),
              "slice_sha256": {name: sha(value.encode()) for name, value in slices.items()},
              "generated_probe_sha256": sha(wrapper.encode()), "binary_sha256": sha(binary.read_bytes()),
              "rustc_path": str(rustc), "rustc_version": version.stdout,
              "cases": len(cases), "mismatches": differences,
              "stdout_sha256": sha(execution.stdout.encode()),
              "whole_crate_compiled": False, "full_material_policy_executed": False,
              "FP8_or_Pearl_policy_qualified": False}
    (directory / "comparison.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    require(not differences, "native quantizer differs from independent exact oracle")
    return report


def rank_mod(matrix, rows=64, cols=64, modulus=work.Q):
    require(len(matrix) == rows * cols, "rank shape")
    data = [[matrix[i * cols + j] % modulus for j in range(cols)] for i in range(rows)]
    rank = 0
    for column in range(cols):
        pivot = next((row for row in range(rank, rows) if data[row][column]), None)
        if pivot is None:
            continue
        data[rank], data[pivot] = data[pivot], data[rank]
        inverse = pow(data[rank][column], -1, modulus)
        data[rank] = [value * inverse % modulus for value in data[rank]]
        for row in range(rank + 1, rows):
            factor = data[row][column]
            if factor:
                data[row] = [(x - factor * y) % modulus for x, y in zip(data[row], data[rank])]
        rank += 1
        if rank == rows:
            break
    return rank


def integer_product(a, b):
    require(len(a) == len(b) == work.CELLS, "matrix shape")
    return [sum(a[i * 64 + k] * b[k * 64 + j] for k in range(64))
            for i in range(64) for j in range(64)]


def maintenance_inputs():
    path = FORMAL / "vectors/matrices.bin"
    raw = path.read_bytes()
    require(len(raw) == work.CELLS * 8, "matrix vector length")
    values = list(struct.unpack("<" + "I" * (2 * work.CELLS), raw))
    a, b = values[:work.CELLS], values[work.CELLS:]
    expected = json.loads((FORMAL / "vectors/expected.json").read_text())
    require(work.task_id(a, b).hex() == expected["work"]["task"], "committed matrix task mismatch")
    return a, b, {"path": str(path.relative_to(ROOT)), "sha256": sha(raw),
                  "task": expected["work"]["task"],
                  "scope": "historical-maintenance-vector; not neural checkpoint or real activation"}


def _bf16_exact_bits(value):
    bits = fp32_bits(value)
    require(bits & 65535 == 0, "operator input not exactly BF16 representable")
    return bits >> 16


def operator_sensitivity():
    a, b, source = maintenance_inputs()
    a_bits = [_bf16_exact_bits(value / 4096) for value in a]
    b_bits = [fp32_bits(value / 64) for value in b]
    exact_product = integer_product(a, b)
    source_denominator = 4096 * 64
    rows = []
    for a_scale, b_scale in SCALES:
        aqc = [quantize_reference(bits, 7, a_scale, 32767) for bits in a_bits]
        bqc = [quantize_reference(bits, 23, b_scale, 128) for bits in b_bits]
        aq, bq = [v for v, _ in aqc], [v for v, _ in bqc]
        product = integer_product(aq, bq)
        denominator = 1 << (a_scale + b_scale)
        errors = [abs(Fraction(candidate, denominator) - Fraction(original, source_denominator))
                  for candidate, original in zip(product, exact_product)]
        rows.append({"weight_scale_power": a_scale, "activation_scale_power": b_scale,
                     "matches_material_default_scale_parameters": (a_scale, b_scale) == (14, 4),
                     "weight_nonzero": sum(v != 0 for v in aq), "activation_nonzero": sum(v != 0 for v in bq),
                     "weight_clipped": sum(clipped for _, clipped in aqc),
                     "activation_clipped": sum(clipped for _, clipped in bqc),
                     "weight_rank_mod_q": rank_mod(aq), "activation_rank_mod_q": rank_mod(bq),
                     "max_absolute_product_error": fraction_pair(max(errors)),
                     "mean_absolute_product_error": fraction_pair(sum(errors, Fraction()) / len(errors)),
                     "quantized_product_sha256": sha(work.field_bytes([v % work.Q for v in product]))})
    # Isolate clipping under the exact original scale/clip parameters.
    clipped_a = [quantize_reference(_bf16_exact_bits(value / 2), 7, 14, 32767) for value in a]
    clipped_b = [quantize_reference(fp32_bits(value), 23, 4, 128) for value in b]
    clipping_product = integer_product([v for v, _ in clipped_a], [v for v, _ in clipped_b])
    clipping_errors = [abs(Fraction(q, 1 << 18) - Fraction(r, 2)) for q, r in zip(clipping_product, exact_product)]
    structures = []
    for tokens in TOKEN_COUNTS:
        padded = [value if index % 64 < tokens else 0 for index, value in enumerate(b)]
        rank = rank_mod(padded)
        require(rank <= tokens, "zero-padded column rank bound")
        product = integer_product(a, padded)
        require(all(product[index] == 0 for index in range(work.CELLS) if index % 64 >= tokens),
                "padding produced nonzero useful output")
        structures.append({"retained_token_columns": tokens, "rank_mod_q": rank,
                           "nonzero_inputs": sum(value != 0 for value in padded),
                           "padded_output_columns_are_exact_zero": True,
                           "product_sha256": sha(work.field_bytes([v % work.Q for v in product]))})
    return {"source": source,
            "input_transform": {"weight": "exact BF16 A_integer / 4096", "activation": "exact FP32 B_integer / 64"},
            "rounding": "exact IEEE rational -> multiply by power of two -> nearest ties even -> symmetric clipping",
            "scale_controls": rows, "token_padding_controls": structures,
            "clipping_control": {"input_transform": {"weight": "A_integer / 2", "activation": "B_integer"},
                                 "weight_clipped": sum(c for _, c in clipped_a),
                                 "activation_clipped": sum(c for _, c in clipped_b),
                                 "max_absolute_product_error": fraction_pair(max(clipping_errors))},
            "training_executed": False, "convergence_or_model_quality_claim": False,
            "structure_is_not_a_measured_speedup": True}


def field_float_controls():
    path = FORMAL / "vectors/accepted-block/header.bin"
    challenge = wire.H("challenge", path.read_bytes())
    left, right = work.expand(challenge, 0, 512), work.expand(challenge, 1, 512)
    observations = []
    for index in range(32):
        row, column = divmod(index, 8)
        aa = left[row * 8:row * 8 + 8]
        bb = [right[k * 64 + column] for k in range(8)]
        exact_sum = sum(x * y for x, y in zip(aa, bb))
        fp64_sum = sum(float(x) * float(y) for x, y in zip(aa, bb))
        fp32_sum = fp32(0)
        for x, y in zip(aa, bb):
            fp32_sum = fp32(fp32_sum + fp32(fp32(x) * fp32(y)))
        exact, f64, f32 = exact_sum % work.Q, int(fp64_sum) % work.Q, int(fp32_sum) % work.Q
        observations.append({"row": row, "column": column, "exact_field": exact,
                             "float64_then_field": f64, "float32_then_field": f32,
                             "float64_matches": f64 == exact, "float32_matches": f32 == exact})
    bound = 64 * 32767 * 128
    require(bound <= work.Q // 2, "original signed product bound")
    # A successor with equal 32767 clips on both operands loses unique signed decode.
    expanded_bound = 64 * 32767 * 32767
    require(expanded_bound > work.Q // 2, "expanded clips must demonstrate wrap ambiguity")
    residue = expanded_bound % work.Q
    signed = residue if residue <= work.Q // 2 else residue - work.Q
    return {"source_header_sha256": sha(path.read_bytes()), "challenge": challenge.hex(),
            "relation": "first 32 EL*ER entries from real W1 challenge expansion; inner dimension 8",
            "observations": observations,
            "float32_mismatches": sum(not row["float32_matches"] for row in observations),
            "float64_mismatches": sum(not row["float64_matches"] for row in observations),
            "current_clip_bound": bound, "half_field": work.Q // 2,
            "expanded_both_clip_32767_bound": expanded_bound,
            "expanded_example_residue": residue, "expanded_example_signed_decode": signed,
            "expanded_signed_decode_matches_integer": signed == expanded_bound,
            "float_substitution_preserves_W1": False,
            "scope": "finite arithmetic counterexamples, not all GPUs or all floating kernels"}


def run(rustc=None, raw_directory=None):
    cases = quantizer_cases()
    if rustc is None:
        native = {"status": "not-requested-not-executed", "whole_crate_compiled": False}
    else:
        require(raw_directory is not None, "raw directory required for native source probe")
        native = native_quantizer_probe(rustc, raw_directory, cases)
    return {"schema": "pon-isolated-numerical-boundary-research-v1",
            "original_quantizer_source_sha256": sha(QUANTIZER.read_bytes()),
            "research_script_sha256": sha(Path(__file__).read_bytes()),
            "independent_exact_cases": cases, "native_source_slice": native,
            "operator_sensitivity": operator_sensitivity(), "field_float_controls": field_float_controls(),
            "production_W1_modified": False, "new_profile_activated": False,
            "native_checkpoint_or_activation_loaded": False, "training_convergence_established": False,
            "minimum_work_cost_established": False, "timing_or_throughput_claim": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new report path; never overwrite an observation")
    parser.add_argument("--rustc", type=Path, help="absolute compiler path for original-source primitive cross-check")
    parser.add_argument("--raw-directory", type=Path, help="new directory preserving compiler/probe input and output")
    args = parser.parse_args()
    require(not args.output.exists(), "output already exists")
    report = run(args.rustc, args.raw_directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"report": str(args.output), "native_source_slice": report["native_source_slice"]["status"],
                      "numeric_cases": len(report["independent_exact_cases"]),
                      "training_convergence_established": False}, sort_keys=True))


if __name__ == "__main__":
    main()
