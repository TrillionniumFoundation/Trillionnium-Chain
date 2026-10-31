#!/usr/bin/env python3
"""Check exact mutations, all samples and measured stages; no timing upper bound."""
import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
import struct

SCHEMA = "pon-pure-rejection-tail-campaign-v1"
N, CELLS, Q, PROOF = 64, 4096, 4294967291, 49188
PATHS = ("valid-control-full", "mutated-full", "filter-only", "filter-then-full")


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def natural(value):
    return type(value) is int and value >= 0


def h(tag, *parts):
    value = b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag
    for part in parts:
        value += len(part).to_bytes(4, "little") + part
    return hashlib.sha256(value).digest()


def timing(value):
    require(natural(value["wall_ns"]), "wall clock")
    before, after = value["thread_cpu_before_ns"], value["thread_cpu_after_ns"]
    require(all(v is None or natural(v) for v in (before, after)), "raw CPU clock")
    known = before is not None and after is not None and after >= before
    expected = after - before if known else None
    require(value["thread_cpu_ns"] == expected and type(value["cpu_unknown"]) is bool
            and value["cpu_unknown"] == (not known), "CPU unknown or interval accounting")


def statistic(values):
    if any(value is None for value in values):
        return {"observed": sum(value is not None for value in values), "p99_ns": None, "max_ns": None}
    ordered = sorted(values)
    return {"observed": len(ordered), "p99_ns": ordered[(len(ordered)*99+99)//100-1], "max_ns": ordered[-1]}


def check(rows):
    require(bool(rows) and all(row["schema"] == SCHEMA for row in rows), "schema")
    kinds = collections.Counter(row["kind"] for row in rows)
    require(kinds == {"begin": 1, "trace_preparation": 4, "case": 83, "sample": 747, "terminal": 1},
            "complete fixed row coverage")
    begin, end = rows[0], rows[-1]
    require(begin["kind"] == "begin" and end["kind"] == "terminal" and end["status"] == "complete",
            "complete terminal")
    require(begin["rounds"] == 9 and begin["seed"] == 1 and begin["native_admission_attempted"] is False,
            "fixed finite scope")
    for row in (begin, end):
        require(all(row[key] is False for key in ("production_qualified", "global_upper_bound_proved", "hardness_proved")),
                "unearned qualification")
    header = bytes.fromhex(begin["header_hex"])
    valid = bytes.fromhex(begin["valid_proof_hex"])
    require(len(header) == 318 and header[:6] == b"PNH1\x01\x00" and len(valid) == PROOF
            and valid[:4] == b"PNW1", "original native encoding")
    require(hashlib.sha256(valid).hexdigest() == begin["valid_proof_sha256"], "original proof digest")
    target = bytes.fromhex(begin["native_target"])
    challenge, task = h(b"challenge", header), h(b"task", valid[4:4+CELLS*4], valid[4+CELLS*4:4+CELLS*8])
    require(target == b"\x7f" + b"\xff"*31 == header[118:150]
            and challenge.hex() == begin["challenge"] and task.hex() == begin["task"]
            and task == header[278:310], "exact native statement")
    claim = h(b"ticket", challenge, valid[-32:])
    require(claim <= target and claim.hex() == begin["valid_ticket"], "native winning control ticket")
    a, b = [((13*i+17) % 257) for i in range(CELLS)], [((29*i+31) % 263) for i in range(CELLS)]
    expected_c = [sum(a[i*N+k]*b[k*N+j] for k in range(N)) % Q for i in range(N) for j in range(N)]
    require(list(struct.unpack("<"+"I"*(3*CELLS), valid[4:-32])) == a+b+expected_c,
            "exact public A B and independent mathematical C")
    for key in ("prepared_setup", "valid_acquisition", "fact_setup"):
        timing(begin[key])
    vp = begin["valid_progress"]
    require(vp["result"] == "Accepted" and vp["before_verified_work"] is True and vp["before_product"] is True
            and vp["before_replay"] is True and vp["transcript_tiles"] == 512 and vp["timed_with_samples"] is False,
            "valid control complete replay")
    prepared = {}
    for row in (row for row in rows if row["kind"] == "trace_preparation"):
        case = row["case"]
        require(case not in prepared and row["found"] is True and row["internal_tile_index"] is None,
                "trace preparation identity or digest scope")
        index, eligible = row["digest_byte_index"], row["target_eligible_required"]
        require(index in (0, 16, 31) and type(eligible) is bool, "trace position")
        attempts = row["attempts"]
        require(1 <= len(attempts) <= 255, "bounded trace attempts")
        for number, attempt in enumerate(attempts, 1):
            require(attempt["delta"] == number, "dropped trace attempt")
            trace = bytearray(valid[-32:]); trace[index] = (trace[index]+number) % 256
            observed = h(b"ticket", challenge, trace)
            require(attempt["trace"] == trace.hex() and attempt["claimed_ticket"] == observed.hex()
                    and attempt["target_passes"] == (observed <= target), "trace claim or ticket")
            require((observed <= target) == eligible if number == len(attempts)
                    else (observed <= target) != eligible, "trace search outcome")
            timing(attempt["timing"])
        timing(row["total_timing"])
        prepared[case] = valid[:-32] + bytes.fromhex(attempts[-1]["trace"])
    expected = {}
    for ordinal in range(64):
        index = ordinal*(CELLS-1)//63; proof = bytearray(valid); at = 4+(2*CELLS+index)*4
        word = (int.from_bytes(proof[at:at+4], "little")+1) % Q
        proof[at:at+4] = word.to_bytes(4, "little")
        expected[f"product-cell-{index}"] = ("wrong-product", index, bytes(proof), "Product")
    for index in (0, 16, 31):
        case = f"trace-byte-{index}-passing-ticket"
        expected[case] = ("false-trace", index, prepared[case], "Transcript")
    for matrix in range(3):
        for index in (0, CELLS//2, CELLS-1):
            word = matrix*CELLS+index; proof = bytearray(valid); at = 4+word*4
            proof[at:at+4] = Q.to_bytes(4, "little")
            expected[f"invalid-field-word-{word}"] = ("field", word, bytes(proof), "Field")
    for length in (0, 3, PROOF-1, PROOF+1):
        expected[f"invalid-length-{length}"] = ("length", None, (valid+b"\0")[:length], "Length")
    expected["invalid-version"] = ("version", None, valid[:3]+b"0"+valid[4:], "Version")
    proof = bytearray(valid); proof[4:8] = ((a[0]+1) % Q).to_bytes(4, "little")
    expected["wrong-task"] = ("task", 0, bytes(proof), "Task")
    case = "trace-byte-0-failing-ticket"
    expected[case] = ("target", 0, prepared[case], "Target")
    cases = {row["case"]: row for row in rows if row["kind"] == "case"}
    require(list(cases) == list(expected) and len(cases) == 83, "complete ordered case coverage")
    for case, (family, index, proof, outcome) in expected.items():
        row = cases[case]; stage = row["progress"]
        require(row["family"] == family and row["index"] == index and row["proof_length"] == len(proof)
                and row["proof_sha256"] == hashlib.sha256(proof).hexdigest(), "exact case mutation")
        claim = h(b"ticket", challenge, proof[-32:]).hex() if len(proof) == PROOF else None
        require(row["claimed_ticket"] == claim and row["expected_full"] == outcome
                and row["filter_success_is_verified_work"] is False, "case claim or false work authority")
        if family in ("wrong-product", "false-trace"):
            require(bytes.fromhex(claim) <= target and row["encoding_stage"] == "EncodingOnly"
                    and row["statement_stage"] == "StatementOnly", "late rejection bypassed native target")
            require(stage["before_replay"] is True and stage["transcript_tiles"] == 512
                    and stage["before_product"] == (family == "wrong-product"), "late rejection stage")
        else:
            encoding = outcome if family in ("field", "length", "version") else "EncodingOnly"
            require(row["encoding_stage"] == encoding and row["statement_stage"] == outcome
                    and stage["calls"] == 0 and stage["transcript_tiles"] == 0
                    and stage["before_replay"] is False and stage["before_product"] is False, "early rejection stage")
        require(stage["before_verified_work"] is False and stage["result"] == outcome
                and stage["timed_with_samples"] is False
                and row["filter_only"] == ("FactMatchOnly" if family == "false-trace" else outcome),
                "filter pass is not work or replay accounting")
    family_values, case_values, path_values = (collections.defaultdict(list) for _ in range(3))
    seen = set(); case_order = list(expected)
    for row in (r for r in rows if r["kind"] == "sample"):
        round_, step, case = row["round"], row["step"], row["case"]
        require(type(round_) is int and type(step) is int and 0 <= round_ < 9 and 0 <= step < 83
                and (round_, step) not in seen, "duplicate or missing fixed sample")
        seen.add((round_, step)); position = (step+round_*13) % 83
        require(case == case_order[position] and row["family"] == cases[case]["family"], "sample rotation identity")
        measurements = row["measurements"]
        require(len(measurements) == 4, "missing measured path")
        for order, measurement in enumerate(measurements):
            path = PATHS[(order+round_+position) % 4]
            wanted = "Accepted" if path == PATHS[0] else cases[case]["filter_only"] if path == PATHS[2] else cases[case]["expected_full"]
            require(measurement["path"] == path and measurement["order"] == order
                    and measurement["outcome"] == measurement["expected"] == wanted, "measured path outcome/order")
            timing(measurement["timing"])
            family_values[row["family"], path].append(measurement["timing"])
            case_values[case, path].append(measurement["timing"])
            path_values[path,].append(measurement["timing"])
    require(len(seen) == end["samples"] == 747 and end["cases"] == 83 and end["measured_calls"] == 2988,
            "terminal sample coverage")

    def summary(groups, names):
        return [dict(zip(names, key), samples=len(values), wall=statistic([v["wall_ns"] for v in values]),
                     thread_cpu=statistic([v["thread_cpu_ns"] for v in values])) for key, values in sorted(groups.items())]

    return dict(schema="pon-pure-rejection-tail-consistency-v1", cases=83, rounds=9, samples=747, measured_calls=2988,
        product_indices=[i*(CELLS-1)//63 for i in range(64)], trace_digest_byte_indices=[0,16,31],
        family_statistics=summary(family_values, ("family", "path")),
        per_case_statistics=summary(case_values, ("case", "path")),
        path_statistics=summary(path_values, ("path",)),
        all_sample_cpu_known=all(v["thread_cpu_ns"] is not None for group in family_values.values() for v in group),
        percentile_definition="nearest rank ceil(0.99*n); per-case n=9 means p99 equals finite max",
        scope="fixed public mathematics and exact native-target-winning header; no native admission, worst-case bound, hardware authentication or independence claim",
        global_upper_bound_proved=False, production_qualified=False, hardness_proved=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with (gzip.open if args.input.suffix == ".gz" else open)(args.input, "rb") as stream:
        raw = stream.read(8*1024*1024+1)
    require(len(raw) <= 8*1024*1024 and raw.endswith(b"\n"), "bounded complete input")
    result = check([json.loads(line) for line in raw.splitlines()])
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    with args.output.open("x") as output:
        json.dump(result, output, indent=2); output.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit(f"rejection-tail consistency refused: {error}") from error
