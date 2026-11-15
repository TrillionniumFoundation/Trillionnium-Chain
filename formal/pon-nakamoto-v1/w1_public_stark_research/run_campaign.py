#!/usr/bin/env python3
"""Fresh-process complete-W1 research measurements; never changes qualification.

Use `prove FIXTURE_STEM NEW_OUTPUT_DIR` then `verify OUTPUT_DIR`.
The fixture stem has .input.bin, .prefix.bin, .expected-header.bin, .artifacts.bin.
Every command/exit/stream/resource observation is retained. Negative cases are
samples of rejection cost, not a maximum over every attacker input.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
Q = 4_294_967_291
INPUT_BYTES = 49_506
PREFIX_BYTES = 131_072
PUBLIC_BYTES = 377_290


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def execute(label, command, output, expected_success):
    print(json.dumps({"running": label, "command": list(map(str, command))}), flush=True)
    log_path = output / (label + ".stdout-stderr.log")
    resource_path = output / (label + ".time.txt")
    started = time.perf_counter()
    wrapped = ["/usr/bin/time", "-v", "-o", str(resource_path), *map(str, command)]
    with log_path.open("x") as log:
        child = subprocess.Popen(wrapped, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding="utf-8", errors="backslashreplace")
        for line in child.stdout:
            log.write(line)
            log.flush()
            print(line, end="", flush=True)
        code = child.wait()
    wall = time.perf_counter() - started
    objects = []
    for line in log_path.read_text().splitlines():
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                objects.append(obj)
        except json.JSONDecodeError:
            pass
    final = next((o for o in reversed(objects) if "qualification" in o), None)
    observation = {
        "label": label, "command": list(map(str, command)), "exit_code": code,
        "outer_wall_seconds": wall, "expected_success": expected_success,
        "matched_exit_expectation": (code == 0) == expected_success,
        "final": final, "phase_events": [o for o in objects if "phase" in o],
        "resource_text": resource_path.read_text(),
        "combined_log_sha256": sha(log_path.read_bytes()),
    }
    save(output / (label + ".observation.json"), observation)
    print(json.dumps({"finished": label, "exit_code": code, "outer_wall_seconds": wall}), flush=True)
    if (code == 0) != expected_success:
        raise RuntimeError(f"unexpected command outcome: {label}, exit {code}")
    if expected_success and (not final or final.get("qualification") != "HOLD_NO_GO"):
        raise RuntimeError("missing independent final verdict")
    return observation


def sources():
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", Path(__file__).resolve()]
    paths += sorted((ROOT / "src").glob("*.rs"))
    paths += sorted((ROOT / "tests").glob("*.rs"))
    return {str(p.relative_to(ROOT)): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
            for p in paths}


def prove(binary, stem, output):
    output.mkdir(parents=True, exist_ok=False)
    paths = {name: Path(str(stem) + suffix).resolve() for name, suffix in [
        ("raw", ".input.bin"), ("prefix", ".prefix.bin"),
        ("header", ".expected-header.bin"), ("artifacts", ".artifacts.bin")]}
    provenance = {
        "schema": "trnm-w1-stark-campaign-v1", "qualification": "HOLD_NO_GO",
        "machine": platform.uname()._asdict(), "python": sys.version,
        "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS"),
        "binary": str(binary), "binary_sha256": sha(binary.read_bytes()), "sources": sources(),
        "fixtures": {key: {"path": str(p), "bytes": p.stat().st_size,
                            "sha256": sha(p.read_bytes())} for key, p in paths.items()},
        "scope": "fixed original W1 fixture; public-witness preparation and actual proofs; no nonce-search estimate",
    }
    save(output / "provenance.json", provenance)
    prepared = execute("prepare", [binary, "prepare", paths["raw"], paths["prefix"],
                       paths["header"], paths["artifacts"], output], output, True)
    proven = execute("prove", [binary, "prove", output / "statement.bin",
                     paths["header"], paths["artifacts"], output], output, True)
    save(output / "generation.json", {"prepare": prepared, "prove": proven,
         "qualification": "HOLD_NO_GO", "verification_pending": True})


def changed_word(data, offset):
    value = int.from_bytes(data[offset:offset + 4], "little")
    return data[:offset] + ((value + 1) % Q).to_bytes(4, "little") + data[offset + 4:]


def flipped(data, offset):
    return data[:offset] + bytes([data[offset] ^ 1]) + data[offset + 1:]


def changed_first_commitment(data):
    # P3 0.8.0 serializes the first MerkleCap as a Vec: its u64 length
    # follows the eight-byte application envelope. Cap height zero has
    # exactly one digest. Preserve that shape and change its first field
    # element canonically, so this is not a disguised length/shape mutation.
    if len(data) < 24 or int.from_bytes(data[8:16], "little") != 1:
        raise RuntimeError("unexpected locked proof commitment layout")
    modulus = 18_446_744_069_414_584_321
    value = int.from_bytes(data[16:24], "little")
    if value >= modulus:
        raise RuntimeError("unexpected noncanonical commitment element")
    return data[:16] + ((value + 1) % modulus).to_bytes(8, "little") + data[24:]


def verify(binary, output):
    provenance = json.loads((output / "provenance.json").read_text())
    if sha(binary.read_bytes()) != provenance["binary_sha256"]:
        raise RuntimeError("binary changed since proof generation")
    header = Path(provenance["fixtures"]["header"]["path"])
    artifacts = Path(provenance["fixtures"]["artifacts"]["path"])
    for name, path in [("header", header), ("artifacts", artifacts)]:
        if sha(path.read_bytes()) != provenance["fixtures"][name]["sha256"]:
            raise RuntimeError("independent expected fixture changed")
    campaign = output / "verification-campaign"
    campaign.mkdir(exist_ok=False)
    positive = []
    for i in range(3):
        positive.append(execute(f"valid-{i:02d}", [binary, "verify", output / "statement.bin",
                        header, artifacts, output], campaign, True))
        if positive[-1]["final"]["status"] != "VERIFIED_COMPLETE_W1_RESEARCH_ONLY":
            raise RuntimeError("positive was not a complete proof verification")
    public = (output / "statement.bin").read_bytes()
    sp = (output / "sha.proof.bin").read_bytes()
    ap = (output / "arith.proof.bin").read_bytes()
    assert len(public) == PUBLIC_BYTES
    controls = [
        ("public-extra-byte", {"statement.bin": public + b"\x00"}, "bounded file length"),
        ("sha-proof-truncated", {"sha.proof.bin": sp[:-32]}, "proof decoding:"),
        ("sha-proof-trailing-byte", {"sha.proof.bin": sp + b"\x00"}, "proof decoding:"),
        ("sha-commitment-changed", {"sha.proof.bin": changed_first_commitment(sp)}, "sha proof rejected:"),
        ("arith-commitment-changed", {"arith.proof.bin": changed_first_commitment(ap)}, "arithmetic proof rejected:"),
        ("last-C-changed", {"statement.bin": changed_word(public, 8 + INPUT_BYTES - 32 - 4)}, "arithmetic proof rejected:"),
        ("last-prefix-changed", {"statement.bin": changed_word(public, 8 + INPUT_BYTES + PREFIX_BYTES - 4)}, "sha proof rejected:"),
        ("last-AB-intermediate-changed", {"statement.bin": changed_word(public, PUBLIC_BYTES - 4)}, "arithmetic proof rejected:"),
        ("unused-noise-tail-changed", {"statement.bin": flipped(public, 8 + INPUT_BYTES + PREFIX_BYTES + 32 + 4 * 128 * 32 - 1)}, "sha proof rejected:"),
        ("wrong-independent-artifacts", {"expected-artifacts.bin": flipped(artifacts.read_bytes(), 63)}, "sha proof rejected:"),
        ("wrong-independent-header", {"expected-header.bin": flipped(header.read_bytes(), 317)}, "IndependentHeader"),
    ]
    negative = []
    for name, replacements, expected_error_prefix in controls:
        case = campaign / name
        case.mkdir()
        for filename in ["statement.bin", "sha.proof.bin", "arith.proof.bin"]:
            if filename in replacements:
                with (case / filename).open("xb") as stream:
                    stream.write(replacements[filename])
            else:
                os.link(output / filename, case / filename)
        for filename in ["expected-header.bin", "expected-artifacts.bin"]:
            if filename in replacements:
                with (case / filename).open("xb") as stream:
                    stream.write(replacements[filename])
        ch = case / "expected-header.bin" if "expected-header.bin" in replacements else header
        ca = case / "expected-artifacts.bin" if "expected-artifacts.bin" in replacements else artifacts
        obs = execute(name, [binary, "verify", case / "statement.bin", ch, ca, case], campaign, False)
        if not obs["final"] or obs["final"].get("status") != "REJECTED_OR_FAILED":
            raise RuntimeError("negative process crashed without a controlled rejection")
        if not obs["final"].get("error", "").startswith(expected_error_prefix):
            raise RuntimeError(f"{name}: rejection at the wrong stage")
        if expected_error_prefix == "arithmetic proof rejected:":
            phases = {event["phase"] for event in obs["phase_events"]}
            if not {"sha_stark_verify", "arith_verifier_independent_preprocessing_setup", "arith_stark_verify"} <= phases:
                raise RuntimeError(f"{name}: did not reach arithmetic proof verification")
        obs["expected_error_prefix"] = expected_error_prefix
        obs["matched_rejection_stage"] = True
        negative.append(obs)
    save(campaign / "summary.json", {
        "schema": "trnm-complete-w1-independent-verification-campaign-v1",
        "qualification": "HOLD_NO_GO", "positive_count": len(positive), "negative_count": len(negative),
        "positive": positive, "negative": negative,
        "largest_observed_negative_outer_seconds": max(o["outer_wall_seconds"] for o in negative),
        "warning": "sampled controls only; no global latest-rejection or DoS cost bound",
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=ROOT / "target/release/w1-full-public-stark-research")
    sub = parser.add_subparsers(dest="mode", required=True)
    generation = sub.add_parser("prove")
    generation.add_argument("fixture_stem", type=Path)
    generation.add_argument("output", type=Path)
    verification = sub.add_parser("verify")
    verification.add_argument("output", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.mode == "prove":
        prove(binary, args.fixture_stem, args.output.resolve())
    else:
        verify(binary, args.output.resolve(strict=True))


if __name__ == "__main__":
    main()
