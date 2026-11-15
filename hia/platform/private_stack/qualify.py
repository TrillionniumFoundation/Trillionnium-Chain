#!/usr/bin/env python3
"""Observe actual private-stack erasure and Linux failures with public test keys."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build, new_output, run_native, require_success, sha256, write_json
from hia.platform.private_stack.build import Guard, HIA, INPUTS
from hia.tests.test_ed25519 import sign, L
from hia.tools.toolchain import compose_source

HERE = Path(__file__).resolve().parent
STACK_BYTES = 1048576
WORK_BYTES = 141568
SECRET_OFFSETS = {"seed": (31, (-1632, -1616, -1600)),
    "clamped_scalar": (31, (-6640, -6624)), "prefix": (24, (-16656, -16640)),
    "nonce_scalar": (31, (-5504, -5488))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    missing = [name for name in ("as", "ld", "objcopy") if not shutil.which(name)]
    if missing:
        parser.error("Test-only diagnostic assembler tools required: " + ", ".join(missing))
    output = new_output(args.output)
    captured = {}
    for relative in (*INPUTS, "platform/private_stack/qualify.py", "platform/private_stack/observer.s",
            "platform/private_stack/observation_shim.s", "tests/test_ed25519.py", "tools/toolchain.py"):
        path = HIA / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked qualification source: " + relative)
        captured[relative] = path.read_bytes()
    pinned = Build(output / "native-build")
    guard = Guard(pinned)
    source, admitted = compose_source(HIA / "src/crypto/ed25519_sign.hepta")
    for path, raw in admitted:
        captured[path.relative_to(HIA).as_posix()] = raw
    raw = pinned.stage(pinned.compiler, source, "compile-original-signer")
    protected, production = guard.wrap(raw, "signer")
    (output / "raw.flat").write_bytes(raw)
    (output / "guarded.flat").write_bytes(protected)
    for name in ("observer.s", "observation_shim.s"):
        (output / name).write_bytes(captured["platform/private_stack/" + name])
    commands = []
    def command(argv):
        p = subprocess.run(argv, cwd=output, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        row = {"argv": argv, "exit_code": p.returncode, "stdout_sha256": sha256(p.stdout),
               "stderr_sha256": sha256(p.stderr), "stderr_hex": p.stderr.hex()}
        commands.append(row)
        if p.returncode:
            write_json(output / "diagnostic-build-failure.json", {"commands": commands})
            raise RuntimeError("Test-only diagnostic assembly failed")
    command(["as", "--64", "observation_shim.s", "-o", "shim.o"])
    command(["objcopy", "-O", "binary", "-j", ".text", "shim.o", "observed.flat"])
    observed = (output / "observed.flat").read_bytes()
    if not observed.endswith(raw):
        raise ValueError("Diagnostic shim changed the original signer")
    wrapped, diagnostic = guard.wrap(observed, "diagnostic-signer")
    if wrapped[:288] != protected[:288]:
        raise ValueError("Diagnostic used a different production adapter")
    (output / "guarded-observed.flat").write_bytes(wrapped)
    command(["as", "--64", "observer.s", "-o", "observer.o"])
    command(["ld", "-z", "noexecstack", "-o", "observer.elf", "observer.o"])
    executable = (output / "observer.elf").read_bytes()
    observations = []
    residual = []
    for index in range(3):
        seed = hashlib.sha256(("public diagnostic seed " + str(index)).encode()).digest()
        message = hashlib.sha256(b"public diagnostic digest").digest()
        public, signature = sign(seed, message)
        expected = public + signature
        expanded = hashlib.sha512(seed).digest()
        scalar = ((int.from_bytes(expanded[:32], "little") & ((1 << 254) - 8)) | (1 << 254)).to_bytes(32, "little")
        nonce = (int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % L).to_bytes(32, "little")
        secrets = {"seed": seed, "clamped_scalar": scalar, "prefix": expanded[32:], "nonce_scalar": nonce}
        modes = (4, 0, 3, 1, 2) if index == 0 else (4, 0, 3)
        for mode in modes:
            name = f"seed-{index}-mode-{mode}"
            data, receipt = run_native(executable, seed + message + mode.to_bytes(8, "little"), output, name, timeout=15)
            require_success(receipt)
            expected_len = 16 + 104 + 141600 + STACK_BYTES + (STACK_BYTES if mode == 3 else 0)
            if len(data) != expected_len:
                raise ValueError("Missing or oversized native observation: " + name)
            status = int.from_bytes(data[:8], "little")
            mincore = int.from_bytes(data[8:16], "little", signed=True)
            result = data[16:112]
            work = data[120:120+141600]
            caller = data[120+141600:120+141600+STACK_BYTES]
            private = data[120+141600+STACK_BYTES:]
            row = {"case": name, "public_synthetic_seed_hex": seed.hex(), "message_hex": message.hex(),
                "status": status, "actual_mincore_result": mincore, "receipt": receipt,
                "signature_sha256": sha256(result), "expected_signature_sha256": sha256(expected),
                "caller_stack_sha256": sha256(caller), "work_tail_unchanged": work[WORK_BYTES:] == bytes([0xa5])*32}
            if mode in (0, 3, 4):
                row["same_exact_signature_output"] = result == expected
                row["work_used_zero"] = work[:WORK_BYTES] == bytes(WORK_BYTES)
                ok = row["same_exact_signature_output"] and row["work_used_zero"] and row["work_tail_unchanged"]
                spills = []
                for kind, (byte_index, offsets) in SECRET_OFFSETS.items():
                    expected_word = bytes([secrets[kind][byte_index]]) + bytes(7)
                    for offset in offsets:
                        actual = caller[STACK_BYTES+offset:STACK_BYTES+offset+8]
                        spills.append({"kind": kind, "byte_index": byte_index, "offset_below_stack_top": offset,
                            "matches_secret_byte_spill": actual == expected_word,
                            "caller_canary_unchanged": actual == bytes([0xa5])*8})
                row["secret_stack_observations"] = spills
                if mode == 4:
                    row["original_stack_erasure"] = "FAIL" if any(s["matches_secret_byte_spill"] for s in spills) else "NOT_REPRODUCED"
                    residual.append(row)
                    ok = ok and status == 0 and row["original_stack_erasure"] == "FAIL"
                else:
                    ok = ok and all(s["caller_canary_unchanged"] for s in spills)
                    if mode == 0:
                        row["private_mapping_absent_after_release"] = mincore == -12
                        ok = ok and status == 0 and mincore == -12
                    else:
                        row["private_stack_nonzero_bytes"] = sum(v != 0 for v in private)
                        row["private_stack_sha256"] = sha256(private)
                        row["private_stack_bytes"] = len(private)
                        ok = ok and status == 0x80003001 and mincore == 0 and private == bytes(STACK_BYTES)
            else:
                expected_status = 0x80001001 if mode == 1 else 0x80002001
                row["output_unchanged"] = result == bytes(96)
                row["work_unchanged"] = work == bytes([0xa5])*141600
                ok = status == expected_status and row["output_unchanged"] and row["work_unchanged"]
            row["passed_required_observation"] = ok
            observations.append(row)
    stable = all((HIA / relative).read_bytes() == raw for relative, raw in captured.items())
    guard.check_sources()
    report = {"schema": "trnm.hia.private-stack-qualification.v1",
        "status": "PASS_WITH_RETAINED_RAW_SIGNER_ERASURE_FAILURE" if stable and all(x["passed_required_observation"] for x in observations) else "FAIL",
        "source_inputs": {p: {"bytes": len(raw), "sha256": sha256(raw)} for p, raw in sorted(captured.items())},
        "source_inputs_stable": stable, "guard": guard.receipt(), "production_image": production,
        "diagnostic_image": diagnostic, "native_stages": pinned.stages,
        "diagnostic_build_commands": commands, "host_assembled_observers_are_test_only": True,
        "runtime_instruction_bytes_emitted_by_hia": True, "observations": observations,
        "original_raw_signer_stack_erasure": "FAIL", "original_residual_cases": len(residual),
        "whole_key_owner_qualified": False, "async_abort_or_input_seed_erasure_qualified": False,
        "machine_constant_time_proved": False, "late_cleanup_error_forbids_output_publication": True}
    write_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "controls": len(observations), "original_residual_cases": len(residual)}))
    return report["status"] == "FAIL"


if __name__ == "__main__":
    raise SystemExit(main())
