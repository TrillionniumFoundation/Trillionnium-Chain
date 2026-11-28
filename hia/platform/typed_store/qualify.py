"""Physical native staging qualification; no fabricated IO acknowledgements."""
from __future__ import annotations
import argparse
import json
import lzma
from pathlib import Path
import struct
import sys

from hia.platform.build import new_output, write_json, sha256
from hia.platform.typed_store.build import Build, file_identity
from hia.platform.typed_store.cases import BLOCK, SLOT, MAX, Case, cases, delta, kv
from hia.platform.typed_store.native_io import run
from hia.tests.test_state_root import reference

REPOSITORY = Path(__file__).resolve().parents[3]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def safe_process(actual):
    return (not actual["timed_out"] and not actual["gate_errors"] and actual["inputs_unchanged"]
        and not actual.get("controller_stop_requested", False))

def main():
    if not __debug__:
        raise RuntimeError("Optimized Python is not admitted by this qualifier")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = new_output(args.output)
    controls, native_cases = [], []
    base_report = {"schema": "trnm.hia.native-typed-staging-qualification.v1",
        "scope": "Immutable typed row captures, streaming merge, actual staged-file State scan and optional classical root",
        "original_rust": "NOT_RUN", "typed_namespace_or_commit_authority": False,
        "full_node_rewrite_qualified": False, "gsc2_root_qualified": False,
        "continuity_qualified": False, "physical_power_loss_qualified": False,
        "same_uid_continuous_attack_resistance": False,
        "sql_materialization_error_order_qualified": False,
        "full_serde_error_text_or_source_chain_parity": False,
        "original_cpu_or_input_acquisition_budget_qualified": False}
    try:
        build = Build(output / "build", REPOSITORY)
        executable, build_receipt = build.build()
        case_root = output / "semantic"
        case_root.mkdir(mode=0o700)
        corpus_path = output / "corpus.jsonl"
        with corpus_path.open("w") as corpus:
            for index, case in enumerate(cases()):
                corpus.write(json.dumps(case.corpus(), separators=(",", ":")) + "\n")
                actual = run(executable, case_root / f"{index:04}-{case.name}", kv(case.before),
                    delta(case.changes), detach=case.detach, root=case.root, profile=case.profile,
                    cancel=case.cancel, cancel_class=case.cancel_class, token=case.token)
                expected_progress = case.progress()
                checks = {"process": safe_process(actual), "code": actual["exit"] == case.code,
                    "progress": actual["progress_records"] == expected_progress}
                if case.code == 0:
                    expected = kv(case.result)
                    digest = reference(case.result)[1] if case.root else bytes(32)
                    receipt = actual.get("receipt", {})
                    checks.update(output=actual.get("output_hex") == expected.hex(), no_stderr=not actual["stderr_hex"],
                        receipt=receipt == {"kind": 2 if case.root else 1, "count": len(case.result),
                            "output_bytes": len(expected), "delta_count": len(case.changes),
                            "progresses": len(expected_progress), "block_hex": BLOCK.hex(),
                            "slot": SLOT, "root_hex": digest.hex(), "reserved": 0})
                    observed_root = receipt.get("root_hex") if case.root else None
                    observed_result = actual.get("output_hex")
                else:
                    checks.update(no_receipt=not actual["stdout_hex"], no_staged_bytes=actual["output_bytes"] == 0,
                        diagnostic=len(actual.get("diagnostic", [])) == 7 and actual["diagnostic"][0] == case.code
                            and actual["diagnostic"][3] == len(expected_progress) and actual["diagnostic"][6] == 0)
                    if case.code == 80:
                        checks["callback_identity"] = actual["diagnostic"][4:6] == [case.cancel_class, case.token]
                    observed_root, observed_result = None, None
                ok = all(checks.values())
                controls.append({"name": case.name, "status": "PASS" if ok else "FAIL",
                    "checks": checks, "actual": actual})
                write_json(output / "running-controls.json", {"controls": controls})
                require(ok, "Semantic native mismatch: " + case.name + " " + json.dumps(checks))
                native_cases.append({"name": case.name, "code": actual["exit"],
                    "progresses": len(actual["progress_records"]), "result_hex": observed_result,
                    "root_hex": observed_root})
        physical = output / "physical"
        physical.mkdir(mode=0o700)
        empty, no_changes = kv(()), delta(())
        stopped = run(executable, physical / "owned-controller-stop", empty, no_changes,
            kill=1, stop_file=output / "stop-owned-control")
        ok = (not stopped["timed_out"] and not stopped["gate_errors"] and stopped["inputs_unchanged"]
            and stopped["exit"] == -9 and stopped["controller_stop_requested"]
            and stopped["controller_stop"][0]["signal_outcome"] == "sent"
            and not stopped["stdout_hex"] and stopped["output_bytes"] == 0)
        controls.append({"name": "owned-controller-stop", "status": "PASS" if ok else "FAIL", "actual": stopped})
        require(ok, "Explicit controller stop did not kill and reap its actual owned native child")
        caps = {name: 65 for name in ("unsealed-base", "unsealed-delta", "output-mode",
            "output-link", "output-nonempty", "output-append", "output-readonly", "output-alias-base",
            "gw-output-alias", "gr-output-alias", "gw-base-alias", "gr-delta-alias",
            "gw-read-end", "gr-write-end", "gate-self-loop", "gw-separate-regular",
            "gr-separate-regular", "gate-rdwr-fifo", "gate-opath-fifo")}
        caps["output-locked"] = 67
        for name, code in caps.items():
            actual = run(executable, physical / name, empty, no_changes, capability=name)
            ok = safe_process(actual) and actual["exit"] == code and not actual["stdout_hex"]
            ok = ok and not actual["progress_records"] and actual["output_hex"] == actual["output_before_hex"]
            controls.append({"name": name, "status": "PASS" if ok else "FAIL", "actual": actual})
            require(ok, "Physical capability refusal differs: " + name)
        for cls in (1, 2, 3, 4):
            actual = run(executable, physical / f"cancel-class-{cls}", empty, no_changes,
                cancel=1, cancel_class=cls, token=MAX - cls)
            ok = safe_process(actual) and actual["exit"] == 80 and actual["output_bytes"] == 0
            ok = ok and not actual["stdout_hex"] and actual["diagnostic"][4:6] == [cls, MAX - cls]
            controls.append({"name": f"cancel-class-{cls}", "status": "PASS" if ok else "FAIL", "actual": actual})
            require(ok, "Opaque callback identity was not preserved")
        for cls, token, name in ((0, 1, "success-token-nonzero"), (5, 7, "unknown-callback-class")):
            actual = run(executable, physical / name, empty, no_changes,
                cancel=1, cancel_class=cls, token=token)
            ok = safe_process(actual) and actual["exit"] == 64 and not actual["stdout_hex"] and actual["output_bytes"] == 0
            controls.append({"name": name, "status": "PASS" if ok else "FAIL", "actual": actual})
            require(ok, "Malformed callback was accepted")
        framed_base = kv(((b"a", b"1"), (b"z", b"2")))
        framed_delta = delta(((b"a", b"1", b"2"), (b"b", None, b"3")))
        malformed = []
        for index in range(len(framed_base)):
            malformed.append((f"base-cut-{index}", framed_base[:index], no_changes, 65 if index < 16 else 66))
        for index in range(len(framed_delta)):
            malformed.append((f"delta-cut-{index}", empty, framed_delta[:index], 65 if index < 56 else 66))
        malformed.extend((
            ("base-trailing", empty + b"x", no_changes, 66),
            ("delta-trailing", empty, no_changes + b"x", 66),
            ("base-count-max", empty[:8] + struct.pack("<Q", MAX), no_changes, 66),
            ("delta-count-max", empty, no_changes[:8] + struct.pack("<Q", MAX) + no_changes[16:], 66),
            ("base-order", kv(((b"z", b"1"), (b"a", b"2"))), no_changes, 66),
            ("base-duplicate", kv(((b"a", b"1"), (b"a", b"2"))), no_changes, 66),
            ("delta-order", empty, delta(((b"z", None, b"1"), (b"a", None, b"2"))), 66),
            ("delta-duplicate", empty, delta(((b"a", None, b"1"), (b"a", None, b"2"))), 66),
            ("base-key-utf8", kv(((b"\xff", b"1"),)), no_changes, 66),
            ("delta-key-utf8", empty, delta(((b"\xff", None, b"1"),)), 66),
        ))
        for name, raw_base, raw_delta, code in malformed:
            actual = run(executable, physical / name, raw_base, raw_delta)
            ok = safe_process(actual) and actual["exit"] == code and not actual["stdout_hex"]
            ok = ok and actual["output_bytes"] == 0 and not actual["progress_records"]
            controls.append({"name": name, "status": "PASS" if ok else "FAIL", "actual": actual})
            require(ok, "Complete immutable capture admission differs: " + name)
        mixed = next(case for case in cases() if case.name == "mixed")
        for point in (1, 3, 5, 7, 9):
            killed = run(executable, physical / f"sigkill-{point}", kv(mixed.before),
                delta(mixed.changes), kill=point)
            ok = safe_process(killed) and killed["exit"] == -9 and not killed["stdout_hex"]
            controls.append({"name": f"sigkill-{point}", "status": "PASS" if ok else "FAIL", "actual": killed})
            require(ok, "SIGKILL produced a success or modified an input")
            restarted = run(executable, physical / f"restart-{point}", kv(mixed.before), delta(mixed.changes))
            cold = run(executable, physical / f"cold-{point}", Path(restarted["output_path"]), no_changes)
            ok = safe_process(restarted) and safe_process(cold) and restarted["exit"] == cold["exit"] == 0
            ok = ok and restarted["output_hex"] == cold["output_hex"] == kv(mixed.result).hex()
            ok = ok and restarted["receipt"]["root_hex"] == cold["receipt"]["root_hex"] == reference(mixed.result)[1].hex()
            controls.append({"name": f"restart-cold-{point}", "status": "PASS" if ok else "FAIL",
                "restarted": restarted, "cold": cold})
            require(ok, "Fresh restart and full cold row scan differ")
        limited = run(executable, physical / "real-efbig", kv(mixed.before), delta(mixed.changes), file_limit=41)
        ok = safe_process(limited) and limited["exit"] == 70 and not limited["stdout_hex"]
        ok = ok and limited["output_bytes"] == 0 and limited["diagnostic"][6] == 0
        controls.append({"name": "real-efbig", "status": "PASS" if ok else "FAIL", "actual": limited})
        require(ok, "Actual partial file-size refusal did not discard staging")
        lost = run(executable, physical / "lost-staging-receipt", kv(mixed.before),
            delta(mixed.changes), lose_receipt=True)
        ok = safe_process(lost) and lost["exit"] == 70 and not lost["stdout_hex"]
        ok = ok and lost["output_hex"] == kv(mixed.result).hex()
        controls.append({"name": "lost-staging-receipt", "status": "PASS" if ok else "FAIL", "actual": lost})
        require(ok, "Lost receipt must not become a successful owner acknowledgement")
        rows = tuple((f"k{index:06}".encode() + b"x" * 153, b'"' + b"v" * 4094 + b'"') for index in range(1024))
        large = run(executable, physical / "large-native", kv(rows), no_changes, timeout=180, retain_bytes=False)
        cold = run(executable, physical / "large-cold", Path(large["output_path"]), no_changes,
            timeout=180, retain_bytes=False)
        expected_root = reference(rows)[1].hex()
        ok = safe_process(large) and safe_process(cold) and large["exit"] == cold["exit"] == 0
        ok = ok and large["output_bytes"] > (1 << 20) and large["output_sha256"] == cold["output_sha256"] == sha256(kv(rows))
        ok = ok and large["receipt"]["root_hex"] == cold["receipt"]["root_hex"] == expected_root
        controls.append({"name": "large-complete-cold-root", "status": "PASS" if ok else "FAIL",
            "native": large, "cold": cold, "independent_root_hex": expected_root})
        require(ok, "Large complete State cold-read root differs")
        build.check_sources()
        comparison = {"schema": "trnm.hia.typed-staging-native-comparison.v1", "status": "PASS",
            "build": build_receipt, "corpus": file_identity(corpus_path), "cases": native_cases}
        write_json(output / "native-comparison.json", comparison)
        with corpus_path.open("rb") as source, lzma.open(output / "corpus.jsonl.xz", "wb", preset=6) as destination:
            while block := source.read(1 << 20):
                destination.write(block)
        report = dict(base_report, status="NATIVE_PASS_ORIGINAL_NOT_RUN", native="PASS",
            native_controls=len(controls), semantic_cases=len(native_cases), controls=controls,
            build=build_receipt, source_inputs_stable=True, full_classic_extent_qualified=False,
            capacity_entry="python3 -B -m hia.platform.typed_store.capacity --stage produce|cold|bounds",
            original_rust_command=["python3", "-B", "-m", "hia.platform.typed_store.rust_oracle",
                "--repository", str(REPOSITORY), "--bundle", str(output), "--output", "FRESH_OUTPUT"])
        write_json(output / "report.json", report)
        print(json.dumps({"status": report["status"], "native_controls": len(controls),
            "semantic_cases": len(native_cases), "report": str(output / "report.json")}))
        return 0
    except BaseException as error:
        write_json(output / "report.json", dict(base_report, status="FAIL", error=repr(error),
            completed_controls=controls))
        raise


if __name__ == "__main__":
    raise SystemExit(main())
