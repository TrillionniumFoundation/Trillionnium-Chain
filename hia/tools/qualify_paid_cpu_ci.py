"""Bind complete actual finite PaidCPU CI evidence without widening its scope."""
from pathlib import Path
import json
import re
import hashlib
import stat
import struct

from hia.tools import qualify_foundation_ci as base

require = base.require
read = base.read
identity = base.identity


def settled_stages(directory, report, labels):
    stages = report.get("stages")
    require(type(stages) is list and len(stages) == len(labels),
            "Complete actual original process roster required")
    result = {}
    for label, row in zip(labels, stages, strict=True):
        folder = directory / label
        require(type(row) is dict and row.get("exit_code") == 0
                and row.get("timed_out") is False and row.get("cleanup") is None
                and row.get("cleanup_limit_seconds") == 3
                and read(folder / "receipt.json") == row,
                "Original process failed, did not settle, or its receipt changed")
        for stream in ("stdout", "stderr"):
            require(identity(folder / (stream + ".raw")) ==
                    {"bytes": row[stream + "_bytes"], "sha256": row[stream + "_sha256"]},
                    "Actual original process output changed")
        result[label] = row
    return result


def positive_test(raw, name):
    text = raw.decode()
    require(re.search(r"(?m)^test " + re.escape(name) + r" \.\.\.", text)
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text),
            "Actual named original test did not execute successfully")



def budget_operations(native):
    owners = native.get("owners")
    require(type(owners) is list and len(owners) == 6,
            "All six actual native owner histories required")
    total = 0
    for row in owners:
        operations = row["trace"]["replay"]["operations"]
        require(type(operations) is list and operations,
                "A complete actual native budget event stream is required")
        total += len(operations)
    require(type(native.get("actual_budget_operations")) is int
            and native["actual_budget_operations"] == total,
            "Native budget event count differs from its complete actual traces")
    return total


def standard_binding(original, source, abi):
    standard = original["standard_library"]
    contract = abi["standard_library"]
    require(standard == source["standard_library"]
            and standard["commit"] == contract["commit"]
            and hashlib.sha256(standard["compiler"].encode()).hexdigest()
            == contract["rustc_version_sha256"]
            and standard["sources"] == contract["sources"],
            "Actual compiler/std source or full compiler version differs")
    require(set(standard["binaries"]) == set(contract["binaries"]),
            "Complete compiled standard-library roster required")
    for name, value in contract["binaries"].items():
        require({k: standard["binaries"][name][k] for k in ("bytes", "sha256")} == value,
                "Actual compiled standard library differs")
    tools = {k: standard[k] for k in ("compiler_executable", "cargo_executable")}
    for key, name in (("compiler_executable", "rustc"), ("cargo_executable", "cargo")):
        value = tools[key]
        require(value["path"] == str(Path(standard["sysroot"]) / "bin" / name)
                and type(value["bytes"]) is int and value["bytes"] > 0
                and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
                "Actual build tool is not a complete pinned-sysroot identity")
    require(original["actual_build_tools"] == tools
            and original["explicit_compiler_environment"] == {
                "RUSTUP_TOOLCHAIN": contract["toolchain"],
                "RUSTC": tools["compiler_executable"]["path"],
                "CARGO": tools["cargo_executable"]["path"],
                "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""},
            "Cargo did not bind the exact actual compiler and empty wrappers")
    return tools


def independent_executable(directory, original):
    binary = directory / "original-test-binary"
    info = base.regular(binary).stat()
    executable = original["executable"]
    require(executable["path"] == str(binary)
            and stat.S_IMODE(info.st_mode) == 0o500 and info.st_nlink == 1
            and identity(binary) == {k: executable[k] for k in ("bytes", "sha256")},
            "Independent actual original executable differs or is mutable/aliased")
    events = [json.loads(line, object_pairs_hook=base.unique_object)
              for line in (directory / "cargo-original-test-build/stdout.raw").read_text().splitlines()
              if line.startswith("{")]
    artifacts = [row for row in events if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "trnm_pon_node"
                 and row["target"].get("kind") == ["lib"]
                 and row.get("profile", {}).get("test") is True
                 and row.get("executable")]
    require(len(artifacts) == 1
            and original["compiled_executable"]["path"] == artifacts[0]["executable"]
            and {k: original["compiled_executable"][k] for k in ("bytes", "sha256")}
            == {k: executable[k] for k in ("bytes", "sha256")},
            "Independent executable is not bound to one actual Cargo test-library artifact")
    return binary


def fault_capture(folder, captured, binary, executable, expected_fault, disabled):
    require(read(folder / "report.json") == captured
            and captured.get("schema") == "trnm.private.actual-original-ptrace-fault.v1"
            and captured.get("status") == "PASS"
            and type(captured.get("exit_code")) is int and captured["exit_code"] == 0
            and captured.get("signal") is None
            and captured.get("complete_owned_process_reaped") is True
            and captured.get("executable_after") == "MATCH"
            and not captured.get("failure") and not captured.get("cleanup_failure")
            and not captured.get("failure_cleanup"),
            "Actual original fault process failed or did not fully reap")
    from hia.platform.paid_cpu.fault_oracle import PREFIX
    require(captured["argv"] == [str(binary), "--exact", PREFIX + "original_actual_fault_profile",
                                "--nocapture", "--test-threads=1"]
            and captured["executable_before"] == executable
            and captured.get("disable_vdso") is disabled
            and captured.get("fault") == expected_fault,
            "Actual original fault executable, command, or injection profile differs")
    for key, name in (("events", "events.jsonl"), ("stdout", "stdout.raw"), ("stderr", "stderr.raw")):
        require(captured[key] == identity(folder / name),
                "Actual original fault raw stream changed: " + key)
    positive_test((folder / "stdout.raw").read_bytes(), PREFIX + "original_actual_fault_profile")
    events = [json.loads(line, object_pairs_hook=base.unique_object)
              for line in (folder / "events.jsonl").read_text().splitlines()]
    require(events and all(type(row.get("sequence")) is int and row["sequence"] == index
                           for index, row in enumerate(events, 1)),
            "Fault trace sequence is incomplete or reordered")
    stored = captured["roster"]
    require(type(stored) is dict and stored
            and all(str(int(key)) == key and int(key) > 0 for key in stored),
            "Fault task identity is not canonical")
    roots = [int(key) for key, row in stored.items() if row["parent"] is None]
    require(len(roots) == 1, "One actual owned original root required")
    root = roots[0]
    roster = {root: {"parent": None, "birth": 0}}
    alive, execs, entries, exits = {root}, [], {}, {}
    for row in events:
        tid = row["tid"]
        require(type(tid) is int and tid in alive,
                "Fault event lies outside its actual birth/terminal lifetime")
        if row["kind"] == "birth":
            child = row["child"]
            require(type(child) is int and child > 0 and child not in roster,
                    "Fault task birth reuses or forges an identity")
            roster[child] = {"parent": tid, "birth": row["sequence"]}
            alive.add(child)
        elif row["kind"] == "terminal":
            require(row.get("exit_code") == 0 and row.get("signal") is None,
                    "An original fault task failed or was killed")
            roster[tid]["terminal"] = row
            alive.remove(tid)
        elif row["kind"] == "exec":
            require(tid == root and row["actual_executable"] == str(binary),
                    "Fault trace executed another process")
            execs.append(row)
        elif row["kind"] == "syscall-entry":
            entries[row["sequence"]] = row
        elif row["kind"] == "syscall-exit":
            start = row["entry"]
            require(start in entries and start not in exits
                    and entries[start]["tid"] == tid and entries[start]["nr"] == row["nr"],
                    "Fault syscall exit does not match its real entry")
            exits[start] = row
    require(not alive and {str(k): v for k, v in roster.items()} == stored,
            "Fault roster does not equal complete actual birth and terminal events")
    require(len(execs) == 1 and execs[0]["auxv"] == captured["auxv"],
            "Fault initial platform observation differs from actual exec")
    aux = captured["auxv"]
    if disabled:
        before = bytes.fromhex(aux["auxv_before_hex"])
        after = bytes.fromhex(aux["auxv_after_hex"])
        require(16 <= len(before) <= 2048 and len(before) % 16 == 0
                and len(after) == len(before)
                and aux.get("private_platform_fixture") is True
                and aux.get("normal_vdso_behavior_claimed") is False,
                "Raw-clock fixture lacks its complete private initial auxv")
        pairs = list(struct.iter_unpack("<QQ", before))
        selected = [index for index, pair in enumerate(pairs) if pair[0] == 33]
        require(len(selected) == 1 and pairs[-1] == (0, 0)
                and all(key != 0 for key, _ in pairs[:-1]),
                "Initial auxv does not contain one vDSO value and complete terminator")
        offset = selected[0] * 16 + 8
        expected = bytearray(before)
        expected[offset:offset+8] = bytes(8)
        value = pairs[selected[0]][1]
        require(value > 0 and aux["AT_SYSINFO_EHDR_before"] == value
                and aux["AT_SYSINFO_EHDR_after"] == 0 and after == bytes(expected)
                and int(aux["actual_vdso_mapping"].split("-", 1)[0], 16) == value
                and aux["actual_vdso_mapping"].endswith("[vdso]"),
                "Private platform fixture changed more than its one vDSO advertisement")
    else:
        require(aux == {"private_platform_fixture": False, "auxv_unchanged": True},
                "Normal vDSO baseline was changed")
    clocks = captured["actual_clock_calls"]
    starts = [start for start, entry in entries.items() if entry["nr"] == 228 and start in exits]
    require([row["entry"] for row in clocks] == sorted(starts, key=lambda n: exits[n]["sequence"]),
            "Actual original clock observations omit or reorder real calls")
    for row in clocks:
        entry, end = entries[row["entry"]], exits[row["entry"]]
        require(row["exit"] == end["sequence"] and row["tid"] == entry["tid"]
                and row["clock_id"] == entry["args"][0]
                and row["result"] == end["result"] and row["injected"] == entry.get("fault"),
                "Clock observation differs from its actual syscall")
        if row["result"] == 0:
            require(bytes.fromhex(row["timespec_hex"]) == struct.pack("<qq", row["seconds"], row["nanoseconds"]),
                    "Successful clock timespec observation differs")
    injections = captured["injections"]
    selected = {key for key, row in entries.items() if "fault" in row}
    require(len({row["entry"] for row in injections}) == len(injections)
            and {row["entry"] for row in injections} == selected
            and bool(injections) == bool(expected_fault),
            "Fault declaration differs from complete actual injected calls")
    kinds = set()
    for row in injections:
        entry, end = entries[row["entry"]], exits[row["entry"]]
        rule = row["rule"]; kinds.add(rule["kind"])
        require(row["tid"] == entry["tid"] and rule == entry["fault"]
                and rule.get("original_syscall_skipped") is True
                and row["actual_skipped_result"] == end["kernel_result_before_injection"] == -38
                and row["injected_result"] == end["result"]
                and row["role"] == entry["role"] and row["role_index"] == entry["role_index"],
                "Injected result differs from the actual selected syscall")
        if rule["kind"] == "clock":
            require(entry["nr"] == 228 and row["clock_id"] == entry["args"][0]
                    and row["role"] in expected_fault["clock_roles"]
                    and row["clock_ordinal"] == entry["role_clock_ordinal"] == expected_fault["clock_when"]
                    and rule["invalid_timespec"] == bool(expected_fault.get("clock_invalid"))
                    and (rule["invalid_timespec"] or rule["error"] == expected_fault["clock_error"]),
                    "Actual clock injection differs from the immutable fault definition")
        else:
            require(rule["kind"] == "clone" and entry["nr"] in (56, 435)
                    and row["role"] == expected_fault["clone_role"]
                    and row["spawn_ordinal"] == entry["role_spawn_ordinal"] == expected_fault["clone_when"]
                    and rule["error"] == 11,
                    "Actual clone injection differs from the immutable fault definition")
    requested = ({"clock"} if expected_fault and "clock_roles" in expected_fault else set()) | (
        {"clone"} if expected_fault and "clone_role" in expected_fault else set())
    require(kinds == requested, "A declared fault kind was not actually reached")
    return captured


def paid_binding(root, expected, repository=base.ROOT):
    from hia.platform.paid_cpu import rust_oracle as oracle
    from hia.platform.paid_cpu import fault_oracle as faults
    from hia.platform.paid_cpu.qualify import validate_bundle
    from hia.platform.paid_cpu.build import HERE

    observations = root / "hia-foundation-observations"
    before = base.check_source_observation(observations, expected)
    after = read(observations / "source-after.json")
    require(after == before, "Complete source-after identity differs from source-before")
    directory = root / "hia-paid-cpu-native"
    original_dir = root / "hia-paid-cpu-original"
    native = validate_bundle(directory, repository)
    original = read(original_dir / "report.json")
    require(original.get("schema") == "trnm.hia.paid-cpu-original-comparison.v1"
            and original.get("status") == "PASS" and original.get("source_after") == "MATCH"
            and original.get("binary_after") == "MATCH" and not original.get("failure"),
            "Actual original PaidCPU comparison did not pass")
    for flag in ("whole_paid_account_closed", "public_request_node_service_closed",
                 "complete_original_block_executor_executed", "original_production_source_changed"):
        require(original.get(flag) is False, "Finite PaidCPU scope changed")
    require(original.get("original_repository_modified") is False,
            "Original repository was modified")
    operation_count = budget_operations(native)
    for field, count in (("native_owner_histories", 6), ("actual_original_budget_calls", operation_count),
                         ("actual_original_boundary_cases", 67),
                         ("actual_original_owner_profiles", 5),
                         ("actual_original_fault_histories", 13),
                         ("retained_original_passed", 23)):
        require(type(original.get(field)) is int and original[field] == count,
                "Actual original PaidCPU coverage differs: " + field)
    require(len(native["owners"]) == 6 and native["actual_budget_operations"] == operation_count
            and len(native["boundaries"]) == 67 and len(native["faults"]) == 13
            and len(native["protocol_controls"]) == 40
            and len(native["trace_negative_controls"]) == 10,
            "Complete actual native PaidCPU coverage required")
    sources, originals = native["source_inputs"], native["original_sources"]
    require(original["source_inputs"] == sources and original["original_sources"] == originals
            and original["native_comparison"] == identity(directory / "native-comparison.json"),
            "Original run used another native/source bundle")
    require(all(sources[k] == originals[k] for k in sources.keys() & originals.keys()),
            "Overlapping original and native sources differ")
    base.check_committed_sources({**originals, **sources}, repository)
    source = read(original_dir / "source-before.json")
    require(identity(original_dir / "source-before.json") == original["source_before"]
            and source["source_inputs"] == sources and source["original_sources"] == originals
            and source["original_repository_head"] == expected["git_head"]
            and source["native_comparison"] == original["native_comparison"],
            "Original complete source-before capture differs")
    require(original["original_production_prefix"] == originals[oracle.ORIGINAL]
            and original["original_production_prefix"]["sha256"] == oracle.ORIGINAL_SHA
            and original["appended_private_cfg_test_child_hex"] == oracle.DECLARATION.hex()
            and original["private_reference_sha256"] == identity(HERE / "rust_reference.rs")["sha256"],
            "Original production prefix or private test child differs")
    abi = read(HERE / "abi.json")
    standard = original["standard_library"]
    tools = standard_binding(original, source, abi)
    from hia.platform.paid_cpu.dependency import captured_std, executable_interpreter
    require(captured_std() == standard, "Actual compiler/std/tool/host libraries changed after original execution")
    executable = original["executable"]
    binary = independent_executable(original_dir, original)
    require(executable_interpreter(binary, standard) == original["original_interpreter"],
            "Original actual ELF loader differs")
    labels = ["cargo-original-test-build", "list-original-tests",
              "retained-original-scalar-tests", "retained-original-flow-tests",
              "mandatory-original-linux-clocks", "actual-original-budget-replays",
              "actual-original-arithmetic-boundaries", "actual-original-real-scoped-profiles"]
    stages = settled_stages(original_dir, original, labels)
    require(stages[labels[0]]["argv"] == [tools["cargo_executable"]["path"],
            "test", "--locked", "--manifest-path",
            str(original_dir / "isolated-source/trillionnium/Cargo.toml"),
            "-p", "trnm-pon-node", "--lib", "--no-run", "--message-format=json",
            "--target-dir", str(root / "hia-paid-cpu-cargo-target")]
            and stages[labels[1]]["argv"] == [str(binary), "--list"],
            "Actual locked build or original test discovery differs")
    listed = (original_dir / labels[1] / "stdout.raw").read_text()
    tests = {line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test")}
    suffixes = ["linux_clocks_are_mandatory", "original_budget_trace_replays",
                "original_private_arithmetic_boundaries", "original_real_scoped_profiles",
                "original_actual_fault_profile"]
    require({oracle.PREFIX + suffix for suffix in suffixes} <= tests,
            "Actual original required tests were not linked")
    expected_groups = []
    for label, prefix in zip(labels[2:4], ("ingress::public_v3::scalar_cpu::tests::",
                                         "ingress::public_v3::scalar_cpu::flow_tests::"), strict=True):
        names = sorted(name for name in tests if name.startswith(prefix))
        require(names and stages[label]["argv"] ==
                [str(binary), prefix, "--nocapture", "--test-threads=1"],
                "Actual retained original group command differs")
        output = (original_dir / label / "stdout.raw").read_text()
        for name in names:
            require(re.search(r"(?m)^test " + re.escape(name) + r" \.\.\.", output),
                    "Retained original test did not execute")
        require(re.search(r"test result: ok\. " + str(len(names)) +
                          r" passed; 0 failed; 0 ignored;", output),
                "Actual retained original group summary differs")
        expected_groups.append({"prefix": prefix, "names": names, "passed": len(names)})
    require(expected_groups == original["retained_original_tests"]
            and sum(g["passed"] for g in expected_groups) == 23,
            "All twenty-three retained original tests required")
    outputs = {}
    for label, suffix in zip(labels[4:], suffixes[:4], strict=True):
        name = oracle.PREFIX + suffix
        argv = stages[label]["argv"]
        expected_test = [str(binary), "--exact", name, "--nocapture", "--test-threads=1"]
        require(argv == expected_test if label != labels[-1] else
                len(argv) == 14 and argv[1:7] == ["-f", "-qq", "-v", "-s", "65536", "-o"]
                and argv[7] == str(original_dir / "actual-original-scoped-clocks.trace")
                and argv[-len(expected_test):] == expected_test
                and argv[-len(expected_test)-1] == "--",
                "Actual named original command differs")
        raw = (original_dir / label / "stdout.raw").read_bytes()
        positive_test(raw, name)
        outputs[label] = oracle.records(raw)
    positive = outputs[labels[4]]
    require(len(positive) == 1 and positive[0] == original["mandatory_original_linux_positive"]
            and positive[0]["kind"] == "linux-positive"
            and positive[0]["clock_failure_cannot_skip"] is True,
            "Mandatory actual original clock control did not execute")
    cases = [{"label": row["name"], "plan": row["plan"], **row["trace"]["replay"]}
             for row in native["owners"]]
    input_value = {
        "schema": "trnm.hia.paid-cpu-original-replay.v1", "cases": cases,
        "boundaries": read(directory / "cases.json")["boundaries"],
        "native_public_abi_accepts_counters": False,
        "full_node_or_public_intake_closed": False}
    require(read(original_dir / "inputs.json") == input_value
            and identity(original_dir / "inputs.json") == original["input"] == source["input"],
            "Actual original replay/counter fixture input differs")
    replay = outputs[labels[5]]
    require([row["label"] for row in replay] == [row["label"] for row in cases],
            "Actual original replay order differs")
    comparisons = []
    for actual, case in zip(replay, cases, strict=True):
        expected_operations = [oracle.expected_operation(event, i)
                               for i, event in enumerate(case["operations"])]
        require(actual["kind"] == "budget-replay" and actual["operations"] == expected_operations
                and actual["final"] == case["expected_final"],
                "Actual original budget methods differ from complete native trace")
        comparisons.append({"label": case["label"], "status": "PASS", "actual_original": actual,
                            "expected_native_final": case["expected_final"],
                            "expected_native_operation_results": expected_operations})
    require(read(original_dir / "budget-comparison.json") == {"cases": comparisons}
            and original["budget_comparisons"] == comparisons,
            "Original budget comparison does not equal captured stdout")
    boundaries = []
    require([row["name"] for row in outputs[labels[6]]] ==
            [row["name"] for row in native["boundaries"]], "Actual original boundary order differs")
    for actual, native_row in zip(outputs[labels[6]], native["boundaries"], strict=True):
        require(actual["kind"] == "private-boundary"
                and actual["original_complete_methods_executed"] is True
                and actual["production_runtime_counter_abi"] is False
                and actual["comparison"] == native_row["comparison"],
                "Actual original private arithmetic boundary differs")
        boundaries.append({"name": actual["name"], "status": "PASS", "actual_original": actual,
                           "actual_native": native_row["comparison"]})
    require(read(original_dir / "boundary-comparison.json") == {"cases": boundaries}
            and original["boundary_comparisons"] == boundaries,
            "Original arithmetic comparison does not equal captured stdout")
    warm = [case for case in cases if not case["cold"]]
    observed = outputs[labels[7]]
    require([row["label"] for row in observed] == [row["label"] for row in warm],
            "Actual original scoped profiles omitted or reordered")
    scopes = [oracle.compare_real(actual, case, directory)
              for actual, case in zip(observed, warm, strict=True)]
    require(scopes == original["actual_original_real_profiles"]
            and read(original_dir / "real-scope-comparison.json") == {"cases": scopes},
            "Original actual scope comparison differs")
    trace = original_dir / "actual-original-scoped-clocks.trace"
    trace_record = original["actual_original_trace"]
    require(trace_record["path"] == str(trace)
            and identity(trace) == {k: trace_record[k] for k in ("bytes", "sha256")},
            "Actual original scoped clock trace differs")
    clock_rows = re.findall(r"^(\d+)[ \t]+clock_gettime\(CLOCK_THREAD_CPUTIME_ID,",
                            trace.read_text(), re.M)
    require(len(set(clock_rows)) >= 8 and len(clock_rows) == trace_record["direct_clock3_call_starts"]
            and sorted(set(map(int, clock_rows))) == trace_record["actual_clock3_tids"]
            and trace_record["complete_original_runtime_syscall_whitelist_claimed"] is False,
            "Actual original working-thread clock observations differ")
    fault_root = original_dir / "fault-differential"
    fault_report = read(fault_root / "report.json")
    expected_fault_record = {"path": str(fault_root / "report.json"),
        **identity(fault_root / "report.json"), "status": "PASS", "cases": 13,
        "private_no_vdso_platform_fixture": True}
    require(original["actual_original_faults"] == expected_fault_record
            and fault_report.get("schema") == "trnm.hia.paid-cpu-actual-original-fault-differential.v1"
            and fault_report.get("status") == "PASS"
            and fault_report.get("source_after") == "MATCH"
            and fault_report.get("executable_after") == "MATCH"
            and fault_report.get("source_before") == sources
            and fault_report.get("executable_before") == {k: executable[k] for k in ("bytes", "sha256")}
            and all(fault_report.get(key) is False for key in (
                "whole_paid_account_closed", "request_node_service_closed", "complete_original_block_executor")),
            "Actual original fault outcome, source, binary or finite scope differs")
    from hia.platform.paid_cpu.cases import original_fault_cases
    definitions = original_fault_cases()
    require([row["name"] for row in fault_report["cases"]] ==
            [row["name"] for row in definitions] and len(definitions) == 13,
            "All thirteen actual original fault cases required")
    require([row["label"] for row in fault_report["baselines"]] ==
            ["normal-vdso-baseline", "raw-fallback-baseline"],
            "Both actual original clock-platform baselines required")
    binary_value = {k: executable[k] for k in ("bytes", "sha256")}
    constructor_final = None
    for row in fault_report["baselines"]:
        folder = fault_root / row["label"]
        captured = read(folder / "report.json")
        disabled = row["label"] == "raw-fallback-baseline"
        fault_capture(folder, captured, binary, binary_value, None, disabled)
        require(identity(folder / "report.json") == row["trace_report"]
                and faults.observation(folder) == row["observation"]
                and faults.role_validation(captured, folder) == row["actual_roles"]
                and row["clock1_syscalls"] == sum(c["clock_id"] == 1 for c in captured["actual_clock_calls"])
                and row["clock3_syscalls"] == sum(c["clock_id"] == 3 for c in captured["actual_clock_calls"]),
                "Actual original normal/raw-fallback baseline differs")
        if disabled:
            clocks = [c for c in captured["actual_clock_calls"] if c["role"] == 1 and c["clock_id"] == 1]
            require(clocks and all(c["result"] == 0 for c in clocks),
                    "Complete actual original constructor clock baseline required")
            constructor_final = clocks[-1]["role_clock_ordinal"]
    require(type(constructor_final) is int and constructor_final > 0
            and fault_report["constructor_final_clock_ordinal"] == constructor_final,
            "Constructor fault target differs from its actual raw baseline")
    previous_bundle = faults.BUNDLE
    try:
        faults.BUNDLE = directory
        for row, case in zip(fault_report["cases"], definitions, strict=True):
            folder = fault_root / case["name"]
            observed = faults.observation(folder)
            captured = read(folder / "report.json")
            requested = {key: value for key, value in case.items() if key not in ("name", "workers", "txs")}
            if requested.get("clock_when") == "constructor-final":
                requested["clock_when"] = constructor_final
            fault_capture(folder, captured, binary, binary_value, requested, True)
            expected_row = faults.compare(case["name"], observed, faults.native_case(case["name"]),
                                          captured, folder)
            require(expected_row == row == read(folder / "comparison.json"),
                    "Actual original fault trace/comparison differs")
    finally:
        faults.BUNDLE = previous_bundle
    dependency = original["locked_clock_dependency"]
    crate = original_dir / ("locked-rustix-" + dependency["version"] + ".crate")
    require(dependency["status"] == "PASS" and dependency["package_checksum_matches_lock"] is True
            and dependency["all_crate_regular_files_match_compiled_registry"] is True
            and identity(crate) == {k: dependency["crate"][k] for k in ("bytes", "sha256")}
            and identity(crate) == {k: original["retained_clock_dependency_crate"][k]
                                   for k in ("bytes", "sha256")},
            "Actual original locked clock dependency differs")
    return {
        "source_inputs": sources, "source_set_sha256": base.object_hash(sources),
        "original_source_set_sha256": base.object_hash(originals),
        "source_observations": {"before": before, "after": after,
                                "before_file": identity(observations / "source-before.json"),
                                "after_file": identity(observations / "source-after.json")},
        "native_comparison": identity(directory / "native-comparison.json"),
        "original_report": identity(original_dir / "report.json"),
        "native_images": {name: {k: row[k] for k in ("bytes", "sha256")}
                          for name, row in native["build"]["images"].items()},
        "native_owner_histories": 6, "native_budget_operations": operation_count,
        "native_arithmetic_boundaries": 67, "native_fault_histories": 13,
        "native_protocol_refusals": 40, "native_trace_refusals": 10,
        "actual_original_budget_calls": operation_count, "actual_original_boundary_cases": 67,
        "actual_original_owner_profiles": 5, "actual_original_fault_histories": 13,
        "retained_original_passed": 23, "mandatory_original_linux_clock": True,
        "original_executable": {k: executable[k] for k in ("bytes", "sha256")},
        "persistent_paid_account_qualified": False,
        "original_service_budget_qualified": False, "full_node_qualified": False}
