"""Re-read actual process bytes; never infer runtime success from counters."""
from collections import Counter
from pathlib import Path
import re
import struct

from .build import canonical, decode, exact, identity, need, read


GROUPS = {"api": 208, "recovery": 151, "files": 111, "cli": 23,
          "unix": 168, "crash": 131}
KINDS = {"api-pair": 675, "cli-pair": 31, "adversarial-peer": 45,
         "daemon-wire": 12, "daemon-deadline": 2, "daemon-live-rollback": 2,
         "saturated-lease": 2, "durability-boundary": 23}
METHODS = {1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
           30, 31, 32, 33, 34, 35, 36, 37, 38, 40, 41, 42, 43, 44, 45, 50, 60, 62}
CRASH = ("journal-write", "journal-fdatasync", "journal-directory-fdatasync",
         "head-write", "head-fsync", "head-rename", "head-directory-fdatasync",
         "ledger-record-write", "ledger-record-fsync", "ledger-record-rename",
         "ledger-record-directory-fsync", "ledger-head-write", "ledger-head-fsync",
         "ledger-head-rename", "ledger-head-directory-fsync")
FAULT = ("journal-fdatasync", "journal-directory-fdatasync", "head-fsync", "head-rename",
         "ledger-record-fsync", "ledger-record-directory-fsync", "ledger-head-fsync", "ledger-head-rename")


def hex_bytes(value):
    need(isinstance(value, str) and re.fullmatch("(?:[0-9a-f]{2})*", value) is not None,
         "Noncanonical observed hex bytes")
    return bytes.fromhex(value)


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, "Expected an exact nonnegative integer")
    return value


def requests(raw):
    result = []
    while raw:
        need(len(raw) >= 32 and raw[:8] == b"HCSAPI01", "Incomplete saved API request")
        op, size, reserved = struct.unpack("<3Q", raw[8:32])
        need(reserved == 0 and size <= len(raw) - 32, "Invalid saved API request envelope")
        result.append((op, raw[32:32 + size]))
        raw = raw[32 + size:]
    return result


def responses(raw):
    result = []
    while raw:
        need(len(raw) >= 48 and raw[:8] == b"HCSAPO01", "Incomplete saved API response")
        header = list(struct.unpack("<5Q", raw[8:48]))
        need(header[0] in (0, 1, 2) and header[3] <= len(raw) - 48, "Invalid saved API response envelope")
        result.append({"header": header, "body": raw[48:48 + header[3]].hex()})
        raw = raw[48 + header[3]:]
    return result


def evidence_manifest(directory):
    """The files/ tree deliberately contains hostile symlinks and FIFOs.

    Inventory only controller evidence. Never follow or read test storage as
    an evidence file; every admitted controller path is regular and canonical.
    """
    result = {}
    for child in sorted(directory.iterdir()):
        if child.name in ("files", "runtime.json"):
            continue
        need(not child.is_symlink(), "Symlinked runtime evidence")
        paths = sorted(child.rglob("*")) if child.is_dir() else [child]
        for path in paths:
            need(not path.is_symlink(), "Symlinked runtime evidence")
            if path.is_dir():
                continue
            name = path.relative_to(directory).as_posix()
            result[name] = identity(read(directory, name))
    return result


def validate_runtime(directory, expected_binaries):
    directory = Path(directory).absolute()
    need(directory.resolve(strict=True) == directory and not directory.is_symlink(),
         "Canonical runtime evidence directory required")
    report = decode(read(directory, "runtime.json"))
    need(report["schema"] == "trnm.hia.checkpoint-store-runtime.v1" and report["status"] == "PASS"
         and report["failure"] is None and report["cleanup_failures"] == []
         and report["power_failure_claimed"] is False and report["whole_node_replacement"] is False,
         "Incomplete runtime observation")
    need(exact(report["binaries"], expected_binaries), "Runtime executable identities differ")
    need(exact(report["files"], evidence_manifest(directory)), "Actual runtime evidence inventory differs")
    rows = decode(read(directory, "observations.json"))
    need(exact(identity(read(directory, "observations.json")), report["observations"])
         and len(rows) == sum(GROUPS.values()) == 792, "Incomplete runtime observation roster")
    need(exact(dict(Counter(row["kind"] for row in rows)), KINDS), "Runtime comparison families differ")
    expected_groups = []
    for group, count in GROUPS.items():
        expected_groups.extend([group] * count)
    need([row["group"] for row in rows] == expected_groups
         and exact([row["ordinal"] for row in rows], list(range(len(rows))))
         and all(row["status"] == "PASS" for row in rows), "Runtime group order or outcome differs")
    roots = report["paths"]
    for name, value in roots.items():
        path = Path(value)
        need(path.is_absolute() and path.as_posix() == value and ".." not in path.parts,
             "Noncanonical captured runtime path: " + name)
    need(set(roots) == {"output", "native_api", "native_cli", "original_api", "original_cli"},
         "Runtime invocation boundary differs")
    process_cache, used, cli_used, daemons = {}, set(), set(), set()

    def process(folder):
        need(re.fullmatch(r"process-[0-9]+", folder) is not None, "Invalid API process evidence path")
        if folder in process_cache:
            return process_cache[folder]
        receipt = decode(read(directory, folder + "/receipt.json"))
        roles = [kind for kind in ("native", "original")
                 if receipt["argv"] == [roots[kind + "_api"]]]
        need(len(roles) == 1, "API process was not the selected executable")
        role = roles[0]
        expected = expected_binaries[role + "_api"]
        need(exact(receipt["executable_before"], expected) and exact(receipt["executable_after"], expected)
             and type(receipt["exit_code"]) is int and receipt["exit_code"] == 0
             and receipt["cleanup"] is None, "API process failed or changed its executable")
        for stream in ("stdin", "stdout", "stderr"):
            need(exact(identity(read(directory, folder + "/" + stream + ".raw")), receipt[stream]),
                 "API process raw stream differs")
        need(read(directory, folder + "/stderr.raw") == b"", "API process emitted diagnostics")
        ins = requests(read(directory, folder + "/stdin.raw"))
        outs = responses(read(directory, folder + "/stdout.raw"))
        need(len(ins) == len(outs) and all(a[0] == b["header"][4] for a, b in zip(ins, outs)),
             "API request/response coverage differs")
        process_cache[folder] = role, ins, outs
        return process_cache[folder]

    def actual_call(folder, index, op, body, observed, role=None):
        actual_role, ins, outs = process(folder)
        index = integer(index, 1)
        key = folder, index
        need(key not in used and index <= len(ins), "Duplicate or missing observed API call")
        used.add(key)
        need((role is None or role == actual_role) and ins[index - 1] == (op, body)
             and exact(outs[index - 1], observed), "API comparison differs from actual process bytes")
        return observed

    def cli(folder, observed, role):
        need(re.fullmatch(r"cli-[0-9]+-" + role, folder) is not None and folder not in cli_used,
             "Duplicate or noncanonical CLI process")
        cli_used.add(folder)
        receipt = decode(read(directory, folder + "/receipt.json"))
        need(receipt["argv_hex"] and hex_bytes(receipt["argv_hex"][0]) == roots[role + "_cli"].encode()
             and exact(receipt["executable"], expected_binaries[role + "_cli"])
             and receipt["cleanup"] is None and exact(receipt["result"], observed),
             "CLI process identity or result differs")
        need(type(observed["exit"]) is int and observed["exit"] in (0, 1, 64), "Unexpected original CLI exit")
        for stream in ("stdout", "stderr"):
            need(read(directory, folder + "/" + stream + ".raw") == hex_bytes(observed[stream]),
                 "CLI comparison differs from actual raw stream")

    def daemon(folder):
        need(re.fullmatch(r"daemon-[0-9]+", folder) is not None, "Invalid daemon process path")
        receipt = decode(read(directory, folder + "/receipt.json"))
        role = next((role for role in ("native", "original")
                     if receipt["argv"][0] == roots[role + "_cli"]), None)
        need(role is not None and exact(receipt["executable"], expected_binaries[role + "_cli"]),
             "Daemon executable differs")
        argv = receipt["argv"]
        need((argv[1] == "register-new" and len(argv) == 4)
             or (argv[1] == "reopen" and len(argv) == 5), "Daemon invocation differs")
        if argv[1] == "reopen":
            need(argv[4] == str(Path(roots["output"]) / folder / "independent-pin.raw")
                 and len(read(directory, folder + "/independent-pin.raw")) == 84,
                 "Daemon independently supplied pin is missing")
        for stream in ("stdout", "stderr"):
            need(exact(identity(read(directory, folder + "/" + stream + ".raw")), receipt[stream]),
                 "Daemon raw stream differs")
        need(type(receipt["exit_code"]) is int, "Noninteger daemon exit")
        if receipt["cleanup"] is None:
            need(receipt["exit_code"] == 1 and read(directory, folder + "/stderr.raw"),
                 "Daemon integrity refusal did not terminate")
        else:
            need(exact(receipt["cleanup"], {"signal": "SIGKILL", "intentional_daemon_stop": True})
                 and receipt["exit_code"] == -9, "Daemon cleanup was not the explicit test stop")
        daemons.add(folder)
        return receipt

    saturated = []
    boundaries = set()
    for row in rows:
        kind = row["kind"]
        if kind == "api-pair":
            op = integer(row["op"])
            for role in ("native", "original"):
                actual_call(row[role + "_process"], row[role + "_call"], op,
                            hex_bytes(row[role + "_input"]), row[role], role)
            a, b = row["native"], row["original"]
            need(type(row["normalize_path"]) is bool, "Invalid comparison normalization")
            if row["normalize_path"]:
                need(op in (13, 32) and a["header"][0] == b["header"][0] == 0,
                     "Unpermitted path comparison normalization")
                normalized = []
                for role, value in (("native", a), ("original", b)):
                    root = str(Path(roots["output"]) / "files" / (row["case"] + "-" + role))
                    need(row[role + "_root"] == root, "Accessor comparison root differs")
                    raw = hex_bytes(value["body"])
                    need(raw.startswith(root.encode() + b"/"), "Accessor returned another path")
                    raw = raw.replace(root.encode(), b"$ROOT")
                    header = [*value["header"][:3], len(raw), value["header"][4]]
                    normalized.append({"header": header, "body": raw.hex()})
                a, b = normalized
            need(exact(a, b), "Actual original/native method results differ")
            if row["label"] == "partial-deadline":
                need(all(170_000_000 < integer(row[role + "_elapsed_ns"]) < 320_000_000
                         for role in ("native", "original")), "Client elapsed deadline differs")
        elif kind == "cli-pair":
            for role in ("native", "original"):
                cli(row[role + "_process"], row[role], role)
            need(exact(row["native"], row["original"]), "Actual original/native CLI results differ")
        elif kind == "adversarial-peer":
            need(len(row["sessions"]) == 2, "Fresh client socket pair is missing")
            need(row["sessions"][0]["request_hex"] == row["sessions"][1]["request_hex"],
                 "Native/original client requests differ")
            for session in row["sessions"]:
                raw = hex_bytes(session["request_hex"])
                need((row["case"] == "zero-timeout" and not raw)
                     or (len(raw) >= 4 and int.from_bytes(raw[:4], "big") == len(raw) - 4),
                     "Adversarial peer did not observe a complete bounded request")
                for send in session["sends"]:
                    hex_bytes(send["data_hex"])
                    need(send["result"] in ("sent", "BrokenPipeError", "ConnectionResetError"),
                         "Adversarial peer send did not complete")
        elif kind == "daemon-wire":
            daemon(row["daemon"])
            index = int(row["case"].rsplit("-", 1)[1])
            malformed = ((bytes(4), b""), (struct.pack(">I", 4097), b""),
                         (b"\0\0\0\1x", b"\0\0\0\10CP2S\2\7\0\0"),
                         (struct.pack(">I", 4096) + b"x" * 4096, b"\0\0\0\10CP2S\2\7\0\0"),
                         (b"\0\0", b""), (struct.pack(">I", 10) + b"partial", b""))
            need(0 <= index < len(malformed)
                 and (hex_bytes(row["request_hex"]), hex_bytes(row["response_hex"])) == malformed[index],
                 "Daemon malformed-frame result differs")
        elif kind == "daemon-deadline":
            daemon(row["daemon"])
            need(type(row["elapsed_seconds"]) in (float, int) and 4.5 <= row["elapsed_seconds"] < 7.5
                 and row["response_hex"] == "", "Daemon restarted the elapsed frame budget")
        elif kind == "daemon-live-rollback":
            receipt = daemon(row["daemon"])
            role, ins, outs = process(row["process"])
            index = integer(row["call"], 1)
            need(index <= len(ins), "Missing rollback client call")
            actual_call(row["process"], index, 34, ins[index - 1][1], row["result"], "native")
            need(row["result"]["header"][0] == 1
                 and b"unexpected load response" in hex_bytes(row["result"]["body"])
                 and row["exit_code"] == receipt["exit_code"] == 1, "Rollback returned a cached value")
            actions = row["mixed_client_actions"]
            need(len(actions) == 4 and [a["op"] for a in actions] == [35, 35, 37, 37],
                 "Mixed client checked/trait operations are missing")
            for action, client in zip(actions, ("original", "native", "original", "native"), strict=True):
                value = {"header": action["header"], "body": action["body"]}
                actual_call(action["process"], action["call"], action["op"], hex_bytes(action["input"]), value, client)
                need(action["header"][0] == 0, "Mixed client mutation was refused")
        elif kind == "saturated-lease":
            cli(row["process"], row["result"], row["case"])
            need(integer(row["queued_connections"], 1) <= 64 and row["result"]["exit"] == 1
                 and b"lock checkpoint socket owner" in hex_bytes(row["result"]["stderr"]),
                 "Saturated live socket was replaced")
            saturated.append(row["result"])
        elif kind == "durability-boundary":
            need(row["case"] not in boundaries, "Duplicate durability boundary")
            boundaries.add(row["case"])
            validate_boundary(directory, row, roots, expected_binaries)
        else:
            raise ValueError("Unknown runtime observation family")
    need(exact(saturated[0], saturated[1]), "Saturated socket refusal differs")
    need(boundaries == {"crash-" + name for name in CRASH} | {"eio-" + name for name in FAULT},
         "Complete actual crash/fault boundary roster differs")
    folders = {p.name for p in directory.iterdir() if p.is_dir() and re.fullmatch(r"process-[0-9]+", p.name)}
    for folder in folders:
        process(folder)
    all_calls = {(folder, index) for folder, (_, ins, _) in process_cache.items() for index in range(1, len(ins) + 1)}
    need(all_calls == used and len(used) == 1360, "Actual API process calls were omitted or duplicated")
    need({op for _, ins, _ in process_cache.values() for op, _ in ins} == METHODS,
         "Complete original public method comparison roster differs")
    actual_cli = {p.name for p in directory.iterdir() if p.is_dir() and p.name.startswith("cli-")}
    need(actual_cli == cli_used and len(cli_used) == 64, "CLI process evidence was omitted")
    actual_daemons = {p.name for p in directory.iterdir() if p.is_dir() and p.name.startswith("daemon-")}
    for folder in actual_daemons:
        daemon(folder)
    need(daemons == actual_daemons and len(daemons) == 10, "Production daemon execution roster differs")
    return report


def validate_boundary(directory, row, roots, binaries):
    fault = row["case"].startswith("eio-")
    target = row["case"][4:] if fault else row["case"][6:]
    need(row["fault_injected"] is fault and row["power_failure_claimed"] is False
         and exact(row["disk_at_boundary"][0], row["disk_at_boundary"][1]),
         "Crash observation or explicit fault mode differs")
    outputs, actions = [], []
    for role in ("native", "original"):
        folder = row["case"] + "-" + role
        trace = decode(read(directory, folder + "/trace.json"))
        expected = binaries[role + "_api"]
        storage = Path(roots["output"]) / "files" / folder
        if target.startswith("ledger-"):
            storage /= "state"
        need(trace["schema"] == "trnm.checkpoint-store-owned-process-trace.v1"
             and trace["status"] == "PASS" and trace["failure"] is None
             and "supervisor_cleanup" not in trace and trace["target"] == target
             and trace["storage"] == str(storage) and trace["fault_injected"] is fault
             and trace["power_failure_claimed"] is False
             and trace["executable"] == roots[role + "_api"]
             and exact(trace["executable_before"], expected) and exact(trace["executable_after"], expected),
             "Owned durability child identity or terminal observation differs")
        for stream, label in (("stdin", "input"), ("stdout", "stdout"), ("stderr", "stderr")):
            need(exact(identity(read(directory, folder + "/" + stream + ".raw")), trace[label]),
                 "Actual traced process bytes differ")
        need(read(directory, folder + "/stderr.raw") == b"", "Traced child emitted diagnostics")
        ops = [op for op, _ in requests(read(directory, folder + "/stdin.raw"))]
        need(ops == ([40, 43, 42, 44, 45] if target.startswith("ledger-") else [11, 17, 16, 14, 19]),
             "Durability child command roster differs")
        events = trace["events"]
        need(exact([event["sequence"] for event in events], list(range(1, len(events) + 1)))
             and events[0]["kind"] == "initial-wait" and events[-1]["kind"] == "terminal"
             and sum(event["kind"] == "exec" and event["actual"] == roots[role + "_api"] for event in events) == 1,
             "Actual syscall trace sequence differs")
        need(len(trace["actions"]) == 1, "Durability action was missing or repeated")
        action = trace["actions"][0]
        entry_number = integer(action["entry"], 1)
        need(entry_number <= len(events), "Selected syscall entry is absent")
        entry = events[entry_number - 1]
        exits = [event for event in events if event["kind"] == "exit" and event["entry"] == entry_number]
        need(entry["kind"] == "entry" and entry["storage_stage"] == target and len(exits) == 1
             and exits[0]["nr"] == entry["nr"] and exits[0]["storage_stage"] == target
             and action["stage"] == target, "Action is not bound to its actual syscall")
        expected_nr = 1 if target.endswith("write") else 82 if target.endswith("rename") else 75 if target.endswith("fdatasync") else 74
        need(entry["nr"] == expected_nr, "Crash boundary selected the wrong kernel operation")
        if fault:
            need(action["kind"] == "injected-EIO" and action["kernel_result"] == -38 and action["result"] == -5
                 and entry["injected_eio"] is True and exits[0]["kernel_result"] == -38
                 and exits[0]["result"] == -5 and type(trace["exit_code"]) is int
                 and trace["exit_code"] == 0 and trace["signal"] is None,
                 "Explicit injected EIO was not observed")
        else:
            need(action["kind"] == "SIGKILL-after-real-syscall" and action["exit"] == exits[0]["sequence"]
                 and exits[0]["result"] >= 0 and exits[0]["result"] == exits[0]["kernel_result"]
                 and trace["exit_code"] is None and trace["signal"] == 9,
                 "Crash cut was not after a real successful syscall")
        output = read(directory, folder + "/stdout.raw")
        values = responses(output)
        need(len(values) == (5 if fault else 1) and values[0]["header"][0] == 0,
             "Crash cut passed the mutation acknowledgement")
        if fault:
            need(values[1]["header"][0] == 1, "Injected mutation failure reported success")
        outputs.append(output.hex())
        actions.append(trace["actions"])
    need(exact(actions, row["actions"]) and outputs == [row["native_output"], row["original_output"]]
         and outputs[0] == outputs[1], "Actual native/original durability results differ")
