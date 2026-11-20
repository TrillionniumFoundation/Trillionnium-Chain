"""Fresh complete original gate plus public and append-only private observers."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import time
import traceback

from hia.platform.peer_lease_unix.original_build import Original, PROFILE, cargo_events
from hia.platform.peer_lease_unix.process import Processes
from .contract import ROOT, HERE, capture, identity, need

APPEND_LIB = b"\npub use payload::qualification_payload_codec_v1;\n"
LIBRARIES = ("trnm_peer_lease", "fs2", "libc", "rustix", "sha2")


def selected_libraries(events):
    result = {}
    for name in LIBRARIES:
        rows = [event for event in events if event["target"]["name"] == name
                and not event["profile"]["test"]
                and any(path.endswith(".rlib") for path in event["filenames"])]
        expected_profile = {**PROFILE, "opt_level": "3"} if name == "sha2" else PROFILE
        need(len(rows) == 1 and rows[0]["profile"] == expected_profile,
             "Original dependency/profile not unique: " + name)
        event = rows[0]
        paths = [path for path in event["filenames"] if path.endswith(".rlib")]
        need(len(paths) == 1, "Multiple original rlibs: " + name)
        if name == "trnm_peer_lease":
            need(event["manifest_path"] == str(ROOT / "trillionnium/crates/trnm-peer-lease/Cargo.toml")
                 and set(event["features"]) == {"default", "candidate-recovery-socket"},
                 "Original public library features changed")
        result[name] = {"path": paths[0], "cargo_event": event, **identity(capture(paths[0]))}
    return result


def commands(output, tools, libraries, dependencies):
    output = Path(output)
    common = [tools["rustc"]["path"], "--edition=2021", "-C", "opt-level=0", "-C", "debuginfo=2",
              "-C", "debug-assertions=yes", "-C", "overflow-checks=yes"]
    for directory in dependencies:
        common += ["-L", "dependency=" + directory]
    external = []
    for name in LIBRARIES[1:]:
        external += ["--extern", name + "=" + libraries[name]["path"]]
    return {
        "observer-rustfmt": [tools["rustfmt"]["path"], "--edition", "2021", "--check",
            str(HERE / "public_reference.rs"), str(HERE / "metadata_reference.rs"),
            str(HERE / "metadata_reference_hook.rs")],
        "public-observer": [*common, "--crate-name", "payload_public_observer", "--extern",
            "trnm_peer_lease=" + libraries["trnm_peer_lease"]["path"], str(HERE / "public_reference.rs"),
            "-o", str(output / "public-reference.elf")],
        "private-library": [*common, "--crate-name", "trnm_peer_lease", "--crate-type", "rlib",
            "--cfg", 'feature="candidate-recovery-socket"', "--cfg", 'feature="default"', *external,
            str(output / "private-source/src/lib.rs"), "-o", str(output / "libpayload_private_reference.rlib")],
        "private-observer": [*common, "--crate-name", "payload_metadata_observer", "--extern",
            "trnm_peer_lease=" + str(output / "libpayload_private_reference.rlib"), str(HERE / "metadata_reference.rs"),
            "-o", str(output / "metadata-reference.elf")],
    }


def run(output, check):
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink(), "Original output must be fresh")
    output.mkdir(mode=0o700)
    report = {"schema": "trnm.hia.payload-metadata-original.v1", "status": "FAIL",
              "reused_prior_execution": False, "public_observer_links_unchanged_original": True,
              "private_observer_original_functions_replaced": False}
    processes = None
    started = time.monotonic_ns()
    try:
        original = Original(output / "complete", check)
        complete = original.build()
        report["complete_report"] = identity(capture(output / "complete/build.json"))
        events = cargo_events(capture(output / "complete/processes/retained-original-tests/stdout.raw"))
        libraries = selected_libraries(events)
        report["libraries"] = libraries
        dependencies = sorted({str(Path(path).parent) for event in events
                               for path in event["filenames"] if path.endswith((".rlib", ".rmeta"))})
        report["dependencies"] = dependencies
        source = ROOT / "trillionnium/crates/trnm-peer-lease"
        target = output / "private-source"
        target.mkdir(mode=0o700)
        instrumentation = {}
        for path in sorted(source.rglob("*")):
            if path.is_dir():
                need(not path.is_symlink(), "Linked original source directory")
                continue
            raw = capture(path)
            relative = path.relative_to(source).as_posix()
            changed = raw
            if relative == "src/payload.rs":
                changed += b"\n" + capture(HERE / "metadata_reference_hook.rs")
            elif relative == "src/lib.rs":
                changed += APPEND_LIB
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(changed)
            instrumentation[relative] = {"original": identity(raw), "observed": identity(changed),
                                         "appended_test_hook": changed != raw}
        report["instrumentation"] = instrumentation
        processes = Processes(output / "processes", ROOT, original.environment, check)
        for name, argv in commands(output, complete["tools"], libraries, dependencies).items():
            processes.run(name, argv, timeout=30)
        report["public_reference"] = {"path": "public-reference.elf", **identity(capture(output / "public-reference.elf"))}
        report["private_reference"] = {"path": "metadata-reference.elf", **identity(capture(output / "metadata-reference.elf"))}
        report["private_library"] = {"path": "libpayload_private_reference.rlib", **identity(capture(output / "libpayload_private_reference.rlib"))}
        for row in libraries.values():
            need(identity(capture(row["path"])) == {key: row[key] for key in ("bytes", "sha256")},
                 "Fresh original dependency changed during observer compilation")
        check()
        report.update(status="PASS", source_inputs_stable=True, retained_tests=complete["retained_tests"],
                      complete_original_tests_preserved=True)
        return report
    except BaseException as error:
        report.update(failure=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        report["stages"] = processes.rows if processes else []
        report["elapsed_ns"] = time.monotonic_ns() - started
        (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
