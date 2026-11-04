#!/usr/bin/env python3
"""Read one immutable DA diagnostic artifact; execute no archived code."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "qualification/original-artifact-readback-20261104/readback.py"
HELPER_BLOB = "f81cf081b20cd0b652b4b09f4591aa05305c050e"
BRANCH = "refs/heads/research/chain-da-sequence-readback-20261104-gpt6"
SPEC = {
    "artifact_id": 13295132077,
    "artifact_name": "da-sequence-diagnostic-e5adb2df25db655800f9e52806e91b427d734490-1",
    "run_id": 41771237697,
    "bytes": 61541,
    "sha256": "af855c28548c7cd9e31c545194285285aed40255d31e416133107652c4fd3bef",
    "source": "e5adb2df25db655800f9e52806e91b427d734490",
    "tree": "2bb9f0f3718891ba1df19087a2fa8b96e19bf05b",
}
DECODED_LIMIT = 4 * 1024 * 1024
MEMBER_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 128 * 1024
WANTED = ("source-before.json", "source-after.json", "receipt.json",
          "registry.log", "original-module.log")


ERROR_CODES = frozenset({
    "FROZEN_NETWORK_HELPER", "NAME_RESULT_COUNT", "TEST_IDENTIFIER_SHAPE",
    "READ_ONLY_JOB_SCOPE", "OUTSIDE_SOURCE", "ADDRESS_SPACE_AVAILABLE",
    "READ_TOKEN_REQUIRED", "MEMBER_COUNT", "MEMBER_BYTE_LIMIT",
    "RETURNED_DECODED_LIMIT", "AMBIGUOUS_REQUIRED_MEMBER", "DECODED_SIZE",
    "REQUIRED_LOGS", "ORIGINAL_SOURCE_BINDING", "RECEIPT_SOURCE_BINDING",
    "EXACT_COMMANDS", "ACTUAL_LOG_DIGEST_BINDING", "ORIGINAL_REGISTRY_SIZE",
    "OUTPUT_BYTES", "OUTCOME_FLAG_TYPE", "EXIT_CODE_TYPE_OR_RANGE",
    "READER_CONTROL_FAILED",
})


class ReadbackRejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ReadbackRejected(code)


def safe_failure(error):
    code = (error.args[0] if type(error) is ReadbackRejected
            and len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in ERROR_CODES else "UNCLASSIFIED")
    return {"readback_error": code, "native_executed": False}


def checked_outcomes(receipt, module):
    flags = {
        "recorded_diagnostic_module_passed": module["passed"],
        "recorded_diagnostic_complete": receipt["complete"],
        "recorded_diagnostic_all_passed": receipt["diagnostic_all_passed"],
    }
    require(all(type(value) is bool for value in flags.values()), "OUTCOME_FLAG_TYPE")
    exit_code = module["execution"]["exit_code"]
    require(type(exit_code) is int and -255 <= exit_code <= 255,
            "EXIT_CODE_TYPE_OR_RANGE")
    return {**flags, "native_exit_code": exit_code}


def reader_controls():
    import copy

    receipt = {"complete": True, "diagnostic_all_passed": False}
    module = {"passed": False, "execution": {"exit_code": 0}}
    correct = checked_outcomes(receipt, module)
    require(correct == {"recorded_diagnostic_complete": True,
                        "recorded_diagnostic_all_passed": False,
                        "recorded_diagnostic_module_passed": False,
                        "native_exit_code": 0}, "READER_CONTROL_FAILED")
    for field in ("complete", "diagnostic_all_passed", "passed"):
        test_receipt, test_module = copy.deepcopy(receipt), copy.deepcopy(module)
        (test_module if field == "passed" else test_receipt)[field] = "must-not-print"
        try:
            checked_outcomes(test_receipt, test_module)
        except ReadbackRejected as error:
            require(safe_failure(error)["readback_error"] == "OUTCOME_FLAG_TYPE",
                    "READER_CONTROL_FAILED")
        else:
            raise ReadbackRejected("READER_CONTROL_FAILED")
    for bad in (True, "must-not-print", 256):
        try:
            checked_outcomes(receipt, {"passed": False, "execution": {"exit_code": bad}})
        except ReadbackRejected as error:
            require(safe_failure(error)["readback_error"] == "EXIT_CODE_TYPE_OR_RANGE",
                    "READER_CONTROL_FAILED")
        else:
            raise ReadbackRejected("READER_CONTROL_FAILED")
    require(safe_failure(ValueError("must-not-print"))["readback_error"] == "UNCLASSIFIED",
            "READER_CONTROL_FAILED")
    require(safe_failure(ReadbackRejected("must-not-print"))["readback_error"] == "UNCLASSIFIED",
            "READER_CONTROL_FAILED")
    return {"synthetic_schema_controls_passed": 9, "native_executed": False}


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def load_helper():
    raw = HELPER.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                       usedforsecurity=False).hexdigest()
    require(blob == HELPER_BLOB, "FROZEN_NETWORK_HELPER")
    spec = importlib.util.spec_from_file_location("frozen_reader", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def name_rows(values):
    # Only libtest-parser identifiers; never arbitrary captured test output.
    values = sorted(values)
    require(len(values) <= 174, "NAME_RESULT_COUNT")
    require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]{0,255}", name)
                for name in values), "TEST_IDENTIFIER_SHAPE")
    return [{"identifier": name, "sha256": hashlib.sha256(name.encode()).hexdigest()}
            for name in values]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_REPOSITORY") == "TrillionniumFoundation/Trillionnium-Chain"
            and os.environ.get("GITHUB_REF") == BRANCH, "READ_ONLY_JOB_SCOPE")
    out = args.out.resolve()
    require(not out.is_relative_to(ROOT), "OUTSIDE_SOURCE")
    out.mkdir(parents=True, exist_ok=False)
    limits = resource.getrlimit(resource.RLIMIT_AS)
    cap = min([512 * 1024 * 1024] + [value for value in limits if value >= 0])
    require(cap >= 128 * 1024 * 1024, "ADDRESS_SPACE_AVAILABLE")
    resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    print(json.dumps(reader_controls(), sort_keys=True), flush=True)
    helper = load_helper()
    token = os.environ.get("GH_TOKEN")
    require(isinstance(token, str) and token, "READ_TOKEN_REQUIRED")
    repo = helper.REPOSITORY
    metadata = helper.api_json(f"/repos/{repo}/actions/artifacts/{SPEC['artifact_id']}", token)
    run = helper.api_json(f"/repos/{repo}/actions/runs/{SPEC['run_id']}/attempts/1", token)
    commit = helper.api_json(f"/repos/{repo}/git/commits/{SPEC['source']}", token)
    helper.check_metadata(SPEC, metadata, run, commit)
    retained = {}
    all_members = []
    returned = 0
    with tempfile.TemporaryDirectory(prefix="trnm-da-artifact-") as temporary:
        archive = Path(temporary) / "original.zip"
        helper.download(SPEC, token, archive, {"compressed": 128 * 1024})
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            require(0 < len(infos) <= 64, "MEMBER_COUNT")
            declared = helper.validate_members(infos, DECODED_LIMIT)
            for info in infos:
                require(info.file_size <= MEMBER_LIMIT, "MEMBER_BYTE_LIMIT")
                data = bytearray()
                sha = hashlib.sha256()
                with zf.open(info) as stream:
                    while True:
                        block = stream.read(min(64 * 1024, DECODED_LIMIT - returned + 1))
                        if not block:
                            break
                        returned += len(block)
                        require(returned <= DECODED_LIMIT, "RETURNED_DECODED_LIMIT")
                        sha.update(block)
                        if any(info.filename in (name, "da-sequence-diagnostic/" + name)
                               for name in WANTED):
                            data.extend(block)
                all_members.append({"name_sha256": hashlib.sha256(info.filename.encode()).hexdigest(),
                                    "bytes": info.file_size, "sha256": sha.hexdigest()})
                for name in WANTED:
                    if info.filename in (name, "da-sequence-diagnostic/" + name):
                        require(name not in retained, "AMBIGUOUS_REQUIRED_MEMBER")
                        retained[name] = bytes(data)
        require(returned == declared, "DECODED_SIZE")
    require(set(retained) == set(WANTED), "REQUIRED_LOGS")
    before = helper.parse_json(retained["source-before.json"])
    after = helper.parse_json(retained["source-after.json"])
    require(before == after and before.get("tested_commit") == SPEC["source"]
            and before.get("tested_tree") == SPEC["tree"]
            and before.get("tracked_worktree_verified") is True, "ORIGINAL_SOURCE_BINDING")
    receipt = helper.parse_json(retained["receipt.json"])
    require(receipt.get("source_before") == before and receipt.get("source_after") == after,
            "RECEIPT_SOURCE_BINDING")
    registries = [row for row in receipt["commands"] if row.get("log") == "registry.log"]
    modules = [row for row in receipt["native_cases"] if row.get("name") == "original-module"]
    require(len(registries) == 1 and len(modules) == 1, "EXACT_COMMANDS")
    require(registries[0]["log_digest"] == digest(retained["registry.log"])
            and modules[0]["execution"]["log_digest"] == digest(retained["original-module.log"]),
            "ACTUAL_LOG_DIGEST_BINDING")
    outcomes = checked_outcomes(receipt, modules[0])
    registry = retained["registry.log"].decode("utf-8")
    module = retained["original-module.log"].decode("utf-8")
    names = re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", registry, re.M)
    successful = re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", module, re.M)
    summaries = [list(map(int, row)) for row in re.findall(
        r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out;", module, re.M)]
    require(len(names) == 174 and len(set(names)) == 174, "ORIGINAL_REGISTRY_SIZE")
    counts = Counter(successful)
    report = {
        "schema": "trnm-da-diagnostic-original-log-readback-v1",
        "reader_source": os.environ["GITHUB_SHA"],
        "original": SPEC,
        "archive_sha_size_all_member_crc_verified": True,
        "decoded_bytes": returned,
        "member_count": len(all_members),
        "members": all_members,
        "original_source_receipts_match": True,
        "exact_registry_count": len(names),
        "successful_line_count": len(successful),
        "unique_successful_names": len(counts),
        "module_summaries": summaries,
        **outcomes,
        "missing_success_names": name_rows(set(names) - set(successful)),
        "unexpected_success_names": name_rows(set(successful) - set(names)),
        "duplicate_success_names": name_rows(name for name, count in counts.items() if count != 1),
        "required_input_digests": {name: digest(data) for name, data in retained.items()},
        "scope": "Readback of original diagnostic logs; no archived code executed, no native rerun, no original baseline or performance qualification.",
        "native_executed": False,
        "original_baseline_qualified": False,
        "host_qualified": False,
        "performance_qualified": False,
        "production_activation": False,
    }
    encoded = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(encoded) <= OUTPUT_LIMIT, "OUTPUT_BYTES")
    (out / "READBACK.json").write_bytes(encoded)
    print("DA_LOG_READBACK " + encoded.decode(), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # No signed URLs, token, raw API response or arbitrary test text.
        print(json.dumps(safe_failure(error), sort_keys=True))
        raise SystemExit(1) from None
