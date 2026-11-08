#!/usr/bin/env python3
"""Verify exact native suite provenance before capturing original paired bytes."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--tests-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-native-tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chain-scripts", type=Path, required=True)
    parser.add_argument("--collector", type=Path, default=Path(__file__).with_name("capture_native_learning_exports.py"))
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.expected_head), "EXACT_SOURCE_REQUIRED")
    require(re.fullmatch(r"[0-9a-f]{40}", args.expected_tree)
            and re.fullmatch(r"[0-9a-f]{40}", args.expected_native_tree), "EXACT_SOURCE_TREES_REQUIRED")
    sys.path.insert(0, str(args.chain_scripts.resolve()))
    import cell_adoption_readback as native
    result_raw = native.read_bounded(args.result, 4 * 1024 * 1024)
    result = native.decode(result_raw, 4 * 1024 * 1024)
    require(type(result["exit_code"]) is int and result["exit_code"] == 0 and result["error"] is None,
            "NATIVE_RUN_FAILED")
    require(result["source_unchanged"] is True and result["source_before"] == result["source_after"], "SOURCE_CHANGED")
    source = result["source_before"]
    require(source["head"] == args.expected_head and source["status"] == "" and source["tree"] == source["index_tree"], "EXACT_CLEAN_SOURCE")
    require(source["tree"] == args.expected_tree and source["native_tree"] == args.expected_native_tree,
            "EXACT_SOURCE_TREES")
    require(result["engineering_controls_only"] is True and result["actual_model_execution"] is False
            and result["production_final_use_qualified"] is False and result["pins_are_fixture_derived"] is True,
            "FIXTURE_SCOPE_CHANGED")
    require(type(result["steps"]) is list and len(result["steps"]) == 1, "ONE_NATIVE_SUITE_REQUIRED")
    step = result["steps"][0]
    require(type(step["exit_code"]) is int and step["exit_code"] == 0 and step["source_after"] == source, "NATIVE_STEP_FAILED")
    log_raw = native.read_bounded(args.log, 64 * 1024 * 1024)
    xml_raw = native.read_bounded(args.junit, 16 * 1024 * 1024)
    tests_raw = native.read_bounded(args.tests, 1024 * 1024)
    require(sha(tests_raw) == native.hex_digest(args.tests_sha256), "FROZEN_TEST_REGISTRY_PIN")
    for raw, record in ((log_raw, step["log"]), (xml_raw, step["junit"])):
        require(type(record["bytes"]) is int and len(raw) == record["bytes"] and sha(raw) == record["sha256"], "NATIVE_RAW_ARTIFACT_CHANGED")
    tests = native.decode(tests_raw, 1024 * 1024)
    require(type(tests) is list and tests and all(type(name) is str and name for name in tests)
            and len(tests) == len(set(tests)), "EXACT_UNIQUE_TEST_NAMES")
    xml = ET.fromstring(xml_raw)
    cases = xml.findall(".//testcase")
    names = [case.attrib.get("name") for case in cases]
    require(Counter(names) == Counter(tests) == Counter(step["junit"]["testcases"]), "NATIVE_TEST_DENOMINATOR")
    require(xml.attrib.get("tests") == str(len(tests)) and xml.attrib.get("failures") == "0"
            and xml.attrib.get("errors") == "0", "NATIVE_JUNIT_SUMMARY")
    require(not any(case.find(tag) is not None for case in cases for tag in ("error", "failure", "skipped")), "NATIVE_CASE_NOT_PASS")
    run_ids = re.findall(rb"Nextest run ID ([0-9a-f-]{36})", log_raw)
    require(len(run_ids) == 1 and run_ids[0].decode() == step["junit"]["run_id"] == xml.attrib.get("uuid"), "NATIVE_RUN_ID")
    spec = importlib.util.spec_from_file_location("capture_native_learning_exports", args.collector)
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    saved_argv = sys.argv
    try:
        sys.argv = [str(args.collector), "--log", str(args.log), "--output", str(args.output),
                    "--chain-scripts", str(args.chain_scripts), "--hepta-source", args.expected_head]
        collector.main()
    finally:
        sys.argv = saved_argv
    for name, raw in (("native-result.json", result_raw), ("native-controls.junit.xml", xml_raw),
                      ("expected-native-test-names.json", tests_raw)):
        with (args.output / name).open("xb") as stream:
            stream.write(raw)
        require((args.output / name).read_bytes() == raw, "CAPTURE_RAW_READBACK")
    validation = dict(schema="trnm-cell-learning-native-capture-validation-v2", source=source,
        native_result_sha256=sha(result_raw), native_log_sha256=sha(log_raw), native_junit_sha256=sha(xml_raw),
        expected_test_names_sha256=sha(tests_raw), expected_test_count=len(tests), actual_test_count=len(cases),
        native_run_id=run_ids[0].decode(), native_selected_suite_passed=True,
        actual_model_execution=False, independent_evaluation_established=False,
        production_final_use_qualified=False, portable_current_permission=False,
        pins_are_fixture_derived=True, actor_fixture_cases=2, readback_phases=4,
        raw_document_fields_rewritten=False, fixture_manifest_sha256=sha((args.output / "fixture-manifest.json").read_bytes()))
    with (args.output / "capture-validation.json").open("x") as stream:
        json.dump(validation, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(validation, sort_keys=True))


if __name__ == "__main__":
    main()
