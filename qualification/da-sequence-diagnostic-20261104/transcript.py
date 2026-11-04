#!/usr/bin/env python3
"""Exact libtest transcript handling for the frozen package-selected DA diagnostic."""
from __future__ import annotations

import re

SELECTOR = "cell::discovery::sequence_tests::tcp_two_bootstraps_newer_owner_sequence_never_dials_superseded_endpoint"
RETENTION_PARENT = "cell::retention::tests::real_process_death_after_payload_sync_recovers_ack_without_origin_or_new_capacity"
RETENTION_CHILD = "cell::retention::tests::retention_process_child"
RETENTION_BLOCK = (f"test {RETENTION_PARENT} ... \n"
                   "running 1 test\n"
                   f"test {RETENTION_CHILD} ... ok\n")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def observations(log, selected, registered_names):
    # A source-bound subprocess fixture exits before its own harness completion.
    # Its inherited stdout leaves the CHILD prefix open; the outer PARENT "ok"
    # closes that line. Recognize exactly this one immutable formatter shape.
    raw_success_rows = len(re.findall(
        r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", log, re.M))
    nested_count = 0 if selected else log.count(RETENTION_BLOCK)
    if not selected and nested_count == 1:
        log = log.replace(RETENTION_BLOCK, f"test {RETENTION_PARENT} ... ok\n")
    summaries = [tuple(map(int, row)) for row in re.findall(
        r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out;", log, re.M)]
    success = re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", log, re.M)
    # Exact-selector --nocapture may put fixed diagnostics after the test name.
    selected_present = re.search(r"^test " + re.escape(SELECTOR) + r" \.\.\.", log, re.M) is not None
    expected = (1, 0, 0, 0, 173) if selected else (174, 0, 0, 0, 0)
    passed = summaries == [expected] and (selected_present if selected else
              nested_count <= 1 and len(success) == 174
              and len(set(success)) == 174 and set(success) == set(registered_names))
    return {"passed": passed, "native_summaries": summaries,
            "selected_case_present": selected_present,
            "completed_plain_success_rows": len(success),
            "raw_plain_success_rows": raw_success_rows,
            "retention_child_prefix_blocks": nested_count,
            "exchange_diagnostic_lines": [line for line in log.splitlines()
                if "cell_discovery_exchange " in line],
            "scope": "Diagnostic case/module observations only; no original full-workspace or Host qualification."}



def reader_controls():
    names = [SELECTOR] + [f"fixture::case_{number}" for number in range(173)]
    full = "\n".join(f"test {name} ... ok" for name in names) + (
        "\ntest result: ok. 174 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n")
    selected = (f"test {SELECTOR} ... cell_discovery_exchange round=0\nok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 173 filtered out;\n")
    cases = [
        (observations(full, False, names)["passed"], True),
        (observations(selected, True, names)["passed"], True),
        (observations(full.replace(f"test {names[0]} ... ok\n", ""), False, names)["passed"], False),
        (observations(full.replace(names[1], names[2]), False, names)["passed"], False),
        (observations(full.replace(names[1], "fixture::foreign"), False, names)["passed"], False),
        (observations(full.replace("174 passed", "173 passed"), False, names)["passed"], False),
        (observations(selected.replace(SELECTOR, "fixture::foreign"), True, names)["passed"], False),
        (observations(selected.replace("0 failed", "1 failed"), True, names)["passed"], False),
    ]
    nested_names = [SELECTOR, RETENTION_PARENT, RETENTION_CHILD] + [
        f"nested_fixture::case_{number}" for number in range(171)]
    ordinary = "\n".join(f"test {name} ... ok" for name in nested_names) + (
        "\ntest result: ok. 174 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n")
    parent_row = f"test {RETENTION_PARENT} ... ok\n"
    nested = ordinary.replace(parent_row, RETENTION_BLOCK)
    # Exact old failure: the outer case has no whole-line success and CHILD
    # appears twice. Keep it as a required negative for the former parser.
    legacy_success = re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", nested, re.M)
    legacy_false_negative = (len(legacy_success) == 174
                             and len(set(legacy_success)) == 173
                             and RETENTION_PARENT not in legacy_success)
    cases.extend([
        (legacy_false_negative, True),
        (observations(nested, False, nested_names)["passed"], True),
        (observations(nested.replace(RETENTION_BLOCK, RETENTION_BLOCK.replace(
            "... ok\n", "... FAILED\n")), False, nested_names)["passed"], False),
        (observations(nested.replace(RETENTION_BLOCK, RETENTION_BLOCK.replace(
            RETENTION_CHILD, "nested_fixture::foreign")), False, nested_names)["passed"], False),
        (observations(nested.replace(RETENTION_BLOCK, ""), False, nested_names)["passed"], False),
        (observations(nested.replace(RETENTION_BLOCK, RETENTION_BLOCK * 2),
                      False, nested_names)["passed"], False),
        (observations(nested.replace(RETENTION_BLOCK + f"test {RETENTION_CHILD} ... ok\n",
                                    RETENTION_BLOCK, 1),
                      False, nested_names)["passed"], False),
        (observations(nested.replace("174 passed", "173 passed"),
                      False, nested_names)["passed"], False),
    ])
    require(all(actual is expected for actual, expected in cases), "READER_CONTROL_FAILED")
    return {"synthetic_parser_cases_passed": len(cases), "native_tests_executed": 0}

