#!/usr/bin/env python3
"""M17: closed-format trigger inventory regression, not a general YAML parser.

The existing runner/offline-policy validators remain responsible for executable
workflow safety. This guard rejects syntax outside the reviewed trigger subset
rather than silently approximating GitHub's event or glob semantics.
"""
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/trnm-canonical-input-fuzz-smoke.yml"
OWNED = (
    "formal/poco-convergence-v1/**",
    "config/poco-convergence-v1.json",
    "docs/protocol/poco-convergence-v1/**",
    "trillionnium/crates/trnm-consensus-crypto/**",
    "trillionnium/crates/trnm-native-execution-v0/**",
    "scripts/ci/test_pcc1_workflow_coverage_v1.py",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inventories(source):
    require(source.count("\non:\n") == 1, "unique canonical on block required")
    body = source.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    result, event, section = {}, None, None
    main_only = False
    for line in body.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"  (pull_request|push|workflow_dispatch):", line)
        if match:
            event = match.group(1)
            require(event not in result, "duplicate event")
            result[event] = []
            section = None
        elif line == "    branches: [main]":
            require(event == "push" and not main_only, "unexpected branch filter")
            main_only = True
            section = "branches"
        elif line == "    paths:":
            require(event in ("pull_request", "push") and not result[event], "duplicate paths")
            require(section != "paths", "duplicate empty paths")
            section = "paths"
        elif line.startswith('      - "'):
            require(section == "paths", "path outside paths")
            value = json.loads(line[8:])
            require(isinstance(value, str) and value and not value.startswith("!"), "unsafe path")
            require(value not in result[event], "duplicate path")
            result[event].append(value)
        else:
            raise ValueError("unsupported trigger syntax: " + line)
    require(set(result) == {"pull_request", "push", "workflow_dispatch"}, "missing event")
    require(main_only, "main push trigger required")
    for name in ("pull_request", "push"):
        require(set(OWNED) <= set(result[name]), "lost owned input: " + name)
    return result


class TriggerCoverageTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_current_reviewed_trigger_inventory(self):
        inventories(self.source)

    def test_each_owned_input_removal_is_rejected_for_each_event(self):
        for event in ("pull_request", "push"):
            start = self.source.index("  " + event + ":\n")
            following = re.search(r"\n  [a-z_]+:", self.source[start + 3:])
            end = start + 3 + following.start() if following else len(self.source)
            prefix, body, suffix = self.source[:start], self.source[start:end], self.source[end:]
            for pattern in OWNED:
                with self.subTest(event=event, missing=pattern):
                    needle = '      - "' + pattern + '"\n'
                    self.assertEqual(body.count(needle), 1)
                    with self.assertRaises(ValueError):
                        inventories(prefix + body.replace(needle, "", 1) + suffix)

    def test_each_tracked_owned_file_has_single_change_coverage(self):
        rules = inventories(self.source)
        paths = subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=ROOT, timeout=30
        ).decode("utf-8").split("\0")
        for pattern in OWNED:
            prefix = pattern[:-2] if pattern.endswith("/**") else None
            owned = [p for p in paths if (p.startswith(prefix) if prefix else p == pattern)]
            self.assertTrue(owned, "empty owned inventory: " + pattern)
            for path in owned:
                for event in ("pull_request", "push"):
                    with self.subTest(path=path, event=event):
                        self.assertTrue(any(
                            path.startswith(p[:-2]) if p.endswith("/**") else path == p
                            for p in rules[event]
                        ))

    def test_negation_and_duplicate_event_are_not_silently_accepted(self):
        needle = '      - "docs/protocol/poco-convergence-v1/**"'
        for replacement in (
            '      - "!docs/protocol/poco-convergence-v1/**"',
            "  pull_request:\n" + needle,
        ):
            with self.assertRaises(ValueError):
                inventories(self.source.replace(needle, replacement, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
