#!/usr/bin/env python3
"""Check a frozen complete native roster; no performance or security authority."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

ROSTERS = json.loads(Path(__file__).with_name("w1_native_rosters_v1.json").read_text())

def require_named_success(text, selector):
    """Accept one libtest result, including nocapture output before its status.

    A following named test or suite summary closes the record. Diagnostic text
    cannot supply another test's status or replace a missing terminal result.
    """
    starts = list(re.finditer(r'^test (\S+) \.\.\. ', text, re.M))
    matches = [i for i, match in enumerate(starts) if match[1] == selector]
    if len(matches) != 1:
        raise ValueError(selector + ': missing or duplicate native control')
    i = matches[0]
    end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
    body = text[starts[i].end():end].split('\ntest result:', 1)[0]
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines or lines[-1] != 'ok':
        raise ValueError(selector + ': native control did not succeed')
    if any(line in ('ok', 'FAILED') or line.startswith('ignored') for line in lines[:-1]):
        raise ValueError(selector + ': ambiguous native outcome')


def check(text, profile):
    expected = ROSTERS[profile]
    names = expected["names"]
    ignored = set(expected["ignored"])
    if len(set(names)) != len(names) or not ignored.issubset(names):
        raise ValueError("invalid frozen roster")
    rows = re.findall(r"^test (\S+) \.\.\. ([^\n]*)", text, re.M)
    if Counter(name for name, _ in rows) != Counter(names):
        raise ValueError("missing, extra or duplicate named native control")
    actual_ignored = {name for name, outcome in rows if outcome.startswith("ignored")}
    if actual_ignored != ignored:
        raise ValueError("ignored native identity changed")
    summaries = re.findall(r"^test result: ([^\n]+)", text, re.M)
    prefix = f"ok. {len(names)-len(ignored)} passed; 0 failed; {len(ignored)} ignored; 0 measured; "
    if len(summaries) != 1 or not summaries[0].startswith(prefix):
        raise ValueError("native summary is missing, duplicated or unsuccessful")
    if not re.match(re.escape(prefix) + r"\d+ filtered out; finished in ", summaries[0]):
        raise ValueError("noncanonical native summary")
    if any(outcome.startswith("FAILED") for _, outcome in rows):
        raise ValueError("failed native outcome")
    return {"profile": profile, "named": len(names), "ignored": sorted(ignored)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(ROSTERS), required=True)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.log.read_text(), args.profile), sort_keys=True))

if __name__ == "__main__":
    main()
