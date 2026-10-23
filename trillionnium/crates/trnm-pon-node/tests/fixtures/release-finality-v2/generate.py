#!/usr/bin/env python3
"""Reproduce signed fixture bytes using the unchanged executable V2 reference.

Keys are deterministic PUBLIC TEST FIXTURE ONLY identities from test_protocol.py.
This is a conformance fixture, never performance, independence or efficacy data.
"""
import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
sys.path.insert(0, str(ROOT / "formal/release-finality-v2"))
from test_protocol import Fixture
from protocol import canonical
from verify_certificate import verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    fixture = Fixture()
    try:
        bundle, _, _ = fixture.run()
        files = {"bundle.json": canonical(bundle),
                 "committee.json": canonical(fixture.m),
                 "context.json": canonical(fixture.ctx)}
        files["expected.json"] = canonical(verify(files["bundle.json"],
                                                  files["committee.json"],
                                                  files["context.json"]))
        for name, data in files.items():
            if args.check:
                if (HERE / name).read_bytes() != data:
                    raise ValueError(f"reference fixture differs: {name}")
            else:
                (HERE / name).write_bytes(data)
        print("PASS: original reference signed fixture " + ("checked" if args.check else "generated"))
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
