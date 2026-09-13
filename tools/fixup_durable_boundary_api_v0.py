#!/usr/bin/env python3
"""Align the durable authority adapter with the current node-boundary v0 API.

The durable journal continues to bind the private facts digest into each record
digest. The public receipt intentionally exposes only the operation binding,
stage, sequence, and record digest. Conflicting idempotent replays remain a
specific adapter-level fail-closed error.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs"


def replace_exact(source: str, old: str, new: str, expected: int, label: str) -> str:
    count = source.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} exact edge(s), found {count}")
    return source.replace(old, new, expected)


source = PATH.read_text(encoding="utf-8")
source = replace_exact(
    source,
    '''    InvalidAuthorityCommand(BoundaryErrorV0),
    ActiveStagingExists,
''',
    '''    InvalidAuthorityCommand(BoundaryErrorV0),
    AuthorityFactsMismatch,
    ActiveStagingExists,
''',
    1,
    "durable error enum",
)
source = replace_exact(
    source,
    '''            Self::InvalidAuthorityCommand(error) => {
                write!(f, "authority command rejected: {error}")
            }
            Self::ActiveStagingExists => f.write_str("a snapshot staging generation is already active"),
''',
    '''            Self::InvalidAuthorityCommand(error) => {
                write!(f, "authority command rejected: {error}")
            }
            Self::AuthorityFactsMismatch => {
                f.write_str("authority command facts do not match the durable record")
            }
            Self::ActiveStagingExists => f.write_str("a snapshot staging generation is already active"),
''',
    1,
    "durable error display",
)
source = replace_exact(
    source,
    '''            durable_stage: self.stage,
            durable_sequence: self.sequence,
            facts_digest: self.facts_digest,
            record_digest: self.record_digest,
''',
    '''            durable_stage: self.stage,
            durable_sequence: self.sequence,
            record_digest: self.record_digest,
''',
    1,
    "public authority receipt",
)
conflicting_replay = re.compile(
    r"Err\(DurableFileErrorV0::InvalidAuthorityCommand\(\s*"
    r"BoundaryErrorV0::ReceiptSubstitution,\s*"
    r"\)\)"
)
source, replay_count = conflicting_replay.subn(
    "Err(DurableFileErrorV0::AuthorityFactsMismatch)", source
)
if replay_count != 2:
    raise SystemExit(
        "conflicting idempotent authority replay: "
        f"expected 2 structural edges, found {replay_count}"
    )
source = replace_exact(
    source,
    '''            assert_eq!(prepared.durable_sequence, 0);
            assert_eq!(prepared.facts_digest, node_digest(20));
            assert_eq!(
''',
    '''            assert_eq!(prepared.durable_sequence, 0);
            let replayed = coordinator
                .apply(AuthorityCommandV0::Begin {
                    binding: first,
                    ingress_digest: node_digest(20),
                })
                .unwrap();
            assert_eq!(replayed, prepared);
            assert_eq!(
''',
    1,
    "authority idempotency test",
)
source = replace_exact(
    source,
    '''                DurableFileErrorV0::InvalidAuthorityCommand(
                    BoundaryErrorV0::ReceiptSubstitution
                )
                .to_string()
''',
    '''                DurableFileErrorV0::AuthorityFactsMismatch.to_string()
''',
    1,
    "authority substitution test expectation",
)

if "BoundaryErrorV0::ReceiptSubstitution" in source:
    raise SystemExit("retired ReceiptSubstitution boundary variant remains")
if "facts_digest: self.facts_digest" in source:
    raise SystemExit("private facts digest still leaks into public authority receipt")

PATH.write_text(source, encoding="utf-8")
