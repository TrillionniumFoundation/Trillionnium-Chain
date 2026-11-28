# Separate V0 unsigned candidate, 128-slot profile

This private entry uses exactly the immutable [V0 unsigned candidate
layout](UNSIGNED_CANDIDATE.md) and retains the original order of checks.
It admits at most 128 in **each** artifact, package, required-key and
build-input roster, for an exact total extent at most 459,373 bytes.
It stages the same 168-byte unsigned candidate output (not an authority
or signature verdict); 16,544 disjoint scratch bytes are required.
The original 64-slot ABI and its native SHA, validation and sorting
helpers are unchanged.

The driver preserves the existing original-order wire, header, source,
artifact, package, required-key and provenance membership checks.
After framing and capacity admission it folds the original member
digests directly from the same immutable input, using privately
derived section offsets. Work for each of the three ordered digest
folds is at most seven passes over 128 immutable row indices, with
at most 896 merge copies and comparisons per roster. This reuses the
existing bank access and typed original compare/canonical member
primitives without composing a foreign output back as input.

Original artifact/package/required membership checks precede hashing.
Provenance declaration mismatch precedes individual build-input checks,
as in the original. Duplicate and required membership scans retain
their bounded pairwise order: each duplicate loop visits
at most 8,128 earlier row pairs and required package membership at most
16,384 pairs. Scratch stores canonical hash transcripts below 7,162,
index banks in [12,288,16,384), and five disjoint retained SHA-256 digests
in [16,384,16,544). A refusal changes no output. Wire, earlier prefix
and capacity refusals also keep scratch unchanged; scratch is private
and may change during hashing. This is a finite test profile, not a
production latency guarantee, full original limit, or new verification
API.

Tests compare both stock emitters to the locked original Cargo crate,
including full 128 rosters with long common prefixes, 65 legacy
refusal, odd-run cases, intentional combined earlier/later refusals
and stable output at the always-rejecting original signature boundary.
The callback never authorizes anything; no signatures are made,
accepted, used or verified by the native entry.
