# Closed evaluator-round policy

`closed_round.hepta` implements the complete decision order of
`trillionnium/crates/trnm-verification-profiles/src/closed_round.rs` on an
explicit local representation of its `BTreeSet<String>` and
`BTreeMap<String, u64>` arguments. HIA itself checks every name byte, UTF-8
sequence, count, boundary, ordering relation and evaluator membership.
The entry is `f0(readbuf input, mutbuf output, mutbuf scratch) -> u32`.

This component closes a development evaluator round; it does not authenticate
signatures, establish model truth, grant payment authority or change fork weight.
The caller must still obtain the eligible roster and votes from the appropriate
authenticated owners. No caller-provided validity Boolean or identity hash
stands in for the actual strings.

## Local argument representation

All integers are little-endian. This representation is local to the native
migration and is not a replacement blockchain wire format or signed domain.

| Field | Representation |
| --- | --- |
| Magic | Four exact bytes `CRD1` |
| Maximum score | `u64` |
| Eligible count | `u32` |
| Vote count | `u32` |
| Eligible entries | Count repetitions of `u32 byte_length`, followed by exact UTF-8 bytes |
| Vote entries | Count repetitions of `u32 byte_length`, exact UTF-8 bytes, then `u64 score` |

Both lists must be strictly increasing by their UTF-8 bytes. Duplicates are
refused. Valid UTF-8 preserves the corresponding Rust string order. Empty
strings, NUL, non-ASCII characters and all valid Unicode scalar values remain
valid identities; no normalization or case folding occurs. The entire input
must be consumed. Input has a documented 1 MiB local ABI bound; there is no
smaller name-length or ASCII-only restriction. This bounded entry does not
replace arbitrarily large Rust containers.

## Result contract

Local representation admission precedes the original policy because malformed
bytes do not define either input container. For admitted containers, the exact
original ordering is preserved: roster size, unknown signer, excessive score,
missing vote, then the minimum of all votes.

| Code | Meaning | Output effect |
| --- | --- | --- |
| `0` | Complete: every eligible evaluator voted | Write the minimum as eight little-endian bytes |
| `1` | Pending: an eligible evaluator has not voted | None |
| `2` | `EVALUATOR_ROSTER`: eligible count is outside 2–3 | None |
| `3` | `AUTHORITY`: a vote names an ineligible signer | None |
| `4` | `EVIDENCE`: at least one score exceeds the maximum | None |
| `100` | Invalid magic, truncated field or trailing bytes | None |
| `101` | Invalid UTF-8 | None |
| `102` | Duplicate or noncanonical container ordering | None |
| `103` | Input exceeds the local 1 MiB bound | None |
| `104` | Complete result requires an output of at least eight bytes | None |

A complete minimum of zero is a valid result. Pending is never encoded as a
zero score. Bytes beyond output offset eight and every scratch byte remain
unchanged. Even a zero-length output is allowed for non-complete outcomes.

`hia/tests/test_closed_round.py` runs actual native artifacts against an
independent container oracle, all six arrival orders, full-width score
endpoints, exact Unicode identities, malformed framing and UTF-8, duplicate
keys, output canaries, long names, and an independently emitted native backend.
Native compiler and toolchain identities follow `hia/toolchain.lock.json`.

For the separate original profile admission and exact lookup API, see
[Closed verification profile registry](PROFILE_REGISTRY.md).

For typed digest framing, registry/evidence validation before a backend,
and the private deterministic observation codec, see
[Verification statement preflight and observational output](STATEMENT_PREFLIGHT.md).
