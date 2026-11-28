# Worker task-id query pretty stdout

WTQ2 is the versioned, private pretty-stdout continuation of
[WTQ1](audit_task_query.md). It takes the same already-held canonical WIX1
and selected WJL1 rows and uses the same 64 KiB input, 64-row,
102,400-byte scratch, and 1 MiB output ceilings. Change only the request
tag from `WTQ1` to `WTQ2`; the previous entry rejects that tag and
continues emitting its unchanged binary `WTO1` result.

A source-checked projection of the WTQ1 entry changes only the marker,
measurement, and publication calls. It runs the original shared native
checks on all eight index maps, validates every row, and proves exact
task-to-row coverage before examining the selected results for output.
No new parser or sidecar authority is added. Hit ordinals are emitted in
the same stored ascending order; each object has the original 18 fields
in declaration order, followed by the three query decorations:
`proof_type: null`, `settlement_status` equal to the same validated
row status, and `timestamp_unix_ms: null`. These are the original
task branch defaults, not caller-supplied metadata. The absent
top-level fingerprint field is not emitted.

The pretty row projection leaves the original `wj_row` field value
and type operations intact, including escaped UTF-8, unsigned decimal,
full signed fields, and nullable slots. It changes only the key
punctuation and compact closing suffix. The first pretty prefix is
12 bytes, and all later prefixes are 8 bytes. The existing compact key
helper emits exactly one initial punctuation byte before each quoted
key; a checked projection tests all 18 literal keys. During emission
this one byte is placed in the last already allocated prefix space,
which is restored before appending the post-colon space. Every byte
written belongs to an already measured field prefix; the first pass
uses the same prefix offsets without writing. The query decoration
reads the already-proved status slot and uses the existing string size
and escaping primitives. No output is written until the complete
measurement passes capacity; invalid or insufficient calls leave all
output unchanged. A success preserves the unused output tail.

Output is the exact original two-space-indented `query-audit --task-id`
stdout, including the final LF. The original miss/empty result is
41 bytes. There is no intermediate compact JSON scan or host formatter.

The qualification runs the unchanged source-bound original CLI on four
owned synthetic journals, takes complete typed rows and sidecar facts
from genuine original exports, and compares each native emitter to ten
independently captured raw original query stdout results. It exercises
UTF-8/escaping, repeated task IDs, mixed exclusion, positive zero,
empty/absent, and all 64 ordinals for maximum `u64`. Separate exact
64 KiB typed input and 6× escape expansion checks exercise workspace,
exact and one-short output, and late no-write refusal. The retained
prior WTQ1 receipt confirms both old native artifact hashes are unchanged.

WTQ2 is a pure read-only typed memory candidate. No generic JSON/Serde
coverage, fingerprint lookup, path handling, identity or custody
policy, filesystem access, production stdout routing, or legacy
retirement is implied.
