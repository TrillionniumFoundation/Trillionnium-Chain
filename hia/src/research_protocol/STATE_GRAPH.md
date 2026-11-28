# Native Research state admission

`state_index.hepta` and `state_graph.hepta` implement the original
`ResearchProtocolState` snapshot admission rules from the retained `state.rs`.
They are private continuations for the forthcoming native state owner. Index
bytes supplied by an external caller are not a capability or proof of admission.
The final owner must retain exclusive custody of the arena and hide these entry
symbols. These kernels do not yet replace the complete Research package.

## Original semantics

The raw [state value codec](STATE_VALUES.md) preserves public vector order and
does not validate a graph. The index copies that typed value, records every
object and journal descriptor, and constructs separate sorted pointer indexes.
Descriptors remain in input order so that sorting cannot change the original
first error. Object and command keys use their complete 32 bytes. Nonce identity
uses the complete chain, DID, role and public-key tuple, with original tuple
ordering; no digest or truncated key substitutes for identity.

Graph admission preserves the original sequence:

1. For a bound restore, validate the requested chain before snapshot validation.
2. Require snapshot version 2 and validate authorities.
3. Collect journal records in input order, checking command identity and chain
   consistency, then check the configured chain using sorted command order.
4. Validate nonce identities and reject duplicates.
5. Collect the seven object buckets in original input order, preserving kind,
   zero-version and duplicate-key error precedence.
6. Validate authorities again and traverse each graph bucket in sorted key order.
7. Validate journal fingerprints and their relaxed historical primary references.

Strict references require the current object version; historical references
retain the original relaxed rules. Claim/challenge/resolution backlinks, status,
checked version progression, current claimant shares and challenge resolution
must agree. Restoration deliberately does not add timestamp, evidence or
contributor checks that the original only performs while applying a command.
The state chain is out of band and absent from the snapshot hash.

## Private borrowed interfaces

Both frames have a 24-byte header. Typed words and lengths are u64 little endian.
`RSI1` followed by twenty zero bytes and the raw typed snapshot builds an index.
Its 16-byte result is `RSINDEX1` and the typed byte length. Scratch requires
`266752 + 32 * typed_snapshot_bytes`, checked before writes. Heap sorting avoids
introducing a new collection-count ceiling.

`RSG1` uses operation byte 1 for unbound restore, or 2 followed after the header
by the exact configured chain bytes. The other nineteen header bytes are zero.
The chain must satisfy the original canonical 1–64-byte ASCII contract. The
graph call requires the index arena. It preserves the copied typed snapshot and
the caller's scratch tail. Private descriptor pointers refer only to this live,
exclusive arena; they must not escape as public objects.

Graph results contain 64 bytes of structured error metadata. Status 0 admits
the graph; 64 refuses insufficient capacity and 65 refuses malformed framing.
Semantic statuses preserve the actual original variants: authority 301,
nested payload 402, journal-chain 404, invalid binding 406, configured-chain
mismatch 408, duplicate object 410, missing object 411, version mismatch 412,
unsupported snapshot version 423 and invalid graph 424. Pointer-bearing details
must be copied by the owner before the arena is released. Output capacity and
frame refusals are atomic; semantic refusals do not mutate the snapshot.

## Actual development observations

The six-method graph run passed 463 original/native comparisons and 167 ABI
controls, with two native builds and 1,095 recorded calls in 68.764 seconds.
The original adapter invokes the retained library's real public constructors
and methods. Native results include exact error variants/details, state exports,
canonical bytes and hashes. Truncation, malformed headers, capacities, unsorted
collections and graph/error-order controls retain complete input/output arenas.

That first recorder's schema/scope labels accidentally retained the earlier
state-values name and five-method description. Its actual selected, started and
finished rosters contain all six graph methods. The original record is retained
unchanged; the incorrect labels must not be used to describe its scope. Later
combined qualification must bind the current extended adapter and test sources.

```sh
python3 -m unittest hia.tests.test_research_state_graph -v
```
