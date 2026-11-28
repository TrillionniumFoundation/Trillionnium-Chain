# Offline BEP52 bencode prefix structure

`bep52_bencode_prefix.hepta` exposes only the structural projection of the
original private borrowed `cell/bep52_peer/bencode.rs::decode`. It operates on
one caller-owned immutable loan, without inspecting protocol field names.
It does not construct a decoded tree or inspect the meaning of string
payloads. This is not the canonical metainfo comparator, and neither
implementation falls back to the other.

`f0(readbuf, mutbuf, mutbuf) -> u32` accepts at most 1,048,576 input bytes
and requires at least 24 output and 81 scratch bytes. The successful output
is three 8-byte unsigned big-endian words: root kind (1 bytes, 2 signed
integer, 3 list, 4 dictionary), number of input bytes consumed, and total
number of values including the root but excluding dictionary keys. As in the
original prefix parser, success says nothing about unused suffix. Consumers
that require an entire value must compare the consumed extent to the input
length. No bytes are written to output on refusal; trailing output bytes are
preserved on success. Scratch may change during parsing. Each open container
uses nine scratch bytes (kind and previous borrowed key start/end). The ninth
frame can be opened for an empty container at depth eight; a child admission
would violate the original depth rule.

The original admits a maximum depth of eight (root depth zero), 128 values,
five ASCII length digits, up to 20 raw signed-integer characters, and only
signed 64-bit integers. It rejects leading zeros, integer negative zero and
dictionary keys that are not strictly increasing in byte order. A dictionary
key is checked before entering its value. The native ABI refuses over-cap
inputs before inspecting them; that is a named native limit, not a claim that
the original imposes the same aggregate cap. Within this profile the original
string-specific usize overflow is unreachable.

Statuses: 0 success; 20 complexity, 21 missing or invalid value, 22 string
length digit bound, 23 length delimiter, 24 noncanonical length, 25 truncated
string, 26 integer bound, 27 missing integer terminator, 28 empty integer,
29 invalid digits, 30 noncanonical integer, 31 negative zero, 32 dictionary
key order/duplicate, 33 signed range, 100 input profile bound, and 102
insufficient capacity.

The locked Rust witness compiles the unchanged original parser and its exact
source-extracted `require` helper, with the original crate's error type. The
witness projects the returned value solely to compare root kind, consumed
extent, and census with both stock native outputs on deterministic inert
fixtures. Loading files or content, transport, discovery, network activity,
peer admission, and authority are not part of this component.
