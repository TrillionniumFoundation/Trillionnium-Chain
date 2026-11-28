# Same-byte activation pin and strict JSON prelude

`TAR1\0\0\0\0`, the caller-held 32-byte SHA-256, then one immutable raw JSON
blob. The private f0 hashes this exact blob and checks the pin **before** its
lexical scanner reads the same held bytes. The maximum complete frame is
1 MiB (raw cap 1,048,536 bytes), slightly narrower than the original raw
value cap because the frame carries the expected hash. No external digest,
parsed field copy, or observer controls are accepted in lieu of that scan.

The supported shape is a root object, one immediate nested object level,
and primitive arrays (up to 64 entries). Objects accept arbitrary key
order and at most 32 keys with up to 128 decoded UTF-8 bytes per key.
Uniqueness is over decoded keys within each object, including escaped NUL,
Unicode escapes, or raw UTF-8. Strings use the existing JSON scalar and
canonical UTF-8 helpers; primitive values include null, booleans and
original integer domains. Floats, overflow, leading-zero extensions,
negative zero (a float in the exact frozen original parser), malformed
Unicode/escapes, duplicate decoded names, and illegal trailing bytes are
refused. This structural profile covers ordinary bounded Activation JSON;
other legal JSON shapes are private scope refusals rather than universal
statements about the Rust parser.

Scratch requires 9,920 bytes. Input/output/scratch are disjoint; output
is never written. Status 0 means pin and bounded lexical scan succeeded,
1 means raw SHA mismatch, 2 means strict JSON refusal, 100 private frame,
102 scratch capacity, 103 private shape/key/collection cap, 104 internal
SHA failure. This does **not** deserialize or accept the typed envelope,
check fields or activation bits, prove provenance, call an observer, or
create material/authorization. The paired tests execute the immutable
original private SHA and JSON functions and full original activation on
ordinary synthetic 1/64-token positives as additional reachability evidence.
