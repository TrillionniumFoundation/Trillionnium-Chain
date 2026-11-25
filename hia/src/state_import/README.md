# StateImport forbidden-namespace predicate

`reserved_namespace.hepta` is a finite native port of the original
`trnm_state_import::forbidden_authority_namespace` helper. On the pinned Linux
x86-64 direct and self-hosted backends its checked byte ABI accepts one
borrowed namespace span and two untouched mutable ABI spans. It returns `1` if any of the seven original
case-sensitive prefixes match, or `0` otherwise. It neither reads past a
short span nor treats a delimiter, a NUL byte, UTF-8, or case as special.
The original helper has no namespace-length filter; the checked callable is
limited to the stock 1 MiB span and does not impose the original caller's
distinct 128-byte row limit.

`hia.tests.test_state_import_namespace` compiles the unchanged standalone Rust
function body from the current original crate with a transport-only observer.
It compares both native images, including exact prefixes, one-byte extensions,
truncations, byte mutations and the real 1 MiB callable boundary. It does not
link or qualify the full Rust crate, admit imports, decide row-digest/finality
validity, implement SQLite durability, replace an existing owner, or authorize
any signing state or production activation.
