# Operating scope

This repository does not install or activate a public consensus node. Use a fresh revision2
namespace for local experiments; old SQLite schemas and old genesis context are rejected.
Do not point candidate programs at deployed databases, secrets or real signing identities.

The reference Ledger can explicitly select the native M06 application through
`TRNM_NATIVE_EXECUTOR=/absolute/path/to/release/examples/pon_execute` and
`TRNM_EXECUTION_WORKERS=1|2|4|8`. Missing or mismatched binaries fail; reference fallback is
not automatic. Startup recovers its own initialization/reorg intent and best verified tip.
The subprocess bridge is a tested integration boundary, not a persistent production host.

Run `bash scripts/ci/ci_job.sh protocol-contract` after building prerequisites. The full
Rust lane uses locked dependencies, tests and strict Clippy. Preserve raw failure results
and declare filesystem and backend. Localhost experiments and public fixture keys never
become independent operators, physical durability or real Hepta user-task evidence.
