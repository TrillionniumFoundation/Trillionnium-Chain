# Integration observations

The original native campaign and source identities are retained without edits.
The first root precommit whitespace check found an extra terminal blank line
in the added Cargo manifest content. Its raw failure is retained in
precommit-whitespace-failure.json. Only the extra terminal newline was
removed; parsed TOML before and after is identical.

This is a post-campaign manifest formatting change. The measured hash/profile,
scanner, AIR and backend Rust sources remain unchanged. The only new Rust
example after ABBA is the separately measured structural-controls harness.
Do not relabel historical source receipts as the final commit. The subsequent
exact-commit checks and independent proof replay have their own output records
and compare the measured executable hashes again.
