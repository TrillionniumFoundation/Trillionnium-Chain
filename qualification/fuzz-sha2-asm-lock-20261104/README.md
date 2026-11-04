# Frozen fuzz lock qualification

This isolated branch diagnoses only the independent fuzz lock at owner `44d3def32f515b98fc41f074fe1b88e97f046191`. The six production/CI input files are byte-bound in inputs.json.

The hosted job preserves original `RUSTUP_TOOLCHAIN=nightly-2026-10-01` and locked fetch arguments. It requires a true exit-101 lock refusal; a download or compiler failure cannot stand in for that negative. Cargo generates a proposal in a fresh detached worktree, and the checked-in source stays unchanged. Full TOML package records restrict the result to the exact native-lock ASM record plus one SHA-2 edge, with no other package or metadata drift. Eight synthetic acceptance controls are separate from actual Cargo evidence.

Generated lock bytes, stdout/stderr logs and offline locked metadata are retained. Lock bytes are also emitted in bounded numbered base64 chunks for exact independent readback. No production lock is changed by the generator branch. Original complete fuzz/native/quality qualification remains open until run against a subsequently composed source. No local executable result is claimed.
