# History #538 exact failure and retention repair

The original source `69973c229bafe9ff97c278c29f7b67ec5012c3dd` compiled, then its complete native group aborted with signal 6 after 427.692789821 seconds. The original Clippy check also failed. [Run 40630482334](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40630482334) and the hash-bound observation retain this failed attempt. Both raw failure logs are preserved here.

`Observed` declared its `TestAuthority` before its retention guard. Rust drops struct fields in declaration order, so its temporary fixture directory was deleted before the guard copied evidence. Two instances unwinding through this path caused a destructor panic and process abort. The retention guard now precedes the authority. This preserves the actual positive and physical-negative fixtures before cleanup, including assertion failures.

The compile-source requirement uses an explicit conditional refusal, preserving the same missing-pin panic and actual-source identity checks while removing the Clippy-rejected `option_env!().expect()` form. Ordinary compilation does not manufacture a source pin.

The full diff between old `store.rs` blob `ccc3d01d192eb80e2a837c5858c14e3ce4421ea9` and current `9ee9746e22a95eb77c65dce529fcade7002268d3` was reviewed: it adds a same-Startup material seal, requires it for History owners, retains the original non-History replay, and threads original checkpoints through both State reads. Only that stale recent-batch hash is rebound. The other fifteen pins, all four lanes, commands, assertions and budgets are unchanged.

Both complete format checks and five gate-reader controls passed during preparation. The repaired candidate must pass its own original 22/0/1 native group, strict Clippy, nine material controls and exact-source readback. No new native success is claimed by this document. The original 600-second suite, two-second burst, four-second allowance and four complete process snapshots remain mandatory. Whole History P0, partial initialization, reorg continuation and physical-host qualification remain open.
