# Selected W1 lifetime source survey at the authority checkpoint

This successor binds the same twenty selected source paths to the real runtime
checkpoint `ef6df12a042912664df64f2112c2b1c600dce9fa`. The only changed source
identity relative to the previous survey is
`trillionnium/crates/trnm-pon-node/src/consensus.rs`. Commit
`ce4c5e7a6bc7e69805698b3e1131b425d093eceb` factored a test helper and added
versioned Python domain vectors inside its test module; the surveyed runtime
`required_work` and `retarget` definitions were unchanged.

The [previous twenty-path report](../pon-w1-lifetime-current-20261109/project-report.json)
and its [input](../pon-w1-lifetime-current-20261109/project-input.json) remain
unchanged. The current input is byte-identical to that previous all-unknown
input. The earlier hosted source-identity refusal for `consensus.rs` remains a
failed observation; this successor does not relabel that invocation as passed.
The existing negative control now also checks that the actual consensus blob
from `189b9b5959d836ef6ae96e14fb285948e4920aa9` is rejected by the current survey.

No accounting formula, count or byte limit, numerical assumption, proof
parameter, lifetime bound, authorization rule or qualification flag changed.
This is selected source consistency only: it supplies neither native execution
identity nor complete source/dependency coverage, a QROM theorem, a physical
quantum query budget, independent custody, production activation or a
whole-chain post-quantum guarantee. All security qualifications remain closed.
