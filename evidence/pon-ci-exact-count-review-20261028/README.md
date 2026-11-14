# Exact CI denominator update

The old e25 workflow results stay failed. Four priority service lanes executed 160/160 Rust cases, including nine unique owned-reserve selectors and four final-sample selectors; the subsequent literal seven-selector check refused them. Four branch lanes executed 36/36 unique migration selectors; the literal 35-result check refused them. A fork emits one duplicate success line, which is not an additional test.

The retained source/selector review supports only these exact literal updates: priority reserve 7 to 9, branch owned-reserve 7 to 9, and branch migration 35 to 36. Both new reserve tests apply on the Linux-only lanes. No test/filter, failure allowance, ignore count, resource limit, time limit or confirmation count is reduced. The branch owned-reserve step had not yet run in the failed jobs; it receives no retroactive runtime pass.

The detailed review also records that an older partial-reorganization fixture had changed its injected failure to preserve the intended staging path; it does not claim all 35 older function bodies are identical. The new cancellation lifecycle case and all older selector names remain present.

These changes do not close native campaign, History, PQ, model, or WAN acceptance. Full original logs and hashes remain in the audit readback evidence, separately from this source patch.
