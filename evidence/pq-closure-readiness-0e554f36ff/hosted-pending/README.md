# C2 hosted required-baseline observation

At **2026-11-11 05:29:16 UTC**, PR901 was draft at C2 `0e554f36ffdde3053a5eb1756eb5e526b1935032`. Source-bound required-baseline run `42964980662`, attempt 1, had API status `pending` and null conclusion. The jobs read returned an empty array. Neither external-evidence-contract source lane had an observed terminal result or an executed 71-control count.

The archive retains exact connector responses, parsed data, observation times, and SHA256SUMS. The first workflow-filename collection fetch was rejected as an unsupported connector URL (HTTP 400 / INVALID_ARGUMENT); the supported commit-runs wrapper and individual run read then established this run. The URL rejection is not an authorization denial.

This is one bounded pending observation. It does not relabel local C2 tests as hosted passes, transfer C1 results to C2, or establish whole-chain post-quantum qualification. No workloads, H operations, or large artifact downloads were performed. C1 hosted evidence remains unchanged.
