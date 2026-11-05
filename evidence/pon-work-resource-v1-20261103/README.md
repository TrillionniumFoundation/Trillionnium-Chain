# W1 local legal-verification resource observation

**HOLD. Supplementary local allocation observation, not work-security qualification.**

The unchanged locked release library was built from baseline
`a1f6cd3411681d5f1295e1deadba0b639bb7d4d5` and the candidate working-tree
primitive. The candidate's exact `pon_work.rs` SHA-256 is
`a605dd18d967ec945ea7a4ae7d40549ee8d1ef9b9ce525c5214f5854e35123dc`.
This blob identity binds the measured primitive to the code in this publication;
the local working-tree observation is not a receipt for a clean final commit.
The parent commit named in the raw candidate record is provenance, not a claim
that the unmodified parent includes these changes. Final committed-source CI is
a separate validation record.

The identical safe Rust observer creates 24 complete legal proofs (eight dense,
eight zero-A/nonzero-B, eight sparse-diagonal-A/dense-B fixtures). Each is checked
by the independent scalar verifier and the native verifier. Complete proof
digests and results agree between baseline and candidate. There is no invalid
work generator or network campaign in this observation.

The separate glibc allocation observer counts successful `malloc`, `calloc` and
`realloc` requests. For each fixed executable, subtract the one-loop process
count from the two-loop process count. The only extra work is 24 complete native
verifications; proof generation, scalar verification and output are common.

| Per complete legal native verification | Baseline | Candidate |
| --- | ---: | ---: |
| Successful heap allocation requests | 22 | 18 |
| Cumulative requested bytes | 219,136 | 153,600 |

The difference is 4 allocation requests and 65,536 requested bytes per call
(29.9065%). These are cumulative requests, **not peak live memory or RSS**.
Timing outputs are retained, but a concurrent Node compilation affected the
initial four-process timing batch. No speed, throughput or CPU-rejection ratio
is inferred from those timings. The existing W1 module run recorded 113 passed,
0 failed and 0 ignored, with 12 non-W1 tests filtered.

## Retained material and limits

[observation-summary.json](observation-summary.json) contains the results and
scope; [manifest.json](manifest.json) binds the exact text files. The safe
[legal observer](valid_work_observation.rs), external [allocation observer](alloc_probe.c),
raw process output, build/launch records and test logs are retained. The failed
initial observer compilation is retained as well; its unchecked `write` return
was corrected without disabling `-Werror`.

Compiled executables, the shared allocation observer and rlib are not distributed
in this text bundle. Their observed hashes are provenance observations, not
authenticated execution or proof that a reviewer received those binaries.
This is one local x86_64 environment under the recorded 8-CPU-equivalent and
8-GiB limits. It does not measure complete producer setup/misses, cheap invalid
rejection, transport admission, state processing, durable storage, confirmation,
other architectures or public operation. It does not establish the cheapest
legal algorithm, close the prior rejection-cost failure, measure model benefit,
or change any work-profile, public-readiness or post-quantum qualification flag.
