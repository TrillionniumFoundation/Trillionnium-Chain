# V5 cost-context reader: freshly rebuilt checks and historical compatibility

This evidence was created anew after the previous temporary workspace was lost.
It does not restore or certify the unpublished `bb358a91` source, binaries or
local measurements. The original reader snapshot below is from remote commit
`540d72356a921da31dde1113537382e5c0f0c4fd`; the enclosing commit identifies the
rebuilt implementation. No native miner, admission routine or historical
executable was run for this reader-only evidence.

## Repaired boundary

The original V5 reader checked that paired producer arms agreed, but did not
independently bind that agreement to the frozen native header and work context.
The same synthetic positive now passes both readers, while seven coordinated
mutations pass the actual original reader and fail the rebuilt reader:

| Synthetic mutation | Original reader | Rebuilt reader |
| --- | --- | --- |
| All recorded challenges replaced | Accepted | Refused |
| All header bytes replaced with zeroes | Accepted | Refused |
| All claimed targets changed | Accepted | Refused |
| All claimed tasks changed | Accepted | Refused |
| All state commitments changed and every challenge rehashed | Accepted | Refused |
| All winning and retained packet sizes shortened consistently | Accepted | Refused |
| The last missed challenge changed across an exhausted paired cohort | Accepted | Refused |

[red-green.json](red-green.json) contains actual reader outcomes and source
hashes. [reproduce_reader_counterexamples.py](reproduce_reader_counterexamples.py)
reproduces them using the retained [original reader](original-reader.py.txt).
These synthetic records are parser counterexamples, not measured mining costs
or forged work accepted by the native consensus.

The rebuilt reader independently reconstructs the original evaluation and
continuity profile commitments from configuration, the deterministic maintenance
matrix task, the nonzero initial target, canonical header fields and every
recorded nonce challenge, including misses. Every winning packet must have the
original complete 49,508-byte encoding. Exhausted synthetic controls preserve
the real target; they no longer create exhaustion by setting it to zero.

The complete seed header is additionally pinned to the actual original native
fixture's SHA-256:

`a6b5eb9020a41796ccd885b6c3051a4b12585e77c35269e26dcfc7ab6a4c4204`.

This exact fixture check binds the parent, miner, state, receipts and seed nonce,
including coordinated substitutions followed by challenge recomputation. It is
explicitly **not independent genesis/application execution**. The reader keeps
its standard-library-only dependency boundary. Its new
`pon-legal-ticket-fixed-context-v1` summary also states that full transcripts
and native consensus admission were not reexecuted. Repeated sibling ticket
observations do not acquire chainwork or rewards; the target-derived work totals
are conditional accounting only.

## Actual historical positive compatibility

The selected original artifact is
[x64 artifact 12884798290](https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/12884798290)
from [run 40845715652](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40845715652),
source `974932be6dcfe830ce1ce92d58cb10e89cb8358d`.
The 26,399,254-byte ZIP was downloaded again and its bytes matched the digest
returned by GitHub. The selected original files are retained unchanged in
[historical-v5](historical-v5/), with their hashes in [artifact.json](artifact.json).
[github-artifact-metadata.json](github-artifact-metadata.json) preserves the
independently retrieved GitHub metadata; the full ZIP remains in temporary
storage and is not included in this directory.

| Actual recorded quantity | Result |
| --- | ---: |
| Cohorts / fresh experiment databases | 144 |
| Searches | 11,844 |
| Attempts | 22,590 |
| Hits / first-admission calls | 11,772 |
| Misses | 10,818 |
| Distinct packet IDs | 654 |
| Distinct seed templates | 1 |
| Seed nonce | 3 |
| Rebuilt reader exit status | 0 |

All original header, task, target, network and parameter bindings, and all
recorded nonce challenges passed. The original aggregate fields are unchanged;
see [compatibility.json](compatibility.json),
[hardened-summary.json](hardened-summary.json) and
[reader-process.json](reader-process.json). The source record in the summary
still identifies the historical producer; the reader process separately records
the current reader/configuration hashes and current checkout commit. These
identities must not be conflated.

## Current test observations

| Check | Result | Evidence |
| --- | --- | --- |
| Reader controls | 22 passed | [process](reader-tests-final.process.json), [output](reader-tests-final.stderr.log) |
| Paired diagnostics controls | 8 passed | [process](diagnostics-tests-final.process.json), [output](diagnostics-tests-final.stderr.log) |
| Original-vs-rebuilt reader execution | One shared positive; seven old-accept/new-refuse cases | [raw result](red-green.json) |
| Recovered original x64 capture | Accepted unchanged | [process](reader-process.json) |

Initial successful test outputs are also retained. The final test processes bind
the three modified Python files before and after execution. Whole-worktree
commit identity and current native execution are separate root-level gates;
this directory does not claim that these historical captures were newly mined.

The effective minimum cost over unknown algorithms, hardware, batching or
precomputation remains unqualified. This reader repair cannot establish public
service availability, work hardness, model usefulness or quantum security.
