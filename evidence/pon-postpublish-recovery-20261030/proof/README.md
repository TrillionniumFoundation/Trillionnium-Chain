# Recovery of the successful complete-W1 receiver CI observation

This is a new recovery capture from the original GitHub Actions artifact after
the local environment was lost. It does **not** claim to recreate the previous
unpublished 72-file evidence snapshot. The 57 selected original small files are
recovered byte-for-byte from the pinned ZIP; this README, recovery metadata,
inventory and readback script were created during recovery.

The actual native execution remains the successful
[run 40988668868](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40988668868),
[job 123845534943](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40988668868/job/123845534943),
on commit `1d11f875493f8125e36b9adceacb342df108e5e5`, tree
`64b82137eebeb96b572abc62e5fce39af3593200`. Recovery did not execute a native
verifier, generate a proof or relabel these results as execution on a later head.

## Original execution and retained outcomes

[Run metadata](github-run.json), [job steps](github-jobs.json),
[artifact metadata](github-artifacts.json) and the complete
[decoded job log](github-job.log) were retrieved again during recovery.
Every recorded job step concluded successfully. The original source guards
[before](original/source-before.json) and [after](original/source-after.json)
are equal: 7,435 tracked entries and 960,706,544 tracked bytes, with the exact
commit and tree above and verified tracked working bytes.

| Original CI check | Recorded outcome |
| --- | --- |
| Bounded fixture controls | 39 passed |
| Case metadata reader controls | 15 passed |
| Locked native host build and tests | Build succeeded; 17 tests passed |
| Strict host/relation Clippy and formatting | Successful workflow step |
| Original full audit on the real proof | Positive verified; 16 negative controls rejected |
| Eight individually measured receiver cases | All expected outcomes observed |

The original process receipts, control logs and case reports remain in
`original/`; their exact file hashes are in [original-files.json](original-files.json).
The [new readback output](readback.stdout.json) derives these counts and case
observations from those retained records. The full original audit is
[original-audit.stdout.log](original/original-audit.stdout.log).

## Receiver costs and their scope

These are individual observations on the historical **Composite** receipt.
They are not new Succinct measurements or a replacement for the earlier
Succinct experiment. Each case first verifies the original real proof; that
separately measured positive prerequisite warms the verifier.

| Case | Actual outcome | Receiver time, ms |
| --- | --- | ---: |
| Valid receipt | Verified | 1272.364197 |
| First seal tampered | Verification failed | 50.405329 |
| Last seal tampered | Verification failed | 1256.471868 |
| Wrong verifier parameters | Verification failed | 29.542129 |
| Wrong statement miner | Verification failed | 28.926692 |
| Truncated receipt | Malformed encoding | 0.012643 |
| Trailing receipt bytes | Malformed encoding | 0.012954 |
| Seal-length allocation bomb | Refused without evaluation | 0.003917 |

The receiver interval covers bounded preflight, SDK decoding, strict verification
and decoded-receipt drop. It excludes file I/O, the positive prerequisite,
case construction, source and byte hashes, error formatting, JSON output and
process startup. These are single warmed measurements, not independent cold
trials, throughput estimates, end-to-end network admission costs or speedup
claims. The prerequisite costs are retained separately in the original reports
and the readback output.

Late-seal rejection still takes about 1.256 seconds in this observation, close
to valid verification. Correct rejection does not establish cheap rejection,
honest service under hostile traffic, a lower bound on mining cost or any
quantitative quantum-security claim. All original minimum-work-cost, public
ingress, PQ128 and consensus-authority flags remain false.

## Recovery identities and retained objects

The downloaded artifact is `12947349925`, named
`w1-audit-one-1d11f875493f8125e36b9adceacb342df108e5e5-1`.
Recovery checked the actual ZIP's **15,912,715 bytes** and SHA256
`8fc5e5d914ab2fa99b2b68388837c056fe4a347cc5636d3a12d7be3d96438131`.
All 61 members, totaling 22,289,086 expanded bytes, were read and hashed;
[archive-members.json](archive-members.json) records their identities.
The ZIP itself and the raw guest, input and receipt are not duplicated here.

Those three raw fixture hashes match the existing
[durable fixture manifest](../../pon-pure-security-20261030-rebuild/complete-w1/fixture-objects/manifest.json)
and the original [CI fixture binding](original/fixture-binding.json). The
original fixture is from artifact `12784520070`, run `40608715148`, source
`a54dc7355f58f40784b5a71fe7e73c4062a14951`. This is distinct from the successful
receiver CI artifact being recovered here. The existing
[complete-W1 evidence](../../pon-pure-security-20261030-rebuild/complete-w1/README.md)
is unchanged.

The actual CI verifier is retained as deterministic gzip, with an exact checked
raw round trip:

| Identity | Value |
| --- | --- |
| Raw verifier bytes | 5,990,744 |
| Raw verifier SHA256 | `eb79ac747509af6cf7942e26ca7ce74e3c0f74e944ae291129e8e319d8c50b43` |
| Gzip bytes | 1,787,512 |
| Gzip SHA256 | `41dbb44f484b8d68397cc05d8e3c6bccf342cfed8166cf3917b9ebd6c8a02929` |
| Gzip Git blob | `a8e5381079d01c3bbf140cb831f84f576c2673da` |

This executable is distinct from the earlier local verifier. Stable CI
before/after hashes and recovery's exact byte identities do not prove a
reproducible build or independent hardware authenticity. The gzip uses level 9,
mtime zero and an empty embedded filename. [recovery-binding.json](recovery-binding.json)
records the path, packaging, fresh recovery time and explicit scope limits.
Temporary signed download URLs are not retained.

## Readback and limits

From the repository root:

```sh
python3 -B evidence/pon-postpublish-recovery-20261030/proof/readback.py
```

The [new readback script](readback.py) checks the 57 original file hashes,
run/job/artifact identities, source guards, four durable fixture chunks and
whole gzip hashes, recovered executable, 13 process receipts, original audit,
eight case metadata bindings, control counts and the 15 embedded source inputs
against `git show` of the immutable execution commit. Its actual successful
invocation is retained in [readback.process.json](readback.process.json).

This is a metadata and byte readback. It does not reverify the proof, rerun SDK
mutation dispatch, independently reconstruct proof shape, remeasure timing or
repeat the full source inventory. Because the downloaded ZIP is not retained
in this directory, a later readback does not recompute its digest; recovery's
actual ZIP verification is recorded separately. Existing original CI reader
results are preserved as observations, not promoted into independent
cryptographic verification by this new script.

The [scoped inventory](files.json) binds the new recovery directory, excluding
itself. Future evidence publication commits do not change the native execution
identity or convert the remaining security and service questions into passes.
