# Six-capability continuation 5176 — research HOLD

Date: 2026-11-08 America/New_York. Parent: `e798d7125724d4b9f98c24d00cc80031f2eab4a9` ([PR #821](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/821)).
This additive candidate does not activate production. Independent acceptance and complete PQ/quantum/lifetime qualification remain false; unknown security bounds remain null.

## Corrections and development observations

| Change | Measured result | Boundary |
| --- | --- | --- |
| M12 V2 payment readback checks the whole journal's latest owner anchor, including advances by other claims | At `58851cf923f6a8b7190b50228b30f3e82a682f9c`: two original-red regressions, then 70 package tests and two compile-fail doc-tests pass; strict Clippy passes | Native SQLite journal with fixture owner callbacks; no real external payment |
| Durable legacy schema reader separately binds historical and current selected openers | Original 71-method suite fails; repaired 73 pass; four independent targeted controls pass | At `b8044adbbb3be4c04c46273a27456d64d63b8f9d` plus recorded patch; source/schema observation only |
| NPQ6 distinguishes null-enum JSON rejection from non-null witness rejection | Red: 3 pass, 1 fail, 1 ignored. Green: 4 pass, 1 original export experiment ignored | All twelve invalid configurations, independent config pin, unchanged database, absent initialization marker and no-fallback assertions remain; production parsing is unchanged |
| Separate current W1 mapping reconstructs retained artifact/control/FRI bindings | At `6f2c5ce28bf39fd4548f6312d2eebe363c77da4b`: 20 original observer and 14 new mapping controls pass; 49 Git blobs and 24 selected upstream sources bound | Both historical source guards must still refuse; original QROM rosters/workflows remain incomplete or failed |

The historical opener retains SHA-256 `63905b7095fe69d6036775847e604eae33faedbbfca5d8997664a68a5f889671`.
The current opener independently requires `088b58a4072271bb60772bfacab6cf06ec4052700cef46f92708453d8b9a07be`.
Closed selector, delegation, header, mode binding and complete body must all agree. Mixed/relabelled profiles and bypassed read-only recovery fail.
Historical source `9f23cd8bde5b06e5d0909521689f0dc7b6d185b8` still extracts the same 5,404-byte legacy DDL. This does not qualify Growth/PQ storage or transitive helper behavior.

The CodeQL branch filter now includes the two actual stacked candidate bases, so real head/merge SARIF can be produced. The original read-only exporter's missing-result refusal and default Code Scanning setup remain unchanged.

## Newly generated research proof

A newly compiled scheduled-SHA P3 backend generated one complete W1 research proof set, containing two STARK components; a separate verifier process accepted it. Prove wall time was 8.991 seconds and verify wall time 0.968 seconds. Eleven ordinary negative controls refused at their expected stages. The current binary is bound to 15 committed source/manifest/lock inputs and SHA-256 `14b779f433b6dcec86bad1f4e5df09c9b7fc8e421ad0fb93bb0800e356ee1a45`.

The statement remains the fixed retained native fixture. Deterministic output equals its historical proof bytes; the fresh prover did not read that old proof. This is a real generation event with create-only output, **not another independent statement sample**. SHA proof: 3,142,981 bytes; arithmetic proof: 454,085 bytes. Research resources were eight CPU cores and 8 GiB memory; swap was not disabled and the host was not exclusive. The original 0.25-core/2-GiB/zero-swap public profile, same-resource net benefit, complete noninteractive soundness and quantum work remain unqualified.

## Original hosted failures remain failures

At exact #821 head `e798d7125724d4b9f98c24d00cc80031f2eab4a9`, 23 observed workflows ended at 16 success / 7 failure.
The original [native campaign run 42532330453](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42532330453) produced 1/3 scheduled baseline confirmations in each of three repeats and 0/3 in both pressure modes in every repeat. Baseline successes ended at roughly 28.09–28.11 seconds. Original deadline failures and denominators remain. The earlier all-zero campaign is a different run.

The original campaign archive is 69,957,763 bytes, SHA-256 `fc54e7c68680177d30f650faef8b7ca1f8838cd33e92adbf60228590b31974a7`. Its readback and member identities are retained. The complete large hosted archive is not duplicated here; selected raw text/JSON evidence and its inventory identify this retention scope.

No successful source check establishes a universal work-cost bound, joint work/time security, independent payment or custody, model generalization, or production release.
