# History, correct-product false traces and fixed Host evidence

This branch preserves exact evidence bytes. It does not qualify PoN work hardness, public service, whole-chain PQ or production activation. Runtime code is identical to the measured `477cc47d75ac88583d35f0ddaa7be354a804c49f`; the separate test/CI follow-up is `dddad3988a665814fd2e331597f605d6ffa608f2`. The measured sources are never relabelled as a later source.

| Observation | Exact source | Actual result |
| --- | --- | --- |
| Correct-C false trace, x64 head/merge | 477cc47 / 5da0d8c; tree 0fd484d | Each 72 actual preparations, 288 searches, 577 trials, 288 Transcript refusals, zero semantic alerts; aggregate receiver/attacker CPU 5.3760253 / 5.3971154 |
| Correct-C false trace, arm64 head/merge | Same exact tree | Same deterministic search streams and counts; aggregate CPU ratios 10.8371282 / 10.8937773 |
| Original/fresh four-second hostile service | 477cc47 / 5da0d8c | All four pressure cases ACK seven; independent active height zero, confirmed zero, PUBLIC_REQUEST_DEADLINE. FAIL |
| Original three-run native campaign | 477cc47 | Nine executed phases, zero confirmations; 18 planned rounds unobserved. FAIL |
| Full hosted runtime, head and merge | 477cc47 / 5da0d8c | Each 836 passed, two original large-parent PUBLIC_MUTATION_CPU_BUDGET failures, 21 ignored. FAIL |
| Local full native_node | dddad398 | 31 passed, zero failed, two explicitly ignored; original Host positive delegated to actual hosted execution |
| Authenticated CLI original fixed Host | dddad398 / a0bd4d81; tree 425ab179 | Both real positive and unprovisioned negative run. Both positives succeed under unchanged 0.25 CPU / 2 GiB Host; source/ELFs and five actual PID memberships verified |

The four cost lanes repeat the same 288 search streams; they are not 1,152 independent mining samples. Ratios are complete primitive setup-plus-search observations for these finite strategies, not cheapest-work lower bounds or public-network attack multipliers. Diagnostic recording and generic product preparation remain avoidable costs. Source, build, release configuration, ELF, compiler and CPU clocks retain their own original manifests.

The single authenticated CLI fixture closes its missing-Host test-context problem. Its original four-second **server lifetime** is not a measured sync latency or the hostile service confirmation deadline. Neither that fixture nor local Clippy/source controls close the original four-second/six-depth/16-worker business gate.

## Retained bytes and identities

`manifest.json` identifies twelve split tar.xz archives, every compressed part, full original member inventories, source/merge/tree identities and the false qualification flags. Four hosted cost artifacts retain all 56 original members each. Three service artifacts retain all 53/1,766/53 original members. Two Host artifacts retain all 31 members each. The local validation archive retains the completed local logs and harness at its capture time; a separate runtime supplement retains both complete hosted runtime job logs. The final archive is an explicitly **uncompiled, unexecuted future V2 draft**, absent from the code branch; no reader or runner exists for that draft, so it yields no result.

Original GitHub ZIP container bytes are not copied into these tar archives. Their original SHA256 digests and sizes are retained in the artifact metadata and summaries. Every original regular member byte is preserved; SQLite sidecars introduced by independent readback are explicitly excluded and documented. Archived paths are original artifact member paths, not paths to execute or extract blindly.

The code and runs remain available at:

- [Code PR #675](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/675)
- [477 W1 observations](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41369097548)
- [477 original campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41369097681)
- [477 required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41369097704)
- [dddad actual fixed Host](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41372976388)

## Verify without extraction

Run `PYTHONDONTWRITEBYTECODE=1 python3 verify_bundle.py --root .` from this directory. The standard-library verifier checks top-level files, ordered part concatenation, complete tar.xz checksums and every declared member byte/hash without extracting archives. Supply `--manifest-sha256 <externally-pinned-digest>` to pin the manifest to an independent immutable reference. A consistency PASS authenticates neither execution nor custody and never changes qualification flags.

Run `PYTHONDONTWRITEBYTECODE=1 python3 test_verify_bundle.py` for small independent positive and tampering controls. Full native results require their retained original execution identities; verifier controls cannot recreate them.

Remaining gates stay HOLD: cheapest legal computation under algorithms/hardware/amortization/quantum strategies, original-budget honest service and large/long History, independently demonstrated model utility, whole-chain PQ and production activation. No main merge, protected-branch bypass or activation is part of this evidence commit.
