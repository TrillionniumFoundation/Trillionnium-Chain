# Exact 9e05 focused native run: complete retained evidence

This folder records [focused run 40492528017](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40492528017), job `122149745379`, attempt 1. GitHub reports **success** for the job and every one of its 17 steps, including cleanup. The job ran from `2026-10-27T11:04:30Z` to `2026-10-27T11:20:47Z`.

The tested source was `9e05ad5d237660fb0ea8b40dd5c29af4225551d3`, exact tree `952666bff72a49d8bc7693b27ff747f56a56b240`. The full API run/jobs payloads and the artifact's original `source.json` agree. This evidence is separate from the earlier d961 run; no earlier execution result supplies a pass here.

## Complete originals and independent readback

[Artifact 12729798390](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40492528017/artifacts/12729798390) has 8,626,197 ZIP bytes and SHA256 `8c635be685ca8bc9a847521099ce7a34986d453281639ec311bfeefdbbc88821`, matching GitHub's artifact digest. Every one of its **29 original files / 10,931,279 member bytes** is retained in [the complete member inventory](artifact-members/manifest.json). Files already compressed with gzip are unchanged. Other member bytes use lossless gzip with mtime 0; each row records original and stored length/hash. No samples, failures, unsupported cohorts or log sections were selected out.

The [full decoded job log](focused-job.log.gz) contains 952,997 UTF-8 bytes. The complete connector response is also retained under `api/`; this is decoded-log preservation, not a claim about the original HTTP transfer encoding. An unsupported direct job-metadata fetch is retained separately as a capture-route refusal; the allowed run/jobs endpoint supplied the complete successful job payload. That tool routing refusal is not a CI failure.

[Independent reader results](readback/result.json) rerun the existing exact-9e05 cost, ingress and rejection-tail readers on all downloaded raw streams. All three returned 0 and produced **byte-identical** consistency JSON to the original artifact. Reader source hashes, command, interpreter, timing and complete stdout/stderr are retained. Recomputed JSON files are losslessly stored as `.json.gz`; command records preserve their names at execution time. No native campaign, build, model or proof was rerun for this capture.

## This run's finite observations

- Cost: all 3,456 declared cohorts, 605,024 attempts, 80,836 winning calls and 50,764 exhausted searches are retained. The 1,600 complete-cost summaries coexist with all unsupported cohort records in the original stream. Actual capture wall time was 282.578592011 seconds.
- Rejection tail: 83 cases, 9 rounds, 747 paired samples / 2,988 measured calls; all 64 product coordinates and trace digest bytes 0/16/31 remain in the complete stream. The capture identifies the retained public mathematical header fixture separately from the actual current-source binary execution. Finite p99/max is not a global rejection bound.
- TCP ingress: actual capture wall time was 105.386577965 seconds. Honest accepted p99 was 21.881358 ms initially, then 75.752861 / 72.131166 ms in the two hostile phases. All 10,516 hostile trace calls were refused; all of those reached full work. Honest accepted calls were 792 / 1,498 / 1,510, corresponding to 52.7360 / 33.2502 / 33.5113 calls per second in the three observed phases. Complete raw calls, budgets, packet identities, preparation costs and CPU observations are retained.

These observations came from one nonexclusive hosted machine. Fixed-parent empty-candidate calls are not chain-growth TPS or a WAN service guarantee. Dispatch CPU excludes reactor CPU; it must not be added to nested full-work CPU. This run does not close correct-C/false-trace full replay, work hardness, arbitrary-Sybil fairness, model efficacy, full-chain PQ or production activation. It is not a successful STARK receipt. No improvement is attributed by comparing timings across different hosts/runs.

## Required workflow remains separate

At the retained `2026-10-27T11:25:55Z` observation, [required run 40492528128](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40492528128) was still `pending` for the same 9e05 head, with no jobs. The full run and empty-job responses are retained. In particular the corrected external-evidence reader suite has **no required-CI pass claimed here**. There was no terminal required-lane failure log available at this observation; a later observation must be added separately, without overwriting this one.

[Capture metadata](capture-observation.json) and [the sealed file inventory](manifest.json) bind the identities and every retained file. API snapshots and raw member data remain the evidence; this README is only an index and scope explanation.
