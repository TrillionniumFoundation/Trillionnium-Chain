# Selected PFT research readout: local observations

The fresh `trnm.pft.selected-research-readout.v1` profile computes through the
actual selected catalog and its original SQLite writer fence. It uses the
existing pinned loader and binary64 core, checks the caller's live boundary
through arithmetic, and returns only an observation. The previous inspection
profile does not gain execution semantics. Host permission, physical resources,
withdrawal and any later external effect remain their original owners.

[LOCAL_OBSERVATION.json](LOCAL_OBSERVATION.json) records the scopes and limits:

- Original #1028 owner controls: 4/4, 686.210791735 seconds including cold build.
- Changed-source native PFT controls: 34/34, including four new real-owner
  controls; 502.531419561 seconds including incremental build, 0.12 seconds in
  the test body. These are 34 distinct current controls, not 38.
- Strict native library/test Clippy: exit 0, 136.248777649 seconds.
- The fixed original metadata roster: 131/131, 415.096259468 seconds.
- Actual current-source reader: 2,642 declared paths, exit 0 in 2.205402735
  seconds; 2,613 frozen originals and every false/null qualification retained.
- Whole-workspace formatting, locked offline Cargo graph, and the unchanged
  inventory-generation policy passed. The inventory adds 13 paths, 1,753 to 1,766.

The original source failure at workflow run 46111934261, job 140877169345 is
preserved alongside its exact log. The earlier 180/240-second compile failures
remain in their original evidence. The new 900-second engineering build cap
does not replace them or the original four-second service objective.

[OBSERVATION_MANIFEST.json](OBSERVATION_MANIFEST.json) and
[RAW_OBSERVATIONS.json.zlib.b64](RAW_OBSERVATIONS.json.zlib.b64) retain 32 exact
raw files, deduplicating identical before/after snapshots. SHA256 map deltas
restore their original JSON formatting and bytes. Run
`python3 evidence/pft-selected-readout-20261128/verify_observations.py` from the
repository root to verify and reconstruct all original raw observations in
memory. The reader writes no files and launches no workload.

The observations precede this evidence envelope and final documentation pin
refresh; they do not attest a later commit. Public synthetic data verifies
numerical and owner boundaries, not learning utility, source independence,
physical cost, service latency, Hepta FinalUse, whole-chain PQ safety, a BP
speed advantage, or foundation-model equivalence. The existing SQLite I/O
boundary remains explicitly UNQUALIFIED in the native build logs.
