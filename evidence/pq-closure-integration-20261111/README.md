# PQ closure integration evidence — 2026-11-11

This package preserves three separate observations. It does not qualify the chain, proof system, quantum work, production deployment, or a release.

| Observation | Source | What is established |
| --- | --- | --- |
| Local adversarial gate comparison | C0 `8add285b6c0a91d8b7812efe2d02c9342f74c91b` versus repaired gate bytes | The original gate accepted six source forgeries; the repair rejected all six. Both unchanged baselines passed. |
| C1 candidate | `c09dbbe9921da12db8bf7240a8a95a0e9a789e50` | Pending validation. The repair and six generator/roster source hashes match C1 Git objects. This is source correspondence, not a completed C1 test or CI verdict. |
| Original hosted PR #894 observations | `31543fb6dde565b62b47436e0b1d399b6d0bd772` | Original campaign failed its criteria in all 9 phases across 3 runs; original CodeQL export timed out with empty analysis/check API responses. The artifacts were read, not rerun. |

## Local C0 comparison

`c0-adversarial/` is an unaltered byte-for-byte copy of the retained comparison directory. It includes the six old-gate acceptance logs, six repaired-gate rejection logs, both baseline logs, original and repaired workflow/gate snapshots, the original reproduction script, `comparison.json`, and the run log. Empty stderr/stdout files are deliberately retained and hashed.

The six mutations replace the historical blob OID, historical regular-file mode, mutually corroborating historical source rows, current source revision, current contract digest, and current closure plus its count. Each repaired rejection names the appropriate historical mapping/materialization or current mapping comparison. Qualification flags remain false.

The comparison harness uses actual generated mapping reports and isolated inert completion fixtures. `real-supplemental/` separately contains the precommit execution records for the real 8 historical and 14 current controls. Neither observation is a full C1 validation. The original harness retains its recorded absolute workspace paths; the complete pinned repository and historical Git objects are prerequisites for rerunning it. Merely reading this package is not a rerun.

## C1 remains pending in this package

See `c1-validation-status.json`. Parent-reported storage exhaustion occurred before native tests started; it is not recorded as a failed native test. Any later C1 results must be added as a new exact-source observation rather than changing these historical records or relabeling the precommit evidence.

## Original hosted campaign: 3 runs, 9 failed phases

Run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42943021545

The raw `results.json`, three original step/result records, original stdout/stderr logs, source identities, and three `campaign-failure.json` records are retained under `hosted-315/campaign/`. Each original run returned 101. All nine phases have `finite_phase_criteria_met=false`, `all_signed_rounds_confirmed_in_window=false`, `receiver_client_state_equal=false`, and no genuine budget depletion. Each phase records `PUBLIC_REQUEST_DEADLINE`; these observations do not by themselves establish a unique root cause.

The existing phase summary is copied without alteration. Every direct and computed field was independently checked against the three full original report JSON members, whose sizes and SHA-256 values are recorded in `campaign-summary-verification.json`. The large reports and binary/database payloads stay in the original ZIP. No campaign was executed during packaging.

## Original CodeQL export and separate default-setup observation

Run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42943021758

`hosted-315/codeql/` preserves the original result/target/source records, raw analysis/check/selection JSON from all 38 polls, and original exporter-control/preflight logs. Every poll has no API-visible analyses or head/merge checks and `ready=false`. The final export has `complete=false`, an explicit deadline error, no authenticated PR gate, and no gate verdict. Empty API returns are not evidence of zero vulnerabilities or a complete scan.

`hosted-315/local-observations/codeql-default-setup-observation.json` is a separate read-only configuration GET observation: configured languages are Actions, Python and Rust, with the returned configuration update timestamp. It does not close the original API export gap or prove which analyses completed during that run. No workflow, repository security setting, or gate was changed while packaging.

## Source verification and retained archives

`archive-references.json` preserves each original ZIP path, byte size, SHA-256, Actions run/artifact IDs, archive download URL, creation time and expiry. Raw structured API metadata is retained under `hosted-315/local-observations/`; its declared archive size and digest were checked against the actual local files.

The 76,625,544-byte campaign ZIP and 214,538-byte CodeQL ZIP are not duplicated. Every declared embedded-manifest member was independently read and hashed: 1,765 campaign members and 198 CodeQL members. The campaign manifest declares both sizes and SHA-256; the CodeQL outer manifest declares SHA-256 only, so the verification distinguishes embedded size claims from ZIP-entry size checks. `archive-read-verification.json` records the exact scope. None of these integrity checks executes or certifies the workload.

`package-manifest.json` inventories every packaged payload with its original file/member provenance and exact bytes/SHA-256. `SHA256SUMS` additionally covers that manifest. `verify_bundle.py` verifies the compact package and, with `--archives`, checks the original ZIPs at their recorded paths. It does not rerun any test or CI workload.

Suggested repository destination: `evidence/pq-closure-integration-20261111/`. Integrate this directory as a whole so raw failures, baselines, source identities and pending status remain connected. Keep the large ZIPs outside Git and use the recorded artifact references. Later C1 results should be separate files with their exact commit and execution scope.
