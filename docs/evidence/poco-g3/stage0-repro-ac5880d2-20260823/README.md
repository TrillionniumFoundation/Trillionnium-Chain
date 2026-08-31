# Stage0 X230 reproducible-build observation — ac5880d2

This directory records a current-candidate manual-SSH build campaign on the
X230 self-hosted runner. The strict clean source candidate binds commit
ac5880d2c9cadfbdbcf04bb294f499ad16ccecb6, Git tree
f6e6079ba172ed3454e93402dba37d8659f32719, empty Git status,
trillionnium/Cargo.lock SHA-256
72e254afa47d8b92fe8803b35869990bcfaa7f8106d9f0d4ecb45d127fbe150b, and
source-candidate SHA-256
36491b5b4070f30aa1904e0ed5d0d219598abb06e4121b43581a7f2cf989ff89.

The first X230 invocation used the frozen v1 builder and completed two
independent offline Cargo release builds. A second independent invocation is
preserved as build-b; both invocations agree on the validator and
material-builder hashes and the directory passes the deep verifier. This
record proves current-candidate native build identity only. A tracked v2
wrapper was also run against the same candidate; its schema-3 report is
preserved as v2-build-report.json and produced the same role hashes
(ea895802… / 1fa700c5…) in this environment. Because the v1 and v2 outputs
matched here, this campaign does not claim a differential rust-src drift
observation; the typed remap-fix bit therefore remains false. The runner used
Rust 1.95.0,
manual SSH, and no paid CI. Host identity is not cryptographically attested.

The current reports deliberately keep production_activation=false,
validator_run_7_completed=false, and all multihost/geo/performance claims
false. This is a native Linux build observation only; it does not prove a
running validator, P2P admission, restart recovery, or production readiness.

The candidate tar, Cargo registry cache, and output binaries remain unbundled.
Their hashes and byte lengths are bound in manifest.json and the two raw
reports. Deep verification (with out-of-band files) is:

~~~text
python3 scripts/poco-fleet/check_stage0_reproducible_build_evidence.py \
  docs/evidence/poco-g3/stage0-repro-ac5880d2-20260823 \
  --source-candidate /path/to/candidate-a.tar \
  --validator-binary /path/to/trnm-poco-lab-validator \
  --material-builder /path/to/trnm-poco-lab-material-builder
~~~
