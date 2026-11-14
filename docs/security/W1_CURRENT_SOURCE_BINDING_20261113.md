# Reviewed W1 current-source bindings, 2026-11-13

## Scope and frozen source

This maintenance change binds already reviewed source identities to
975ab0937243949b73cdbea9f13902802bbd7d00 (tree
c0810db148ae919b2fba75f97ef7aa98beb977c9). It repairs exact source correspondence
and historical evidence selection. It does not grant production activation,
consensus admission, current proof use, a cryptographic theorem, or a lifetime
failure bound. All existing HOLD, false and null qualifications remain.

File bytes fields are exact input identities, checked together with SHA-256.
Updating them after a source review does not change any protocol, CPU, memory,
proof, lifetime or business budget. Reader MAX limits remain unchanged.

## Current W1 implementation inventory

The existing 139-input local inventory changes only the workspace Cargo lock,
crypto Cargo manifest, crypto lib and protocol lib. The exact old objects are
f3f53a76db2867c8906f0aea49ad83a6954d3ef4,
13476fe3b43eb0703ef4b4a982620087bda7243f,
7d7c8623a2fe93b1423be9cd4e4b3283d77ef63d, and
dab61b4530e213ce4547300a058cf9d067f3f86d, respectively. They match the separately
reviewed dependency and source deltas. The dependency graph is a declared lock
resolution, not an audit of third-party implementations. Crypto decoding keeps
canonical checks and rejects weak keys; validated protocol deserialization
narrows acceptance through the existing validation.

Complete enumeration of the six crate directories also identifies the ordinary
trnm-crypto-primitives/tests/ed25519_rfc8032.rs vector source, Git blob
eac60d75e72af744c481a68cb184b5b0ba140c70. It checks two published signing and
verification vectors, has no new production entry point or literal includes,
and raises the enumerated inventory to 140. The other 135 prior rows, all six
crate roots, eight literal includes, 16 selected project sources, saved proof
materials, proof parameters and 15 unresolved obligations stay unchanged.

The complete directory comparison and original unlisted-source refusal remain.
This inventory still does not enumerate external Rust #[path] imports or the
full third-party build graph.

## Dependent route and profile declarations

The STARK registry changes only its current mapping input and the independently
frozen digest of its 18-input roster. The other 17 inputs, all route parameters,
the literature baseline and recorded PDF identity are unchanged. The PDF byte
count describes the historical PDF, not the smaller manifest file.

The proof-profile descriptor and upstream-withdrawal record bind the same new
mapping bytes. approved_current_profile_ids remains empty, and the selected
upstream profile remains withdrawn. No P3 source lock or sampling parameter is
changed; its ordinary source reader consumes the same STARK registry.

## Lifetime observation and historical evidence

The 20 selected lifetime paths keep their order and original historical SHA-256
pins. Six current rows differ: crypto Cargo, Cargo.lock, NPQ6 application parsing,
node store, consensus test vectors, and the quantum-resource declaration model.
The reviewed NPQ6 change counts completely parsed envelopes before applying the
quota while retaining framing and length rejection. Store changes retain full
W1/M06/output/readback completion ownership and the selected hash/work checks.
The consensus delta is test-only. The declaration model rejects inconsistent
T-depth/T-count/total-depth premises; it supplies no physical measurement.

The exact original reader is preserved under
tests/fixtures/w1-lifetime-historical-7150/ledger.py, with Git blob
5e7c8681813baedc88890adacc2fd275b486093a and SHA-256
7e494ba406c63442dfbd17147d006b967cb07d7f6c886ce5779a0f2f05fceef6.
Its containing commit is 1a14f7d4826363daefac9ec10131c66d7e70ece7; its own
SOURCE_BASE remains 7150d96a2112875b4afcf3023361a5cef4a0e4b1. These identities
have different meanings. The current successor ledger is unchanged.

The fixture contains only the existing finite accounting and source reader.
It is not current consensus code or a fallback. CLI use explicitly passes
--root; current-source refusal still requires exit 2 and no successful output.
The current observation keeps the original function in a private, separately
pinned context and makes no historical positive-replay claim.

The fixed closure-historical CI job still checks out 1a14f7d4. Its input and
comparison paths now point to that commit's original lifetime and semantics
evidence. Current observation and historical positive evidence remain separate.
All existing named control identities, including the original frozen roster,
are retained.

## Hash-use review boundary

The 31-source/19-use manifest changes five current source identities and the
dependent proof-profile descriptor. Its independently frozen semantic digest
remains 29189f8e96a255472577479d46204b2b403a1f8e27806da6aa616e417ced0b5b.

The selected full-payload, transaction-root, chunk/BEP52, content-graph and
bounded migration hash bodies retain their algorithms, domains and widths.
The Cell store adds a bounded atomic single-chunk write using existing complete
payload checks and transaction/quota guards. Other deltas export new APIs,
declare a cache module or add scheduling completion bookkeeping. Those added
APIs and bookkeeping purposes are not silently included in the 19-use inventory.
The prior complete-callgraph, source-refinement and qualification limitations
remain false. The bounded migration keeps its original 32-block and 32-MiB
limits.

## Validation boundary

Required validation is the affected ordinary source readers, static contracts,
and existing finite provenance controls, including retained historical refusal
and exact inventory checks. No native proving, mining, campaign, stress,
depletion, or exploit reproduction is authorized by this source-binding change.
The immutable review records retain the original failing observations and the
exact before/after source identities; passing source readers would establish
correspondence only.

## Unmasked historical-job and candidate-descriptor dependencies

Once current source pins could be read, the existing current CI controls reached
a second independent check: the fixed historical QROM job had later current-source
materialization and supplemental controls mixed into its 0c830e0 checkout.
Those later helper files do not exist in that checkout.

The original 38,257-byte job segment is recovered from workflow Git blob
72292b4641dafc36be9f287aa24cc1f9271a9933 at
a715b2c8e89732ce356ebae67f978ef232156c04 (also 8f4d69a5). Its SHA-256 is exactly
the already frozen f88c5e041b943ea39be2de6665e9621b0b6a0c056c44dcae2a6215615eb6b130.
The validator's historical digest and fixed 0c830e0 source identity are unchanged.
The original job executes finite Python source/saved-fixture mapping and
conditional arithmetic; this repair adds no native, mining or depletion task.

All six current-source step bodies are relocated under the existing current
head/prospective-merge job, using its own supplemental output directory. Only
step identifiers, references to those identifiers, and that output variable
change within the transferred bodies. The full 8+14 named receipt checks,
historical Git materialization, current refusal, current mapping, unknown and
hypothetical arithmetic, and exact source-derived report comparisons remain.

| Observation | Required source / owner after repair |
| --- | --- |
| Original 81-name V1 controls and positive mapping | Fixed 0c830e0 historical job, unchanged segment |
| Current named controls, V1 refusal and V2 mapping | Existing exact head/prospective-merge job |
| Eight historical-materializer controls | Current checkout; historical objects read by exact commit/blob, with replacements and lazy fetching disabled |
| Fourteen supplemental current controls | Same current checkout and unchanged 22-name supplemental roster |
| Historical/current reports and arithmetic scope checks | Current job's separate supplemental directory, all original checks retained |
| Final supplemental completion | Current verifier independently rechecks both named receipts; every relocated stage is required |

The named test identities, historical 81-name and current roster hashes, source
before/after checks, event and checkout identities, and both original 20-minute
job ceilings are unchanged. The existing failure/skip tests now cover each
relocated stage and missing supplemental receipts.

The exact candidate profile descriptor is independently recomputed before and
after this mapping update. Only mapping_contract_sha256 changes within its
descriptor; selected proof identity, project and saved-source digests and
upstream snapshot remain identical. The old descriptor
0d47e23d395d6332a0bdf1c9093cf5b19816aad9841e3db6e8cb24f53e0f18b3 becomes
89e80683454b5b5e0152c0454602f0cf631e88ab1da62aaac18a350391fdaf69.
The candidate workflow and fixed test assertion bind that reviewed value.
Exact descriptor mismatch refusal and the upstream-revoked HOLD remain.

## Actor error-contract binding on the reviewed combination

Combination 80ee3a6ad326662074b329d4c9b7c04a5580b504 includes actor correction 1166b1661b389104b2209fc71dd9a81f263f17a1.
Only crypto/lib.rs changes within the 140-input closure: 10,395 to 12,112 bytes,
with new SHA-256 83fe52804bfbc593e2768c3a88764b532539deb8c9e866ee7305286491e16115.
The six crate roots, eight literal includes, 16 selected proof inputs and all other 139 inputs are unchanged.

Canonical encoding and point checks still precede weak-key refusal. A typed marker keeps
the same display text and lets the operator preserve ACTOR_WEAK_KEY. Identity, later
weak-key and fixture-denylist checks remain. The mvcc caller is outside this W1 closure.

The source-map change flows through STARK, profile/upstream, candidate and hash-use
source pins. Selected proof identity, 19 hash-use semantics, all business/MAX budgets
and false/null/HOLD fields remain fixed. The previous exact candidate descriptor is
added to the existing ordinary refusal control. These metadata controls do not execute
native code or confer current-proof-use eligibility.
