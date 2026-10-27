# Exact-source CodeQL triage: PR #506 at 0c804e9f

**Original gate remains failure.** The 9 reported critical/high findings have been traced to their actual code, types, fixture keys and compilation boundaries. No production secret-disclosure or cryptographic-nonce misuse was established at these nine sinks. This review does not dismiss alerts, clear the security gate, or establish that the project is secure.

## Source and observation identity

- Head: `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`; base: `57c1ed545d067937cbd7aaa7570d5f22123265e6`.
- Check: `122144152932`, completed failure, 9 annotations: 5 critical and 4 high.
- Successful export workflow: `40490734470`; artifact `12728983944`, 327,831 bytes, SHA-256 `89951920a4efe0c84289b5cf2d18c301926d4624b4ee7f627bbdd19a42d6930b`.
- ZIP contents and all 138 outer / 134 inner manifest entries were verified. `original-nine-annotations.json` is a byte-identical copy of the exported page; the original ZIP and all original polling/check metadata remain intact.
- Rust analysis `2035397981`, CodeQL 2.27.3, explicitly scans `refs/pull/506/head` at the head above. It exposes 316 results: 289 hard-coded-cryptographic-value and 27 cleartext-logging. Actions and Python categories each expose 0 results. These are API-provided SARIF subsets, not the original full SARIF uploads or all historical branch alerts.
- Each of the 9 original annotations uniquely matches one Rust SARIF result by path, start/end lines, message, rule title, and every exposed column. Annotation 2 has no columns; none are invented. `triage.json` records this separate verified mapping without rewriting the exporter’s original `unproven` gate-association fields.
- The prospective merge `e22045b22fcda846d826243210c998a97d4559a3` is identity context only; these analyses are head scans.

## Nine-by-nine scope table

| # / alert | Reported rule score | Head location (under trnm-pon-node) | Base location | Actual domain and boundary | Review result |
|---|---|---|---|---|---|
| 1 / 1374 | 7.5 | `examples/lifecycle_atomic_continuity.rs:328` | 328 | public ledger sequence embedded in a serialized signed fixture transaction; example | No logging call at selected Vec removal; public fixture sequence. |
| 2 / 1377 | 7.5 | `src/ingress.rs:4148` | 3114 | public development account balance/sequence through an assertion outcome; unit-test | Test-only data/sequence; no demonstrated secret or crypto-nonce misuse. |
| 3 / 1378 | 9.8 | `src/ingress.rs:4222` | 3188 | transaction account sequence 1 on the left branch; unit-test | Test-only data/sequence; no demonstrated secret or crypto-nonce misuse. |
| 4 / 1379 | 9.8 | `src/ingress.rs:4234` | 3200 | transaction account sequence 1 on an alternative right branch; unit-test | Test-only data/sequence; no demonstrated secret or crypto-nonce misuse. |
| 5 / 1380 | 9.8 | `src/ingress.rs:4244` | 3210 | transaction account sequence 2 on the right-branch successor; unit-test | Test-only data/sequence; no demonstrated secret or crypto-nonce misuse. |
| 6 / 1375 | 7.5 | `src/ingress/public_v3/scalar_cpu_completion_tests.rs:297` | 296 | public development account data through a native dispatch outcome; unit-test | Test-only data/sequence; no demonstrated secret or crypto-nonce misuse. |
| 7 / 1376 | 7.5 | `src/ingress/public_v3/scalar_cpu_completion_tests.rs:394` | 392 | public development account data through a deliberately ROOT-invalid outcome; unit-test | Test-only data/sequence; no demonstrated secret or crypto-nonce misuse. |
| 8 / 1457 | 9.8 | `tests/public_v3_from_zero.rs:675` | new test line | public W1 header candidate counter 10000; integration-test | Public header counter in fake-trace rejection test. |
| 9 / 1430 | 9.8 | `tests/public_v3_multiprocess.rs:1903` | 1897 | public transaction account sequence 1025 after 1024 real signed seed transfers; integration-test-ignored-cost-path | Correct ledger sequence after 1024 signed transfers. |

## Why the generic rules do not establish these vulnerabilities

The exact query revision in the SARIF is `a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c`. Its `HardcodedCryptographicValueExtensions.qll:124–150` classifies a call argument as a cryptographic nonce when the resolved parameter is named `nonce`. The five critical results are consistent with that explicit name heuristic. The values here have different protocol semantics:

- In alerts 1378/1379/1380, local `transfer(settings, nonce, ...)` copies 1, 1, and 2 into public `Envelope.nonce`. The first two transactions belong to competing branches from the same genesis; sequence 2 extends the right branch. The native executor at `trnm-mvcc-fee/src/pon_executor.rs:1277` requires the transaction sequence to equal the prior account sequence plus one.
- In alert 1430, the helper uses the same public envelope field. Four seed blocks each contain 256 real signed transactions, producing account sequences 1 through 1024; 1025 is the legitimate next sequence.
- In alert 1457, `genesis_header` copies 10000 into `Header.nonce`. Header encoding/challenge binds this public mining candidate counter. It is neither a cipher IV nor a private signing nonce. The test deliberately requires four counterfeit traces to leave native state and chainwork unchanged.
- The signatures use publicly reproducible `DEV-ONLY-KEY` fixture seeds, not loaded operator secrets. `lib.rs:651–657` explicitly identifies these as public development identities. A constant `signature: [0;64]` is replaced by the actual signature before encoding in the transaction helpers. Replacing sequence values with randomness would break or change the intended protocol tests; it is not an appropriate response to this query.

For the four high-severity logging findings, `SensitiveData.qll` and the shared `SensitiveDataHeuristics.qll` infer sensitivity from identifiers including `account`/`growth_account`. The reported `Account` type has only `balance:u64` and `nonce:u64`. It does not contain a private key, password, encryption IV or authentication token.

Alert 1374 points to `partial.remove(123)`: the receiver is explicitly a `Vec<u8>` returned by serialization of a public, signed fixture transaction. Removing a byte is the intentional malformed-transaction negative case; it is not a log write. Even an out-of-bounds Vec removal would report index/length, not print the vector. The exact generated model that selected this receiver as a log sink was not isolated. The example is runnable and is not cfg(test)-excluded: it creates a new directory and development settings. That distinction is retained rather than using “test-only” for every path.

Alerts 1377/1375/1376 are genuine failure diagnostics, but all three are compiled only in unit tests; their actual fixtures open temporary development nodes and use public identities. Debug-formatting arbitrary future outcomes is broader than necessary, so narrowing those diagnostics to fixed case identifiers and already-checked public error codes can be useful hardening. It would not justify changing the assertions or declaring a production secret leak demonstrated by this dataflow.

## Baseline comparison and attribution

Eight of the nine selected sink lines are byte-identical to the base; only the new from-zero regression test contributes a new selected literal. `base-source-delta.json` records exact old/new blob IDs and line matches. The entire lifecycle example is unchanged. Scalar completion test changes are four `w1_rejection_cache: None` fields; the existing diagnostic strings are unchanged. The multiprocess fixed literal shifts by six lines due to the reviewed history-import observation wiring.

The Account type, both reported native-store sources, signed-transfer helper, native sequence constraint and development-key helper also have identical base/head blobs (`context-source-blobs.json`). Some surrounding call graphs changed. No same-version baseline CodeQL rerun was done, so this review does not assert why the service classified these results as new or that their base alert state was the same. The original check summary itself warns that a large diff may expose alerts not introduced by the PR.

## Narrow next actions; no changes performed

1. Preserve the original failed gate and these annotations. A maintainer can review the per-alert semantic evidence; this report does not dismiss or suppress anything.
2. If a source clarification is chosen, name the test-helper parameter `account_sequence` or `candidate_counter` and retain every public wire-field name, literal value, signed byte, assertion, selector and budget. This expresses the real domain and is not a cryptographic algorithm change. A new exact-source CodeQL run is still necessary; no pass is predicted.
3. For the three diagnostics, retain their predicates and failure coverage while considering minimal public-code/case-only output. For the Vec-removal result, investigate/report the precise upstream model or extraction behavior before changing this correct negative test merely to evade the query.
4. Review the other 307 exposed Rust results separately, and continue the project’s real key-custody/PQ/consensus security gates. A 9/9 local classification is not a 316/316 audit or a project safety proof.

## Reviewable original snippets

### Annotation 1 / alert 1374

**Original title:** Cleartext logging of sensitive information

**Original message:** `This operation writes [self.growth_account(...)](1) to a log file.`

**Conclusion:** The selected operation is Vec<u8>::remove(123), which mutates bytes; it is not a logging call. The byte vector contains a signed public development transaction. The selected taint origin is growth_account -> next_nonce, not private key material. No cleartext-secret disclosure is demonstrated at this sink.

**Compilation/caller boundary:** Separate Cargo example executable. run() creates a new directory and Settings::development_with_profiles; it is not the node daemon. It is runnable, so it is not described as cfg(test)-excluded.

[trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs:57–78](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs#L57)

```rust
   57 fn signature(who: u64, message: &[u8]) -> Result<[u8; 64]> {
   58     let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
   59         .map_err(|_| "DEVELOPMENT_KEY")?;
   60     hex::decode(sign_hex(&key, message))
   61         .map_err(|_| "SIGNATURE_HEX")?
   62         .try_into()
   63         .map_err(|_| "SIGNATURE_LENGTH".into())
   64 }
   65 fn transaction(node: &Node, who: u64, tag: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
   66     let sender = development_public(who)?;
   67     let mut tx = Envelope {
   68         network: node.settings().network(),
   69         sender,
   70         nonce: node.next_nonce(sender)?,
   71         expiry: 2000,
   72         fee_limit: 1_000_000,
   73         tag,
   74         payload,
   75         signature: [0; 64],
   76     };
   77     tx.signature = signature(who, &tx.signing_digest().map_err(|_| "TRANSACTION_DIGEST")?)?;
   78     tx.encode().map_err(|_| "TRANSACTION_CODEC".into())
```

[trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs:187–197](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs#L187)

```rust
  187 fn run() -> Result<()> {
  188     let (directory, blocks) = parse_arguments(&std::env::args().skip(1).collect::<Vec<_>>())?;
  189     fs::create_dir(&directory)?;
  190     fs::create_dir(directory.join("packets"))?;
  191     let wall_start = ingress::now()?;
  192     // All logical headers precede the observed wall clock. Ten seconds of header
  193     // spacing are not ten seconds of actual waiting. Fresh genesis is explicit.
  194     let genesis = wall_start.checked_sub((blocks + 8) * 10).ok_or("CLOCK")?;
  195     let settings = Settings::development_with_profiles(Some(genesis), POLICY, PROFILE)?;
  196     let bootstrap = settings.bootstrap_lifecycle_task()?;
  197     let (model, input, a, b) = settings.bootstrap_task_material()?;
```

[trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs:323–338](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs#L323)

```rust
  323                 invalid.push((
  324                     "window",
  325                     transaction(n, 1, 22, bad.encode().map_err(|_| "ATOMIC_CODEC")?)?,
  326                 ));
  327                 let mut partial = transaction(n, 1, 22, payload.clone())?;
  328                 partial.remove(123);
  329                 invalid.push(("partial", partial));
  330                 let original = n.read_active()?;
  331                 let stats = n.stats()?;
  332                 for (case, raw) in invalid {
  333                     rejection_attempts += 1;
  334                     let failure = n.make_with_task(
  335                         parent,
  336                         vec![raw],
  337                         development_public(3)?,
  338                         genesis + height * 10,
```

[trillionnium/crates/trnm-pon-node/src/store.rs:2157–2167](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/store.rs#L2157)

```rust
 2157     pub fn next_nonce(&self, sender: Hash) -> Result<u64> {
 2158         if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
 2159             return self
 2160                 .growth_account(self.active()?.0, sender)?
 2161                 .map_or(0, |a| a.nonce)
 2162                 .checked_add(1)
 2163                 .ok_or_else(|| "NONCE_OVERFLOW".into());
 2164         }
 2165         let state = self.state_at(self.active()?.0)?;
 2166         next_nonce_from_state(&state, sender)
 2167     }
```

### Annotation 2 / alert 1377

**Original title:** Cleartext logging of sensitive information

**Original message:** `This operation writes [account](1) to a log file.
This operation writes [account(...)](2) to a log file.`

**Conclusion:** Failure-only assertion diagnostic under cfg(test); its reported Account source has balance and nonce fields only. The helper opens a fresh development fixture. No production private-key or credential disclosure is demonstrated.

**Compilation/caller boundary:** ingress.rs #[cfg(test)] mod tests; helper existing_replay_cancelled_after_owner_acquisition called only by tests in that module.

[trillionnium/crates/trnm-pon-node/src/ingress.rs:2511–2517](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L2511)

```rust
 2511 #[cfg(test)]
 2512 mod tests {
 2513     use super::*;
 2514 
 2515     #[cfg(target_os = "linux")]
 2516     #[test]
 2517     fn history_paid_epoch_crash_cut_refuses_new_cold_credit() {
```

[trillionnium/crates/trnm-pon-node/src/ingress.rs:3599–3619](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L3599)

```rust
 3599     fn pending_packet_with_backend(
 3600         authenticated: bool,
 3601     ) -> (tempfile::TempDir, Mutex<Node>, Packet) {
 3602         let dir = tempfile::tempdir().unwrap();
 3603         let clock = now().unwrap();
 3604         let settings = crate::Settings::development(Some(clock - 100)).unwrap();
 3605         let node = if authenticated {
 3606             Node::open_with_authenticated_state(dir.path(), settings.clone(), 2).unwrap()
 3607         } else {
 3608             Node::open(dir.path(), settings.clone(), 2).unwrap()
 3609         };
 3610         let packet = node
 3611             .make(
 3612                 settings.genesis(),
 3613                 vec![],
 3614                 crate::development_public(0).unwrap(),
 3615                 clock - 90,
 3616                 4096,
 3617             )
 3618             .unwrap();
 3619         (dir, Mutex::new(node), packet)
```

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4109–4119](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4109)

```rust
 4109     fn existing_replay_cancelled_after_owner_acquisition(already_active: bool) {
 4110         for authenticated in [false, true] {
 4111             let (_directory, node, packet) = pending_packet_with_backend(authenticated);
 4112             let id = packet.id().unwrap();
 4113             {
 4114                 let mut owner = node.lock().unwrap();
 4115                 owner.admit(&packet, now().unwrap()).unwrap();
 4116                 if already_active {
 4117                     owner.activate_observed(id, now().unwrap()).unwrap();
 4118                 }
 4119             }
```

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4145–4149](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4145)

```rust
 4145             assert!(
 4146                 matches!(&outcome, Err(error) if error.is(ErrorCode::PublicRequestCancelled)
 4147                     && !error.requires_owner_stop()),
 4148                 "existing replay ignored cancellation: active={already_active} authenticated={authenticated} visits={} outcome={outcome:?}",
 4149                 visits.get(),
```

### Annotation 3 / alert 1378

**Original title:** Hard-coded cryptographic value

**Original message:** `This hard-coded value is used as [a nonce](1).`

**Conclusion:** Not a cryptographic encryption/AEAD or signature-generation nonce. The integer becomes Envelope.nonce, is public signed transaction input, and must equal current ledger sequence + 1. Fixed known development keys belong to this test fixture.

**Compilation/caller boundary:** Local helper inside cfg(test) reorg test; left branch starts from genesis.

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4183–4208](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4183)

```rust
 4183     #[test]
 4184     fn existing_replay_cancelled_reorg_recovers_signed_payments_once() {
 4185         use rusqlite::OptionalExtension;
 4186         use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
 4187         use trnm_protocol::pon_wire::Envelope;
 4188         fn transfer(settings: &Settings, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
 4189             let mut payload = crate::development_public(recipient).unwrap().to_vec();
 4190             payload.extend(amount.to_le_bytes());
 4191             let mut tx = Envelope {
 4192                 network: settings.network(),
 4193                 sender: crate::development_public(0).unwrap(),
 4194                 nonce,
 4195                 expiry: 1000,
 4196                 fee_limit: 1_000_000,
 4197                 tag: 1,
 4198                 payload,
 4199                 signature: [0; 64],
 4200             };
 4201             let key =
 4202                 signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
 4203                     .unwrap();
 4204             tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
 4205                 .unwrap()
 4206                 .try_into()
 4207                 .unwrap();
 4208             tx.encode().unwrap()
```

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4210–4229](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4210)

```rust
 4210         for authenticated in [false, true] {
 4211             let directory = tempfile::tempdir().unwrap();
 4212             let clock = now().unwrap();
 4213             let settings = Settings::development(Some(clock - 1000)).unwrap();
 4214             let mut owner = if authenticated {
 4215                 Node::open_with_authenticated_state(directory.path(), settings.clone(), 2).unwrap()
 4216             } else {
 4217                 Node::open(directory.path(), settings.clone(), 2).unwrap()
 4218             };
 4219             let left = owner
 4220                 .make(
 4221                     settings.genesis(),
 4222                     vec![transfer(&settings, 1, 1, 11)],
 4223                     crate::development_public(7).unwrap(),
 4224                     clock - 990,
 4225                     4096,
 4226                 )
 4227                 .unwrap();
 4228             let left_id = owner.admit(&left, clock).unwrap();
 4229             owner.activate_observed(left_id, clock).unwrap();
```

### Annotation 4 / alert 1379

**Original title:** Hard-coded cryptographic value

**Original message:** `This hard-coded value is used as [a nonce](1).`

**Conclusion:** Both branches legitimately begin at the same genesis account sequence. This is branch conflict/reorg coverage, not repeated use of an AEAD nonce under a secret key.

**Compilation/caller boundary:** Same cfg(test) helper; the right branch parent is genesis, not the left block.

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4183–4208](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4183)

```rust
 4183     #[test]
 4184     fn existing_replay_cancelled_reorg_recovers_signed_payments_once() {
 4185         use rusqlite::OptionalExtension;
 4186         use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
 4187         use trnm_protocol::pon_wire::Envelope;
 4188         fn transfer(settings: &Settings, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
 4189             let mut payload = crate::development_public(recipient).unwrap().to_vec();
 4190             payload.extend(amount.to_le_bytes());
 4191             let mut tx = Envelope {
 4192                 network: settings.network(),
 4193                 sender: crate::development_public(0).unwrap(),
 4194                 nonce,
 4195                 expiry: 1000,
 4196                 fee_limit: 1_000_000,
 4197                 tag: 1,
 4198                 payload,
 4199                 signature: [0; 64],
 4200             };
 4201             let key =
 4202                 signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
 4203                     .unwrap();
 4204             tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
 4205                 .unwrap()
 4206                 .try_into()
 4207                 .unwrap();
 4208             tx.encode().unwrap()
```

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4231–4240](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4231)

```rust
 4231             let right = owner
 4232                 .make(
 4233                     settings.genesis(),
 4234                     vec![transfer(&settings, 1, 2, 7)],
 4235                     crate::development_public(8).unwrap(),
 4236                     clock - 989,
 4237                     4096,
 4238                 )
 4239                 .unwrap();
 4240             let right_id = owner.admit(&right, clock).unwrap();
```

### Annotation 5 / alert 1380

**Original title:** Hard-coded cryptographic value

**Original message:** `This hard-coded value is used as [a nonce](1).`

**Conclusion:** The next ledger sequence after the right-branch sequence 1. It is signed public message data, not a private signature nonce or IV.

**Compilation/caller boundary:** Same cfg(test) helper; successor parent is right_id.

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4183–4208](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4183)

```rust
 4183     #[test]
 4184     fn existing_replay_cancelled_reorg_recovers_signed_payments_once() {
 4185         use rusqlite::OptionalExtension;
 4186         use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
 4187         use trnm_protocol::pon_wire::Envelope;
 4188         fn transfer(settings: &Settings, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
 4189             let mut payload = crate::development_public(recipient).unwrap().to_vec();
 4190             payload.extend(amount.to_le_bytes());
 4191             let mut tx = Envelope {
 4192                 network: settings.network(),
 4193                 sender: crate::development_public(0).unwrap(),
 4194                 nonce,
 4195                 expiry: 1000,
 4196                 fee_limit: 1_000_000,
 4197                 tag: 1,
 4198                 payload,
 4199                 signature: [0; 64],
 4200             };
 4201             let key =
 4202                 signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
 4203                     .unwrap();
 4204             tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
 4205                 .unwrap()
 4206                 .try_into()
 4207                 .unwrap();
 4208             tx.encode().unwrap()
```

[trillionnium/crates/trnm-pon-node/src/ingress.rs:4241–4251](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress.rs#L4241)

```rust
 4241             let target = owner
 4242                 .make(
 4243                     right_id,
 4244                     vec![transfer(&settings, 2, 3, 9)],
 4245                     crate::development_public(8).unwrap(),
 4246                     clock - 979,
 4247                     4096,
 4248                 )
 4249                 .unwrap();
 4250             let target_id = owner.admit(&target, clock).unwrap();
 4251             let expected = owner.state_at(target_id).unwrap();
```

### Annotation 6 / alert 1375

**Original title:** Cleartext logging of sensitive information

**Original message:** `This operation writes [account](1) to a log file.
This operation writes [account(...)](2) to a log file.`

**Conclusion:** Failure-only assertion diagnostic in a Linux unit test. Its reported source is public Account balance/sequence; receiver/identity are fresh fixed development fixtures. No production secret disclosure is demonstrated.

**Compilation/caller boundary:** scalar_cpu.rs includes this file only under cfg(all(test,target_os="linux")). Test covers false product, valid full W1, and stored exact replay.

[trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs:1019–1021](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L1019)

```rust
 1019 #[cfg(all(test, target_os = "linux"))]
 1020 #[path = "scalar_cpu_completion_tests.rs"]
 1021 mod completion_tests;
```

[trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs:241–259](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs#L241)

```rust
  241 #[test]
  242 fn only_fresh_successful_native_w1_promotes_not_false_product_or_existing_packet() {
  243     use super::super::{
  244         public_dispatch, MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
  245         PublicPolicy, PublicServer, Request,
  246     };
  247     use crate::ingress::DevelopmentIdentity;
  248     let (directory, settings, packet) = packet();
  249     let node = Mutex::new(Node::open(&directory.path().join("receiver"), settings, 1).unwrap());
  250     let server = PublicServer::new(
  251         DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
  252         PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
  253     )
  254     .unwrap();
  255     let stop = Arc::new(AtomicBool::new(false));
  256     let metrics = Mutex::new(PublicMetrics::default());
  257     let mut false_product = packet.clone();
  258     let at = 4 + 8 * trnm_crypto_primitives::pon_work::CELLS;
  259     let value = u32::from_le_bytes(false_product.proof[at..at + 4].try_into().unwrap());
```

[trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs:291–300](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs#L291)

```rust
  291         );
  292         if index == 0 {
  293             assert_eq!(outcome.unwrap_err().to_string(), "WORK:Product");
  294         } else {
  295             assert!(
  296                 outcome.is_ok(),
  297                 "native completion/replay failed: {outcome:?}"
  298             );
  299         }
  300         assert_eq!(
```

### Annotation 7 / alert 1376

**Original title:** Cleartext logging of sensitive information

**Original message:** `This operation writes [account](1) to a log file.
This operation writes [account(...)](2) to a log file.`

**Conclusion:** Failure-only assertion diagnostic in a Linux unit test. The assertion verifies native rejection and unchanged state after valid W1; its reported Account source is not credential material.

**Compilation/caller boundary:** Same cfg(test,Linux) file; same_valid_w1_native_invalid_packet_cannot_reacquire_completion_priority.

[trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs:1019–1021](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L1019)

```rust
 1019 #[cfg(all(test, target_os = "linux"))]
 1020 #[path = "scalar_cpu_completion_tests.rs"]
 1021 mod completion_tests;
```

[trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs:313–335](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs#L313)

```rust
  313 #[test]
  314 fn same_valid_w1_native_invalid_packet_cannot_reacquire_completion_priority() {
  315     use super::super::{
  316         public_dispatch, MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
  317         PublicPolicy, PublicServer, Request,
  318     };
  319     use crate::ingress::DevelopmentIdentity;
  320     use trnm_crypto_primitives::pon_work;
  321     let (directory, settings, mut candidate) = packet();
  322     let node = Mutex::new(Node::open(&directory.path().join("receiver"), settings, 1).unwrap());
  323     let before = node.lock().unwrap().read_active().unwrap();
  324     let a: Vec<u32> = candidate.proof[4..4 + 4 * pon_work::CELLS]
  325         .chunks_exact(4)
  326         .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
  327         .collect();
  328     let b: Vec<u32> = candidate.proof[4 + 4 * pon_work::CELLS..4 + 8 * pon_work::CELLS]
  329         .chunks_exact(4)
  330         .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
  331         .collect();
  332     let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
  333     // Mine exactly one genuine full W1 for an intentionally wrong native State
  334     // commitment. Repeated request envelopes reuse this same acquired work.
  335     candidate.header.state[0] ^= 1;
```

[trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs:389–399](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs#L389)

```rust
  389         promotions.push(server.mutation_cpu.lock().unwrap().verified_completions);
  390         permit.finish(&measurement, &server, &metrics).unwrap();
  391         assert!(
  392             matches!(&outcome, Err(error) if error.to_string() == "ROOT"
  393             && !error.requires_owner_stop()),
  394             "full-W1 native-invalid outcome changed: {outcome:?}"
  395         );
  396         assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
  397         assert!(node
  398             .lock()
  399             .unwrap()
```

### Annotation 8 / alert 1457

**Original title:** Hard-coded cryptographic value

**Original message:** `This hard-coded value is used as [a nonce](1).`

**Conclusion:** The helper copies the value to Header.nonce. It fixes one public challenge while the test constructs four fake traces and requires full native rejection without chainwork/state change. This counter is not required to be secret or unpredictable.

**Compilation/caller boundary:** Cargo integration-test source under tests/, #[test] four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged. New test in this PR; fresh temporary development Node.

[trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs:171–187](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L171)

```rust
  171 fn genesis_header(settings: &Settings, target: Hash, nonce: u64, task: Hash) -> Header {
  172     Header {
  173         network: settings.network(),
  174         parameters: settings.parameters(),
  175         parent: settings.genesis(),
  176         height: 1,
  177         timestamp: settings.genesis_time() + 1,
  178         target,
  179         miner: development_public(0).unwrap(),
  180         transactions: sequence_root("transactions", &[]),
  181         // Deliberately untrusted commitments. These must not shortcut the W1
  182         // replay; the unchanged native admission checks execution after W1.
  183         state: [0; 32],
  184         receipts: [0; 32],
  185         work_task: task,
  186         nonce,
  187     }
```

[trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs:663–692](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L663)

```rust
  663 #[test]
  664 fn four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged() {
  665     // One actual genesis header/challenge/task/target, four distinct fake traces.
  666     // None of the four attack submissions acquires a valid work proof.
  667     let temp = tempfile::tempdir().unwrap();
  668     let now = ingress::now().unwrap();
  669     let settings = Settings::development(Some(now - 100)).unwrap();
  670     let mut node = Node::open(temp.path(), settings.clone(), 2).unwrap();
  671     let (a, b) = maintenance();
  672     let task = pon_work::task_id(&a, &b).unwrap();
  673     let genesis = settings.genesis();
  674     let target = node.expected_target(genesis).unwrap();
  675     let mut header = genesis_header(&settings, target, 10_000, task);
  676     // This must be a fresh valid Node header context, not the legacy fixed
  677     // 2025 test header that would fail TIME before W1 verification.
  678     header.timestamp = settings.genesis_time() + 1;
  679     header.miner = development_public(0).unwrap();
  680     let challenge = header.challenge();
  681     let initial_stats = node.stats().unwrap();
  682     let initial_active = node.read_active().unwrap();
  683     let construction_started = Instant::now();
  684     let construction_cpu = ThreadCpuStamp::start();
  685     let prefix = w1_from_zero::proof_prefix(&a, &b).unwrap();
  686     let mut cases = Vec::new();
  687     for nonce in 0..128_u64 {
  688         let (trace, ticket) = w1_from_zero::trial(challenge, nonce);
  689         if target != [0; 32] && ticket <= target {
  690             let mut proof = prefix.clone();
  691             proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
  692             cases.push((nonce, trace, ticket, proof));
```

### Annotation 9 / alert 1430

**Original title:** Hard-coded cryptographic value

**Original message:** `This hard-coded value is used as [a nonce](1).`

**Conclusion:** signed_campaign_seed creates 4 blocks x 256 transactions with sequences 1..1024. The literal is the next account sequence, passed to the known-development-key helper. It is not a cipher nonce.

**Compilation/caller boundary:** tests/public_v3_multiprocess.rs integration target; the true/signed_seed branch is invoked by an explicitly ignored fixed-cost test. A separate ordinary test invokes the false branch.

[trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs:1487–1515](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1487)

```rust
 1487 fn signed_campaign_seed(miner: &mut Node, settings: &Settings) -> Vec<Packet> {
 1488     let mut seed = Vec::new();
 1489     // Real funded accounts and full signed execution, not injected SQL/state or
 1490     // a cheap verifier fixture. All processes still use the original CPU budget.
 1491     for block in 0..4_u64 {
 1492         let transactions = (0..256_u64)
 1493             .map(|slot| {
 1494                 let nonce = block * 256 + slot + 1;
 1495                 support::signed_transfer(
 1496                     settings,
 1497                     nonce,
 1498                     hash(b"multiprocess-funded-account-v1", &[&nonce.to_le_bytes()]),
 1499                 )
 1500             })
 1501             .collect();
 1502         let packet = miner
 1503             .make_consensus_maintenance(
 1504                 miner.active().unwrap().0,
 1505                 transactions,
 1506                 development_public(0).unwrap(),
 1507                 settings.genesis_time() + (block + 1) * 10,
 1508                 4096,
 1509             )
 1510             .unwrap();
 1511         replay(miner, std::slice::from_ref(&packet));
 1512         seed.push(packet);
 1513     }
 1514     seed
 1515 }
```

[trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs:1853–1872](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1853)

```rust
 1853 }
 1854 
 1855 #[test]
 1856 fn valid_work_state_root_replays_are_paid_without_admission() {
 1857     root_replay_component_cost(false);
 1858 }
 1859 
 1860 #[test]
 1861 #[ignore = "explicit fixed 1024-signed-seed component cost; not a saturation campaign"]
 1862 fn signed_seed_state_root_replay_component_cost() {
 1863     root_replay_component_cost(true);
 1864 }
 1865 
 1866 // Keep the original eight-transaction/two-worker regression and its positive
 1867 // scoped-worker assertion. The additional fixture uses the original campaign's
 1868 // exact four seed blocks and first business transaction, with one M06 worker.
 1869 fn root_replay_component_cost(signed_seed: bool) {
 1870     let output = std::env::var_os("TRNM_CI_RECEIPT_DIR")
 1871         .map(PathBuf::from)
 1872         .unwrap_or_else(|| tempfile::tempdir().unwrap().keep())
```

[trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs:1883–1912](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs#L1883)

```rust
 1883     let open =
 1884         |path: &Path| Node::open_with_authenticated_state(path, settings.clone(), workers).unwrap();
 1885     let setup_started = Instant::now();
 1886     let setup_cpu = support::cpu();
 1887     let mut producer = open(&output.join("producer"));
 1888     let seed = if signed_seed {
 1889         signed_campaign_seed(&mut producer, &settings)
 1890     } else {
 1891         Vec::new()
 1892     };
 1893     let producer_setup_cost = json!({"cpu_ns":support::elapsed_cpu(setup_cpu),
 1894         "wall_ns":setup_started.elapsed().as_nanos(),"seed_blocks":seed.len(),
 1895         "signed_seed_transfers":seed.iter().map(|p|p.transactions.len()).sum::<usize>(),
 1896         "scope":"fresh owner open; all actual seed signing, search, execution and durable replay; Node search attempt counts unavailable, not omitted from CPU"});
 1897     support::write_new(&output.join("producer-setup.json"), &producer_setup_cost);
 1898     let reference_started = Instant::now();
 1899     let reference_cpu = support::cpu();
 1900     let transactions = if signed_seed {
 1901         vec![support::signed_transfer(
 1902             &settings,
 1903             1025,
 1904             development_public(1).unwrap(),
 1905         )]
 1906     } else {
 1907         (1..=8)
 1908             .map(|sequence| {
 1909                 support::signed_transfer(&settings, sequence, development_public(1).unwrap())
 1910             })
 1911             .collect()
 1912     };
```

[trillionnium/crates/trnm-pon-node/tests/support/multiprocess_support.rs:125–144](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/tests/support/multiprocess_support.rs#L125)

```rust
  125 pub fn signed_transfer(settings: &Settings, nonce: u64, recipient: [u8; 32]) -> Vec<u8> {
  126     let mut payload = recipient.to_vec();
  127     payload.extend_from_slice(&1_u64.to_le_bytes());
  128     let mut envelope = Envelope {
  129         network: settings.network(),
  130         sender: development_public(0).unwrap(),
  131         nonce,
  132         expiry: 10000,
  133         fee_limit: 1_000_000,
  134         tag: 1,
  135         payload,
  136         signature: [0; 64],
  137     };
  138     let key =
  139         signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
  140     envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
  141         .unwrap()
  142         .try_into()
  143         .unwrap();
  144     envelope.encode().unwrap()
```

## Common type and protocol evidence

[trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs:81–86](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs#L81)

```rust
   81 #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
   82 #[serde(deny_unknown_fields)]
   83 pub struct Account {
   84     pub balance: u64,
   85     pub nonce: u64,
   86 }
```

[trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs:150–155](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs#L150)

```rust
  150         match node.kind {
  151             Kind::Leaf(stored, account) => {
  152                 crate::ensure(stored == owner, "NATIVE_ACCOUNT_COLLISION")
  153                     .map_err(Error::local_integrity)?;
  154                 return Ok(Some(account));
  155             }
```

[trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs:287–305](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs#L287)

```rust
  287     for (key, before, after) in deltas {
  288         progress()?;
  289         if !key.starts_with("account:") {
  290             continue;
  291         }
  292         let after = after
  293             .as_ref()
  294             .ok_or_else(|| Error::from("NATIVE_ACCOUNT_DELETION").local_integrity())?;
  295         let (owner, next) = account(key, after)?;
  296         let prior = before
  297             .as_ref()
  298             .map(|bytes| account(key, bytes).map(|row| row.1))
  299             .transpose()?;
  300         crate::ensure(
  301             lookup(db, original.clone(), owner, &empty)? == prior
  302                 && prior.is_none_or(|prior| next.nonce >= prior.nonce),
  303             "NATIVE_ACCOUNT_DELTA",
  304         )
  305         .map_err(Error::local_integrity)?;
```

[trillionnium/crates/trnm-pon-node/src/lib.rs:651–657](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/src/lib.rs#L651)

```rust
  651 /// These identities are publicly known test identities, never production key custody.
  652 pub fn development_public(i: u64) -> Result<Hash> {
  653     let seed = hash(b"DEV-ONLY-KEY", &[&i.to_le_bytes()]);
  654     let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed))
  655         .map_err(|_| Error::from("DEV_KEY"))?;
  656     digest(&trnm_crypto_primitives::public_key_hex(&key))
  657 }
```

[trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs:1266–1277](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs#L1266)

```rust
 1266 fn apply_prepared_with_account_access(
 1267     base: &State,
 1268     prepared: &Prepared,
 1269     height: u64,
 1270     cfg: &Config,
 1271     account_access: Option<&AccountPointAccess<'_>>,
 1272 ) -> Result<Patch> {
 1273     let tx = &prepared.envelope;
 1274     let sender = prepared.sender.clone();
 1275     let mut s = View::new(base, account_access);
 1276     let acct = s.account(&sender)?;
 1277     require(tx.nonce == add(field(&acct, "nonce")?, 1)?, "NONCE")?;
```

[trillionnium/crates/trnm-protocol/src/pon_wire.rs:120–149](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-protocol/src/pon_wire.rs#L120)

```rust
  120 impl Header {
  121     pub fn encode(&self) -> Vec<u8> {
  122         let mut o = Vec::with_capacity(HEADER_BYTES);
  123         o.extend(b"PNH1");
  124         o.extend(1_u16.to_le_bytes());
  125         for h in [self.network, self.parameters, self.parent] {
  126             o.extend(h)
  127         }
  128         o.extend(self.height.to_le_bytes());
  129         o.extend(self.timestamp.to_le_bytes());
  130         for h in [
  131             self.target,
  132             self.miner,
  133             self.transactions,
  134             self.state,
  135             self.receipts,
  136             self.work_task,
  137         ] {
  138             o.extend(h)
  139         }
  140         o.extend(self.nonce.to_le_bytes());
  141         o
  142     }
  143     pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
  144         if bytes.len() != HEADER_BYTES {
  145             return Err(WireError::Length);
  146         }
  147         let mut r = Reader { bytes, pos: 0 };
  148         if r.take::<4>()? != *b"PNH1" || r.take::<2>()? != 1_u16.to_le_bytes() {
  149             return Err(WireError::Version);
```

[trillionnium/crates/trnm-protocol/src/pon_wire.rs:262–286](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-protocol/src/pon_wire.rs#L262)

```rust
  262 impl Envelope {
  263     pub fn unsigned(&self) -> Result<Vec<u8>, WireError> {
  264         payload_len(self.tag, &self.payload)?;
  265         if self.nonce == 0 || self.fee_limit > 10_000_000 {
  266             return Err(WireError::Noncanonical);
  267         }
  268         let mut o = Vec::with_capacity(159 + self.payload.len());
  269         o.extend(b"PNX1");
  270         o.extend(self.network);
  271         o.extend(self.sender);
  272         o.extend(self.nonce.to_le_bytes());
  273         o.extend(self.expiry.to_le_bytes());
  274         o.extend(self.fee_limit.to_le_bytes());
  275         o.push(self.tag);
  276         o.extend((self.payload.len() as u16).to_le_bytes());
  277         o.extend(&self.payload);
  278         Ok(o)
  279     }
  280     pub fn encode(&self) -> Result<Vec<u8>, WireError> {
  281         let mut o = self.unsigned()?;
  282         o.extend(self.signature);
  283         Ok(o)
  284     }
  285     pub fn signing_digest(&self) -> Result<Hash, WireError> {
  286         Ok(hash(b"tx-sign", &[&self.unsigned()?]))
```

[trillionnium/crates/trnm-pon-node/Cargo.toml:1–13](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c804e9f5bcf6e972bbb4524c744d4b3c8801c34/trillionnium/crates/trnm-pon-node/Cargo.toml#L1)

```rust
    1 [package]
    2 name = "trnm-pon-node"
    3 version = "0.1.0"
    4 edition.workspace = true
    5 license.workspace = true
    6 authors.workspace = true
    7 publish = false
    8 
    9 [package.metadata.trnm]
   10 module = "M15"
   11 role = "experimental-native-composition"
   12 production_activation = false
   13 consensus_authority = false
```

## Primary query source URLs

- [CleartextLogging.ql](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/rust/ql/src/queries/security/CWE-312/CleartextLogging.ql)
- [HardcodedCryptographicValue.ql](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/rust/ql/src/queries/security/CWE-798/HardcodedCryptographicValue.ql)
- [CleartextLoggingExtensions.qll](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/rust/ql/lib/codeql/rust/security/CleartextLoggingExtensions.qll)
- [HardcodedCryptographicValueExtensions.qll](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/rust/ql/lib/codeql/rust/security/HardcodedCryptographicValueExtensions.qll)
- [SensitiveData.qll](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/rust/ql/lib/codeql/rust/security/SensitiveData.qll)
- [SensitiveDataHeuristics.qll](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/shared/concepts/codeql/concepts/internal/SensitiveDataHeuristics.qll)

This was a read-only review within the same assistant session, not independent external operator/management certification. No Rust, Cargo, Bazel or CodeQL run was launched; no source or security status was modified. Raw observation files retain their original source identity.
