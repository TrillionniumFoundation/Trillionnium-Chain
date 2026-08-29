# TRNM Agent Merge Queue v1

Status: **subordinate integration contract; no automatic merge authority**

## 1. Queue waves

| Wave | Packages | Entry condition | Exit condition |
|---|---|---|---|
| M0 | A00, A01 | exact latest candidate known | ownership/source truth and clean-clone contract reviewed |
| M1 | interface freeze | M0 reviewed | capability digests and ICR paths accepted |
| M2 | A02 | M1 interfaces accepted | recovery/Core Ack module closed candidate + independent replay |
| M3 | A03 | A02 interface digest accepted | ordinary proposal/Vote module closed candidate |
| M4 | A04 | A03 application-seal interface accepted | application/finality module closed candidate |
| M5 | A05 | A03/A04 receipts accepted | Safety/checkpoint/anti-rollback module closed candidate |
| M6 | A06 | A02-A05 test hooks fixed | full fault matrix and independent replay candidate |
| M7 | G1 review | M2-M6 reviewed | signed accepted G1 evidence or explicit reopen |
| M8 | A07 | accepted R4/G1 authority | 4/7-node evidence candidate and review |
| M9 | A08, A09 | spec preparation allowed; promotion needs G1 | normative inventory/conformance review |
| M10 | A10 | A08/A09 interface digests stable | 30 W0-W7 rows candidate |
| M11 | A11, A12, A13 | G2.0 interfaces stable | DA/Agent/Execution candidate interfaces |
| M12 | A14 | DA/Agent/Execution interface digests stable | verification/challenge candidate |
| M13 | A15 | Agent/Execution/Result interfaces stable | settlement candidate |
| M14 | A16 | all G2 plane interfaces stable | whole-node/sync/light-client candidate |
| M15 | A17 | accepted predecessor evidence as applicable | benchmark/security/ops package candidate |

## 2. PR admission record

Every queued PR records:

```text
package_id
agent_id
base_commit
base_tree
head_commit
changed_paths
owned_path_check
interface_versions
upstream_evidence_ids
test/evidence index
known gaps
non-claims
downstream invalidation
reviewers
queue_wave
```

## 3. Hard rejection

Reject or return to Draft when:

- base/source/tree is stale or absent;
- another active Agent owns a changed path/surface;
- an interface change has no accepted ICR;
- feature code and global truth promotion are mixed;
- evidence scope/authority/classification is absent;
- failed safety/economic/root/profile/custody mutant is hidden;
- independent review/replay is required but absent;
- a later Gate is promoted while a predecessor is unaccepted;
- `MODULE_CLOSED_CANDIDATE` is presented as Gate acceptance;
- the author attempts to merge its own PR.

## 4. Integration owner

A00 coordinates the queue but cannot approve safety correctness or merge its own
changes. Required domain reviewers are assigned from owners not responsible for
the implementation. Critical G1/G2F interfaces require at least:

- source module owner;
- consuming module owner;
- fault/independent replay owner;
- applicable safety/crypto/economic/light-client reviewer.

## 5. Rebase and invalidation

A changed base does not authorize blind rebase. The Agent emits `BASE_DRIFT`,
computes changed authority inputs and identifies the minimum rerun set.

After rebase:

- regenerate source/tree/interface/evidence digests;
- replay negative mutants;
- rerun every dependent boundary;
- retain old evidence as superseded/invalidated;
- request fresh independent review.

## 6. Merge result

Merging a package changes code/document history only. Machine Gate status changes
through a separate truth-only PR referencing accepted signed evidence. No
merge queue entry directly sets production or activation truth.
