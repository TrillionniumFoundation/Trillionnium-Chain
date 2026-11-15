//! Original indivisible M12 parents and durable, separately observed V3 children.
//! A completed parent is a current complete readback, never Positive or payment.

use super::*;
use std::{collections::BTreeMap, thread::ThreadId};
use trnm_data_availability::cell::CellRs46StoredShardV1;
use trnm_service_settlement::native_budget::{NativeBudgetEffectCheckV1, NativeFundingSourceV1};

use super::journal::ChildStateV3;

fn current_deadline(deadline: Instant) -> Result<()> {
    ensure(Instant::now() < deadline, "NATIVE_CELL_GROUP_DEADLINE")
}
fn group_error(error: impl std::fmt::Display) -> crate::Error {
    format!("NATIVE_CELL_GROUP_OWNER: {error}").into()
}
fn group_window(group: &NativeCellShardParentGroupV3) -> Result<(u64, u64)> {
    let first = group
        .children
        .first()
        .ok_or("NATIVE_CELL_GROUP_EMPTY")?
        .contract
        .owner();
    let window = (first.retain_from_height, first.retain_until_height);
    ensure(
        group.children.iter().all(|child| {
            let owner = child.contract.owner();
            (owner.retain_from_height, owner.retain_until_height) == window
        }),
        "NATIVE_CELL_GROUP_COMMON_WINDOW",
    )?;
    Ok(window)
}
fn parent_checks<'a>(
    groups: &'a [NativeCellShardParentGroupV3],
) -> Result<Vec<NativeBudgetEffectCheckV1<'a>>> {
    groups
        .iter()
        .map(|group| {
            Ok(NativeBudgetEffectCheckV1 {
                policy: &group.policy,
                claim: &group.claim,
                operation: group.operation,
                effect: group.claim.subject,
                window: Some(group_window(group)?),
            })
        })
        .collect()
}

/// There is deliberately no Clone/serialization/public constructor. This grant
/// exists only in the invocation which received the original M12 New result.
struct FreshParentGrantV3 {
    group: Hash,
    source: NativeFundingSourceV1,
    anchor: NativeBudgetAnchorV1,
    row: serde_json::Value,
    thread: ThreadId,
    deadline: Instant,
}
impl FreshParentGrantV3 {
    fn check(
        &self,
        node: &mut Node,
        group: &NativeCellShardParentGroupV3,
        deadline: Instant,
    ) -> Result<()> {
        current_deadline(self.deadline)?;
        ensure(
            deadline == self.deadline
                && self.thread == std::thread::current().id()
                && group.operation == self.group
                && group.policy.source == self.source,
            "NATIVE_CELL_GROUP_FRESH_GRANT_SCOPE",
        )?;
        let actual = node.native_funding_observation(self.source)?;
        ensure(
            actual.source == self.source
                && actual.anchor == self.anchor
                && actual.row.as_ref() == Some(&self.row),
            "NATIVE_CELL_GROUP_FRESH_FUNDING_CHANGED",
        )
    }
}

pub(super) struct ParentRunV3 {
    operation: Hash,
    subject: Hash,
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    replay: NativeBudgetReplayV1,
    grant: Option<FreshParentGrantV3>,
}
impl ParentRunV3 {
    pub(super) fn is_fresh(&self) -> bool {
        self.grant.is_some()
    }

    fn verify_binding(&self, group: &NativeCellShardParentGroupV3) -> Result<()> {
        ensure(
            group.operation == self.operation
                && group.claim.subject == self.subject
                && types::native_cell_shard_parent_group_subject_v3(self.plan, self.kind, group)?
                    == self.subject,
            "NATIVE_CELL_GROUP_RUN_BINDING",
        )
    }

    /// True means this call just persisted a child's first Pending intent.
    /// False permits only target reconciliation; it never permits initial I/O.
    pub(super) fn authorize_child(
        &self,
        node: &mut Node,
        journal: &mut NativeCellShardGroupJournalV3,
        group: &NativeCellShardParentGroupV3,
        index: usize,
        deadline: Instant,
    ) -> Result<bool> {
        current_deadline(deadline)?;
        self.verify_binding(group)?;
        let state = journal.state(group.operation, index, deadline)?;
        if let Some(grant) = &self.grant {
            grant.check(node, group, deadline)?;
            ensure(
                state == ChildStateV3::Unstarted,
                "NATIVE_CELL_GROUP_FRESH_CHILD_ALREADY_STARTED",
            )?;
            journal.begin_child(group.operation, index, deadline)?;
            Ok(true)
        } else {
            ensure(
                self.replay != NativeBudgetReplayV1::New,
                "NATIVE_CELL_GROUP_GRANT_MISSING",
            )?;
            ensure(
                matches!(state, ChildStateV3::Pending | ChildStateV3::Done(_)),
                "NATIVE_CELL_GROUP_UNSTARTED_WITHOUT_FRESH_GRANT",
            )?;
            if self.replay == NativeBudgetReplayV1::Done {
                ensure(
                    matches!(state, ChildStateV3::Done(_)),
                    "NATIVE_CELL_GROUP_DONE_PARENT_INCOMPLETE_CHILD",
                )?;
            }
            Ok(false)
        }
    }
}

/// Complete-batch original M12 simulation precedes roster registration, holds
/// and intents. All rosters and all holds are installed before any live grant
/// returns to a caller which could dispatch a provider operation.
pub(super) fn prepare_parents(
    node: &mut Node,
    budgets: &mut NativeBudgetStoreV1,
    journal: &mut NativeCellShardGroupJournalV3,
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    groups: &[NativeCellShardParentGroupV3],
    deadline: Instant,
) -> Result<Vec<ParentRunV3>> {
    current_deadline(deadline)?;
    ensure(
        !groups.is_empty() && groups.len() <= 64,
        "NATIVE_CELL_GROUP_PARENT_COUNT",
    )?;
    let checks = parent_checks(groups)?;
    let expected = budgets.check_effects(node, &checks).map_err(group_error)?;
    // An old parent never supplies permission to recreate absent child history.
    for (group, replay) in groups.iter().zip(&expected) {
        let descriptor = types::descriptor(plan, kind, group)?;
        let bindings = types::bindings(kind, group)?;
        ensure(
            group.claim.subject
                == types::native_cell_shard_parent_group_subject_v3(plan, kind, group)?,
            "NATIVE_CELL_GROUP_PARENT_SUBJECT",
        )?;
        if *replay != NativeBudgetReplayV1::New {
            journal.require_roster(group.operation, &descriptor, &bindings, deadline)?;
            for index in 0..bindings.len() {
                let state = journal.state(group.operation, index, deadline)?;
                ensure(
                    state != ChildStateV3::Unstarted,
                    "NATIVE_CELL_GROUP_UNSTARTED_WITHOUT_FRESH_GRANT",
                )?;
                if *replay == NativeBudgetReplayV1::Done {
                    ensure(
                        matches!(state, ChildStateV3::Done(_)),
                        "NATIVE_CELL_GROUP_DONE_PARENT_INCOMPLETE_CHILD",
                    )?;
                }
            }
        }
    }
    for (group, replay) in groups.iter().zip(&expected) {
        let descriptor = types::descriptor(plan, kind, group)?;
        let bindings = types::bindings(kind, group)?;
        journal.register(
            group.operation,
            &descriptor,
            &bindings,
            *replay == NativeBudgetReplayV1::New,
            deadline,
        )?;
        if *replay == NativeBudgetReplayV1::New {
            for index in 0..bindings.len() {
                ensure(
                    journal.state(group.operation, index, deadline)? == ChildStateV3::Unstarted,
                    "NATIVE_CELL_GROUP_CHILD_HISTORY_WITHOUT_PARENT_INTENT",
                )?;
            }
        }
    }
    let mut observations = Vec::with_capacity(groups.len());
    for group in groups {
        current_deadline(deadline)?;
        observations.push(node.native_funding_observation(group.policy.source)?);
        budgets
            .open_budget(node, group.policy.clone())
            .map_err(group_error)?;
        budgets
            .reserve(node, group.claim.clone())
            .map_err(group_error)?;
    }
    let mut runs = Vec::with_capacity(groups.len());
    for ((group, expected), observation) in groups.iter().zip(expected).zip(observations) {
        current_deadline(deadline)?;
        let (from, until) = group_window(group)?;
        let replay = budgets
            .begin_effect_in_window(
                node,
                group.claim.claim,
                group.operation,
                group.claim.subject,
                from,
                until,
            )
            .map_err(group_error)?;
        ensure(
            replay == expected,
            "NATIVE_CELL_GROUP_PARENT_CHANGED_AFTER_PREFLIGHT",
        )?;
        let grant = if replay == NativeBudgetReplayV1::New {
            let row = observation
                .row
                .ok_or("NATIVE_CELL_GROUP_NEW_SOURCE_ABSENT")?;
            let grant = FreshParentGrantV3 {
                group: group.operation,
                source: group.policy.source,
                anchor: observation.anchor,
                row,
                thread: std::thread::current().id(),
                deadline,
            };
            grant.check(node, group, deadline)?;
            Some(grant)
        } else {
            None
        };
        runs.push(ParentRunV3 {
            operation: group.operation,
            subject: group.claim.subject,
            plan,
            kind,
            replay,
            grant,
        });
    }
    current_deadline(deadline)?;
    Ok(runs)
}

pub(super) struct ParentCompletionV3<'a> {
    pub plan: Hash,
    pub kind: NativeCellShardGroupKindV3,
    pub groups: &'a [NativeCellShardParentGroupV3],
    pub runs: &'a [ParentRunV3],
    pub observed: &'a BTreeMap<Hash, Hash>,
    pub deadline: Instant,
}

pub(super) fn finish_parents(
    node: &mut Node,
    budgets: &mut NativeBudgetStoreV1,
    journal: &mut NativeCellShardGroupJournalV3,
    completion: ParentCompletionV3<'_>,
) -> Result<Vec<NativeCellShardParentGroupReadbackV3>> {
    let ParentCompletionV3 {
        plan,
        kind,
        groups,
        runs,
        observed,
        deadline,
    } = completion;
    current_deadline(deadline)?;
    ensure(groups.len() == runs.len(), "NATIVE_CELL_GROUP_RUN_COVERAGE")?;
    let mut receipts = Vec::with_capacity(groups.len());
    // Validate the complete current set before appending any parent completion.
    for (group, run) in groups.iter().zip(runs) {
        run.verify_binding(group)?;
        if let Some(grant) = &run.grant {
            grant.check(node, group, deadline)?;
        }
        let descriptor = types::descriptor(plan, kind, group)?;
        let bindings = types::bindings(kind, group)?;
        journal.require_roster(group.operation, &descriptor, &bindings, deadline)?;
        let mut wire = Vec::with_capacity(32 + 64 * bindings.len());
        wire.extend_from_slice(&group.operation);
        for (index, binding) in bindings.iter().enumerate() {
            let receipt = *observed
                .get(&binding.operation)
                .ok_or("NATIVE_CELL_GROUP_CURRENT_CHILD_MISSING")?;
            ensure(
                receipt != [0; 32]
                    && journal.state(group.operation, index, deadline)?
                        == ChildStateV3::Done(receipt),
                "NATIVE_CELL_GROUP_CHILD_NOT_DONE_CURRENT",
            )?;
            wire.extend_from_slice(&binding.operation);
            wire.extend_from_slice(&receipt);
        }
        receipts.push(hash(
            b"trnm.native-cell-parent-group-current-readback.v3\0",
            &[&group.claim.subject, &wire],
        ));
    }
    for (group, receipt) in groups.iter().zip(&receipts) {
        current_deadline(deadline)?;
        budgets
            .complete_effect(group.claim.claim, group.operation, *receipt)
            .map_err(group_error)?;
    }
    let checks = parent_checks(groups)?;
    let final_replays = budgets.check_effects(node, &checks).map_err(group_error)?;
    ensure(
        final_replays
            .iter()
            .all(|r| *r == NativeBudgetReplayV1::Done),
        "NATIVE_CELL_GROUP_PARENT_INCOMPLETE",
    )?;
    current_deadline(deadline)?;
    Ok(groups
        .iter()
        .zip(receipts)
        .map(|(group, receipt)| NativeCellShardParentGroupReadbackV3 {
            operation: group.operation,
            claim: group.claim.claim,
            receipt,
            replay: NativeBudgetReplayV1::Done,
        })
        .collect())
}

fn storage_receipt(child: &NativeCellShardGroupChildV3) -> Hash {
    hash(
        b"trnm.native-cell-group-child-storage-readback.v3\0",
        &[&child.claim.subject],
    )
}

pub(super) fn observe_storage_child(
    provider: &mut CellRs46ShardProviderV1,
    child: &NativeCellShardGroupChildV3,
    deadline: Instant,
) -> Result<(CellRs46StoredShardV1, Hash)> {
    current_deadline(deadline)?;
    let stored = observe_original(provider, &child.contract, deadline, &mut || {
        if Instant::now() < deadline {
            Ok(())
        } else {
            Err(CellErrorV1::Invalid(
                "native grouped storage readback deadline",
            ))
        }
    })?;
    current_deadline(deadline)?;
    Ok((stored, storage_receipt(child)))
}

fn storage_reservation(
    verification: &NativeCellRetainedShardVerificationBudgetV1,
    chunks: usize,
    wire_bytes: u64,
    source_bytes: u64,
) -> Result<CellRs46RepairUsageV1> {
    let attempts = u32::try_from(chunks)
        .ok()
        .and_then(|count| count.checked_mul(2))
        .ok_or("NATIVE_CELL_GROUPED_SIZE")?;
    let used = verification.usage();
    let next = CellRs46RepairUsageV1 {
        attempts_committed: used
            .attempts_committed
            .checked_add(attempts)
            .ok_or("NATIVE_CELL_GROUPED_SIZE")?,
        input_bytes_committed: used
            .input_bytes_committed
            .checked_add(
                wire_bytes
                    .checked_mul(2)
                    .ok_or("NATIVE_CELL_GROUPED_SIZE")?,
            )
            .ok_or("NATIVE_CELL_GROUPED_SIZE")?,
        reconstruction_bytes_committed: used
            .reconstruction_bytes_committed
            .checked_add(
                wire_bytes
                    .checked_add(source_bytes)
                    .and_then(|bytes| bytes.checked_mul(2))
                    .ok_or("NATIVE_CELL_GROUPED_SIZE")?,
            )
            .ok_or("NATIVE_CELL_GROUPED_SIZE")?,
        cache_bytes_committed: used.cache_bytes_committed,
    };
    ensure(
        next.attempts_committed <= verification.attempts
            && next.input_bytes_committed <= verification.input_bytes
            && next.reconstruction_bytes_committed <= verification.reconstruction_bytes,
        "NATIVE_CELL_GROUPED_VERIFICATION_RESERVATION",
    )?;
    Ok(next)
}

impl Node {
    /// Each Task remains one original indivisible M12 parent. Complete V3 child
    /// history and original CSP1 bytes are additionally required before Done.
    pub fn retain_native_cell_grouped_shard_plan_v3(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        targets: NativeCellPagedRetainedShardPlanTargetsV2<'_>,
        request: NativeCellGroupedShardStorageRequestV3,
        journal: &mut NativeCellShardGroupJournalV3,
        verification: &mut NativeCellRetainedShardVerificationBudgetV1,
    ) -> Result<NativeCellGroupedShardPlanReadbackV3> {
        let NativeCellPagedRetainedShardPlanTargetsV2 {
            catalog,
            plan_file,
            providers,
            cache,
        } = targets;
        let deadline = verification.deadline;
        current_deadline(deadline)?;
        ensure(
            !request.groups.is_empty(),
            "NATIVE_CELL_GROUPED_EMPTY_STORAGE",
        )?;
        let observed = self
            .native_funding_observation(request.groups[0].policy.source)?
            .anchor;
        let plan = plan_file.commitment();
        let contracts = load_contracts(plan_file, catalog, observed.height, deadline)?;
        journal.verify_context(
            &journal_context(self, plan, contracts[0][0].owner().owner_generation),
            deadline,
        )?;
        types::validate_groups(
            plan,
            NativeCellShardGroupKindV3::Storage,
            &request.groups,
            &[0, 1, 2, 3, 4, 5],
            &contracts,
            providers,
        )?;
        let (source_bytes, wire_bytes) = original_bytes(&contracts)?;
        let reservation =
            storage_reservation(verification, contracts.len(), wire_bytes, source_bytes)?;
        for (slot, provider) in providers.iter().enumerate() {
            let expected: Vec<_> = contracts.iter().map(|chunk| &chunk[slot]).collect();
            provider
                .check_reservations(&expected, deadline)
                .map_err(group_error)?;
        }
        ensure(
            self.native_funding_observation(request.groups[0].policy.source)?
                .anchor
                == observed,
            "NATIVE_CELL_GROUPED_CURRENT_ANCHOR_CHANGED",
        )?;
        plan_file
            .read_complete_current(catalog, observed.height, deadline)
            .map_err(group_error)?;
        let runs = prepare_parents(
            self,
            budgets,
            journal,
            plan,
            NativeCellShardGroupKindV3::Storage,
            &request.groups,
            deadline,
        )?;
        verification.committed = reservation;
        let width = NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3;
        let per_provider = contracts.len().div_ceil(width);
        let mut covered = 0;
        for page_index in 0..plan_file.plan().page_count() {
            let page = plan_file
                .read_page(page_index, deadline)
                .map_err(group_error)?;
            for (local_index, chunk) in page.chunks().iter().enumerate() {
                let global = page.start_chunk() + local_index;
                ensure(global == covered, "NATIVE_CELL_GROUPED_COVERAGE")?;
                let need_stage =
                    (0..6).any(|slot| runs[slot * per_provider + global / width].is_fresh());
                if need_stage {
                    plan_file
                        .stage_chunk_from_catalog(
                            page_index,
                            local_index,
                            catalog,
                            cache,
                            observed.height,
                            deadline,
                        )
                        .map_err(group_error)?;
                }
                let mut actual = Vec::with_capacity(6);
                for (slot, provider) in providers.iter_mut().enumerate() {
                    current_deadline(deadline)?;
                    let group_index = slot * per_provider + global / width;
                    let group = &request.groups[group_index];
                    let child_index = global - group.first_chunk;
                    let child = &group.children[child_index];
                    ensure(
                        child.contract == chunk.slots()[slot],
                        "NATIVE_CELL_GROUPED_COVERAGE",
                    )?;
                    let fresh = runs[group_index].authorize_child(
                        self,
                        journal,
                        group,
                        child_index,
                        deadline,
                    )?;
                    let (stored, receipt) = if fresh {
                        let (target, stored) = provider
                            .publish_controlled(
                                &child.contract,
                                child.contract.operation(),
                                cache,
                                deadline,
                                &mut || {
                                    if Instant::now() < deadline {
                                        Ok(())
                                    } else {
                                        Err(CellErrorV1::Invalid("native grouped initial deadline"))
                                    }
                                },
                            )
                            .map_err(group_error)?;
                        ensure(
                            target.acknowledged && !target.retired,
                            "NATIVE_CELL_GROUPED_TARGET_ACK",
                        )?;
                        (stored, storage_receipt(child))
                    } else {
                        observe_storage_child(provider, child, deadline)?
                    };
                    journal.complete_child(group.operation, child_index, receipt, deadline)?;
                    actual.push(stored);
                }
                verify_actual_codeword(&contracts[global], &actual, &mut verification.inner)?;
                current_deadline(deadline)?;
                covered += 1;
            }
        }
        ensure(covered == contracts.len(), "NATIVE_CELL_GROUPED_COVERAGE")?;
        let mut current = BTreeMap::new();
        for (global, chunk) in contracts.iter().enumerate() {
            let mut actual = Vec::with_capacity(6);
            for (slot, provider) in providers.iter_mut().enumerate() {
                let group = &request.groups[slot * per_provider + global / width];
                let child = &group.children[global - group.first_chunk];
                let (stored, receipt) = observe_storage_child(provider, child, deadline)?;
                ensure(
                    current
                        .insert(child.contract.operation(), receipt)
                        .is_none(),
                    "NATIVE_CELL_GROUPED_DUPLICATE_CURRENT_CHILD",
                )?;
                actual.push(stored);
            }
            verify_actual_codeword(chunk, &actual, &mut verification.inner)?;
            current_deadline(deadline)?;
        }
        ensure(
            self.native_funding_observation(request.groups[0].policy.source)?
                .anchor
                == observed,
            "NATIVE_CELL_GROUPED_CURRENT_ANCHOR_CHANGED",
        )?;
        plan_file
            .read_complete_current(catalog, observed.height, deadline)
            .map_err(group_error)?;
        let parents = finish_parents(
            self,
            budgets,
            journal,
            ParentCompletionV3 {
                plan,
                kind: NativeCellShardGroupKindV3::Storage,
                groups: &request.groups,
                runs: &runs,
                observed: &current,
                deadline,
            },
        )?;
        current_deadline(deadline)?;
        Ok(NativeCellGroupedShardPlanReadbackV3 {
            plan,
            observed_at: observed,
            parents,
            children: covered * 6,
            verification_usage: verification.usage(),
            codec_usage: verification.codec_usage(),
        })
    }
}
