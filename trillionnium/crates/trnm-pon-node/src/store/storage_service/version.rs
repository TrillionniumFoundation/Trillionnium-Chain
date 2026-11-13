//! Ordinary Node/M12 ownership for complete TCA3 version retention.
//!
//! The complete-version service and the original physical member services are
//! separately admitted native tasks. Their local reservations are distinct
//! obligations, not extra payload copies, independent replicas or payments.
//! Shared members retain their original task, claim, immutable terms and effect;
//! a new version cannot silently rename them or extend their physical leases.

use std::collections::BTreeSet;

use super::*;
use trnm_data_availability::cell::{
    CellVersionCatalogAnchorV3, CellVersionRetentionContractV3, CellVersionRetentionReadbackV3,
    CellVersionRetentionStoreV3,
};
use trnm_service_settlement::native_budget::{NativeBudgetAnchorV1, NativeBudgetEffectCheckV1};

#[derive(Clone, Debug)]
pub struct NativeCellVersionRetentionRequestV3 {
    /// A distinct complete-version service task, separate from its members.
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub contract: CellVersionRetentionContractV3,
    /// Original observed catalog prefix; an exact scheduler reservation may already exist.
    pub expected_catalog: CellVersionCatalogAnchorV3,
    /// Exact original physical claims in the contract's canonical object order.
    /// Every member has its own indivisible task. Completed shared members keep
    /// those same identities and only undergo fresh target readback.
    pub members: Vec<NativeCellRetentionRequestV1>,
}

#[derive(Clone, Debug)]
pub struct NativeCellVersionEffectReadbackV3 {
    pub target: CellVersionRetentionReadbackV3,
    pub effect: Hash,
    pub target_receipt: Hash,
    pub replay: NativeBudgetReplayV1,
    pub members: Vec<NativeCellEffectReadbackV1>,
}

#[derive(Clone, Debug)]
pub struct NativeCellVersionRepairRequestV3 {
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub version_operation: Hash,
    pub object_operation: Hash,
    pub repair_operation: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCellVersionRetirementReadbackV3 {
    pub operation: Hash,
    pub version: [u8; 64],
    pub contract_commitment: Hash,
    /// Current original-chain observation, not finality or a funding grant.
    pub observed_at: NativeBudgetAnchorV1,
}

fn initial_receipt(effect: Hash) -> Hash {
    hash(b"trnm.native-cell-initial-readback.v1\0", &[&effect])
}

fn version_receipt(effect: Hash) -> Hash {
    hash(
        b"trnm.native-cell-version-initial-readback.v3\0",
        &[&effect],
    )
}

fn storage_binding(
    policy: &NativeBudgetPolicyV1,
    claim: &NativeBudgetClaimV1,
    funding: Hash,
    effect: Hash,
    bytes: u64,
    from: u64,
    until: u64,
) -> Result<()> {
    task_policy(policy, claim)?;
    let blocks = until
        .checked_sub(from)
        .filter(|span| *span > 0)
        .and_then(|span| bytes.checked_mul(span))
        .ok_or("NATIVE_CELL_BYTE_BLOCK_OVERFLOW")?;
    ensure(
        claim.claim == funding
            && claim.subject == effect
            && until <= policy.deadline
            && matches!(claim.resource_reservation,
                NativeBudgetResourcesV1::Storage { retained_bytes, retained_byte_blocks }
                if retained_bytes >= bytes && retained_byte_blocks >= blocks),
        "NATIVE_CELL_STORAGE_BINDING",
    )
}

fn version_checks<'a>(
    retention: &CellVersionRetentionStoreV3,
    request: &'a NativeCellVersionRetentionRequestV3,
) -> Result<(Hash, Vec<NativeBudgetEffectCheckV1<'a>>)> {
    let contract = &request.contract;
    let effect = retention
        .contract_commitment(contract)
        .map_err(owner_error)?;
    ensure(
        request.members.len() == contract.objects.len(),
        "NATIVE_CELL_VERSION_MEMBER_COVERAGE",
    )?;
    let bytes = contract.objects.iter().try_fold(0_u64, |total, object| {
        total
            .checked_add(object.manifest.size())
            .ok_or("NATIVE_CELL_VERSION_BYTE_OVERFLOW")
    })?;
    storage_binding(
        &request.policy,
        &request.claim,
        contract.funding_operation,
        effect,
        bytes,
        contract.retain_from_height,
        contract.retain_until_height,
    )?;
    ensure(
        request.claim.beneficiary == contract.responsible_owner,
        "NATIVE_CELL_VERSION_OWNER_BINDING",
    )?;
    let mut identities = BTreeSet::new();
    for identity in [
        contract.operation,
        request.claim.claim,
        request.policy.budget,
    ] {
        ensure(
            identity != [0; 32] && identities.insert(identity),
            "NATIVE_CELL_VERSION_IDENTITY_ALIAS",
        )?;
    }
    let mut sources = BTreeSet::from([request.policy.source]);
    let mut checks = Vec::with_capacity(request.members.len() + 1);
    for (member, object) in request.members.iter().zip(&contract.objects) {
        ensure(
            member.contract == *object,
            "NATIVE_CELL_VERSION_MEMBER_COVERAGE",
        )?;
        for identity in [object.operation, member.claim.claim, member.policy.budget] {
            ensure(
                identity != [0; 32] && identities.insert(identity),
                "NATIVE_CELL_VERSION_IDENTITY_ALIAS",
            )?;
        }
        ensure(
            sources.insert(member.policy.source),
            "NATIVE_CELL_VERSION_TASK_ALIAS",
        )?;
        ensure(
            member.claim.beneficiary == contract.responsible_owner,
            "NATIVE_CELL_VERSION_OWNER_BINDING",
        )?;
        let member_effect = object.commitment(retention.store_id());
        storage_binding(
            &member.policy,
            &member.claim,
            object.funding_operation,
            member_effect,
            object.manifest.size(),
            object.retain_from_height,
            object.retain_until_height,
        )?;
        checks.push(NativeBudgetEffectCheckV1 {
            policy: &member.policy,
            claim: &member.claim,
            operation: object.operation,
            effect: member_effect,
            window: Some((object.retain_from_height, object.retain_until_height)),
        });
    }
    // Member intents precede the outer intent. If an outer effect already
    // exists, every original member intent must exist as well; recovery cannot
    // use an incomplete journal as permission for previously unrecorded work.
    checks.push(NativeBudgetEffectCheckV1 {
        policy: &request.policy,
        claim: &request.claim,
        operation: contract.operation,
        effect,
        window: Some((contract.retain_from_height, contract.retain_until_height)),
    });
    Ok((effect, checks))
}

fn check_recovery_members(replays: &[NativeBudgetReplayV1]) -> Result<()> {
    let (root, members) = replays
        .split_last()
        .ok_or("NATIVE_CELL_VERSION_MEMBER_COVERAGE")?;
    ensure(
        *root == NativeBudgetReplayV1::New
            || members
                .iter()
                .all(|replay| *replay != NativeBudgetReplayV1::New),
        "NATIVE_CELL_VERSION_MEMBER_INTENT_MISSING",
    )
}

impl Node {
    /// The ordinary native funding owner admits a complete TCA3 closure before
    /// any original member copy. Preflight writes nothing; each real journal
    /// call still repeats its original checks. Independent owners are not one
    /// atomic transaction, and any partial/unknown effect remains charged.
    pub fn retain_native_cell_version(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        retention: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        request: NativeCellVersionRetentionRequestV3,
        deadline: Instant,
    ) -> Result<NativeCellVersionEffectReadbackV3> {
        storage_deadline(deadline)?;
        let (effect, checks) = version_checks(retention, &request)?;
        storage_deadline(deadline)?;
        let preflight = budgets.check_effects(self, &checks).map_err(owner_error)?;
        check_recovery_members(&preflight)?;
        storage_deadline(deadline)?;
        for check in &checks {
            budgets
                .open_budget(self, check.policy.clone())
                .map_err(owner_error)?;
            storage_deadline(deadline)?;
            budgets
                .reserve(self, check.claim.clone())
                .map_err(owner_error)?;
            storage_deadline(deadline)?;
        }
        // Preserve the complete pending root before its individual slots or
        // payloads. A failure never removes references or invents a refund.
        retention
            .reserve_version(request.contract.clone(), request.expected_catalog, deadline)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        let mut replays = Vec::with_capacity(checks.len());
        for check in &checks {
            let (from, until) = check.window.ok_or("NATIVE_CELL_VERSION_WINDOW")?;
            replays.push(
                budgets
                    .begin_effect_in_window(
                        self,
                        check.claim.claim,
                        check.operation,
                        check.effect,
                        from,
                        until,
                    )
                    .map_err(owner_error)?,
            );
            storage_deadline(deadline)?;
        }
        check_recovery_members(&replays)?;
        let replay = *replays
            .last()
            .ok_or("NATIVE_CELL_VERSION_MEMBER_COVERAGE")?;
        if replay == NativeBudgetReplayV1::New {
            for ((check, member_replay), object) in
                checks.iter().zip(&replays).zip(&request.contract.objects)
            {
                storage_deadline(deadline)?;
                let target = match member_replay {
                    NativeBudgetReplayV1::New => retention.acknowledge_member(
                        request.contract.operation,
                        object.operation,
                        cache,
                        deadline,
                    ),
                    NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done => retention
                        .reconcile_member(request.contract.operation, object.operation, deadline),
                }
                .map_err(owner_error)?;
                ensure(
                    target.acknowledged && !target.retired,
                    "NATIVE_CELL_TARGET_ACK",
                )?;
                storage_deadline(deadline)?;
                budgets
                    .complete_effect(
                        check.claim.claim,
                        object.operation,
                        initial_receipt(check.effect),
                    )
                    .map_err(owner_error)?;
                storage_deadline(deadline)?;
            }
        }
        // Pending/Done outer effects have no source-bearing path. This also
        // prevents redispatch of members after an interrupted multi-copy call.
        let target = retention
            .reconcile_version(request.contract.operation, deadline, &mut || Ok(()))
            .map_err(owner_error)?;
        ensure(
            target.acknowledged && !target.retired && target.contract_commitment == effect,
            "NATIVE_CELL_VERSION_TARGET_ACK",
        )?;
        let mut members = Vec::with_capacity(request.members.len());
        for ((check, member_replay), member_target) in
            checks.iter().zip(&replays).zip(&target.objects)
        {
            storage_deadline(deadline)?;
            let receipt = initial_receipt(check.effect);
            budgets
                .complete_effect(check.claim.claim, check.operation, receipt)
                .map_err(owner_error)?;
            members.push(NativeCellEffectReadbackV1 {
                target: member_target.clone(),
                effect: check.effect,
                target_receipt: receipt,
                replay: *member_replay,
                repair_cpu_observation: None,
            });
        }
        let target_receipt = version_receipt(effect);
        storage_deadline(deadline)?;
        budgets
            .complete_effect(
                request.claim.claim,
                request.contract.operation,
                target_receipt,
            )
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        Ok(NativeCellVersionEffectReadbackV3 {
            target,
            effect,
            target_receipt,
            replay,
            members,
        })
    }

    /// A separately funded repair remains bound to the full original root and
    /// one exact physical member. An expired dispatch window permits only the
    /// original target-only reconciliation, never another copy or byte charge.
    pub fn repair_native_cell_version_member(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        retention: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        request: NativeCellVersionRepairRequestV3,
        deadline: Instant,
    ) -> Result<NativeCellEffectReadbackV1> {
        storage_deadline(deadline)?;
        task_policy(&request.policy, &request.claim)?;
        let cpu_ns = match request.claim.resource_reservation {
            NativeBudgetResourcesV1::Repair { cpu_ns, .. } if cpu_ns > 0 => cpu_ns,
            _ => return Err("NATIVE_CELL_REPAIR_CPU_REQUIRED".into()),
        };
        let mut cpu = RepairCpuOwner::start(cpu_ns, deadline).map_err(owner_error)?;
        let contract = retention
            .contract(request.version_operation, deadline)
            .map_err(owner_error)?;
        let object = contract
            .objects
            .iter()
            .find(|object| object.operation == request.object_operation)
            .ok_or("NATIVE_CELL_VERSION_MEMBER_COVERAGE")?;
        let effect = native_cell_version_repair_subject_v3(
            retention,
            &contract,
            request.object_operation,
            request.repair_operation,
            request.claim.claim,
        )?;
        let until = contract
            .repair_deadline_height
            .checked_add(1)
            .ok_or("NATIVE_CELL_VERSION_REPAIR_WINDOW")?;
        ensure(
            request.claim.subject == effect
                && request.claim.beneficiary == contract.responsible_owner
                && request.claim.claim != contract.funding_operation
                && request.repair_operation != contract.operation
                && request.repair_operation != [0; 32]
                && request.claim.claim != [0; 32]
                && request.claim.claim != request.repair_operation
                && contract.objects.iter().all(|member| {
                    request.claim.claim != member.funding_operation
                        && request.repair_operation != member.operation
                })
                && until <= request.policy.deadline
                && matches!(request.claim.resource_reservation,
                    NativeBudgetResourcesV1::Repair { download_bytes, attempts, .. }
                    if download_bytes >= object.manifest.size() && attempts >= 1),
            "NATIVE_CELL_VERSION_REPAIR_BINDING",
        )?;
        let checks = [NativeBudgetEffectCheckV1 {
            policy: &request.policy,
            claim: &request.claim,
            operation: request.repair_operation,
            effect,
            window: Some((contract.retain_from_height, until)),
        }];
        cpu.check().map_err(owner_error)?;
        budgets.check_effects(self, &checks).map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        budgets
            .open_budget(self, request.policy.clone())
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        budgets
            .reserve(self, request.claim.clone())
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let replay = budgets
            .begin_effect_in_window(
                self,
                request.claim.claim,
                request.repair_operation,
                effect,
                contract.retain_from_height,
                until,
            )
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let target = match replay {
            NativeBudgetReplayV1::New => {
                let current = self.native_funding_observation(request.policy.source)?;
                cpu.check().map_err(owner_error)?;
                retention.repair_member(
                    request.version_operation,
                    request.object_operation,
                    request.repair_operation,
                    current.anchor.height,
                    cache,
                    deadline,
                    &mut || cpu.check(),
                )
            }
            NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done => retention
                .reconcile_repair_member(
                    request.version_operation,
                    request.object_operation,
                    request.repair_operation,
                    deadline,
                    &mut || cpu.check(),
                ),
        }
        .map_err(owner_error)?;
        ensure(
            target.acknowledged && !target.retired,
            "NATIVE_CELL_TARGET_ACK",
        )?;
        let target_receipt = hash(b"trnm.native-cell-version-repair-readback.v3\0", &[&effect]);
        cpu.check().map_err(owner_error)?;
        budgets
            .complete_effect(
                request.claim.claim,
                request.repair_operation,
                target_receipt,
            )
            .map_err(owner_error)?;
        let repair_cpu_observation = Some(
            cpu.finish(replay == NativeBudgetReplayV1::New)
                .map_err(owner_error)?,
        );
        Ok(NativeCellEffectReadbackV1 {
            target,
            effect,
            target_receipt,
            replay,
            repair_cpu_observation,
        })
    }

    fn completed_version_anchor(
        &mut self,
        budgets: &NativeBudgetStoreV1,
        retention: &CellVersionRetentionStoreV3,
        contract: &CellVersionRetentionContractV3,
        deadline: Instant,
    ) -> Result<NativeBudgetAnchorV1> {
        let effect = retention
            .contract_commitment(contract)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        let anchor = budgets
            .reobserve_completed_effect(
                self,
                contract.funding_operation,
                contract.operation,
                effect,
                Some((contract.retain_from_height, contract.retain_until_height)),
                version_receipt(effect),
            )
            .map_err(owner_error)?;
        for object in &contract.objects {
            storage_deadline(deadline)?;
            let member_effect = object.commitment(retention.store_id());
            let current = budgets
                .reobserve_completed_effect(
                    self,
                    object.funding_operation,
                    object.operation,
                    member_effect,
                    Some((object.retain_from_height, object.retain_until_height)),
                    initial_receipt(member_effect),
                )
                .map_err(owner_error)?;
            ensure(current == anchor, "NATIVE_CELL_VERSION_ANCHOR_CHANGED")?;
        }
        storage_deadline(deadline)?;
        Ok(anchor)
    }

    /// Retire only the completed root under its original journal and current
    /// native chain. Root retirement alone does not reclaim any shared object.
    pub fn retire_native_cell_version(
        &mut self,
        budgets: &NativeBudgetStoreV1,
        retention: &mut CellVersionRetentionStoreV3,
        operation: Hash,
        deadline: Instant,
    ) -> Result<NativeCellVersionRetirementReadbackV3> {
        storage_deadline(deadline)?;
        let contract = retention
            .contract(operation, deadline)
            .map_err(owner_error)?;
        let observed_at = self.completed_version_anchor(budgets, retention, &contract, deadline)?;
        retention
            .retire_version(operation, observed_at.height, deadline)
            .map_err(owner_error)?;
        let contract_commitment = retention
            .contract_commitment(&contract)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        Ok(NativeCellVersionRetirementReadbackV3 {
            operation,
            version: contract.version.commitment(),
            contract_commitment,
            observed_at,
        })
    }

    /// Physical reclamation repeats full rooted GC after checking every original
    /// completed funding effect and the current chain. Any other live or pending
    /// root, an unexpired physical term or unsettled repair still refuses.
    pub fn retire_native_cell_version_member(
        &mut self,
        budgets: &NativeBudgetStoreV1,
        retention: &mut CellVersionRetentionStoreV3,
        version_operation: Hash,
        object_operation: Hash,
        mut successor: Option<&mut CellVersionRetentionStoreV3>,
        deadline: Instant,
    ) -> Result<CellRetentionReadbackV1> {
        storage_deadline(deadline)?;
        let contract = retention
            .contract(version_operation, deadline)
            .map_err(owner_error)?;
        let object = contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or("NATIVE_CELL_VERSION_MEMBER_COVERAGE")?;
        let current = self.completed_version_anchor(budgets, retention, &contract, deadline)?;
        if let Some(expected) = object.successor {
            if retention
                .retired_object_readback(object_operation, deadline)
                .map_err(owner_error)?
                .is_none()
            {
                let next = successor
                    .as_deref_mut()
                    .ok_or("NATIVE_CELL_SUCCESSOR_REQUIRED")?;
                let next_contract = next
                    .object_contract(expected.1, deadline)
                    .map_err(owner_error)?;
                self.check_retirement_successor(
                    budgets,
                    expected,
                    next.store_id(),
                    &next_contract,
                    current,
                    deadline,
                )?;
            }
        }
        let result = retention
            .retire_object(object_operation, current.height, successor, deadline)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        Ok(result)
    }
}

/// Immutable ordinary-task output for one original complete-root member repair.
pub fn native_cell_version_repair_subject_v3(
    retention: &CellVersionRetentionStoreV3,
    contract: &CellVersionRetentionContractV3,
    object_operation: Hash,
    repair_operation: Hash,
    repair_claim: Hash,
) -> Result<Hash> {
    let object = contract
        .objects
        .iter()
        .find(|object| object.operation == object_operation)
        .ok_or("NATIVE_CELL_VERSION_MEMBER_COVERAGE")?;
    let root = retention
        .contract_commitment(contract)
        .map_err(owner_error)?;
    Ok(hash(
        b"trnm.native-cell-version-repair-subject.v3\0",
        &[
            &root,
            &object.commitment(retention.store_id()),
            &repair_operation,
            &repair_claim,
        ],
    ))
}
