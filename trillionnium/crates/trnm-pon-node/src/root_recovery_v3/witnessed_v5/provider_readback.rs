//! Read-only reconciliation under the existing V5 freshness owner.
//!
//! The provider retains the original V4 operation/material identity. V5 adds
//! live witness checks around the historical enrollment lookup, not a second
//! effect attempt or authority to execute an old intent. Revocation and expiry
//! do not prevent learning what an already entered operation did.
use super::{
    require, OwnerBudgetV3, RecoveryFloorV4, RootOwnerResultV3, RootOwnerV3, WitnessedRootOwnerV5,
};
use crate::root_recovery_v3::effect_readback_v4::{ProviderEnrollmentV4, ReadbackMaterialV4};
use trnm_crypto_primitives::pq_root_v3::DualFamilyRosterV3;
use trnm_release_bundle::root_recovery_v3::DigestV3;

impl WitnessedRootOwnerV5 {
    /// Reconstruct the exact historical provider read identity while requiring
    /// fresh authenticated V5 witness agreement. Provider keys must be disjoint
    /// from the complete retained Root/service roles and from this witness.
    /// The resulting identity grants no effect, M15 entry or redispatch power.
    pub fn provider_readback_enrollment_v4(
        &mut self,
        operation: DigestV3,
        provider: [u8; 32],
        roster: DualFamilyRosterV3,
        material: ReadbackMaterialV4<'_>,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEnrollmentV4> {
        self.with_provider_readback(&roster, budget, |root, budget| {
            root.provider_readback_enrollment_v4(
                operation,
                provider,
                roster.clone(),
                material,
                budget,
            )
        })
    }

    pub(in crate::root_recovery_v3) fn refresh_provider_enrollment_v4(
        &mut self,
        enrollment: &ProviderEnrollmentV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        self.with_provider_readback(enrollment.roster(), budget, |root, budget| {
            root.refresh_provider_enrollment(enrollment, budget)
        })
    }

    fn with_provider_readback<T>(
        &mut self,
        roster: &DualFamilyRosterV3,
        budget: &mut OwnerBudgetV3,
        read: impl FnOnce(&mut RootOwnerV3, &mut OwnerBudgetV3) -> RootOwnerResultV3<T>,
    ) -> RootOwnerResultV3<T> {
        let result = (|| {
            self.healthy(budget)?;
            let original = budget.identity.clone();
            let witness_keys = self.witness.policy.witness_roster().key_ids();
            require(
                roster
                    .key_ids()
                    .iter()
                    .all(|key| !witness_keys.contains(key)),
                "ROOT_PROVIDER_WITNESS_CROSS_ROLE_KEY",
            )?;
            let before = self.context(budget)?.head;
            // The V4 historical reader requires a recovery floor. Here it can
            // only come from the just authenticated live V5 witness, after
            // exact local-history/anchor agreement. It is never reconstructed
            // from an old provider journal or used as a witness fallback.
            self.inner.recovery_floor = Some(RecoveryFloorV4::from_external_pin(
                &self.inner.enrollment,
                before,
            )?);
            let observation = read(&mut self.inner, budget);
            budget.check_identity(&original)?;
            let value = observation?;
            // The original anchor callback can yield. Recheck the complete V5
            // owner after it before returning the historical identity.
            let after = self.context(budget)?.head;
            require(before == after, "ROOT_PROVIDER_WITNESS_SNAPSHOT_CHANGED")?;
            budget.check_identity(&original)?;
            Ok(value)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
}
