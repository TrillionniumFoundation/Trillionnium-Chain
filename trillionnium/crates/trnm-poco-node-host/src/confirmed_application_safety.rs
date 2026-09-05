use crate::PocoNodeHostV0;
use trnm_poco_node_authority::{
    AuthorityReceiptV0, AuthorityStageV0, ConfirmedApplicationSafetyAuthorityV0,
    ConfirmedSafetyContinuationV0, NodeAuthorityErrorV0, OperationBindingV0,
};

impl PocoNodeHostV0 {
    /// Wire ApplicationSealed from one non-forgeable checkpoint capability and
    /// return the one-use continuation for SafetyPersisted.
    pub fn advance_confirmed_application_v0(
        &mut self,
        binding: OperationBindingV0,
        facts: ConfirmedApplicationSafetyAuthorityV0,
    ) -> Result<(AuthorityReceiptV0, ConfirmedSafetyContinuationV0), NodeAuthorityErrorV0> {
        let (digest, continuation) = facts
            .into_application_stage_v0(binding)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        let receipt = self.advance_authority_exact(
            binding,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            digest,
        )?;
        Ok((receipt, continuation))
    }

    /// Wire SafetyPersisted by consuming the exact continuation returned by
    /// `advance_confirmed_application_v0` for the same operation.
    pub fn advance_confirmed_safety_v0(
        &mut self,
        binding: OperationBindingV0,
        continuation: ConfirmedSafetyContinuationV0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        let digest = continuation
            .into_safety_stage_v0(binding)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        self.advance_authority_exact(
            binding,
            AuthorityStageV0::ApplicationSealed,
            AuthorityStageV0::SafetyPersisted,
            digest,
        )
    }
}
