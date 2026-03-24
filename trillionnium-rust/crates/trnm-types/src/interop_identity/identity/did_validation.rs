use super::{AuditAction, DidRecord, IdentityRegistry, InteropIdentityError};

impl IdentityRegistry {
    pub fn register_did(
        &mut self,
        did: String,
        controller: String,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("did", &did)?;
        Self::validate_identity_field("controller", &controller)?;

        if self.dids.contains_key(&did) {
            return Err(InteropIdentityError::DidAlreadyExists { did });
        }
        self.dids.insert(
            did.clone(),
            DidRecord {
                did: did.clone(),
                controller: controller.clone(),
                created_at: at_height,
                revoked_at: None,
            },
        );
        self.push_audit(AuditAction::DidRegistered, controller, did, at_height, None);
        Ok(())
    }

    pub fn revoke_did(
        &mut self,
        actor: String,
        did: &str,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;
        Self::validate_identity_field("did", did)?;

        let did_rec = self
            .dids
            .get_mut(did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: did.to_string(),
            })?;

        Self::ensure_actor_controls_did(&actor, did_rec)?;

        let (is_first_revoke, did_revoke_anchor) =
            if let Some(first_revoked_at) = did_rec.revoked_at {
                if at_height < first_revoked_at {
                    return Err(InteropIdentityError::InvalidDidRevocationHeight {
                        created_at: first_revoked_at,
                        revoked_at: at_height,
                    });
                }
                (false, first_revoked_at)
            } else {
                if at_height < did_rec.created_at {
                    return Err(InteropIdentityError::InvalidDidRevocationHeight {
                        created_at: did_rec.created_at,
                        revoked_at: at_height,
                    });
                }
                did_rec.revoked_at = Some(at_height);
                (true, at_height)
            };

        if is_first_revoke {
            self.push_audit(
                AuditAction::DidRevoked,
                actor,
                did.to_string(),
                did_revoke_anchor,
                None,
            );
        }

        let to_revoke: Vec<u64> = self
            .capabilities
            .iter()
            .filter_map(|(token_id, token)| {
                (token.subject_did == did && token.revoked_at.is_none()).then_some(*token_id)
            })
            .collect();

        for token_id in to_revoke {
            let (subject, cascade_revoke_height) = {
                let Some(token) = self.capabilities.get_mut(&token_id) else {
                    continue;
                };
                let cascade_revoke_height = did_revoke_anchor.max(token.issued_at);
                token.revoked_at = Some(cascade_revoke_height);
                (token.subject_did.clone(), cascade_revoke_height)
            };
            self.push_audit(
                AuditAction::CapabilityRevoked,
                "system:cascade".to_string(),
                subject,
                cascade_revoke_height,
                Some(format!("cascade_on_did_revoke token_id={}", token_id)),
            );
        }

        Ok(())
    }

    pub fn verify_capability(
        &self,
        actor: &str,
        token_id: u64,
        required_scope: super::CapabilityScope,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", actor)?;

        let token = self
            .capabilities
            .get(&token_id)
            .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;

        let did =
            self.dids
                .get(&token.subject_did)
                .ok_or_else(|| InteropIdentityError::DidNotFound {
                    did: token.subject_did.clone(),
                })?;

        if !did.is_active_at(at_height) {
            return Err(InteropIdentityError::DidRevoked {
                did: did.did.clone(),
            });
        }

        if !token.is_active_at(at_height) {
            return Err(InteropIdentityError::CapabilityInactive {
                token_id,
                at_height,
                issued_at: token.issued_at,
                expires_at: token.expires_at,
                revoked_at: token.revoked_at,
            });
        }

        if token.scope != required_scope {
            return Err(InteropIdentityError::CapabilityScopeMismatch {
                token_id,
                expected: required_scope,
                actual: token.scope,
            });
        }

        Self::ensure_actor_controls_did(actor, did)?;
        Ok(())
    }
}
