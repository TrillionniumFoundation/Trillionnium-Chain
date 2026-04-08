use super::{
    AuditAction, CapabilityScope, CapabilityToken, IdentityRegistry, InteropIdentityError,
};

impl IdentityRegistry {
    pub fn issue_capability(
        &mut self,
        actor: String,
        subject_did: String,
        scope: CapabilityScope,
        at_height: u64,
        expires_at: Option<u64>,
    ) -> Result<u64, InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;
        Self::validate_identity_field("subject_did", &subject_did)?;

        if let Some(exp) = expires_at {
            if exp < at_height {
                return Err(InteropIdentityError::InvalidCapabilityExpiry {
                    issued_at: at_height,
                    expires_at: exp,
                });
            }
        }

        match self.dids.get(&subject_did) {
            Some(did) if did.is_active() => {
                Self::ensure_actor_controls_did(&actor, did)?;
                if at_height < did.created_at {
                    return Err(InteropIdentityError::InvalidCapabilityIssueHeight {
                        did: subject_did.clone(),
                        created_at: did.created_at,
                        issued_at: at_height,
                    });
                }
            }
            Some(_) => {
                return Err(InteropIdentityError::DidRevoked {
                    did: subject_did.clone(),
                });
            }
            None => {
                return Err(InteropIdentityError::DidNotFound {
                    did: subject_did.clone(),
                });
            }
        }

        self.next_capability_id += 1;
        let token_id = self.next_capability_id;
        self.capabilities.insert(
            token_id,
            CapabilityToken {
                token_id,
                subject_did: subject_did.clone(),
                scope,
                issued_at: at_height,
                expires_at,
                revoked_at: None,
            },
        );
        self.push_audit(
            AuditAction::CapabilityIssued,
            actor,
            subject_did,
            at_height,
            Some(format!("token_id={}", token_id)),
        );
        Ok(token_id)
    }

    pub fn revoke_capability(
        &mut self,
        actor: String,
        token_id: u64,
        at_height: u64,
        note: Option<String>,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;

        let subject_did = self
            .capabilities
            .get(&token_id)
            .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?
            .subject_did
            .clone();
        let did = self
            .dids
            .get(&subject_did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: subject_did.clone(),
            })?;
        Self::ensure_actor_controls_did(&actor, did)?;

        let subject = {
            let token = self
                .capabilities
                .get_mut(&token_id)
                .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;
            if let Some(first_revoked_at) = token.revoked_at {
                if at_height < first_revoked_at {
                    return Err(InteropIdentityError::InvalidCapabilityRevocationHeight {
                        issued_at: first_revoked_at,
                        revoked_at: at_height,
                    });
                }
                return Ok(());
            }
            if at_height < token.issued_at {
                return Err(InteropIdentityError::InvalidCapabilityRevocationHeight {
                    issued_at: token.issued_at,
                    revoked_at: at_height,
                });
            }
            token.revoked_at = Some(at_height);
            token.subject_did.clone()
        };
        self.push_audit(
            AuditAction::CapabilityRevoked,
            actor,
            subject,
            at_height,
            note,
        );
        Ok(())
    }

    pub fn renew_capability(
        &mut self,
        actor: String,
        token_id: u64,
        at_height: u64,
        expires_at: Option<u64>,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;

        if let Some(exp) = expires_at {
            if exp < at_height {
                return Err(InteropIdentityError::InvalidCapabilityExpiry {
                    issued_at: at_height,
                    expires_at: exp,
                });
            }
        }

        let subject_did = self
            .capabilities
            .get(&token_id)
            .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?
            .subject_did
            .clone();
        let did = self
            .dids
            .get(&subject_did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: subject_did.clone(),
            })?;
        if !did.is_active() {
            return Err(InteropIdentityError::DidRevoked {
                did: did.did.clone(),
            });
        }
        Self::ensure_actor_controls_did(&actor, did)?;

        {
            let token = self
                .capabilities
                .get_mut(&token_id)
                .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;
            if !token.is_active_at(at_height) {
                return Err(InteropIdentityError::CapabilityInactive {
                    token_id,
                    at_height,
                    issued_at: token.issued_at,
                    expires_at: token.expires_at,
                    revoked_at: token.revoked_at,
                });
            }
            if let Some(current_expiry) = token.expires_at {
                match expires_at {
                    Some(requested_expiry) if requested_expiry < current_expiry => {
                        return Err(InteropIdentityError::CapabilityRenewalRegression {
                            current_expires_at: current_expiry,
                            requested_expires_at: requested_expiry,
                        });
                    }
                    None => {
                        return Err(InteropIdentityError::CapabilityRenewalCannotClearExpiry {
                            current_expires_at: current_expiry,
                        });
                    }
                    _ => {}
                }
            }
            if token.expires_at == expires_at {
                return Ok(());
            }
            token.expires_at = expires_at;
        }

        self.push_audit(
            AuditAction::CapabilityRenewed,
            actor,
            subject_did,
            at_height,
            Some(format!("token_id={} expires_at={:?}", token_id, expires_at)),
        );
        Ok(())
    }
}
