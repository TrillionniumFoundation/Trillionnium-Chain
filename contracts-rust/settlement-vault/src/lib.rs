use audit_events::AuditEvent;
use std::collections::HashMap;

pub type AccountId = String;
pub type RequestId = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    Unauthorized,
    Paused,
    AlreadyPaused,
    NotPaused,
    InvalidAmount,
    InsufficientBalance,
    DuplicateRequest,
    RequestNotFound,
    InvalidStateTransition,
    BalanceOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultEvent {
    Deposited {
        caller: String,
        account: String,
        amount: u128,
    },
    Locked {
        request_id: String,
        account: String,
        amount: u128,
    },
    Released {
        request_id: String,
        account: String,
        amount: u128,
    },
    Slashed {
        request_id: String,
        beneficiary: String,
        amount: u128,
    },
    Transferred {
        from: String,
        to: String,
        amount: u128,
    },
    Paused,
    Unpaused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    Locked,
    Released,
    Slashed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRecord {
    pub account: AccountId,
    pub amount: u128,
    pub status: LockStatus,
}

#[derive(Debug, Clone)]
pub struct SettlementVault {
    owner: AccountId,
    paused: bool,
    balances: HashMap<AccountId, u128>,
    locks: HashMap<RequestId, LockRecord>,
    audit_log: Vec<VaultEvent>,
}

impl SettlementVault {
    pub fn new(owner: impl Into<AccountId>) -> Self {
        Self {
            owner: owner.into(),
            paused: false,
            balances: HashMap::new(),
            locks: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn balance_of(&self, account: &str) -> u128 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    pub fn lock_record(&self, request_id: &str) -> Option<&LockRecord> {
        self.locks.get(request_id)
    }

    pub fn audit_log(&self) -> &[VaultEvent] {
        &self.audit_log
    }

    pub fn consume_audit_log(&mut self) -> Vec<VaultEvent> {
        std::mem::take(&mut self.audit_log)
    }

    pub fn normalized_audit_log(&self) -> Vec<AuditEvent> {
        self.audit_log
            .iter()
            .map(Self::normalize_audit_event)
            .collect()
    }

    fn normalize_audit_event(event: &VaultEvent) -> AuditEvent {
        match event {
            VaultEvent::Deposited {
                caller,
                account,
                amount,
            } => {
                let mut normalized = AuditEvent::new("settlement-vault", "vault.deposited");
                normalized.actor = Some(caller.clone());
                normalized.object_id = Some(account.clone());
                normalized.amount = Some(*amount);
                normalized
            }
            VaultEvent::Locked {
                request_id,
                account,
                amount,
            } => {
                let mut normalized = AuditEvent::new("settlement-vault", "vault.locked");
                normalized.actor = Some(account.clone());
                normalized.object_id = Some(request_id.clone());
                normalized.related_id = Some(account.clone());
                normalized.amount = Some(*amount);
                normalized
            }
            VaultEvent::Released {
                request_id,
                account,
                amount,
            } => {
                let mut normalized = AuditEvent::new("settlement-vault", "vault.released");
                normalized.actor = Some(account.clone());
                normalized.object_id = Some(request_id.clone());
                normalized.related_id = Some(account.clone());
                normalized.amount = Some(*amount);
                normalized
            }
            VaultEvent::Slashed {
                request_id,
                beneficiary,
                amount,
            } => {
                let mut normalized = AuditEvent::new("settlement-vault", "vault.slashed");
                normalized.actor = Some(beneficiary.clone());
                normalized.object_id = Some(request_id.clone());
                normalized.related_id = Some(beneficiary.clone());
                normalized.amount = Some(*amount);
                normalized
            }
            VaultEvent::Transferred { from, to, amount } => {
                let mut normalized = AuditEvent::new("settlement-vault", "vault.transferred");
                normalized.actor = Some(from.clone());
                normalized.object_id = Some(from.clone());
                normalized.related_id = Some(to.clone());
                normalized.amount = Some(*amount);
                normalized
            }
            VaultEvent::Paused => {
                let normalized = AuditEvent::new("settlement-vault", "vault.paused");
                normalized
            }
            VaultEvent::Unpaused => {
                let normalized = AuditEvent::new("settlement-vault", "vault.unpaused");
                normalized
            }
        }
    }

    pub fn deposit(&mut self, caller: &str, account: &str, amount: u128) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        self.ensure_not_paused()?;
        if amount == 0 {
            return Err(VaultError::InvalidAmount);
        }

        self.credit_balance(account, amount)?;
        self.audit_log.push(VaultEvent::Deposited {
            caller: caller.to_string(),
            account: account.to_string(),
            amount,
        });
        Ok(())
    }

    pub fn lock(
        &mut self,
        caller: &str,
        request_id: &str,
        account: &str,
        amount: u128,
    ) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        self.ensure_not_paused()?;

        if amount == 0 {
            return Err(VaultError::InvalidAmount);
        }
        if self.locks.contains_key(request_id) {
            return Err(VaultError::DuplicateRequest);
        }

        let balance = self.balances.entry(account.to_string()).or_insert(0);
        if *balance < amount {
            return Err(VaultError::InsufficientBalance);
        }
        *balance -= amount;

        self.locks.insert(
            request_id.to_string(),
            LockRecord {
                account: account.to_string(),
                amount,
                status: LockStatus::Locked,
            },
        );

        self.audit_log.push(VaultEvent::Locked {
            request_id: request_id.to_string(),
            account: account.to_string(),
            amount,
        });

        Ok(())
    }

    pub fn release(&mut self, caller: &str, request_id: &str) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        self.ensure_not_paused()?;

        let (account, amount) = {
            let lock = self
                .locks
                .get_mut(request_id)
                .ok_or(VaultError::RequestNotFound)?;

            if lock.status != LockStatus::Locked {
                return Err(VaultError::InvalidStateTransition);
            }

            lock.status = LockStatus::Released;
            (lock.account.clone(), lock.amount)
        };

        self.credit_balance(&account, amount)?;
        self.audit_log.push(VaultEvent::Released {
            request_id: request_id.to_string(),
            account,
            amount,
        });
        Ok(())
    }

    pub fn slash(
        &mut self,
        caller: &str,
        request_id: &str,
        beneficiary: &str,
    ) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        self.ensure_not_paused()?;

        let amount = {
            let lock = self
                .locks
                .get_mut(request_id)
                .ok_or(VaultError::RequestNotFound)?;

            if lock.status != LockStatus::Locked {
                return Err(VaultError::InvalidStateTransition);
            }

            lock.status = LockStatus::Slashed;
            lock.amount
        };

        self.credit_balance(beneficiary, amount)?;
        self.audit_log.push(VaultEvent::Slashed {
            request_id: request_id.to_string(),
            beneficiary: beneficiary.to_string(),
            amount,
        });
        Ok(())
    }

    pub fn transfer(
        &mut self,
        caller: &str,
        from: &str,
        to: &str,
        amount: u128,
    ) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        self.ensure_not_paused()?;
        if amount == 0 {
            return Err(VaultError::InvalidAmount);
        }

        let from_entry = self.balances.entry(from.to_string()).or_insert(0);
        if *from_entry < amount {
            return Err(VaultError::InsufficientBalance);
        }
        *from_entry -= amount;

        self.credit_balance(to, amount)?;
        self.audit_log.push(VaultEvent::Transferred {
            from: from.to_string(),
            to: to.to_string(),
            amount,
        });
        Ok(())
    }

    pub fn pause(&mut self, caller: &str) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        if self.paused {
            return Err(VaultError::AlreadyPaused);
        }

        self.paused = true;
        self.audit_log.push(VaultEvent::Paused);
        Ok(())
    }

    pub fn unpause(&mut self, caller: &str) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        if !self.paused {
            return Err(VaultError::NotPaused);
        }

        self.paused = false;
        self.audit_log.push(VaultEvent::Unpaused);
        Ok(())
    }

    fn ensure_owner(&self, caller: &str) -> Result<(), VaultError> {
        if caller != self.owner {
            return Err(VaultError::Unauthorized);
        }
        Ok(())
    }

    fn ensure_not_paused(&self) -> Result<(), VaultError> {
        if self.paused {
            return Err(VaultError::Paused);
        }
        Ok(())
    }

    fn credit_balance(&mut self, account: &str, amount: u128) -> Result<(), VaultError> {
        let entry = self.balances.entry(account.to_string()).or_insert(0);
        *entry = entry
            .checked_add(amount)
            .ok_or(VaultError::BalanceOverflow)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_lock_release_happy_path() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 100).unwrap();
        assert_eq!(vault.balance_of("alice"), 100);

        vault.lock("owner", "req-1", "alice", 60).unwrap();
        assert_eq!(vault.balance_of("alice"), 40);
        assert_eq!(
            vault.lock_record("req-1").unwrap().status,
            LockStatus::Locked
        );

        vault.release("owner", "req-1").unwrap();
        assert_eq!(vault.balance_of("alice"), 100);
        assert_eq!(
            vault.lock_record("req-1").unwrap().status,
            LockStatus::Released
        );
    }

    #[test]
    fn duplicate_request_is_rejected() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 100).unwrap();
        vault.lock("owner", "req-dup", "alice", 10).unwrap();

        let err = vault
            .lock("owner", "req-dup", "alice", 10)
            .expect_err("duplicate request must fail");
        assert_eq!(err, VaultError::DuplicateRequest);
    }

    #[test]
    fn unauthorized_actions_are_rejected() {
        let mut vault = SettlementVault::new("owner");

        assert_eq!(
            vault.deposit("alice", "alice", 50).unwrap_err(),
            VaultError::Unauthorized
        );
        vault.deposit("owner", "alice", 50).unwrap();

        assert_eq!(
            vault.lock("mallory", "req-1", "alice", 10).unwrap_err(),
            VaultError::Unauthorized
        );
        assert_eq!(
            vault.pause("mallory").unwrap_err(),
            VaultError::Unauthorized
        );
        assert_eq!(
            vault.unpause("mallory").unwrap_err(),
            VaultError::Unauthorized
        );
    }

    #[test]
    fn illegal_state_transition_is_rejected() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 100).unwrap();
        vault.lock("owner", "req-1", "alice", 20).unwrap();
        vault.release("owner", "req-1").unwrap();

        let err = vault
            .slash("owner", "req-1", "treasury")
            .expect_err("cannot slash after release");
        assert_eq!(err, VaultError::InvalidStateTransition);
    }

    #[test]
    fn pause_blocks_state_changes_until_unpause() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 100).unwrap();
        vault.pause("owner").unwrap();

        assert_eq!(vault.pause("owner").unwrap_err(), VaultError::AlreadyPaused);
        assert_eq!(
            vault.deposit("owner", "alice", 1).unwrap_err(),
            VaultError::Paused
        );
        assert_eq!(
            vault.lock("owner", "req-paused", "alice", 1).unwrap_err(),
            VaultError::Paused
        );

        vault.unpause("owner").unwrap();
        assert_eq!(vault.unpause("owner").unwrap_err(), VaultError::NotPaused);

        vault.lock("owner", "req-paused", "alice", 1).unwrap();
    }

    #[test]
    fn slash_transfers_to_beneficiary() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 30).unwrap();
        vault.lock("owner", "req-2", "alice", 30).unwrap();
        vault.slash("owner", "req-2", "treasury").unwrap();

        assert_eq!(vault.balance_of("alice"), 0);
        assert_eq!(vault.balance_of("treasury"), 30);
        assert_eq!(
            vault.lock_record("req-2").unwrap().status,
            LockStatus::Slashed
        );
    }

    #[test]
    fn audit_log_records_vault_events() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 100).unwrap();
        vault.lock("owner", "req-1", "alice", 25).unwrap();
        vault.release("owner", "req-1").unwrap();

        vault.deposit("owner", "alice", 30).unwrap();
        vault.transfer("owner", "alice", "bob", 20).unwrap();

        vault.pause("owner").unwrap();
        vault.unpause("owner").unwrap();
        assert_eq!(vault.unpause("owner").unwrap_err(), VaultError::NotPaused);

        vault.lock("owner", "req-2", "alice", 10).unwrap();
        vault.slash("owner", "req-2", "treasury").unwrap();

        let normalized = vault.normalized_audit_log();
        let logs = vault.consume_audit_log();

        assert!(logs.iter().any(|event| matches!(
            event,
            VaultEvent::Deposited { caller, account, amount }
                if caller == "owner" && account == "alice" && *amount == 100
        )));
        assert!(logs.iter().any(|event| matches!(
            event,
            VaultEvent::Locked { request_id, account, amount }
                if request_id == "req-1" && account == "alice" && *amount == 25
        )));
        assert!(logs.iter().any(|event| matches!(
            event,
            VaultEvent::Released { request_id, account, amount }
                if request_id == "req-1" && account == "alice" && *amount == 25
        )));
        assert!(logs.iter().any(|event| matches!(
            event,
            VaultEvent::Transferred { from, to, amount }
                if from == "alice" && to == "bob" && *amount == 20
        )));
        assert!(logs.iter().any(|event| matches!(event, VaultEvent::Paused)));
        assert!(logs
            .iter()
            .any(|event| matches!(event, VaultEvent::Unpaused)));
        assert!(logs.iter().any(|event| matches!(
            event,
            VaultEvent::Slashed { request_id, beneficiary, amount }
                if request_id == "req-2" && beneficiary == "treasury" && *amount == 10
        )));

        assert!(normalized
            .iter()
            .any(|event| event.event_type == "vault.deposited"));
        assert!(normalized
            .iter()
            .any(|event| event.event_type == "vault.locked"));
        assert!(normalized
            .iter()
            .any(|event| event.event_type == "vault.released"));
        assert!(normalized
            .iter()
            .any(|event| event.event_type == "vault.transferred"));
        assert!(normalized
            .iter()
            .any(|event| event.event_type == "vault.slashed"));
        assert!(normalized
            .iter()
            .any(|event| event.source == "settlement-vault"));
        assert!(normalized.iter().any(|event| {
            event.event_type == "vault.locked"
                && event.object_id.as_deref() == Some("req-1")
                && event.related_id.as_deref() == Some("alice")
        }));
        assert!(normalized.iter().any(|event| {
            event.event_type == "vault.released"
                && event.object_id.as_deref() == Some("req-1")
                && event.related_id.as_deref() == Some("alice")
        }));
        assert!(normalized.iter().any(|event| {
            event.event_type == "vault.transferred"
                && event.object_id.as_deref() == Some("alice")
                && event.related_id.as_deref() == Some("bob")
        }));
        assert!(normalized.iter().any(|event| {
            event.event_type == "vault.slashed"
                && event.object_id.as_deref() == Some("req-2")
                && event.related_id.as_deref() == Some("treasury")
        }));

        assert!(vault.audit_log().is_empty());
    }

    #[test]
    fn transfer_moves_balance_between_accounts() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 50).unwrap();
        vault.lock("owner", "req-1", "alice", 20).unwrap();

        let err = vault.transfer("mallory", "alice", "bob", 10).unwrap_err();
        assert_eq!(err, VaultError::Unauthorized);

        let err = vault.transfer("owner", "alice", "bob", 0).unwrap_err();
        assert_eq!(err, VaultError::InvalidAmount);

        vault.transfer("owner", "alice", "bob", 30).unwrap();
        assert_eq!(vault.balance_of("alice"), 0);
        assert_eq!(vault.balance_of("bob"), 30);

        assert_eq!(
            vault.transfer("owner", "alice", "bob", 999).unwrap_err(),
            VaultError::InsufficientBalance
        );
    }
}
