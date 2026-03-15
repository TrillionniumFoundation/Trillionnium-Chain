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
}

impl SettlementVault {
    pub fn new(owner: impl Into<AccountId>) -> Self {
        Self {
            owner: owner.into(),
            paused: false,
            balances: HashMap::new(),
            locks: HashMap::new(),
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

    pub fn deposit(
        &mut self,
        caller: &str,
        account: &str,
        amount: u128,
    ) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        self.ensure_not_paused()?;
        if amount == 0 {
            return Err(VaultError::InvalidAmount);
        }

        self.credit_balance(account, amount)
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

        self.credit_balance(&account, amount)
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

        self.credit_balance(beneficiary, amount)
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

        self.credit_balance(to, amount)
    }

    pub fn pause(&mut self, caller: &str) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        if self.paused {
            return Err(VaultError::AlreadyPaused);
        }

        self.paused = true;
        Ok(())
    }

    pub fn unpause(&mut self, caller: &str) -> Result<(), VaultError> {
        self.ensure_owner(caller)?;
        if !self.paused {
            return Err(VaultError::NotPaused);
        }

        self.paused = false;
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
        *entry = entry.checked_add(amount).ok_or(VaultError::BalanceOverflow)?;
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
        assert_eq!(vault.pause("mallory").unwrap_err(), VaultError::Unauthorized);
        assert_eq!(vault.unpause("mallory").unwrap_err(), VaultError::Unauthorized);
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
    fn transfer_moves_balance_between_accounts() {
        let mut vault = SettlementVault::new("owner");

        vault.deposit("owner", "alice", 50).unwrap();
        vault.lock("owner", "req-1", "alice", 20).unwrap();

        let err = vault
            .transfer("mallory", "alice", "bob", 10)
            .unwrap_err();
        assert_eq!(err, VaultError::Unauthorized);

        let err = vault
            .transfer("owner", "alice", "bob", 0)
            .unwrap_err();
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
