use crate::*;

impl StateStore {
    pub fn set_balance(&mut self, address: impl Into<String>, amount: u128) {
        self.invalidate_state_root_cache();
        let address = address.into();
        if amount == 0 {
            self.balances.remove(&address);
        } else {
            self.balances.insert(address, amount);
        }
    }

    pub fn balance_of(&self, address: &str) -> u128 {
        self.balances.get(address).copied().unwrap_or(0)
    }

    pub fn debit_balance(&mut self, address: &str, amount: u128) -> Result<(), String> {
        let cur = self.balance_of(address);
        if cur < amount {
            return Err(format!(
                "insufficient balance: address={}, have={}, need={}",
                address, cur, amount
            ));
        }
        self.invalidate_state_root_cache();
        let next = cur - amount;
        if next == 0 {
            self.balances.remove(address);
        } else {
            self.balances.insert(address.to_string(), next);
        }
        Ok(())
    }

    pub fn credit_balance(&mut self, address: &str, amount: u128) -> Result<(), String> {
        let cur = self.balance_of(address);
        let next = cur.checked_add(amount).ok_or_else(|| {
            format!(
                "balance overflow on credit: address={}, current={}, amount={}",
                address, cur, amount
            )
        })?;
        self.invalidate_state_root_cache();
        if next == 0 {
            self.balances.remove(address);
        } else {
            self.balances.insert(address.to_string(), next);
        }
        Ok(())
    }
}
