// Copyright (c) 2026 A-TownChain-Okosystems — Apache-2.0
//! Overflow-safe wallet balance accounting.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balance {
    pub confirmed: u128,
    pub pending: u128,
    pub staked: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceError {
    Overflow,
    InsufficientFunds,
}

impl Balance {
    pub fn available(&self) -> Result<u128, BalanceError> {
        self.confirmed
            .checked_sub(self.staked)
            .ok_or(BalanceError::InsufficientFunds)?
            .checked_sub(self.pending)
            .ok_or(BalanceError::InsufficientFunds)
    }

    pub fn credit_confirmed(&mut self, amount: u128) -> Result<(), BalanceError> {
        self.confirmed = self.confirmed.checked_add(amount).ok_or(BalanceError::Overflow)?;
        Ok(())
    }

    pub fn debit_confirmed(&mut self, amount: u128) -> Result<(), BalanceError> {
        self.confirmed = self
            .confirmed
            .checked_sub(amount)
            .ok_or(BalanceError::InsufficientFunds)?;
        Ok(())
    }

    pub fn reserve_pending(&mut self, amount: u128) -> Result<(), BalanceError> {
        if self.available()? < amount {
            return Err(BalanceError::InsufficientFunds);
        }
        self.pending = self.pending.checked_add(amount).ok_or(BalanceError::Overflow)?;
        Ok(())
    }

    pub fn release_pending(&mut self, amount: u128) -> Result<(), BalanceError> {
        self.pending = self
            .pending
            .checked_sub(amount)
            .ok_or(BalanceError::InsufficientFunds)?;
        Ok(())
    }

    pub fn stake(&mut self, amount: u128) -> Result<(), BalanceError> {
        if self.available()? < amount {
            return Err(BalanceError::InsufficientFunds);
        }
        self.staked = self.staked.checked_add(amount).ok_or(BalanceError::Overflow)?;
        Ok(())
    }

    pub fn unstake(&mut self, amount: u128) -> Result<(), BalanceError> {
        self.staked = self
            .staked
            .checked_sub(amount)
            .ok_or(BalanceError::InsufficientFunds)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_is_overflow_safe() {
        let mut balance = Balance::default();
        balance.credit_confirmed(u128::MAX).unwrap();
        assert_eq!(balance.credit_confirmed(1), Err(BalanceError::Overflow));
    }

    #[test]
    fn pending_reservation_is_bounded_by_available_balance() {
        let mut balance = Balance { confirmed: 100, ..Default::default() };
        assert!(balance.reserve_pending(100).is_ok());
        assert_eq!(balance.available().unwrap(), 0);
        assert_eq!(balance.reserve_pending(1), Err(BalanceError::InsufficientFunds));
    }

    #[test]
    fn staking_is_bounded_by_available_balance() {
        let mut balance = Balance { confirmed: 100, ..Default::default() };
        assert!(balance.stake(60).is_ok());
        assert_eq!(balance.available().unwrap(), 40);
        assert_eq!(balance.stake(41), Err(BalanceError::InsufficientFunds));
    }
}
