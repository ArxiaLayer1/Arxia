//! Escrow contract for Arxia.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Escrow state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowState {
    /// Funds are locked.
    Locked,
    /// Funds have been released to the recipient.
    Released,
    /// Funds have been refunded to the sender.
    Refunded,
}

/// An escrow contract.
#[derive(Debug, Clone)]
pub struct Escrow {
    /// Sender account.
    pub sender: String,
    /// Recipient account.
    pub recipient: String,
    /// Amount held (micro-ARX).
    pub amount: u64,
    /// Current state.
    pub state: EscrowState,
    /// Timeout timestamp (unix ms).
    pub timeout: u64,
}

impl Escrow {
    /// Create a new escrow.
    pub fn new(sender: String, recipient: String, amount: u64, timeout: u64) -> Self {
        Self {
            sender,
            recipient,
            amount,
            state: EscrowState::Locked,
            timeout,
        }
    }

    /// Release funds to the recipient.
    pub fn release(&mut self) -> Result<(), &'static str> {
        if self.state != EscrowState::Locked {
            return Err("escrow is not in locked state");
        }
        self.state = EscrowState::Released;
        Ok(())
    }

    /// Refund funds to the sender (only after timeout).
    pub fn refund(&mut self, current_time: u64) -> Result<(), &'static str> {
        if self.state != EscrowState::Locked {
            return Err("escrow is not in locked state");
        }
        if current_time < self.timeout {
            return Err("timeout has not elapsed");
        }
        self.state = EscrowState::Refunded;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escrow_release() {
        let mut escrow = Escrow::new("alice".into(), "bob".into(), 1_000_000, 1000);
        assert_eq!(escrow.state, EscrowState::Locked);
        escrow.release().unwrap();
        assert_eq!(escrow.state, EscrowState::Released);
    }

    #[test]
    fn test_escrow_refund_after_timeout() {
        let mut escrow = Escrow::new("alice".into(), "bob".into(), 1_000_000, 1000);
        assert!(escrow.refund(500).is_err());
        assert!(escrow.refund(1000).is_ok());
        assert_eq!(escrow.state, EscrowState::Refunded);
    }

    #[test]
    fn test_escrow_double_release() {
        let mut escrow = Escrow::new("alice".into(), "bob".into(), 1_000_000, 1000);
        escrow.release().unwrap();
        assert!(escrow.release().is_err());
    }
}
