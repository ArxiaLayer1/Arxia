//! Relay node reputation scoring.

/// Reputation score for a relay node.
#[derive(Debug, Clone)]
pub struct RelayScore {
    /// Relay node public key (hex-encoded).
    pub relay_id: String,
    /// Current score (higher is better).
    pub score: i64,
    /// Total messages successfully relayed.
    pub messages_relayed: u64,
    /// Total messages that failed or were dropped.
    pub messages_failed: u64,
}

impl RelayScore {
    /// Create a new relay score with default values.
    pub fn new(relay_id: String) -> Self {
        Self {
            relay_id,
            score: 100,
            messages_relayed: 0,
            messages_failed: 0,
        }
    }

    /// Record a successful relay.
    pub fn record_success(&mut self) {
        self.messages_relayed += 1;
        self.score += 1;
    }

    /// Record a failed relay attempt.
    pub fn record_failure(&mut self) {
        self.messages_failed += 1;
        self.score -= 5;
    }

    /// Apply slashing penalty for proven misbehavior.
    pub fn slash(&mut self, penalty: i64) {
        self.score -= penalty;
    }

    /// Whether this relay is in good standing.
    pub fn is_trusted(&self) -> bool {
        self.score > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_score_new() {
        let score = RelayScore::new("relay1".to_string());
        assert_eq!(score.score, 100);
        assert!(score.is_trusted());
    }

    #[test]
    fn test_relay_score_success() {
        let mut score = RelayScore::new("relay1".to_string());
        score.record_success();
        assert_eq!(score.score, 101);
        assert_eq!(score.messages_relayed, 1);
    }

    #[test]
    fn test_relay_score_failure() {
        let mut score = RelayScore::new("relay1".to_string());
        score.record_failure();
        assert_eq!(score.score, 95);
        assert_eq!(score.messages_failed, 1);
    }

    #[test]
    fn test_relay_score_slashing() {
        let mut score = RelayScore::new("relay1".to_string());
        score.slash(150);
        assert_eq!(score.score, -50);
        assert!(!score.is_trusted());
    }
}
