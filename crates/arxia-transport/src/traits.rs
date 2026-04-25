//! Transport trait definition.

use arxia_core::ArxiaError;

/// A message sent over the transport layer.
#[derive(Debug, Clone)]
pub struct TransportMessage {
    /// Sender identifier (hex-encoded public key).
    pub from: String,
    /// Recipient identifier (hex-encoded public key, or empty for broadcast).
    pub to: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Timestamp when the message was created (ms since epoch).
    pub timestamp: u64,
}

/// Errors specific to the transport layer.
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Message exceeds the MTU for this transport.
    PayloadTooLarge {
        /// Size of the payload.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// The transport channel is disconnected.
    Disconnected,
    /// The message was lost (simulated packet loss).
    MessageLost,
    /// The send-side buffer is at capacity. The caller MUST slow down or
    /// drain its outbox before retrying. Returned by transports that bound
    /// their outbox to prevent unbounded memory growth (CRIT-012).
    BackPressure {
        /// Configured capacity of the outbox (messages, not bytes).
        capacity: usize,
    },
    /// Generic transport error.
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload too large: {} > {}", size, max)
            }
            Self::Disconnected => write!(f, "transport disconnected"),
            Self::MessageLost => write!(f, "message lost"),
            Self::BackPressure { capacity } => {
                write!(f, "transport outbox full (capacity {})", capacity)
            }
            Self::Other(msg) => write!(f, "transport error: {}", msg),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<TransportError> for ArxiaError {
    fn from(e: TransportError) -> Self {
        ArxiaError::Transport(e.to_string())
    }
}

/// Trait for all Arxia transport implementations.
pub trait TransportTrait {
    /// Send a message to a specific peer or broadcast.
    fn send(&mut self, msg: TransportMessage) -> Result<(), TransportError>;

    /// Try to receive a pending message (non-blocking).
    fn try_recv(&mut self) -> Option<TransportMessage>;

    /// Maximum transmission unit in bytes.
    fn mtu(&self) -> usize;
}
