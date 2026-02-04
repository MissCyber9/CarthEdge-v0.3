use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("ratchet is locked (recovery required)")]

    RatchetLocked,
    #[error("forced recovery triggered by policy")]

    ForcedRecovery,

    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("crypto error")]
    Crypto,
    #[error("policy gate blocked: {0}")]
    GateBlocked(String),
    #[error("not implemented")]
    NotImplemented,
}
