use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("invalid envelope")]
    InvalidEnvelope,

    #[error("gate blocked: {0}")]
    GateBlocked(String),

    #[error("ratchet locked")]
    RatchetLocked,

    #[error("forced recovery required")]
    ForcedRecovery,

    #[error("replay detected")]
    ReplayDetected,

    #[error("skipped key store error")]
    SkippedStoreError,
}
