use crate::error::CoreError;
use crate::types::GateDecision;

/// Trait: core stays chain-agnostic. Host app wires real QKeyRotationV1 calls.
/// Sensitive operations MUST be gated with op_name + op_context.
pub trait QkrGate {
    fn gate(&self, op_name: &str, op_context: &[u8]) -> Result<GateDecision, CoreError>;
}

/// Minimal in-memory gate for offline tests (ALLOW).
pub struct AllowAllGate;

impl QkrGate for AllowAllGate {
    fn gate(&self, op_name: &str, _op_context: &[u8]) -> Result<GateDecision, CoreError> {
        Ok(GateDecision {
            allowed: true,
            reason_codes: vec![],
            human: format!("ALLOW (stub) op={}", op_name),
        })
    }
}

/// Helper: enforce decision uniformly.
pub fn require_allowed(dec: &GateDecision) -> Result<(), CoreError> {
    if dec.allowed {
        Ok(())
    } else {
        let mut msg = dec.human.clone();
        if !dec.reason_codes.is_empty() {
            msg.push_str(" reason_codes=");
            for r in &dec.reason_codes {
                msg.push_str(&format!("{},", r.0));
            }
        }
        Err(CoreError::GateBlocked(msg))
    }
}
