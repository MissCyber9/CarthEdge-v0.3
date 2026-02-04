package ratchet

// QKR (QKeyRotationV1) adapter interface.
// Implemented later by CarthEdge core; tests use a deterministic mock.
type QKR interface {
// Authorize MUST be pure/deterministic: same inputs -> same decision.
// opContext is canonical bytes built from header_hash + aad_hash + counters.
Authorize(op OpCode, opContext []byte) (Decision, error)
}

type Decision struct {
Allow bool

// Optional: policy may force recovery/lock.
ForceRecovery bool

// Optional: policy may tighten bounds (e.g. MaxSkip).
MaxSkip uint32

// Stable reason codes for introspection (optional).
ReasonCode uint32
}
