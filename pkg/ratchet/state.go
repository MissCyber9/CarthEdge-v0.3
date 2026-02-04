package ratchet

import (
"crypto/subtle"
"encoding/binary"
"errors"
"fmt"
)

// ====== Hard constraints (must match spec) ======

const (
// Domain separation labels (documented in docs/ratchet_spec.md)
labelRK = "ce.ratchet.rk.v1"
labelCKs = "ce.ratchet.ck_s.v1"
labelCKr = "ce.ratchet.ck_r.v1"
labelMK = "ce.ratchet.mk.v1"
labelH = "ce.ratchet.h.v1"   // header key / binder (optional future)
labelAAD = "ce.ratchet.aad.v1"

// Replay window (skipped keys) — MUST be explicit, testable, deterministic.
// This is a DEFAULT; policy may further restrict via QKeyRotationV1.
DefaultMaxSkip = uint32(2000)
)

// ErrKind is a stable, test-friendly classification.
// It must remain small and deterministic (no raw strings in tests).
type ErrKind uint16

const (
ErrNone ErrKind = iota
ErrInvariant
ErrReplay
ErrDesync
ErrPolicyBlocked
ErrAADMismatch
ErrCiphertextInvalid
ErrStateLocked
ErrUnsupported
)

type RatchetError struct {
Kind   ErrKind
Detail string // not used for strict equality in tests; tests compare Kind primarily
}

func (e *RatchetError) Error() string {
if e.Detail == "" {
return fmt.Sprintf("ratchet error kind=%d", e.Kind)
}
return fmt.Sprintf("ratchet error kind=%d: %s", e.Kind, e.Detail)
}

func ek(kind ErrKind, detail string) error { return &RatchetError{Kind: kind, Detail: detail} }

// ====== Public state model ======
//
// This is an SDK-only structure.
// It must contain NO permanent identifiers.
// Any "peer identity" must be external and ephemeral (e.g., session-scoped).
//
// QKeyRotationV1 governs:
// - when DH ratchet may occur
// - when chain steps may advance
// - when decrypt may consume skipped keys
// - when recovery is forced by policy block
//
// All sensitive ops must bind an op_context (canonical bytes).

type State struct {
// Version for on-disk encoding (if any).
// Increment only with explicit migrations.
Version uint16

// Root key (RK) evolves on each DH ratchet step.
RK [32]byte

// DH ratchet keys (X25519):
// - DHs: our current ratchet private key
// - DHr: their current ratchet public key
DHsPriv [32]byte
DHsPub  [32]byte
DHrPub  [32]byte

// Chain keys:
CKs [32]byte // send chain key
CKr [32]byte // recv chain key

// Message counters:
Ns uint32 // number of messages sent in current sending chain
Nr uint32 // number of messages received in current receiving chain
PN uint32 // number of messages in previous sending chain (for header)

// Current ratchet "step" counters:
// DHRatchetCount increments on each DH ratchet event.
DHRatchetCount uint32

// Replay protection:
// - Skipped keys are indexed by (DHRatchetCount, MsgNr).
// - This map MUST be bounded and prunable deterministically.
Skipped map[SkipKey]MsgKeyRecord

// Policy-derived bounds (may be tightened by QKeyRotation policy).
MaxSkip uint32

// Locking / introspection:
// If Locked == true, operations must fail with ErrStateLocked until recovery completes.
Locked bool
// Last error kind saved for introspection; not security sensitive.
LastErr ErrKind
}

// SkipKey indexes a skipped message key uniquely per ratchet epoch.
type SkipKey struct {
Epoch uint32 // equals State.DHRatchetCount at time key was derivable
Nr    uint32 // message number within that receiving chain
}

// MsgKeyRecord stores a derived message key plus minimal metadata.
// Note: message key bytes are sensitive; ensure zeroization on delete in future hardening.
type MsgKeyRecord struct {
MK   [32]byte
Used bool // once used, must not be accepted again (explicit replay protection)
}

// Invariants are strict rules that must hold before/after every sensitive transition.
// Do NOT silently fix state; return ErrInvariant unless a QKR-governed recovery path is invoked.
func (s *State) Validate() error {
if s.Version == 0 {
// Version 0 is reserved (uninitialized)
return ek(ErrInvariant, "state version=0")
}
if s.MaxSkip == 0 {
return ek(ErrInvariant, "MaxSkip=0")
}
if s.MaxSkip > 1_000_000 {
// hard ceiling to prevent memory DoS even if policy misconfigured
return ek(ErrInvariant, "MaxSkip too large")
}
// No permanent identifiers: nothing to validate directly, but we keep the struct clean by design.

// Counters are uint32; overflow is possible in theory.
// We treat wrap-around as invariant violation (caller must recover under policy).
// (Tests can force this by setting Ns or Nr near max.)
// NOTE: Go uint32 wraps; detect after increments where relevant.

if s.Skipped == nil {
// Keep it non-nil to simplify deterministic pruning and tests.
return ek(ErrInvariant, "Skipped map is nil")
}
return nil
}

// MustInitForNewSession sets safe defaults, without generating any keys.
// Key generation and handshake are external to this file.
// This function intentionally avoids RNG to preserve deterministic tests.
func (s *State) MustInitForNewSession() {
s.Version = 1
s.MaxSkip = DefaultMaxSkip
s.Skipped = make(map[SkipKey]MsgKeyRecord, 0)
s.Locked = false
s.LastErr = ErrNone
}

// MarkErr is a helper for deterministic introspection.
// Do not leak sensitive data in Detail strings.
func (s *State) MarkErr(kind ErrKind) {
s.LastErr = kind
}

// ====== Replay guard utilities ======

var (
ErrReplayUsedKey  = ek(ErrReplay, "skipped key already used")
ErrReplayUnknown  = ek(ErrReplay, "message key not found")
ErrReplayOverflow = ek(ErrReplay, "skipped keys overflow")
)

// ConsumeSkipped marks a skipped key as used and returns MK.
// MUST be called only under QKeyRotation-governed decrypt_msg.
func (s *State) ConsumeSkipped(epoch, nr uint32) ([32]byte, error) {
var zero [32]byte
rec, ok := s.Skipped[SkipKey{Epoch: epoch, Nr: nr}]
if !ok {
s.MarkErr(ErrReplay)
return zero, ErrReplayUnknown
}
if rec.Used {
s.MarkErr(ErrReplay)
return zero, ErrReplayUsedKey
}
rec.Used = true
s.Skipped[SkipKey{Epoch: epoch, Nr: nr}] = rec
return rec.MK, nil
}

// PutSkipped inserts a skipped MK. It must remain bounded.
func (s *State) PutSkipped(epoch, nr uint32, mk [32]byte) error {
if uint32(len(s.Skipped)) >= s.MaxSkip {
s.MarkErr(ErrReplay)
return ErrReplayOverflow
}
key := SkipKey{Epoch: epoch, Nr: nr}
if rec, ok := s.Skipped[key]; ok {
// If an existing record differs, that's a derivation mismatch => invariant violation.
// If same, keep earliest and preserve Used flag.
if subtle.ConstantTimeCompare(rec.MK[:], mk[:]) != 1 {
s.MarkErr(ErrInvariant)
return ek(ErrInvariant, "skipped mk mismatch")
}
return nil
}
s.Skipped[key] = MsgKeyRecord{MK: mk, Used: false}
return nil
}

// PruneSkipped deterministically removes Used records first, then oldest by (Epoch,Nr).
// Caller must provide deterministic ordering; this is a simple, stable strategy.
func (s *State) PruneSkipped() {
// Keep as no-op skeleton in v0.3.0; implemented in v0.3.2 with stable ordering.
}

// ====== op_context canonicalization ======
//
// Sensitive ops MUST bind op_context bytes.
// This function is intentionally tiny and deterministic.
// The full op_context rules are in docs/ratchet_spec.md.
//
// Layout (stable):
//   "CEOC" (4 bytes)
//   version (u16)
//   op (u16)
//   epoch (u32)
//   Ns (u32)
//   Nr (u32)
//   header_hash[32] (from EnvelopeV2 canonical header bytes)
//   aad_hash[32] (from EnvelopeV2 AAD canonical bytes)
//
// Hashing primitives live elsewhere; this file only builds a frame.

type OpCode uint16

const (
OpRatchetStepSend OpCode = 1
OpRatchetStepRecv OpCode = 2
OpDecryptMsg      OpCode = 3
)

func BuildOpContext(op OpCode, epoch, ns, nr uint32, headerHash, aadHash [32]byte) []byte {
out := make([]byte, 0, 4+2+2+4+4+4+32+32)
out = append(out, 'C', 'E', 'O', 'C')
tmp := make([]byte, 2)

binary.BigEndian.PutUint16(tmp, 1) // op_context version
out = append(out, tmp...)

binary.BigEndian.PutUint16(tmp, uint16(op))
out = append(out, tmp...)

u32 := make([]byte, 4)
binary.BigEndian.PutUint32(u32, epoch)
out = append(out, u32...)
binary.BigEndian.PutUint32(u32, ns)
out = append(out, u32...)
binary.BigEndian.PutUint32(u32, nr)
out = append(out, u32...)

out = append(out, headerHash[:]...)
out = append(out, aadHash[:]...)
return out
}

// ====== Minimal sanity for v0.3.0 ======

var ErrNotImplemented = errors.New("not implemented")

