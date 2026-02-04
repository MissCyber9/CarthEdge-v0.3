package ratchet

// RatchetStepRecvSameChain advances CKr until targetN and returns MK for targetN.
// Replay protection is partially implemented via skipped keys store.
func RatchetStepRecvSameChain(qkr QKR, s *State, targetEpoch, targetN uint32, headerHash, aadHash [32]byte) (mk [32]byte, err error) {
if err := s.Validate(); err != nil {
s.MarkErr(ErrInvariant)
return mk, err
}
if s.Locked {
s.MarkErr(ErrStateLocked)
return mk, ek(ErrStateLocked, "state locked")
}
if targetEpoch != s.DHRatchetCount {
s.MarkErr(ErrDesync)
return mk, ek(ErrDesync, "epoch mismatch (dh ratchet not implemented in v0.3.1)")
}

opctx := BuildOpContext(OpRatchetStepRecv, s.DHRatchetCount, s.Ns, s.Nr, headerHash, aadHash)
dec, derr := qkr.Authorize(OpRatchetStepRecv, opctx)
if derr != nil {
s.MarkErr(ErrPolicyBlocked)
return mk, ek(ErrPolicyBlocked, "qkr authorize error")
}
if dec.ForceRecovery {
s.Locked = true
s.MarkErr(ErrPolicyBlocked)
return mk, ek(ErrPolicyBlocked, "policy forced recovery")
}
if dec.MaxSkip != 0 && dec.MaxSkip < s.MaxSkip {
s.MaxSkip = dec.MaxSkip
}
if !dec.Allow {
s.MarkErr(ErrPolicyBlocked)
return mk, ek(ErrPolicyBlocked, "policy blocked")
}

// If targetN < Nr => must be a skipped key
if targetN < s.Nr {
return s.ConsumeSkipped(s.DHRatchetCount, targetN)
}

// If targetN > Nr => derive skipped keys deterministically
for s.Nr < targetN {
ckNext, mkSkip := DeriveChain(s.CKr)
s.CKr = ckNext
if err := s.PutSkipped(s.DHRatchetCount, s.Nr, mkSkip); err != nil {
s.MarkErr(ErrReplay)
return mk, err
}
s.Nr++
if s.Nr == 0 {
s.MarkErr(ErrDesync)
return mk, ek(ErrDesync, "Nr overflow")
}
}

// Now s.Nr == targetN: derive MK for this message
ckNext, mkOut := DeriveChain(s.CKr)
s.CKr = ckNext
s.Nr++
if s.Nr == 0 {
s.MarkErr(ErrDesync)
return mk, ek(ErrDesync, "Nr overflow")
}
return mkOut, nil
}
