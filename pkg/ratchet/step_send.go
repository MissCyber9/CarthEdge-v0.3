package ratchet

func RatchetStepSend(qkr QKR, s *State, headerHash, aadHash [32]byte) (mk [32]byte, err error) {
if err := s.Validate(); err != nil {
s.MarkErr(ErrInvariant)
return mk, err
}
if s.Locked {
s.MarkErr(ErrStateLocked)
return mk, ek(ErrStateLocked, "state locked")
}

opctx := BuildOpContext(OpRatchetStepSend, s.DHRatchetCount, s.Ns, s.Nr, headerHash, aadHash)
dec, derr := qkr.Authorize(OpRatchetStepSend, opctx)
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

ckNext, mk2 := DeriveChain(s.CKs)
s.CKs = ckNext

// increment Ns (detect wrap by checking overflow to 0)
prev := s.Ns
s.Ns++
if s.Ns == 0 || s.Ns < prev {
s.MarkErr(ErrDesync)
return mk, ek(ErrDesync, "Ns overflow")
}

return mk2, nil
}
