package ratchet

type mockQKR struct {
allow         bool
forceRecovery bool
maxSkip       uint32
}

func (m mockQKR) Authorize(op OpCode, opContext []byte) (Decision, error) {
return Decision{
Allow:         m.allow,
ForceRecovery: m.forceRecovery,
MaxSkip:       m.maxSkip,
ReasonCode:    0,
}, nil
}
