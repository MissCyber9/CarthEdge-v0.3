package ratchet

import "testing"

func freshState() *State {
var s State
s.MustInitForNewSession()
// seed chain keys deterministically
for i := 0; i < 32; i++ { s.CKs[i] = byte(i); s.CKr[i] = byte(100 + i) }
return &s
}

func TestStepSendBlockedByPolicy(t *testing.T) {
s := freshState()
var hh, ah [32]byte
_, err := RatchetStepSend(mockQKR{allow:false}, s, hh, ah)
if err == nil { t.Fatal("expected error") }
}

func TestStepSendAdvancesNs(t *testing.T) {
s := freshState()
var hh, ah [32]byte
_, err := RatchetStepSend(mockQKR{allow:true}, s, hh, ah)
if err != nil { t.Fatal(err) }
if s.Ns != 1 { t.Fatalf("expected Ns=1, got %d", s.Ns) }
}

func TestStepRecvOutOfOrderWithinWindow(t *testing.T) {
s := freshState()
var hh, ah [32]byte

// Receive message #2 first => store skipped for #0,#1 then derive #2
_, err := RatchetStepRecvSameChain(mockQKR{allow:true, maxSkip:10}, s, s.DHRatchetCount, 2, hh, ah)
if err != nil { t.Fatal(err) }
if s.Nr != 3 { t.Fatalf("expected Nr=3, got %d", s.Nr) }

// Now consume skipped #1
_, err = RatchetStepRecvSameChain(mockQKR{allow:true, maxSkip:10}, s, s.DHRatchetCount, 1, hh, ah)
if err != nil { t.Fatal(err) }

// Replay same skipped #1 => must fail
_, err = RatchetStepRecvSameChain(mockQKR{allow:true, maxSkip:10}, s, s.DHRatchetCount, 1, hh, ah)
if err == nil { t.Fatal("expected replay error") }
}
