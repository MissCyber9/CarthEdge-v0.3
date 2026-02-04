package ratchet

import "testing"

func TestDeriveChainDeterministic(t *testing.T) {
var ck [32]byte
for i := 0; i < 32; i++ { ck[i] = byte(i) }

ck2a, mka := DeriveChain(ck)
ck2b, mkb := DeriveChain(ck)

if ck2a != ck2b { t.Fatal("ckNext not deterministic") }
if mka != mkb { t.Fatal("mk not deterministic") }
if ck2a == ck { t.Fatal("ckNext must change") }
}

func TestDeriveRootDeterministic(t *testing.T) {
var rk, dh [32]byte
for i := 0; i < 32; i++ { rk[i] = byte(255 - i); dh[i] = byte(i) }

rk1a, ck1a := DeriveRoot(rk, dh)
rk1b, ck1b := DeriveRoot(rk, dh)

if rk1a != rk1b { t.Fatal("rk not deterministic") }
if ck1a != ck1b { t.Fatal("ck not deterministic") }
}
