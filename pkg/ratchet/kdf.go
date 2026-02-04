package ratchet

import (
"crypto/hkdf"
"crypto/sha256"
"io"
)

func hkdfExpand(salt, ikm []byte, info string, outLen int) []byte {
h := hkdf.New(sha256.New, ikm, salt, []byte(info))
out := make([]byte, outLen)
_, _ = io.ReadFull(h, out)
return out
}

// DeriveRoot derives (rk', ck') from (rk, dh) with stable label.
func DeriveRoot(rk [32]byte, dh [32]byte) (rkOut [32]byte, ckOut [32]byte) {
buf := hkdfExpand(rk[:], dh[:], labelRK, 64)
copy(rkOut[:], buf[:32])
copy(ckOut[:], buf[32:64])
return
}

// DeriveChain derives (ckNext, mk) from ck with stable label.
func DeriveChain(ck [32]byte) (ckNext [32]byte, mk [32]byte) {
buf := hkdfExpand(nil, ck[:], labelMK, 64)
copy(ckNext[:], buf[:32])
copy(mk[:], buf[32:64])
return
}
