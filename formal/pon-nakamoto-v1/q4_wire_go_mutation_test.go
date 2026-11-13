package main

import (
	"encoding/hex"
	"testing"
)

// Every single changed byte of the frozen signed packet must fail its original
// research identity and/or one of the two genuine Ed25519 signatures.
func TestFullSignedPacketSingleBitCorruption(t *testing.T) {
	f := fixture(t)
	raw, err := hex.DecodeString(f.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != PacketSize {
		t.Fatal("wrong fixture")
	}
	for offset := range raw {
		for bit := 0; bit < 8; bit++ {
			changed := append([]byte(nil), raw...)
			changed[offset] ^= byte(1 << bit)
			bad := f
			bad.Signed = hex.EncodeToString(changed)
			if _, err := Verify(bad, 900); err == nil {
				t.Fatalf("corrupt packet accepted at byte %d bit %d", offset, bit)
			}
		}
	}
}
