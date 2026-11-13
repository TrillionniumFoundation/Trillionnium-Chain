package main

import (
	"encoding/binary"
	"testing"
	w1 "trillionnium/pon-w1-research-oracle"
)

func TestCookieHashMatchesSignedResourceFormula(t *testing.T) {
	var id [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	for _, bits := range []int{8, 12, 16, 20} {
		for _, nonce := range []uint64{0, 1, 5, 31, 1234, 98765} {
			var n [8]byte
			binary.LittleEndian.PutUint64(n[:], nonce)
			got := w1.Hash("public-ticket-v3", id[:], n[:])
			expected := binary.BigEndian.Uint32(got[:4])>>uint(32-bits) == 0
			if ticket(id, nonce, bits) != expected {
				t.Fatalf("bits:%d nonce:%d", bits, nonce)
			}
		}
	}
}
func TestFourFalseTracesAreRejectedAfterCheapTicket(t *testing.T) {
	var challenge, target [32]byte
	for i := range challenge {
		challenge[i] = byte(i)
		target[i] = 255
	}
	target[0] = 127
	z := make([]uint32, w1.Cells)
	task := w1.Hash("task", words(z), words(z))
	for i := 0; i < 4; i++ {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(i))
		trace := w1.Hash("public-v3-from-zero-v1", challenge[:], n[:])
		proof := append(append(append([]byte("PNW1"), words(z)...), words(z)...), words(z)...)
		proof = append(proof, trace[:]...)
		if err := w1.Precheck(challenge, task, target, proof); err != nil {
			t.Fatalf("precheck:%d:%v", i, err)
		}
		if err := w1.Verify(challenge, task, target, proof); err == nil || err.Error() != "Transcript" {
			t.Fatalf("false:%d:%v", i, err)
		}
	}
}
