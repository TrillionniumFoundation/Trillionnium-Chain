package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestFieldBoundariesAndSerialization(t *testing.T) {
	if _, _, _, _, e := decodeProof(nil); e == nil || e.Error() != "LENGTH" {
		t.Fatal(e)
	}
	proof := make([]byte, proofLength)
	copy(proof[:4], "PNW1")
	a, b, p, _, e := decodeProof(proof)
	if e != nil {
		t.Fatal(e)
	}
	if len(a) != 4096 || len(b) != 4096 || len(p) != 4096 {
		t.Fatal("bad matrix lengths")
	}
	binary.LittleEndian.PutUint32(proof[4:8], uint32(modulus))
	if _, _, _, _, e := decodeProof(proof); e == nil || e.Error() != "FIELD" {
		t.Fatalf("bad field e=%v", e)
	}
	if !bytes.Equal(fieldBytes([]uint32{0, 1, 0x12345678}), []byte{0, 0, 0, 0, 1, 0, 0, 0, 0x78, 0x56, 0x34, 0x12}) {
		t.Fatal("wrong LE")
	}
}
func TestMatrixModNoOverflowAndZero(t *testing.T) {
	max := uint32(modulus - 1)
	if modMulAcc(0, max, max) != 1 {
		t.Fatalf("q-1 squared !=1")
	}
	if modAdd(max, max) != uint32(modulus-2) {
		t.Fatalf("q-1+q-1 mismatch")
	}
	a := make([]uint32, matrixCells)
	b := make([]uint32, matrixCells)
	a[0] = 1
	b[0] = max
	p := product(a, b, matrixN, matrixN, matrixN)
	if p[0] != max || p[1] != 0 {
		t.Fatalf("product first=%d next=%d", p[0], p[1])
	}
}
func TestKnownHashTagDifferentiation(t *testing.T) {
	a := h("task", []byte{1}, []byte{2})
	if fmt.Sprintf("%x", a) != "48cc18aaa6e0e374fae1b457cfe6b14e5bce7a2649a27ef4661eb0f3de7170ea" {
		t.Fatal("cross-language domain/hash framing mismatch")
	}
	b := h("ticket", []byte{1}, []byte{2})
	c := h("task", []byte{1, 2})
	if a == b || a == c || b == c {
		t.Fatal("hash domain collision")
	}
	if h("task", []byte{1}, []byte{2}) != a {
		t.Fatal("nondeterministic")
	}
}
func TestEmptyTranscriptRejects(t *testing.T) {
	proof := make([]byte, proofLength)
	copy(proof[:4], "PNW1")
	challenge := digest{1}
	a := make([]uint32, matrixCells)
	b := make([]uint32, matrixCells)
	task := h("task", fieldBytes(a), fieldBytes(b))
	var maximum digest
	for i := range maximum {
		maximum[i] = 255
	}
	_, _, err := verify(challenge, task, maximum, proof)
	if err == nil || err.Error() != "TRANSCRIPT" {
		t.Fatalf("need transcript refusal, got %v", err)
	}
}
