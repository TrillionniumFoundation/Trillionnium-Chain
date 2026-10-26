package w1falsification

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func tensors() ([]uint32, []uint32) {
	a := make([]uint32, Cells)
	b := make([]uint32, Cells)
	for i := range a {
		a[i] = uint32((13*i + 17) % 257)
		b[i] = uint32((29*i + 31) % 263)
	}
	return a, b
}
func TestW1FullRelationAndMutants(t *testing.T) {
	challenge := H("challenge", []byte("specific-test-header"))
	a, b := tensors()
	task, e := TaskID(a, b)
	if e != nil {
		t.Fatal(e)
	}
	target := Digest{}
	for i := range target {
		target[i] = 255
	}
	proof, e := Proof(challenge, a, b)
	if e != nil {
		t.Fatal(e)
	}
	if len(proof) != ProofBytes {
		t.Fatalf("invalid size %d", len(proof))
	}
	product, e := Verify(challenge, task, target, proof)
	if e != nil {
		t.Fatal(e)
	}
	actual := MM(a, b, N, N, N)
	if !bytes.Equal(encodeField(product), encodeField(actual)) {
		t.Fatal("decoded product mismatch")
	}
	// Tamper the claimed transcript and show passing ticket is not authority.
	forged := append([]byte(nil), proof...)
	forged[len(forged)-1] ^= 1
	if e := CheapPrecheck(challenge, task, target, forged); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(challenge, task, target, forged); e != ErrTranscript {
		t.Fatalf("fake transcript not rejected: %v", e)
	}
	forged = append([]byte(nil), proof...)
	forged[4+2*Cells*4] ^= 1
	if _, e := Verify(challenge, task, target, forged); e != ErrProduct {
		t.Fatalf("false result: %v", e)
	}
	forged = append([]byte(nil), proof...)
	forged[4+Cells*4] ^= 1
	if _, e := Verify(challenge, task, target, forged); e != ErrTask {
		t.Fatalf("false task: %v", e)
	}
	var invalid Digest
	if e := CheapPrecheck(challenge, task, invalid, proof); e != ErrTarget {
		t.Fatal(e)
	}
}
func TestMaintenanceFixedMaterialProducesDeterministicTranscript(t *testing.T) {
	a, b := tensors()
	ch := H("challenge", []byte("stable-pow-input"))
	p, e := Proof(ch, a, b)
	if e != nil {
		t.Fatal(e)
	}
	second, e := Proof(ch, a, b)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(p, second) {
		t.Fatal("noncanonical transcript")
	}
	if sha256.Sum256(p) != sha256.Sum256(second) {
		t.Fatal("hash mismatch")
	}
	if p[0] != 'P' || p[1] != 'N' || p[2] != 'W' || p[3] != '1' {
		t.Fatal("bad magic")
	}
	// Exact modeled field basis also tests non-zero structured public material.
	if got := binary.LittleEndian.Uint32(p[4:8]); got != 17 {
		t.Fatalf("first A %d", got)
	}
}
func TestCheapTicketForgeryVsFullReplayCost(t *testing.T) {
	a, b := tensors()
	ch := H("challenge", []byte("offline-admission-cost"))
	task, _ := TaskID(a, b)
	proof, e := Proof(ch, a, b)
	if e != nil {
		t.Fatal(e)
	}
	target := Digest{}
	for i := range target {
		target[i] = 255
	}
	falseTrace := append([]byte(nil), proof...)
	falseTrace[len(falseTrace)-1] ^= 1
	const rounds = 32
	cheapStart := time.Now()
	for i := 0; i < rounds; i++ {
		if e := CheapPrecheck(ch, task, target, falseTrace); e != nil {
			t.Fatal(e)
		}
	}
	cheapTime := time.Since(cheapStart)
	fullStart := time.Now()
	for i := 0; i < rounds; i++ {
		if _, e := Verify(ch, task, target, falseTrace); e != ErrTranscript {
			t.Fatal(e)
		}
	}
	fullTime := time.Since(fullStart)
	if fullTime <= 0 || cheapTime <= 0 {
		t.Fatal("nonpositive clocks")
	}
	t.Logf("local Go wall-only: cheap-precheck=%s for %d; full-rejection=%s for %d; ratio=%.2f (not W1 public-network evidence)", cheapTime, rounds, fullTime, rounds, float64(fullTime)/float64(cheapTime))
	// Test does not assert any cost ratio as a universally proven hardness bound.
	_ = fmt.Sprintf("%x", sha256.Sum256(falseTrace))
}
