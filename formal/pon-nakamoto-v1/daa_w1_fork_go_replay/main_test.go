package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Fixed vectors extracted from one actually generated winning W1 header in the
// 52-proof Python campaign, not dynamically recomputed expected golden hashes.
const firstHeaderSHA256 = "7633718be86c7c8dc48c3372a4a599c74df8e25a5d62e4347674f503e8a45c33"
const firstProofSHA256 = "a519f33532f8635ecbcc8a830fe218d131e2d7e15e9d3fe2d3452884bc2b8d5b"
const firstBlockID = "d282071437c71b8f245a688f3b1869cdc8cecc420d8bc32ff47d8ec1254891d5"

func firstFixture(t *testing.T) ([]byte, []byte, Frame) {
	t.Helper()
	a, b := matrixMaterial()
	v := newVerifier()
	genesis := v.TipA
	target, err := v.target(genesis)
	if err != nil {
		t.Fatal(err)
	}
	targetHash, err := beHash(target)
	if err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 318)
	copy(h, []byte("PNH1\x01\x00"))
	n := H("w1-fork-research-network-v1", []byte("nonactivated"))
	p := H("w1-fork-research-parameters-v1", []byte("nonactivated"))
	miner := H("research-miner", []byte("A"))
	task := H("task", toBytes(a), toBytes(b))
	copy(h[6:38], n[:])
	copy(h[38:70], p[:])
	copy(h[70:102], genesis[:])
	binary.LittleEndian.PutUint64(h[102:110], 1)
	binary.LittleEndian.PutUint64(h[110:118], start+spacing)
	copy(h[118:150], targetHash[:])
	copy(h[150:182], miner[:])
	copy(h[182:214], HBytes("research-empty-transactions", []byte("not-M06")))
	copy(h[214:246], HBytes("research-state-not-M06", genesis[:], h[102:110]))
	copy(h[246:278], HBytes("research-empty-receipts", []byte("not-M06")))
	copy(h[278:310], task[:])
	ch := H("challenge", h)
	proof, err := prove(ch, a, b)
	if err != nil {
		t.Fatal(err)
	}
	id := H("block", h, proof[len(proof)-32:])
	frame := Frame{Phase: "shared", Now: start + spacing, Header: hex.EncodeToString(h),
		Proof: base64.StdEncoding.EncodeToString(proof), BlockID: hex.EncodeToString(id[:]),
		Attempts: 1, Selection: "genesis-maintenance", OptionalSource: true}
	return h, proof, frame
}
func TestFixedPythonW1ReferenceHashesAndRealFullVerifier(t *testing.T) {
	h, p, frame := firstFixture(t)
	dh, dp := sha256.Sum256(h), sha256.Sum256(p)
	if hex.EncodeToString(dh[:]) != firstHeaderSHA256 || hex.EncodeToString(dp[:]) != firstProofSHA256 || frame.BlockID != firstBlockID {
		t.Fatalf("Go computation drift from independently frozen Python proof: header=%x proof=%x block=%s", dh, dp, frame.BlockID)
	}
	if len(p) != proofBytes {
		t.Fatalf("unexpected work proof size %d", len(p))
	}
	ch := H("challenge", h)
	a, b := matrixMaterial()
	task := H("task", toBytes(a), toBytes(b))
	var target Hash
	copy(target[:], h[118:150])
	if err := verifyW1(ch, task, target, p); err != nil {
		t.Fatal(err)
	}
	verifier := newVerifier()
	if err := verifier.readFrame(frame, true); err != nil {
		t.Fatal(err)
	}
	if verifier.Winners != 1 || verifier.Attempts != 1 {
		t.Fatal("incorrect work count")
	}
}
func TestCheapFakeTranscriptFailsAfterValidTicket(t *testing.T) {
	h, p, _ := firstFixture(t)
	a, b := matrixMaterial()
	task := H("task", toBytes(a), toBytes(b))
	ch := H("challenge", h)
	var target Hash
	copy(target[:], h[118:150])
	prefix := append([]byte("PNW1"), toBytes(a)...)
	prefix = append(prefix, toBytes(b)...)
	prefix = append(prefix, make([]byte, 4*cells)...)
	var fake []byte
	for i := uint64(0); i < 256; i++ {
		var seed [8]byte
		binary.LittleEndian.PutUint64(seed[:], i)
		claimed := sha256.Sum256(append([]byte("fake-W1"), seed[:]...))
		ticket := H("ticket", ch[:], claimed[:])
		if bytes.Compare(ticket[:], target[:]) <= 0 {
			fake = append(append([]byte{}, prefix...), claimed[:]...)
			break
		}
	}
	if fake == nil {
		t.Fatal("no candidate passed cheap ticket predicate")
	}
	if bytes.Equal(fake, p) {
		t.Fatal("forgery equals valid proof")
	}
	if err := verifyW1(ch, task, target, fake); err == nil {
		t.Fatal("cheap ticket acquired forged valid work")
	}
	var actualTicket Hash
	copy(actualTicket[:], fake[len(fake)-32:])
	if actualTicket == (Hash{}) {
		t.Fatal("invalid diagnostic")
	}
}
func TestNoImplicitLeaseFallbackAndBadWorkCannotMutateView(t *testing.T) {
	_, _, frame := firstFixture(t)
	mutate := []func(*Frame){
		func(x *Frame) { x.Selection = "automatic-expired-task" },
		func(x *Frame) { x.OptionalSource = false },
		func(x *Frame) { x.Now = start - 500 },
		func(x *Frame) { x.Attempts = 2 },
		func(x *Frame) { x.BlockID = hex.EncodeToString(make([]byte, 32)) },
	}
	for i, change := range mutate {
		v := newVerifier()
		candidate := frame
		change(&candidate)
		if e := v.readFrame(candidate, true); e == nil {
			t.Fatalf("mutation %d accepted", i)
		}
		if len(v.Rows) != 1 || v.TipA != v.TipB {
			t.Fatalf("mutation %d changed chain state", i)
		}
	}
}
