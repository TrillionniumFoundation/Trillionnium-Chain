package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

type fixture struct {
	raw               []byte
	old, next         Lease
	model             ModelMaterial
	requester, source ed25519.PrivateKey
}

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("TEST_ONLY_Q4_GO_" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func material() ModelMaterial {
	a, b := make([]byte, fieldBytes), make([]byte, fieldBytes)
	for i := 0; i < 4096; i++ {
		binary.LittleEndian.PutUint32(a[i*4:], uint32((13*i+17)%257))
		binary.LittleEndian.PutUint32(b[i*4:], uint32((29*i+31)%263))
	}
	return ModelMaterial{a, b}
}
func leaseFixture() fixture {
	req, src := testKey("requester"), testKey("source")
	v := Lease{
		Slot: 0, Purpose: 4, Network: H("fixture-network", []byte("distinct development chain")),
		Parameters:           H("fixture-parameters", []byte("q4 r9")),
		SourceRecord:         H("source-record", []byte("author")),
		Authorization:        H("authorization", []byte("fixture")),
		AvailabilityManifest: H("availability-manifest", []byte("test")),
		AvailabilityRoot:     H("availability-root", []byte("test")),
		Generation:           1, Revision: 1, NotBefore: 0, Expires: 1000, AvailableUntil: 1100, CostClass: 1,
	}
	copy(v.Requester[:], req.Public().(ed25519.PublicKey))
	copy(v.Source[:], src.Public().(ed25519.PublicKey))
	v.Demand = H("qualified-demand-id-v2", v.Network[:], v.Parameters[:], v.Requester[:], le(v.Generation))
	next := v
	next.Revision = 2
	next.NotBefore = 800
	next.Expires = 1500
	next.AvailableUntil = 1600
	return fixture{old: v, next: next, requester: req, source: src, model: material()}
}
func taskFor(f fixture, sourceSequence uint64) []byte {
	v := f.next
	x := make([]byte, taskBytes)
	copy(x, "QWT1")
	binary.LittleEndian.PutUint16(x[4:6], 1)
	x[6] = v.Purpose
	x[7] = 1
	x[8] = 1
	x[9] = 0
	x[10] = 1
	var ids [16]Hash
	ids[0], ids[1], ids[2], ids[3], ids[4] = v.Network, v.Parameters, H("qualified-task-profile-v1", []byte("pon-matmul-transcript-64-v1")), v.Source, v.Demand
	ids[5] = v.BoundSource()
	ids[6] = H("artifact", f.model.A)
	ids[7] = H("qualified-task-layer-v1", ids[6][:], []byte("entire-row-major-field-layer-64x64"))
	ids[8] = H("qualified-task-input-v1", f.model.B)
	ids[9] = H("qualified-task-recipe-v1", []byte("canonical-field-matrix64-product-v1"))
	ids[10] = H("task", f.model.A, f.model.B)
	ids[11], ids[12], ids[13], ids[14] = v.AvailabilityManifest, v.AvailabilityRoot, v.Authorization, v.Withdrawal()
	ids[15] = H("qualified-task-output-meter-v1", ids[0][:], ids[1][:], ids[4][:], ids[6][:], ids[7][:], ids[8][:], ids[9][:], ids[10][:])
	for i, id := range ids {
		copy(x[12+i*32:], id[:])
	}
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint16(x[524+i*2:], 64)
	}
	ns := []uint64{sourceSequence, v.NotBefore, v.Expires, v.AvailableUntil, 262144}
	for i, n := range ns {
		binary.LittleEndian.PutUint64(x[532+i*8:], n)
	}
	binary.LittleEndian.PutUint32(x[572:], fieldBytes)
	binary.LittleEndian.PutUint32(x[576:], fieldBytes)
	if v.Purpose != 1 {
		binary.LittleEndian.PutUint32(x[580:], 1)
	}
	return x
}
func signFixture(f fixture, sourceSequence uint64) []byte {
	lease, err := f.next.Encode()
	if err != nil {
		panic(err)
	}
	leaseID, err := f.next.ID()
	if err != nil {
		panic(err)
	}
	innerUnsigned := make([]byte, 0, 620)
	innerUnsigned = append(innerUnsigned, []byte("QWA2")...)
	innerUnsigned = append(innerUnsigned, leaseID[:]...)
	innerUnsigned = append(innerUnsigned, taskFor(f, sourceSequence)...)
	m := H("qualified-task-source-sign-v2", innerUnsigned)
	signed := append(innerUnsigned, ed25519.Sign(f.source, m[:])...)
	payload := append(lease, signed...)
	if len(payload) != payloadBytes {
		panic("wrong payload length")
	}
	unsigned := make([]byte, 0, 1123)
	unsigned = append(unsigned, []byte("PNX1")...)
	unsigned = append(unsigned, f.next.Network[:]...)
	unsigned = append(unsigned, f.old.Requester[:]...)
	unsigned = append(unsigned, le(3)...)
	unsigned = append(unsigned, le(1900)...)
	unsigned = append(unsigned, le(1_000_000)...)
	unsigned = append(unsigned, 22)
	var n [2]byte
	binary.LittleEndian.PutUint16(n[:], payloadBytes)
	unsigned = append(unsigned, n[:]...)
	unsigned = append(unsigned, payload...)
	digest := H("tx-sign", unsigned)
	return append(unsigned, ed25519.Sign(f.requester, digest[:])...)
}
func priorTask(f fixture) PriorTask {
	a := H("artifact", f.model.A)
	b := H("qualified-task-input-v1", f.model.B)
	c := H("task", f.model.A, f.model.B)
	layer := H("qualified-task-layer-v1", a[:], []byte("entire-row-major-field-layer-64x64"))
	recipe := H("qualified-task-recipe-v1", []byte("canonical-field-matrix64-product-v1"))
	meter := H("qualified-task-output-meter-v1", f.old.Network[:], f.old.Parameters[:], f.old.Demand[:], a[:], layer[:], b[:], recipe[:], c[:])
	return PriorTask{Lease: f.old, Active: true, SourceSequence: 1, NextRequesterNonce: 3, Model: a, Input: b, MatrixTask: c, Meter: meter}
}
func signedFixture() fixture { f := leaseFixture(); f.raw = signFixture(f, 2); return f }
func expectErr(t *testing.T, f fixture, h uint64, sourceSequence uint64, nonce uint64, expected string) {
	t.Helper()
	p := priorTask(f)
	p.SourceSequence = sourceSequence
	p.NextRequesterNonce = nonce
	err := VerifyQ4(f.raw, p, h, f.model)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("want %s got %v", expected, err)
	}
}
func TestQ4BothRealSignaturesAndByteIdentity(t *testing.T) {
	f := signedFixture()
	if err := VerifyQ4(f.raw, priorTask(f), 900, f.model); err != nil {
		t.Fatal(err)
	}
	if len(f.raw) != 1187 {
		t.Fatal("wrong complete Q4 bytes")
	}
	if _, err := DecodeTask(f.raw[95+leaseBytes+36 : 95+leaseBytes+620]); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLease(f.raw[95 : 95+leaseBytes]); err != nil {
		t.Fatal(err)
	}
	// Exact record identity, not an undocumented signature/permission claim.
	txid := H("tx-id", f.raw)
	if !nonzero(txid) {
		t.Fatal("empty tx id")
	}
	// Frozen independent byte vector for later native Rust parity checks.
	if got := fmt.Sprintf("%x", sha256.Sum256(f.raw)); got != "97dade3ee25e63c3a3413f5b1f108a6c6f8e9ebce1c717aaa757f08b5a4fefca" {
		t.Fatalf("signed transaction bytes drifted: %s", got)
	}
	if got := fmt.Sprintf("%x", txid); got != "5cec002e5e54493563850ffaf372a37b81f906f4ed5a11b44a2de84287706dd0" {
		t.Fatalf("PoN transaction-id drifted: %s", got)
	}
	expectErr(t, f, 1001, 1, 3, "Q4_OVERLAP")
	expectErr(t, f, 900, 2, 3, "QWA_BINDING_SEQUENCE")
	expectErr(t, f, 900, 1, 4, "PNX_NONCE_EXPIRY_FEE")
}
func TestQ4MutationCannotMintSourceOrRequesterAuthority(t *testing.T) {
	f := signedFixture()
	b := append([]byte(nil), f.raw...)
	b[1123] ^= 1
	f.raw = b
	expectErr(t, f, 900, 1, 3, "PNX_SIGNATURE")
	f = signedFixture()
	b = append([]byte(nil), f.raw...)
	b[1122] ^= 1
	// Requester signature itself must also be recomputed if payload changes.
	msg := H("tx-sign", b[:1123])
	copy(b[1123:], ed25519.Sign(f.requester, msg[:]))
	f.raw = b
	expectErr(t, f, 900, 1, 3, "QWA_SOURCE_SIGNATURE")
	f = signedFixture()
	b = append([]byte(nil), f.raw...)
	b[93] = 0
	f.raw = b
	expectErr(t, f, 900, 1, 3, "PNX_VERSION")
	f = signedFixture()
	f.raw = f.raw[:1186]
	expectErr(t, f, 900, 1, 3, "PNX_LENGTH")
	f = signedFixture()
	b = append([]byte(nil), f.raw...)
	b[95+337] = 1
	msg = H("tx-sign", b[:1123])
	copy(b[1123:], ed25519.Sign(f.requester, msg[:]))
	f.raw = b
	expectErr(t, f, 900, 1, 3, "QDL_RESERVED")
}
func TestQ4FullySignedButInvalidTemporalAndContextControls(t *testing.T) {
	f := leaseFixture()
	f.next.NotBefore = 901
	f.next.Expires = 1500
	f.next.AvailableUntil = 1600
	f.raw = signFixture(f, 2)
	expectErr(t, f, 900, 1, 3, "Q4_OVERLAP")
	f = leaseFixture()
	f.next.Revision = 3
	f.raw = signFixture(f, 2)
	expectErr(t, f, 900, 1, 3, "Q4_OVERLAP")
	f = leaseFixture()
	f.next.Expires = 1000
	f.next.AvailableUntil = 1100
	f.raw = signFixture(f, 2)
	expectErr(t, f, 900, 1, 3, "Q4_OVERLAP")
	f = leaseFixture()
	f.next.Slot = 1
	f.raw = signFixture(f, 2)
	expectErr(t, f, 900, 1, 3, "Q4_BINDING")
	f = leaseFixture()
	f.raw = signFixture(f, 3)
	expectErr(t, f, 900, 1, 3, "QWA_BINDING_SEQUENCE")
	f = leaseFixture()
	f.next.Parameters = H("wrong-parameters", []byte("validly signed but not current"))
	f.next.Demand = H("qualified-demand-id-v2", f.next.Network[:], f.next.Parameters[:], f.next.Requester[:], le(1))
	f.raw = signFixture(f, 2)
	expectErr(t, f, 900, 1, 3, "Q4_BINDING")
}
func TestQ4PhysicalMaterialAndParentSourceAreNotInvented(t *testing.T) {
	f := signedFixture()
	other := f.model
	other.A = append([]byte(nil), other.A...)
	other.A[0] ^= 1
	if err := VerifyQ4(f.raw, priorTask(f), 900, other); err == nil || err.Error() != "QWA_MATERIAL" {
		t.Fatalf("material substitution: %v", err)
	}
	f = signedFixture()
	f.old.Source = H("fake-prior-source", []byte("no verified parent"))
	expectErr(t, f, 900, 1, 3, "Q4_BINDING")
	f = signedFixture()
	f.old.Requester = f.old.Source
	expectErr(t, f, 900, 1, 3, "QDL_IDENTITY")
	f = signedFixture()
	f.old.Revision = maxU64
	// An untrusted forged old lease never establishes native authority.
	expectErr(t, f, 900, 1, 3, "Q4_OVERLAP")
}

func TestQ4SignedMaterialMutationCannotEraseOriginalParentBinding(t *testing.T) {
	f := signedFixture()
	prior := priorTask(f)
	f.model.A = append([]byte(nil), f.model.A...)
	f.model.A[0] ^= 1
	f.raw = signFixture(f, 2) // both signatures genuinely reissued
	if err := VerifyQ4(f.raw, prior, 900, f.model); err == nil || err.Error() != "Q4_PRIOR_MATERIAL" {
		t.Fatalf("parent mutation: %v", err)
	}
	prior.Active = false
	if err := VerifyQ4(f.raw, prior, 900, f.model); err == nil || err.Error() != "Q4_PARENT_INACTIVE" {
		t.Fatalf("revoked parent: %v", err)
	}
}
