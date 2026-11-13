// Research-only, independent Go Q4 byte/signature verifier.
// It has NO source-owner, chain-state, FinalUse, data-availability, or admission authority.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	leaseBytes     = 344
	taskBytes      = 584
	statementBytes = 684
	payloadBytes   = leaseBytes + statementBytes
	envelopeBytes  = 159 + payloadBytes
	fieldBytes     = 64 * 64 * 4
	maxU64         = ^uint64(0)
)

type Hash [32]byte

func H(tag string, parts ...[]byte) Hash {
	s := sha256.New()
	s.Write([]byte("TRNM-PON1\x00"))
	var n [4]byte
	binary.LittleEndian.PutUint16(n[:2], uint16(len(tag)))
	s.Write(n[:2])
	s.Write([]byte(tag))
	for _, p := range parts {
		binary.LittleEndian.PutUint32(n[:], uint32(len(p)))
		s.Write(n[:])
		s.Write(p)
	}
	var out Hash
	copy(out[:], s.Sum(nil))
	return out
}
func le(v uint64) []byte          { var b [8]byte; binary.LittleEndian.PutUint64(b[:], v); return b[:] }
func hashAt(b []byte, i int) Hash { var h Hash; copy(h[:], b[i:i+32]); return h }
func fail(code string) error      { return errors.New(code) }
func need(ok bool, code string) error {
	if !ok {
		return fail(code)
	}
	return nil
}
func nonzero(h Hash) bool { return h != (Hash{}) }

type Lease struct {
	Slot                                                                byte
	Purpose                                                             byte
	Network, Parameters, Demand, Requester, Source                      Hash
	SourceRecord, Authorization, AvailabilityManifest, AvailabilityRoot Hash
	Generation, Revision, NotBefore, Expires, AvailableUntil            uint64
	CostClass                                                           byte
}

func DecodeLease(raw []byte) (Lease, error) {
	var v Lease
	if len(raw) != leaseBytes {
		return v, fail("QDL_LENGTH")
	}
	if !bytes.Equal(raw[:4], []byte("QDL2")) || binary.LittleEndian.Uint16(raw[4:6]) != 2 {
		return v, fail("QDL_VERSION")
	}
	v.Slot, v.Purpose = raw[6], raw[7]
	hs := []*Hash{&v.Network, &v.Parameters, &v.Demand, &v.Requester, &v.Source, &v.SourceRecord, &v.Authorization, &v.AvailabilityManifest, &v.AvailabilityRoot}
	for i, p := range hs {
		*p = hashAt(raw, 8+i*32)
	}
	fields := []*uint64{&v.Generation, &v.Revision, &v.NotBefore, &v.Expires, &v.AvailableUntil}
	for i, p := range fields {
		*p = binary.LittleEndian.Uint64(raw[296+i*8 : 304+i*8])
	}
	v.CostClass = raw[336]
	if !bytes.Equal(raw[337:], make([]byte, 7)) {
		return v, fail("QDL_RESERVED")
	}
	if v.Slot >= 32 || v.Purpose < 1 || v.Purpose > 4 || v.CostClass != 1 {
		return v, fail("QDL_CLASS")
	}
	for _, p := range hs {
		if !nonzero(*p) {
			return v, fail("QDL_IDENTITY")
		}
	}
	if v.Requester == v.Source || v.Generation == 0 || v.Revision == 0 {
		return v, fail("QDL_IDENTITY")
	}
	if v.Demand != H("qualified-demand-id-v2", v.Network[:], v.Parameters[:], v.Requester[:], le(v.Generation)) {
		return v, fail("QDL_DEMAND")
	}
	if v.Expires <= v.NotBefore || v.Expires-v.NotBefore > 1000 || v.Expires > maxU64-100 || v.AvailableUntil != v.Expires+100 {
		return v, fail("QDL_WINDOW")
	}
	return v, nil
}
func (v Lease) Encode() ([]byte, error) {
	b := make([]byte, leaseBytes)
	copy(b[:4], "QDL2")
	binary.LittleEndian.PutUint16(b[4:6], 2)
	b[6], b[7] = v.Slot, v.Purpose
	hs := []Hash{v.Network, v.Parameters, v.Demand, v.Requester, v.Source, v.SourceRecord, v.Authorization, v.AvailabilityManifest, v.AvailabilityRoot}
	for i, h := range hs {
		copy(b[8+i*32:], h[:])
	}
	ns := []uint64{v.Generation, v.Revision, v.NotBefore, v.Expires, v.AvailableUntil}
	for i, x := range ns {
		binary.LittleEndian.PutUint64(b[296+i*8:], x)
	}
	b[336] = v.CostClass
	if _, err := DecodeLease(b); err != nil {
		return nil, err
	}
	return b, nil
}
func (v Lease) ID() (Hash, error) {
	b, err := v.Encode()
	if err != nil {
		return Hash{}, err
	}
	return H("qualified-demand-lease-v2", b), nil
}
func (v Lease) BoundSource() Hash {
	id, _ := v.ID()
	return H("qualified-demand-source-record-v2", id[:], v.SourceRecord[:])
}
func (v Lease) Withdrawal() Hash { id, _ := v.ID(); return H("qualified-demand-frontier-v2", id[:]) }

type ModelMaterial struct{ A, B []byte }

func (m ModelMaterial) validate() error {
	if len(m.A) != fieldBytes || len(m.B) != fieldBytes {
		return fail("MATERIAL_LENGTH")
	}
	for _, p := range [][]byte{m.A, m.B} {
		for i := 0; i < len(p); i += 4 {
			if binary.LittleEndian.Uint32(p[i:i+4]) >= 4294967291 {
				return fail("MATERIAL_FIELD")
			}
		}
	}
	return nil
}

type Task struct {
	Purpose, CostClass, Numeric, Hardness, Reuse           byte
	Ids                                                    [16]Hash
	DemandNonce, NotBefore, Expires, AvailableUntil, Units uint64
	ModelBytes, InputBytes, OutputLimit                    uint32
}

func DecodeTask(raw []byte) (Task, error) {
	var t Task
	if len(raw) != taskBytes {
		return t, fail("QWT_LENGTH")
	}
	if !bytes.Equal(raw[:4], []byte("QWT1")) || binary.LittleEndian.Uint16(raw[4:6]) != 1 {
		return t, fail("QWT_VERSION")
	}
	t.Purpose, t.CostClass, t.Numeric, t.Hardness, t.Reuse = raw[6], raw[7], raw[8], raw[9], raw[10]
	if raw[11] != 0 || raw[530] != 0 || raw[531] != 0 {
		return t, fail("QWT_RESERVED")
	}
	for i := 0; i < 16; i++ {
		t.Ids[i] = hashAt(raw, 12+i*32)
		if !nonzero(t.Ids[i]) {
			return t, fail("QWT_IDENTITY")
		}
	}
	for i := 0; i < 3; i++ {
		if binary.LittleEndian.Uint16(raw[524+i*2:526+i*2]) != 64 {
			return t, fail("QWT_SHAPE")
		}
	}
	ns := []*uint64{&t.DemandNonce, &t.NotBefore, &t.Expires, &t.AvailableUntil, &t.Units}
	for i, p := range ns {
		*p = binary.LittleEndian.Uint64(raw[532+i*8 : 540+i*8])
	}
	t.ModelBytes = binary.LittleEndian.Uint32(raw[572:576])
	t.InputBytes = binary.LittleEndian.Uint32(raw[576:580])
	t.OutputLimit = binary.LittleEndian.Uint32(raw[580:584])
	if t.Purpose < 1 || t.Purpose > 4 || t.CostClass != 1 || t.Numeric != 1 || t.Hardness != 0 || t.Reuse != 1 || t.Units != 262144 || t.DemandNonce == 0 || t.ModelBytes != fieldBytes || t.InputBytes != fieldBytes {
		return t, fail("QWT_PROFILE")
	}
	wantOutput := uint32(1)
	if t.Purpose == 1 {
		wantOutput = 0
	}
	if t.OutputLimit != wantOutput {
		return t, fail("QWT_OUTPUT_LIMIT")
	}
	if t.NotBefore > t.Expires || t.Expires-t.NotBefore > 1000 || t.AvailableUntil < t.Expires {
		return t, fail("QWT_WINDOW")
	}
	if t.Ids[2] != H("qualified-task-profile-v1", []byte("pon-matmul-transcript-64-v1")) || t.Ids[9] != H("qualified-task-recipe-v1", []byte("canonical-field-matrix64-product-v1")) {
		return t, fail("QWT_PROFILE_HASH")
	}
	model := t.Ids[6]
	if t.Ids[7] != H("qualified-task-layer-v1", model[:], []byte("entire-row-major-field-layer-64x64")) {
		return t, fail("QWT_LAYER")
	}
	want := H("qualified-task-output-meter-v1", t.Ids[0][:], t.Ids[1][:], t.Ids[4][:], t.Ids[6][:], t.Ids[7][:], t.Ids[8][:], t.Ids[9][:], t.Ids[10][:])
	if t.Ids[15] != want {
		return t, fail("QWT_METER")
	}
	return t, nil
}

// PriorTask values are supplied by an independently authenticated parent-state
// owner. This Go code cannot construct, verify or upgrade that native authority.
type PriorTask struct {
	Lease                              Lease
	Active                             bool
	SourceSequence, NextRequesterNonce uint64
	Model, Input, MatrixTask, Meter    Hash
}

// VerifyQ4 checks exact canonical syntax, both real signatures and the selected
// predecessor/height/material bindings. It CANNOT establish the trusted predecessor,
// ownership, revocation, state, resource, W1, DA, or chain-confirmation facts.
// The caller must supply a separately verified native predecessor and current nonce.
func VerifyQ4(raw []byte, prior PriorTask, height uint64, material ModelMaterial) error {
	previous := prior.Lease
	oldSourceSequence := prior.SourceSequence
	expectedRequesterNonce := prior.NextRequesterNonce
	if !prior.Active {
		return fail("Q4_PARENT_INACTIVE")
	}
	for _, v := range []Hash{prior.Model, prior.Input, prior.MatrixTask, prior.Meter} {
		if !nonzero(v) {
			return fail("Q4_PARENT_BINDINGS")
		}
	}
	if len(raw) != envelopeBytes {
		return fail("PNX_LENGTH")
	}
	if _, err := previous.Encode(); err != nil {
		return err
	}
	if !bytes.Equal(raw[:4], []byte("PNX1")) || raw[92] != 22 || binary.LittleEndian.Uint16(raw[93:95]) != payloadBytes {
		return fail("PNX_VERSION")
	}
	if err := material.validate(); err != nil {
		return err
	}
	before := raw[:1123]
	if hashAt(raw, 4) != previous.Network || hashAt(raw, 36) != previous.Requester {
		return fail("PNX_CONTEXT_OR_REQUESTER")
	}
	nonce := binary.LittleEndian.Uint64(raw[68:76])
	expiry := binary.LittleEndian.Uint64(raw[76:84])
	fee := binary.LittleEndian.Uint64(raw[84:92])
	if nonce != expectedRequesterNonce || nonce == 0 || expiry < height || fee > 10000000 {
		return fail("PNX_NONCE_EXPIRY_FEE")
	}
	requesterMessage := H("tx-sign", before)
	if !ed25519.Verify(ed25519.PublicKey(previous.Requester[:]), requesterMessage[:], raw[1123:]) {
		return fail("PNX_SIGNATURE")
	}
	next, err := DecodeLease(raw[95 : 95+leaseBytes])
	if err != nil {
		return err
	}
	if next.Network != previous.Network || next.Parameters != previous.Parameters || next.Slot != previous.Slot || next.Purpose != previous.Purpose || next.Requester != previous.Requester || next.Source != previous.Source || next.Demand != previous.Demand || next.Generation != previous.Generation || next.CostClass != previous.CostClass || next.SourceRecord != previous.SourceRecord || next.Authorization != previous.Authorization || next.AvailabilityManifest != previous.AvailabilityManifest || next.AvailabilityRoot != previous.AvailabilityRoot {
		return fail("Q4_BINDING")
	}
	if next.Revision != previous.Revision+1 || previous.Revision == maxU64 || height > previous.Expires || previous.NotBefore > next.NotBefore || next.NotBefore > height || next.NotBefore > previous.Expires || next.Expires <= previous.Expires {
		return fail("Q4_OVERLAP")
	}
	signed := raw[95+leaseBytes : 1123]
	if !bytes.Equal(signed[:4], []byte("QWA2")) {
		return fail("QWA_VERSION")
	}
	leaseID, _ := next.ID()
	if !bytes.Equal(signed[4:36], leaseID[:]) {
		return fail("QWA_LEASE_ID")
	}
	t, err := DecodeTask(signed[36:620])
	if err != nil {
		return err
	}
	if t.Ids[0] != next.Network || t.Ids[1] != next.Parameters || t.Ids[3] != next.Source || t.Ids[4] != next.Demand || t.Ids[5] != next.BoundSource() || t.Ids[11] != next.AvailabilityManifest || t.Ids[12] != next.AvailabilityRoot || t.Ids[13] != next.Authorization || t.Ids[14] != next.Withdrawal() || t.Purpose != next.Purpose || t.CostClass != next.CostClass || t.NotBefore != next.NotBefore || t.Expires != next.Expires || t.AvailableUntil != next.AvailableUntil || t.DemandNonce != oldSourceSequence+1 || oldSourceSequence == maxU64 {
		return fail("QWA_BINDING_SEQUENCE")
	}
	if t.Ids[6] != prior.Model || t.Ids[8] != prior.Input || t.Ids[10] != prior.MatrixTask || t.Ids[15] != prior.Meter {
		return fail("Q4_PRIOR_MATERIAL")
	}
	if t.Ids[6] != H("artifact", material.A) || t.Ids[8] != H("qualified-task-input-v1", material.B) || t.Ids[10] != H("task", material.A, material.B) {
		return fail("QWA_MATERIAL")
	}
	sourceMsg := H("qualified-task-source-sign-v2", signed[:620])
	if !ed25519.Verify(ed25519.PublicKey(next.Source[:]), sourceMsg[:], signed[620:684]) {
		return fail("QWA_SOURCE_SIGNATURE")
	}
	return nil
}

func main() { fmt.Println("research-only: run go test main.go main_test.go (no chain authority)") }
