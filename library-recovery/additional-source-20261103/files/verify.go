// Package q4reference independently checks the fixed Q4 dual-signed wire format.
//
// This is a research oracle, NOT a consensus, source-authority, material
// availability, current-parent, expenditure, inclusion or FinalUse verifier.
// Its caller pins a network, parameters, canonical old lease/source bytes and
// containing height from an independent authoritative Node observation.
package q4reference

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	LeaseBytes          = 344
	StatementBytes      = 684
	EnvelopeBytes       = 1187
	SourceManifestBytes = 584
	RetentionBlocks     = uint64(100)
	MaxLife             = uint64(1000)
)

type Digest [32]byte

// Input bytes are untrusted. Previous-version authority is caller-supplied:
// this function cannot prove the old lease is in the active parent or unrevoked.
type Input struct {
	Network            Digest
	Parameters         Digest
	OldLease           []byte
	OldSourceStatement []byte
	RenewalTransaction []byte
	ContainingHeight   uint64
}

type Observation struct {
	TransactionID        Digest
	LeaseID              Digest
	SourceStatementID    Digest
	Requester            Digest
	Source               Digest
	Slot                 uint8
	PreviousRevision     uint64
	SuccessorRevision    uint64
	FromHeight           uint64
	LastContainingHeight uint64
}

func fail(code string) error { return errors.New("Q4_" + code) }
func zero(b []byte) bool     { return bytes.Equal(b, make([]byte, len(b))) }
func u64(b []byte) uint64    { return binary.LittleEndian.Uint64(b) }
func same(a, b []byte) bool  { return bytes.Equal(a, b) }
func boundedAdd(a, b uint64) (uint64, bool) {
	if ^uint64(0)-a < b {
		return 0, false
	}
	return a + b, true
}
func digest(data []byte) Digest    { return sha256.Sum256(data) }
func fromBytes(data []byte) Digest { var out Digest; copy(out[:], data); return out }

// Exact SHA-256 framing from pon_wire::hash, NOT bare SHA-256 or tagged JSON.
func hash(tag string, parts ...[]byte) Digest {
	h := sha256.New()
	h.Write([]byte("TRNM-PON1\x00"))
	var two [2]byte
	binary.LittleEndian.PutUint16(two[:], uint16(len(tag)))
	h.Write(two[:])
	h.Write([]byte(tag))
	var four [4]byte
	for _, p := range parts {
		binary.LittleEndian.PutUint32(four[:], uint32(len(p)))
		h.Write(four[:])
		h.Write(p)
	}
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

// The fixed wire uses Ed25519 over the EXACT 32-byte hash, not its hex text.
func sigOK(pub, sig []byte, hashed Digest) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && !zero(pub) &&
		ed25519.Verify(ed25519.PublicKey(pub), hashed[:], sig)
}

type lease struct {
	raw                                                                                               []byte
	slot, purpose, cost                                                                               uint8
	network, params, demand, requester, source, sourceRecord, authorization, availManifest, availRoot []byte
	generation, revision, from, expires, availableUntil                                               uint64
	id                                                                                                Digest
}

func parseLease(raw []byte) (lease, error) {
	l := lease{}
	if len(raw) != LeaseBytes || !same(raw[:4], []byte("QDL2")) || binary.LittleEndian.Uint16(raw[4:6]) != 2 {
		return l, fail("LEASE_CODEC")
	}
	if !zero(raw[337:344]) {
		return l, fail("LEASE_RESERVED")
	}
	l.raw = raw
	l.slot = raw[6]
	l.purpose = raw[7]
	l.cost = raw[336]
	l.network = raw[8:40]
	l.params = raw[40:72]
	l.demand = raw[72:104]
	l.requester = raw[104:136]
	l.source = raw[136:168]
	l.sourceRecord = raw[168:200]
	l.authorization = raw[200:232]
	l.availManifest = raw[232:264]
	l.availRoot = raw[264:296]
	l.generation = u64(raw[296:304])
	l.revision = u64(raw[304:312])
	l.from = u64(raw[312:320])
	l.expires = u64(raw[320:328])
	l.availableUntil = u64(raw[328:336])
	if l.slot >= 32 || l.purpose < 1 || l.purpose > 4 || l.cost != 1 ||
		l.generation == 0 || l.revision == 0 || same(l.requester, l.source) {
		return lease{}, fail("LEASE_SEMANTICS")
	}
	for _, b := range [][]byte{l.network, l.params, l.demand, l.requester, l.source, l.sourceRecord, l.authorization, l.availManifest, l.availRoot} {
		if zero(b) {
			return lease{}, fail("LEASE_ZERO_IDENTITY")
		}
	}
	var g [8]byte
	binary.LittleEndian.PutUint64(g[:], l.generation)
	d := hash("qualified-demand-id-v2", l.network, l.params, l.requester, g[:])
	if !same(l.demand, d[:]) {
		return lease{}, fail("DEMAND_ID")
	}
	until, ok := boundedAdd(l.expires, RetentionBlocks)
	if !ok || l.from >= l.expires || l.expires-l.from > MaxLife || l.availableUntil != until {
		return lease{}, fail("LEASE_WINDOW")
	}
	l.id = hash("qualified-demand-lease-v2", raw)
	return l, nil
}

type manifest struct {
	raw                                      []byte
	purpose, cost                            byte
	hashes                                   [16][]byte
	sourceSeq, from, expires, until, logical uint64
	modelSize, inputSize, credit             uint32
}

func parseManifest(raw []byte) (manifest, error) {
	m := manifest{}
	if len(raw) != SourceManifestBytes || !same(raw[:4], []byte("QWT1")) || binary.LittleEndian.Uint16(raw[4:6]) != 1 {
		return m, fail("MANIFEST_CODEC")
	}
	if raw[11] != 0 || !zero(raw[530:532]) {
		return m, fail("MANIFEST_RESERVED")
	}
	m.raw = raw
	m.purpose = raw[6]
	m.cost = raw[7]
	if m.purpose < 1 || m.purpose > 4 || m.cost != 1 || raw[8] != 1 || raw[9] != 0 || raw[10] != 1 {
		return m, fail("MANIFEST_PROFILE")
	}
	for i := 0; i < 16; i++ {
		m.hashes[i] = raw[12+i*32 : 12+(i+1)*32]
		if zero(m.hashes[i]) {
			return m, fail("MANIFEST_ZERO_IDENTITY")
		}
	}
	for i := 0; i < 3; i++ {
		if binary.LittleEndian.Uint16(raw[524+i*2:526+i*2]) != 64 {
			return m, fail("MANIFEST_SHAPE")
		}
	}
	m.sourceSeq = u64(raw[532:540])
	m.from = u64(raw[540:548])
	m.expires = u64(raw[548:556])
	m.until = u64(raw[556:564])
	m.logical = u64(raw[564:572])
	m.modelSize = binary.LittleEndian.Uint32(raw[572:576])
	m.inputSize = binary.LittleEndian.Uint32(raw[576:580])
	m.credit = binary.LittleEndian.Uint32(raw[580:584])
	if m.sourceSeq == 0 || m.modelSize != 16384 || m.inputSize != 16384 || m.logical != 262144 || m.expires < m.from || m.expires-m.from > MaxLife || (m.purpose == 1 && m.credit != 0) || (m.purpose != 1 && m.credit != 1) {
		return m, fail("MANIFEST_NUMERIC")
	}
	profile := hash("qualified-task-profile-v1", []byte("pon-matmul-transcript-64-v1"))
	recipe := hash("qualified-task-recipe-v1", []byte("canonical-field-matrix64-product-v1"))
	layer := hash("qualified-task-layer-v1", m.hashes[6], []byte("entire-row-major-field-layer-64x64"))
	meter := hash("qualified-task-output-meter-v1", m.hashes[0], m.hashes[1], m.hashes[4], m.hashes[6], m.hashes[7], m.hashes[8], m.hashes[9], m.hashes[10])
	if !same(m.hashes[2], profile[:]) || !same(m.hashes[9], recipe[:]) || !same(m.hashes[7], layer[:]) || !same(m.hashes[15], meter[:]) {
		return m, fail("MANIFEST_BINDING")
	}
	return m, nil
}

func parseStatement(raw []byte, l lease) (manifest, error) {
	if len(raw) != StatementBytes || !same(raw[:4], []byte("QWA2")) || !same(raw[4:36], l.id[:]) {
		return manifest{}, fail("STATEMENT_LEASE")
	}
	m, err := parseManifest(raw[36:620])
	if err != nil {
		return m, err
	}
	srcRecord := hash("qualified-demand-source-record-v2", l.id[:], l.sourceRecord)
	frontier := hash("qualified-demand-frontier-v2", l.id[:])
	h := m.hashes
	if !same(h[0], l.network) || !same(h[1], l.params) || !same(h[3], l.source) || !same(h[4], l.demand) ||
		!same(h[5], srcRecord[:]) || !same(h[11], l.availManifest) || !same(h[12], l.availRoot) ||
		!same(h[13], l.authorization) || !same(h[14], frontier[:]) ||
		m.purpose != l.purpose || m.cost != l.cost || m.from != l.from || m.expires != l.expires || m.until != l.availableUntil {
		return manifest{}, fail("STATEMENT_BINDING")
	}
	msg := hash("qualified-task-source-sign-v2", raw[:620])
	if !sigOK(l.source, raw[620:684], msg) {
		return manifest{}, fail("SOURCE_SIGNATURE")
	}
	return m, nil
}

// Validate decodes BOTH source statements, checks exact Q4 overlap/immutable task
// lineage, and verifies the requester and source signatures. It returns only
// an independently computed observation, never the Node's private verified type.
func Validate(in Input) (Observation, error) {
	var empty Observation
	if len(in.OldLease) != LeaseBytes || len(in.OldSourceStatement) != StatementBytes || len(in.RenewalTransaction) != EnvelopeBytes {
		return empty, fail("LENGTH")
	}
	prior, err := parseLease(in.OldLease)
	if err != nil {
		return empty, err
	}
	next, err := parseLease(in.RenewalTransaction[95 : 95+LeaseBytes])
	if err != nil {
		return empty, err
	}
	if !same(prior.network, in.Network[:]) || !same(next.network, in.Network[:]) ||
		!same(prior.params, in.Parameters[:]) || !same(next.params, in.Parameters[:]) {
		return empty, fail("CONTEXT")
	}
	if !same(in.RenewalTransaction[:4], []byte("PNX1")) || in.RenewalTransaction[92] != 22 ||
		binary.LittleEndian.Uint16(in.RenewalTransaction[93:95]) != 1028 ||
		!same(in.RenewalTransaction[4:36], in.Network[:]) || !same(in.RenewalTransaction[36:68], prior.requester) ||
		u64(in.RenewalTransaction[68:76]) == 0 || u64(in.RenewalTransaction[84:92]) > 10000000 {
		return empty, fail("ENVELOPE")
	}
	if in.ContainingHeight > u64(in.RenewalTransaction[76:84]) {
		return empty, fail("EXPIRED_TRANSACTION")
	}
	if !same(prior.network, next.network) || !same(prior.params, next.params) || prior.slot != next.slot || prior.purpose != next.purpose || prior.cost != next.cost ||
		!same(prior.demand, next.demand) || !same(prior.requester, next.requester) || !same(prior.source, next.source) ||
		!same(prior.sourceRecord, next.sourceRecord) || !same(prior.authorization, next.authorization) || !same(prior.availManifest, next.availManifest) || !same(prior.availRoot, next.availRoot) ||
		prior.generation != next.generation || prior.revision == ^uint64(0) || next.revision != prior.revision+1 {
		return empty, fail("SUCCESSOR_IMMUTABILITY")
	}
	if next.from < prior.from || next.from > in.ContainingHeight || in.ContainingHeight > prior.expires ||
		in.ContainingHeight < prior.from || next.expires <= prior.expires {
		return empty, fail("Q4_OVERLAP")
	}
	oldManifest, err := parseStatement(in.OldSourceStatement, prior)
	if err != nil {
		return empty, err
	}
	newRaw := in.RenewalTransaction[95+LeaseBytes : 1123]
	newManifest, err := parseStatement(newRaw, next)
	if err != nil {
		return empty, err
	}
	if oldManifest.sourceSeq == ^uint64(0) || newManifest.sourceSeq != oldManifest.sourceSeq+1 {
		return empty, fail("SOURCE_SEQUENCE")
	}
	// The changed statement may only change lease-derived source_record/frontier,
	// signed window and sequence. Every model/input/meter/recipe remains exact.
	for i := 0; i < 16; i++ {
		if i == 5 || i == 14 {
			continue
		}
		if !same(oldManifest.hashes[i], newManifest.hashes[i]) {
			return empty, fail("MATERIAL_IMMUTABILITY")
		}
	}
	if !sigOK(prior.requester, in.RenewalTransaction[1123:], hash("tx-sign", in.RenewalTransaction[:1123])) {
		return empty, fail("REQUESTER_SIGNATURE")
	}
	return Observation{TransactionID: hash("tx-id", in.RenewalTransaction), LeaseID: next.id,
		SourceStatementID: hash("qualified-task-manifest-v2", newRaw[:620]),
		Requester:         digest(prior.requester), Source: digest(prior.source), Slot: prior.slot,
		PreviousRevision: prior.revision, SuccessorRevision: next.revision, FromHeight: next.from, LastContainingHeight: prior.expires}, nil
}
