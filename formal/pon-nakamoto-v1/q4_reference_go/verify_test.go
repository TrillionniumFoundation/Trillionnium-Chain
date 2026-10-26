package q4reference

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func fixedKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("TRNM-Q4-DEV-FIXTURE:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func copyDigest(b []byte) Digest  { var out Digest; copy(out[:], b); return out }
func label(label string) Digest   { return digest([]byte(label)) }
func putU64(dst []byte, n uint64) { binary.LittleEndian.PutUint64(dst, n) }
func putU32(dst []byte, n uint32) { binary.LittleEndian.PutUint32(dst, n) }

type fixture struct {
	in       Input
	req, src ed25519.PrivateKey
}

func (f *fixture) lease(rev, from, expires uint64) []byte {
	raw := make([]byte, LeaseBytes)
	copy(raw[:4], "QDL2")
	binary.LittleEndian.PutUint16(raw[4:6], 2)
	raw[6] = 0
	raw[7] = 4
	copy(raw[8:40], f.in.Network[:])
	copy(raw[40:72], f.in.Parameters[:])
	reqPub := f.req.Public().(ed25519.PublicKey)
	srcPub := f.src.Public().(ed25519.PublicKey)
	copy(raw[104:136], reqPub)
	copy(raw[136:168], srcPub)
	record := label("source_record")
	copy(raw[168:200], record[:])
	auth := label("authorization")
	avail := label("availability manifest")
	copy(raw[200:232], auth[:])
	copy(raw[232:264], avail[:])
	root := label("availability root")
	copy(raw[264:296], root[:])
	putU64(raw[296:304], 1)
	putU64(raw[304:312], rev)
	putU64(raw[312:320], from)
	putU64(raw[320:328], expires)
	putU64(raw[328:336], expires+100)
	raw[336] = 1
	generation := raw[296:304]
	id := hash("qualified-demand-id-v2", raw[8:40], raw[40:72], reqPub, generation)
	copy(raw[72:104], id[:])
	return raw
}
func (f *fixture) manifest(l []byte, seq uint64, model Digest) []byte {
	m := make([]byte, SourceManifestBytes)
	copy(m[:4], "QWT1")
	binary.LittleEndian.PutUint16(m[4:6], 1)
	m[6] = 4
	m[7] = 1
	m[8] = 1
	m[9] = 0
	m[10] = 1
	ld := hash("qualified-demand-lease-v2", l)
	record := hash("qualified-demand-source-record-v2", ld[:], l[168:200])
	frontier := hash("qualified-demand-frontier-v2", ld[:])
	profile := hash("qualified-task-profile-v1", []byte("pon-matmul-transcript-64-v1"))
	recipe := hash("qualified-task-recipe-v1", []byte("canonical-field-matrix64-product-v1"))
	layer := hash("qualified-task-layer-v1", model[:], []byte("entire-row-major-field-layer-64x64"))
	input := label("input-byte-commitment")
	task := label("real-matrix-task-commitment")
	meter := hash("qualified-task-output-meter-v1", l[8:40], l[40:72], l[72:104], model[:], layer[:], input[:], recipe[:], task[:])
	hashes := [][]byte{l[8:40], l[40:72], profile[:], l[136:168], l[72:104], record[:], model[:], layer[:], input[:], recipe[:], task[:], l[232:264], l[264:296], l[200:232], frontier[:], meter[:]}
	for i, b := range hashes {
		copy(m[12+32*i:], b)
	}
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint16(m[524+2*i:], 64)
	}
	putU64(m[532:540], seq)
	copy(m[540:564], l[312:336])
	putU64(m[564:572], 262144)
	putU32(m[572:576], 16384)
	putU32(m[576:580], 16384)
	putU32(m[580:584], 1)
	return m
}
func (f *fixture) statement(l []byte, seq uint64, model Digest) []byte {
	raw := make([]byte, StatementBytes)
	copy(raw[:4], "QWA2")
	id := hash("qualified-demand-lease-v2", l)
	copy(raw[4:36], id[:])
	copy(raw[36:620], f.manifest(l, seq, model))
	msg := hash("qualified-task-source-sign-v2", raw[:620])
	copy(raw[620:], ed25519.Sign(f.src, msg[:]))
	return raw
}
func (f *fixture) signPacket() {
	raw := f.in.RenewalTransaction
	msg := hash("tx-sign", raw[:1123])
	copy(raw[1123:], ed25519.Sign(f.req, msg[:]))
}
func newFixture() fixture {
	req, src := fixedKey("REQUESTER"), fixedKey("SOURCE")
	f := fixture{in: Input{Network: label("network"), Parameters: label("parameters"), ContainingHeight: 905}, req: req, src: src}
	old := f.lease(1, 900, 1000)
	next := f.lease(2, 905, 1400)
	f.in.OldLease = old
	model := label("model-fixture")
	f.in.OldSourceStatement = f.statement(old, 1, model)
	env := make([]byte, EnvelopeBytes)
	copy(env[:4], "PNX1")
	copy(env[4:36], f.in.Network[:])
	copy(env[36:68], req.Public().(ed25519.PublicKey))
	putU64(env[68:76], 1)
	putU64(env[76:84], 2000)
	putU64(env[84:92], 20000)
	env[92] = 22
	binary.LittleEndian.PutUint16(env[93:95], 1028)
	copy(env[95:95+LeaseBytes], next)
	copy(env[95+LeaseBytes:1123], f.statement(next, 2, model))
	f.in.RenewalTransaction = env
	f.signPacket()
	return f
}
func errorHas(t *testing.T, in Input, code string) {
	t.Helper()
	_, err := Validate(in)
	if err == nil || !strings.Contains(err.Error(), code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func TestActualRequesterAndSourceSignaturesAndQ4Boundary(t *testing.T) {
	f := newFixture()
	for _, height := range []uint64{905, 999, 1000} {
		in := f.in
		in.ContainingHeight = height
		got, err := Validate(in)
		if err != nil {
			t.Fatalf("height %d: %v", height, err)
		}
		if got.PreviousRevision != 1 || got.SuccessorRevision != 2 || got.FromHeight != 905 || got.LastContainingHeight != 1000 || got.Slot != 0 || got.TransactionID == ([32]byte{}) {
			t.Fatalf("wrong record: %+v", got)
		}
	}
	in := f.in
	in.ContainingHeight = 904
	errorHas(t, in, "Q4_OVERLAP")
	in.ContainingHeight = 1001
	errorHas(t, in, "Q4_OVERLAP")
}
func TestTamperedAndReSignedBoundaryCases(t *testing.T) {
	f := newFixture()
	in := f.in
	in.RenewalTransaction = bytes.Clone(in.RenewalTransaction)
	in.RenewalTransaction[1123] ^= 1
	errorHas(t, in, "REQUESTER_SIGNATURE")
	in = f.in
	in.RenewalTransaction = bytes.Clone(in.RenewalTransaction)
	in.RenewalTransaction[1122] ^= 1
	f.in = in
	f.signPacket()
	errorHas(t, f.in, "SOURCE_SIGNATURE")
	f = newFixture()
	f.in.OldSourceStatement = bytes.Clone(f.in.OldSourceStatement)
	f.in.OldSourceStatement[620] ^= 1
	errorHas(t, f.in, "SOURCE_SIGNATURE")
	f = newFixture()
	f.in.RenewalTransaction = bytes.Clone(f.in.RenewalTransaction)
	f.in.RenewalTransaction[92] = 21
	f.signPacket()
	errorHas(t, f.in, "ENVELOPE")
	f = newFixture()
	f.in.RenewalTransaction = bytes.Clone(f.in.RenewalTransaction)
	putU64(f.in.RenewalTransaction[68:76], 0)
	f.signPacket()
	errorHas(t, f.in, "ENVELOPE")
	f = newFixture()
	f.in.RenewalTransaction = bytes.Clone(f.in.RenewalTransaction)
	putU64(f.in.RenewalTransaction[76:84], 904)
	f.signPacket()
	errorHas(t, f.in, "EXPIRED_TRANSACTION")
	f = newFixture()
	f.in.RenewalTransaction = bytes.Clone(f.in.RenewalTransaction)
	binary.LittleEndian.PutUint16(f.in.RenewalTransaction[93:95], 1027)
	f.signPacket()
	errorHas(t, f.in, "ENVELOPE")
}
func TestIndependentlyResignedMaliciousSuccessors(t *testing.T) {
	// The attacker here has access to BOTH development signing keys, so the
	// checks demonstrate semantic enforcement, not just signature failures.
	cases := []struct {
		name   string
		modify func(*fixture, []byte, []byte)
	}{
		{"source-replaced", func(f *fixture, l, m []byte) { copy(l[136:168], fixedKey("OTHER_SOURCE").Public().(ed25519.PublicKey)) }},
		{"regressed-sequence", func(f *fixture, l, m []byte) { putU64(m[532:540], 1) }},
		{"wrong-model", func(f *fixture, l, m []byte) {
			wrong := label("new-model")
			copy(m[12+6*32:12+7*32], wrong[:])
			layer := hash("qualified-task-layer-v1", wrong[:], []byte("entire-row-major-field-layer-64x64"))
			copy(m[12+7*32:12+8*32], layer[:])
			meter := hash("qualified-task-output-meter-v1", m[12:44], m[44:76], m[12+4*32:12+5*32], wrong[:], layer[:], m[12+8*32:12+9*32], m[12+9*32:12+10*32], m[12+10*32:12+11*32])
			copy(m[12+15*32:12+16*32], meter[:])
		}},
		{"late-start", func(f *fixture, l, m []byte) {
			putU64(l[312:320], 1001)
			putU64(l[320:328], 1500)
			putU64(l[328:336], 1600)
		}},
		{"backward-revision", func(f *fixture, l, m []byte) { putU64(l[304:312], 1) }},
		{"unfunded-retention", func(f *fixture, l, m []byte) { putU64(l[328:336], 1401) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			old := f.in.OldLease
			raw := f.in.RenewalTransaction
			next := bytes.Clone(raw[95 : 95+LeaseBytes])
			newModel := label("model-fixture")
			m := f.manifest(next, 2, newModel)
			tc.modify(&f, next, m)
			// Rebuild every secondary lease-derived digest AFTER a legal change,
			// except when testing deliberate inconsistency.
			if _, err := parseLease(next); err == nil {
				m = f.manifest(next, 2, newModel)
				if tc.name == "regressed-sequence" {
					putU64(m[532:540], 1)
				}
				if tc.name == "wrong-model" {
					tc.modify(&f, next, m)
				}
			}
			_ = old
			copy(raw[95:95+LeaseBytes], next)
			statement := make([]byte, StatementBytes)
			copy(statement[:4], "QWA2")
			lid := hash("qualified-demand-lease-v2", next)
			copy(statement[4:36], lid[:])
			copy(statement[36:620], m)
			msg := hash("qualified-task-source-sign-v2", statement[:620])
			copy(statement[620:], ed25519.Sign(f.src, msg[:]))
			copy(raw[95+LeaseBytes:1123], statement)
			f.signPacket()
			if _, err := Validate(f.in); err == nil {
				t.Fatal("semantically invalid fully re-signed renewal accepted")
			}
		})
	}
}
func TestNoAuthorityFromUnavailableOrChangedContext(t *testing.T) {
	f := newFixture()
	in := f.in
	in.Network = label("foreign network")
	errorHas(t, in, "CONTEXT")
	in = f.in
	in.Parameters = label("foreign params")
	errorHas(t, in, "CONTEXT")
	in = f.in
	in.OldLease = in.OldLease[:LeaseBytes-1]
	errorHas(t, in, "LENGTH")
	in = f.in
	in.OldSourceStatement = in.OldSourceStatement[:StatementBytes-1]
	errorHas(t, in, "LENGTH")
	in = f.in
	in.RenewalTransaction = in.RenewalTransaction[:EnvelopeBytes-1]
	errorHas(t, in, "LENGTH")
	// Two signatures do NOT show that this caller pinned the actual parent
	// ledger nonce, source head, storage duties, or a real next block.
}

// When explicitly requested, output ONLY PUBLIC fixed-development test fixture
// bytes. Never include a real user's key or turn test bytes into authority.
func TestExportIndependentReferenceVector(t *testing.T) {
	dst := os.Getenv("TRNM_Q4_REFERENCE_VECTOR")
	if dst == "" {
		t.Skip("no explicit vector destination")
	}
	f := newFixture()
	vec := map[string]any{
		"network":              hex.EncodeToString(f.in.Network[:]),
		"parameters":           hex.EncodeToString(f.in.Parameters[:]),
		"old_lease":            hex.EncodeToString(f.in.OldLease),
		"old_source_statement": hex.EncodeToString(f.in.OldSourceStatement),
		"signed_transaction":   hex.EncodeToString(f.in.RenewalTransaction),
		"containing_height":    f.in.ContainingHeight,
	}
	b, err := json.Marshal(vec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(dst, append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedBytesCannotPanicOrBecomeAuthority(t *testing.T) {
	original := newFixture().in
	random := rand.New(rand.NewSource(20261026))
	for n := 0; n < 1024; n++ {
		in := original
		tx := bytes.Clone(original.RenewalTransaction)
		// Both malformed-wire and intact-length mutated payloads must refuse.
		if n%11 == 0 {
			tx = tx[:random.Intn(len(tx))]
		} else {
			for j := 0; j < 1+n%4; j++ {
				idx := random.Intn(len(tx))
				tx[idx] ^= 1 << uint(random.Intn(8))
			}
		}
		in.RenewalTransaction = tx
		if _, err := Validate(in); err == nil {
			t.Fatalf("altered packet %d incorrectly validated", n)
		}
	}
}
func TestPublishedDevelopmentVectorDigestsMatchExpectedByteCommitments(t *testing.T) {
	in := newFixture().in
	got, err := Validate(in)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.TransactionID[:]) != "133e6e6588018bdb8cc5888cd35e9daa5202fdcaa1e458951b3ecb3dd2ee3233" {
		t.Fatal("unexpected tx wire digest")
	}
	if hex.EncodeToString(got.LeaseID[:]) != "bbb982203bb12668be298fcae53ec89f1600098da691133d7a068d931af2f880" {
		t.Fatal("unexpected successor lease digest")
	}
	if hex.EncodeToString(got.SourceStatementID[:]) != "6566c9ed51e887d5f0e3ac0cb32bb95141f71ae873ffc1c2456b2b50607991b0" {
		t.Fatal("unexpected QWA2 statement digest")
	}
}

func TestExactNativeCanonicalPointPrecheck(t *testing.T) {
	p := bytes.Repeat([]byte{255}, 32)
	p[0] = 237
	p[31] = 127
	if canonicalPoint(p) {
		t.Fatal("y==prime accepted")
	}
	negativeOne := bytes.Clone(p)
	negativeOne[0]--
	negativeOne[31] |= 0x80
	if canonicalPoint(negativeOne) {
		t.Fatal("negative signed -1 representation accepted")
	}
	negativeIdentity := make([]byte, 32)
	negativeIdentity[0] = 1
	negativeIdentity[31] = 0x80
	if canonicalPoint(negativeIdentity) {
		t.Fatal("negative identity accepted")
	}
	good := newFixture()
	pub := good.req.Public().(ed25519.PublicKey)
	if !canonicalPoint(pub) {
		t.Fatal("real fixture key rejected")
	}
	signature := good.in.RenewalTransaction[1123:]
	if !canonicalPoint(signature[:32]) {
		t.Fatal("real signed R rejected")
	}
	digest := hash("tx-sign", good.in.RenewalTransaction[:1123])
	if !sigOK(pub, signature, digest) {
		t.Fatal("canonical real signature rejected")
	}
	bad := bytes.Clone(signature)
	copy(bad[:32], p)
	if sigOK(pub, bad, digest) {
		t.Fatal("noncanonical R accepted")
	}
}
