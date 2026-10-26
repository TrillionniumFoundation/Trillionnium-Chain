// A separately coded Q4 cryptographic research reader, not consensus authority.
// Usage: go run verify_q4_vectors.go q4_signed_vectors.json
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Entry struct {
	Name string `json:"name"`
	Raw  string `json:"raw"`
}
type Expected struct {
	Tx        string `json:"tx_id"`
	New       string `json:"new_lease_id"`
	Old       string `json:"old_lease_id"`
	Source    string `json:"source_key"`
	Requester string `json:"requester_key"`
}
type TestVector struct {
	Schema            string   `json:"schema"`
	Raw               string   `json:"raw"`
	OldLease          string   `json:"old_lease"`
	Network           string   `json:"network"`
	Params            string   `json:"parameters"`
	Height            uint64   `json:"containing_height"`
	OldSourceSequence uint64   `json:"old_source_sequence"`
	RequesterSequence uint64   `json:"requester_sequence"`
	Expected          Expected `json:"expected"`
	Rejected          []Entry  `json:"rejected"`
}

func fail(name string) error { return errors.New(name) }
func hashPon(label string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("TRNM-PON1\000"))
	var s [4]byte
	binary.LittleEndian.PutUint16(s[:2], uint16(len(label)))
	h.Write(s[:2])
	h.Write([]byte(label))
	for _, p := range parts {
		binary.LittleEndian.PutUint32(s[:], uint32(len(p)))
		h.Write(s[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func decodeHex(x string) ([]byte, error) { return hex.DecodeString(x) }
func same(x []byte, h [32]byte) bool     { return eq(x, h[:]) }
func u64(raw []byte) uint64              { return binary.LittleEndian.Uint64(raw) }
func lease(raw []byte) ([32]byte, error) {
	var empty [32]byte
	if len(raw) != 344 || !eq(raw[:6], []byte{'Q', 'D', 'L', '2', 2, 0}) {
		return empty, fail("LEASE_GRAMMAR")
	}
	if raw[6] >= 32 || raw[7] < 1 || raw[7] > 4 || raw[336] != 1 || !eq(raw[337:], make([]byte, 7)) {
		return empty, fail("LEASE_BOUNDS")
	}
	if u64(raw[296:304]) == 0 || u64(raw[304:312]) == 0 || u64(raw[320:328]) <= u64(raw[312:320]) || u64(raw[320:328])-u64(raw[312:320]) > 1000 || u64(raw[320:328]) > ^uint64(0)-100 || u64(raw[328:336]) != u64(raw[320:328])+100 {
		return empty, fail("LEASE_WINDOW")
	}
	for i := 0; i < 9; i++ {
		if eq(raw[8+i*32:8+(i+1)*32], make([]byte, 32)) {
			return empty, fail("LEASE_HASH")
		}
	}
	if eq(raw[104:136], raw[136:168]) {
		return empty, fail("LEASE_SAME_OWNER")
	}
	gen := raw[296:304]
	demand := hashPon("qualified-demand-id-v2", raw[8:40], raw[40:72], raw[104:136], gen)
	if !same(raw[72:104], demand) {
		return empty, fail("LEASE_DEMAND")
	}
	return hashPon("qualified-demand-lease-v2", raw), nil
}
func verify(v TestVector, raw []byte) (Expected, error) {
	var blank Expected
	old, e := decodeHex(v.OldLease)
	if e != nil {
		return blank, e
	}
	net, e := decodeHex(v.Network)
	if e != nil {
		return blank, e
	}
	params, e := decodeHex(v.Params)
	if e != nil {
		return blank, e
	}
	oldid, e := lease(old)
	if e != nil {
		return blank, e
	}
	if len(raw) != 1187 {
		return blank, fail("PACKET_LENGTH")
	}
	if !eq(raw[:4], []byte("PNX1")) || !eq(raw[4:36], net) {
		return blank, fail("PACKET_NETWORK")
	}
	if raw[92] != 22 || binary.LittleEndian.Uint16(raw[93:95]) != 1028 {
		return blank, fail("PACKET_TAG")
	}
	if u64(raw[68:76]) != v.RequesterSequence || v.RequesterSequence == 0 || u64(raw[76:84]) < v.Height || u64(raw[84:92]) > 10_000_000 {
		return blank, fail("PACKET_SEQUENCE")
	}
	newRaw := raw[95:439]
	newid, e := lease(newRaw)
	if e != nil {
		return blank, e
	}
	if !eq(newRaw[8:72], old[8:72]) || !eq(newRaw[72:296], old[72:296]) || !eq(newRaw[296:304], old[296:304]) || u64(newRaw[304:312]) != u64(old[304:312])+1 || newRaw[6] != old[6] || newRaw[7] != old[7] || newRaw[336] != old[336] {
		return blank, fail("LEASE_IMMUTABILITY")
	}
	if !eq(newRaw[104:136], raw[36:68]) {
		return blank, fail("REQUESTER_MISMATCH")
	}
	start := u64(newRaw[312:320])
	exp := u64(newRaw[320:328])
	if !(u64(old[312:320]) <= start && start <= v.Height && v.Height <= u64(old[320:328]) && exp > u64(old[320:328])) {
		return blank, fail("LEASE_OVERLAP")
	}
	qwa := raw[439:1123]
	if !eq(qwa[:4], []byte("QWA2")) || !same(qwa[4:36], newid) {
		return blank, fail("SOURCE_LEASE_ID")
	}
	w := qwa[36:620]
	if !eq(w[:6], []byte{'Q', 'W', 'T', '1', 1, 0}) || !eq(w[6:12], []byte{newRaw[7], 1, 1, 0, 1, 0}) {
		return blank, fail("QWT_HEAD")
	}
	claim := func(i int) []byte { return w[12+32*i : 12+32*(i+1)] }
	if !eq(claim(0), net) || !eq(claim(1), params) || !eq(claim(3), newRaw[136:168]) || !eq(claim(4), newRaw[72:104]) || !eq(claim(11), newRaw[232:264]) || !eq(claim(12), newRaw[264:296]) || !eq(claim(13), newRaw[200:232]) {
		return blank, fail("QWT_CONTEXT")
	}
	wp := hashPon("qualified-task-profile-v1", []byte("pon-matmul-transcript-64-v1"))
	recipe := hashPon("qualified-task-recipe-v1", []byte("canonical-field-matrix64-product-v1"))
	if !same(claim(2), wp) || !same(claim(9), recipe) {
		return blank, fail("QWT_PROFILE")
	}
	layer := hashPon("qualified-task-layer-v1", claim(6), []byte("entire-row-major-field-layer-64x64"))
	if !same(claim(7), layer) {
		return blank, fail("QWT_LAYER")
	}
	src := hashPon("qualified-demand-source-record-v2", newid[:], newRaw[168:200])
	withdraw := hashPon("qualified-demand-frontier-v2", newid[:])
	if !same(claim(5), src) || !same(claim(14), withdraw) {
		return blank, fail("QWT_WITHDRAWAL")
	}
	meter := hashPon("qualified-task-output-meter-v1", net, params, claim(4), claim(6), claim(7), claim(8), claim(9), claim(10))
	if !same(claim(15), meter) {
		return blank, fail("QWT_METER")
	}
	if !eq(w[524:532], []byte{'@', 0, '@', 0, '@', 0, 0, 0}) {
		return blank, fail("QWT_SHAPE")
	}
	if v.OldSourceSequence == ^uint64(0) || u64(w[532:540]) != v.OldSourceSequence+1 || u64(w[540:548]) != start || u64(w[548:556]) != exp || u64(w[556:564]) != u64(newRaw[328:336]) || u64(w[564:572]) != 262144 {
		return blank, fail("QWT_SEQUENCE")
	}
	wantLimit := uint32(1)
	if newRaw[7] == 1 {
		wantLimit = 0
	}
	if binary.LittleEndian.Uint32(w[572:576]) != 16384 || binary.LittleEndian.Uint32(w[576:580]) != 16384 || binary.LittleEndian.Uint32(w[580:584]) != wantLimit {
		return blank, fail("QWT_LIMIT")
	}
	srcMessage := hashPon("qualified-task-source-sign-v2", qwa[:620])
	reqMessage := hashPon("tx-sign", raw[:1123])
	if !ed25519.Verify(ed25519.PublicKey(newRaw[136:168]), srcMessage[:], qwa[620:]) {
		return blank, fail("SOURCE_SIGNATURE")
	}
	if !ed25519.Verify(ed25519.PublicKey(raw[36:68]), reqMessage[:], raw[1123:]) {
		return blank, fail("REQUESTER_SIGNATURE")
	}
	txid := hashPon("tx-id", raw)
	return Expected{Tx: hex.EncodeToString(txid[:]), Old: hex.EncodeToString(oldid[:]), New: hex.EncodeToString(newid[:]), Source: hex.EncodeToString(newRaw[136:168]), Requester: hex.EncodeToString(raw[36:68])}, nil
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: go run verify_q4_vectors.go <json>")
	}
	content, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	var v TestVector
	if e = json.Unmarshal(content, &v); e != nil {
		panic(e)
	}
	b, e := decodeHex(v.Raw)
	if e != nil {
		panic(e)
	}
	got, e := verify(v, b)
	if e != nil {
		panic(e)
	}
	if got != v.Expected {
		panic(fmt.Sprintf("expected %+v, got %+v", v.Expected, got))
	}
	for _, test := range v.Rejected {
		b, e = decodeHex(test.Raw)
		if e != nil {
			panic(e)
		}
		if _, e = verify(v, b); e == nil {
			panic("accepted negative case: " + test.Name)
		}
	}
	fmt.Printf("PASS independently decoded dual-signed Q4 packet and %d negative mutations; no Node authority\n", len(v.Rejected))
}
