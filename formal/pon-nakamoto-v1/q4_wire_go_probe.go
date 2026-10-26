// Independent research-only Go verifier of the unchanged 1,187-byte Q4 tag22
// dual-Ed25519 wire. No PoN Node, consensus, signing, mining or owner authority.
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

const PacketSize = 1187

// Hash framing follows native trnm_protocol::pon_wire::hash.
func domainHash(tag string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("TRNM-PON1\x00"))
	var s [4]byte
	binary.LittleEndian.PutUint16(s[:2], uint16(len(tag)))
	h.Write(s[:2])
	h.Write([]byte(tag))
	for _, p := range parts {
		binary.LittleEndian.PutUint32(s[:], uint32(len(p)))
		h.Write(s[:])
		h.Write(p)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

type Fixture struct {
	Signed      string `json:"signed_tag22_pnx1_hex"`
	Old         string `json:"old_lease_qdl2_hex"`
	Requester   string `json:"requester_public_key"`
	Source      string `json:"source_public_key"`
	Network     string `json:"fixture_network"`
	Parameters  string `json:"fixture_parameters"`
	TxID        string `json:"expected_tx_id"`
	OldID       string `json:"expected_old_lease_id"`
	NextID      string `json:"expected_successor_lease_id"`
	StatementID string `json:"expected_source_statement_id"`
}

type Verified struct {
	TxID         string `json:"tx_id"`
	OldID        string `json:"old_lease"`
	NextID       string `json:"next_lease"`
	StatementID  string `json:"source_statement"`
	Height       uint64 `json:"height"`
	ResearchOnly bool   `json:"research_only"`
}

func fromHex(s string, length int) ([]byte, error) {
	if len(s) != length*2 {
		return nil, errors.New("hex size")
	}
	data, err := hex.DecodeString(s)
	if err != nil || len(data) != length {
		return nil, errors.New("hex format")
	}
	return data, nil
}

// Verify performs exact original bytes and signature checks. It DOES NOT know
// whether the separately supplied old lease was really active in parent State.
func Verify(f Fixture, h uint64) (Verified, error) {
	refuse := func(msg string) (Verified, error) { return Verified{}, errors.New(msg) }
	raw, e := fromHex(f.Signed, PacketSize)
	if e != nil {
		return refuse("packet")
	}
	old, e := fromHex(f.Old, 344)
	if e != nil {
		return refuse("old lease")
	}
	requester, e := fromHex(f.Requester, 32)
	if e != nil {
		return refuse("requester")
	}
	source, e := fromHex(f.Source, 32)
	if e != nil {
		return refuse("source")
	}
	network, e := fromHex(f.Network, 32)
	if e != nil {
		return refuse("network")
	}
	parameters, e := fromHex(f.Parameters, 32)
	if e != nil {
		return refuse("parameters")
	}
	if string(raw[:4]) != "PNX1" || string(old[:6]) != "QDL2\x02\x00" {
		return refuse("wire version")
	}
	if string(raw[4:36]) != string(network) || string(raw[36:68]) != string(requester) {
		return refuse("network/requester")
	}
	if binary.LittleEndian.Uint64(raw[68:76]) != 4 || binary.LittleEndian.Uint64(raw[76:84]) < h || raw[92] != 22 || binary.LittleEndian.Uint16(raw[93:95]) != 1028 {
		return refuse("outer context")
	}
	next := raw[95:439]
	if string(next[:6]) != "QDL2\x02\x00" || old[6] != next[6] || old[7] != next[7] {
		return refuse("lease version/slot")
	}
	if old[6] >= 32 || string(next[8:72]) != string(old[8:72]) || string(next[72:296]) != string(old[72:296]) {
		return refuse("lease immutable")
	}
	if string(next[104:136]) != string(requester) || string(next[136:168]) != string(source) {
		return refuse("lease signers")
	}
	if old[336] != 1 || next[336] != 1 || string(old[337:]) != string(make([]byte, 7)) || string(next[337:]) != string(make([]byte, 7)) {
		return refuse("lease flags")
	}
	genOld := binary.LittleEndian.Uint64(old[296:304])
	genNew := binary.LittleEndian.Uint64(next[296:304])
	revOld := binary.LittleEndian.Uint64(old[304:312])
	revNew := binary.LittleEndian.Uint64(next[304:312])
	firstOld := binary.LittleEndian.Uint64(old[312:320])
	firstNew := binary.LittleEndian.Uint64(next[312:320])
	expiresOld := binary.LittleEndian.Uint64(old[320:328])
	expiresNew := binary.LittleEndian.Uint64(next[320:328])
	availableOld := binary.LittleEndian.Uint64(old[328:336])
	availableNew := binary.LittleEndian.Uint64(next[328:336])
	if genOld == 0 || genOld != genNew || revOld == 0 || revOld == ^uint64(0) || revNew != revOld+1 || expiresOld <= firstOld || expiresOld-firstOld > 1000 || expiresOld > ^uint64(0)-100 || availableOld != expiresOld+100 {
		return refuse("old lease")
	}
	if !(firstOld <= firstNew && firstNew <= h && h <= expiresOld && expiresNew > expiresOld) || expiresNew <= firstNew || expiresNew-firstNew > 1000 || expiresNew > ^uint64(0)-100 || availableNew != expiresNew+100 {
		return refuse("overlap")
	}
	var leGen [8]byte
	binary.LittleEndian.PutUint64(leGen[:], genOld)
	demand := domainHash("qualified-demand-id-v2", network, parameters, requester, leGen[:])
	if string(demand[:]) != string(old[72:104]) {
		return refuse("demand identity")
	}
	previousID := domainHash("qualified-demand-lease-v2", old)
	nextID := domainHash("qualified-demand-lease-v2", next)
	unsigned := raw[439:1059]
	if string(unsigned[:4]) != "QWA2" || string(unsigned[4:36]) != string(nextID[:]) || string(unsigned[36:42]) != "QWT1\x01\x00" {
		return refuse("source statement")
	}
	if !ed25519.Verify(ed25519.PublicKey(source), domainHashBytes("qualified-task-source-sign-v2", unsigned), raw[1059:1123]) {
		return refuse("source signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(requester), domainHashBytes("tx-sign", raw[:1123]), raw[1123:]) {
		return refuse("requester signature")
	}
	tx := domainHash("tx-id", raw)
	statement := domainHash("qualified-task-manifest-v2", unsigned)
	if hex.EncodeToString(tx[:]) != f.TxID || hex.EncodeToString(previousID[:]) != f.OldID || hex.EncodeToString(nextID[:]) != f.NextID || hex.EncodeToString(statement[:]) != f.StatementID {
		return refuse("frozen vector identity")
	}
	return Verified{hex.EncodeToString(tx[:]), hex.EncodeToString(previousID[:]), hex.EncodeToString(nextID[:]), hex.EncodeToString(statement[:]), h, true}, nil
}
func domainHashBytes(tag string, parts ...[]byte) []byte { h := domainHash(tag, parts...); return h[:] }

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run q4_wire_go_probe.go FROZEN_JSON")
		os.Exit(2)
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	var v Fixture
	if e = json.Unmarshal(raw, &v); e != nil {
		panic(e)
	}
	result, e := Verify(v, 900)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	encoded, e := json.Marshal(result)
	if e != nil {
		panic(e)
	}
	fmt.Println(string(encoded))
}
