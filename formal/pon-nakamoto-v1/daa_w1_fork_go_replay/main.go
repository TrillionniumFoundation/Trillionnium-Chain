// Independently coded W1 proof + work-difficulty replay for the research fork
// fixture. No consensus activation, signed Q4 source, native Node, or WAN claim.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
)

const (
	n                  = 64
	rank               = 8
	q           uint64 = 4294967291
	cells              = n * n
	proofBytes         = 4 + 3*cells*4 + 32
	start       uint64 = 1000000
	spacing     uint64 = 10
	reportLimit        = 24000000
)

type Hash [32]byte

var ErrProof = errors.New("W1 transcript or material invalid")

func H(tag string, parts ...[]byte) Hash {
	h := sha256.New()
	h.Write([]byte("TRNM-PON1\x00"))
	var b [4]byte
	binary.LittleEndian.PutUint16(b[:2], uint16(len(tag)))
	h.Write(b[:2])
	h.Write([]byte(tag))
	for _, p := range parts {
		binary.LittleEndian.PutUint32(b[:], uint32(len(p)))
		h.Write(b[:])
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}
func toBytes(x []uint32) []byte {
	out := make([]byte, 4*len(x))
	for i, v := range x {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out
}
func matrixMaterial() ([]uint32, []uint32) {
	a, b := make([]uint32, cells), make([]uint32, cells)
	for i := 0; i < cells; i++ {
		a[i] = uint32((13*i + 17) % 257)
		b[i] = uint32((29*i + 31) % 263)
	}
	return a, b
}
func product(a, b []uint32, rows, inner, cols int) []uint32 {
	out := make([]uint32, rows*cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			var s uint64
			for k := 0; k < inner; k++ {
				s = (s + uint64(a[i*inner+k])*uint64(b[k*cols+j])%q) % q
			}
			out[i*cols+j] = uint32(s)
		}
	}
	return out
}
func expand(ch Hash, label byte) ([]uint32, error) {
	out := make([]uint32, 0, n*rank)
	for counter := uint32(0); len(out) < n*rank; counter++ {
		if counter >= 128 {
			return nil, ErrProof
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], counter)
		digest := H("noise", ch[:], []byte{label}, b[:])
		for k := 0; k < 32; k += 4 {
			v := binary.LittleEndian.Uint32(digest[k : k+4])
			if uint64(v) < q {
				out = append(out, v)
			}
		}
	}
	return out[:n*rank], nil
}
func evaluate(ch Hash, a, b []uint32) ([]uint32, Hash, error) {
	if len(a) != cells || len(b) != cells {
		return nil, Hash{}, ErrProof
	}
	for _, v := range append(append([]uint32{}, a...), b...) {
		if uint64(v) >= q {
			return nil, Hash{}, ErrProof
		}
	}
	el, e := expand(ch, 0)
	if e != nil {
		return nil, Hash{}, e
	}
	er, e := expand(ch, 1)
	if e != nil {
		return nil, Hash{}, e
	}
	fl, e := expand(ch, 2)
	if e != nil {
		return nil, Hash{}, e
	}
	fr, e := expand(ch, 3)
	if e != nil {
		return nil, Hash{}, e
	}
	aa, bb := make([]uint32, cells), make([]uint32, cells)
	eprod := product(el, er, n, rank, n)
	fprod := product(fl, fr, n, rank, n)
	for i := 0; i < cells; i++ {
		aa[i] = uint32((uint64(a[i]) + uint64(eprod[i])) % q)
		bb[i] = uint32((uint64(b[i]) + uint64(fprod[i])) % q)
	}
	accum := make([]uint32, cells)
	hasher := sha256.New()
	hasher.Write([]byte("TRNM-PON-TRACE1\x00"))
	hasher.Write(ch[:])
	var cell [4]byte
	for i0 := 0; i0 < n; i0 += rank {
		for j0 := 0; j0 < n; j0 += rank {
			for k0 := 0; k0 < n; k0 += rank {
				for i := i0; i < i0+rank; i++ {
					for j := j0; j < j0+rank; j++ {
						idx := i*n + j
						s := uint64(accum[idx])
						for k := k0; k < k0+rank; k++ {
							s = (s + uint64(aa[i*n+k])*uint64(bb[k*n+j])%q) % q
						}
						accum[idx] = uint32(s)
						binary.LittleEndian.PutUint32(cell[:], accum[idx])
						hasher.Write(cell[:])
					}
				}
			}
		}
	}
	c1 := product(product(a, fl, n, n, rank), fr, n, rank, n)
	c2 := product(el, product(er, bb, rank, n, n), n, rank, n)
	actual := make([]uint32, cells)
	for i := 0; i < cells; i++ {
		actual[i] = uint32((uint64(accum[i]) + 2*q - uint64(c1[i]) - uint64(c2[i])) % q)
	}
	var trace Hash
	copy(trace[:], hasher.Sum(nil))
	return actual, trace, nil
}
func prove(ch Hash, a, b []uint32) ([]byte, error) {
	prod, trace, e := evaluate(ch, a, b)
	if e != nil {
		return nil, e
	}
	proof := make([]byte, 0, proofBytes)
	proof = append(proof, []byte("PNW1")...)
	proof = append(proof, toBytes(a)...)
	proof = append(proof, toBytes(b)...)
	proof = append(proof, toBytes(prod)...)
	proof = append(proof, trace[:]...)
	if len(proof) != proofBytes {
		panic("internal proof size")
	}
	return proof, nil
}
func verifyW1(ch, task, target Hash, raw []byte) error {
	if len(raw) != proofBytes || string(raw[:4]) != "PNW1" {
		return ErrProof
	}
	a, b, claimed := make([]uint32, cells), make([]uint32, cells), make([]uint32, cells)
	for i := 0; i < 3*cells; i++ {
		v := binary.LittleEndian.Uint32(raw[4+i*4 : 8+i*4])
		if uint64(v) >= q {
			return ErrProof
		}
		switch {
		case i < cells:
			a[i] = v
		case i < 2*cells:
			b[i-cells] = v
		default:
			claimed[i-2*cells] = v
		}
	}
	if H("task", toBytes(a), toBytes(b)) != task {
		return ErrProof
	}
	ticket := H("ticket", ch[:], raw[len(raw)-32:])
	if bytes.Compare(ticket[:], target[:]) > 0 || target == (Hash{}) {
		return ErrProof
	}
	prod, trace, e := evaluate(ch, a, b)
	if e != nil {
		return e
	}
	if !bytes.Equal(trace[:], raw[len(raw)-32:]) {
		return ErrProof
	}
	for i := 0; i < cells; i++ {
		if prod[i] != claimed[i] {
			return ErrProof
		}
	}
	return nil
}
func unpackHash(raw string) (Hash, error) {
	var out Hash
	if len(raw) != 64 {
		return out, errors.New("noncanonical hash length")
	}
	v, e := hex.DecodeString(raw)
	if e != nil || hex.EncodeToString(v) != raw {
		return out, errors.New("noncanonical hash hex")
	}
	copy(out[:], v)
	return out, nil
}
func beInt(h Hash) *big.Int { return new(big.Int).SetBytes(h[:]) }
func beHash(v *big.Int) (Hash, error) {
	var out Hash
	if v.Sign() <= 0 || v.BitLen() > 256 {
		return out, errors.New("invalid target")
	}
	copy(out[32-len(v.Bytes()):], v.Bytes())
	return out, nil
}
func requiredWork(v *big.Int) *big.Int {
	top := new(big.Int).Lsh(big.NewInt(1), 256)
	return top.Div(top, new(big.Int).Add(new(big.Int).Set(v), big.NewInt(1)))
}
func median(times []uint64) uint64 {
	temp := append([]uint64{}, times...)
	sort.Slice(temp, func(i, j int) bool { return temp[i] < temp[j] })
	if len(temp) > 11 {
		temp = temp[:11]
	}
	return temp[len(temp)/2]
}

type Frame struct {
	Phase          string `json:"phase"`
	Now            uint64 `json:"now"`
	Header         string `json:"header"`
	Proof          string `json:"proof"`
	BlockID        string `json:"block_id"`
	Attempts       int    `json:"attempts"`
	Selection      string `json:"selection"`
	OptionalSource bool   `json:"optional_source_available"`
}
type Campaign struct {
	Schema  string                 `json:"schema"`
	Context map[string]interface{} `json:"context"`
	Events  []Frame                `json:"events"`
	Summary map[string]interface{} `json:"summary"`
}
type ChainBlock struct {
	ID     Hash
	Parent Hash
	Height uint64
	Time   uint64
	Target *big.Int
	Work   *big.Int
}
type Verifier struct {
	Rows              map[Hash]ChainBlock
	TipA              Hash
	TipB              Hash
	Winners, Attempts int
}

func newVerifier() *Verifier {
	genesis := H("w1-fork-research-genesis-v1", []byte("nonactivated"))
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	initial := new(big.Int).Rsh(new(big.Int).Set(maximum), 1)
	v := &Verifier{Rows: map[Hash]ChainBlock{}, TipA: genesis, TipB: genesis}
	v.Rows[genesis] = ChainBlock{ID: genesis, Height: 0, Time: start, Target: initial, Work: big.NewInt(0)}
	return v
}
func (v *Verifier) ancestry(tip Hash) ([]ChainBlock, error) {
	rows := []ChainBlock{}
	for i := 0; i <= 192; i++ {
		h, ok := v.Rows[tip]
		if !ok {
			return nil, errors.New("missing parent")
		}
		rows = append(rows, h)
		if h.Height == 0 {
			return rows, nil
		}
		tip = h.Parent
	}
	return nil, errors.New("ancestry budget")
}
func (v *Verifier) target(parent Hash) (*big.Int, error) {
	rows, e := v.ancestry(parent)
	if e != nil {
		return nil, e
	}
	h := rows[0].Height + 1
	if h%16 != 0 {
		return new(big.Int).Set(rows[0].Target), nil
	}
	if len(rows) < 16 {
		return nil, errors.New("retarget ancestry missing")
	}
	observed := uint64(1)
	if rows[0].Time > rows[15].Time {
		observed = rows[0].Time - rows[15].Time
	}
	if observed < 38 {
		observed = 38
	}
	if observed > 600 {
		observed = 600
	}
	result := new(big.Int).Mul(rows[0].Target, new(big.Int).SetUint64(observed))
	result.Div(result, big.NewInt(150))
	if result.Sign() == 0 {
		result = big.NewInt(1)
	}
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	if result.Cmp(maximum) > 0 {
		result = maximum
	}
	return result, nil
}
func (v *Verifier) readFrame(ev Frame, strict bool) error {
	if ev.Phase != "shared" && ev.Phase != "A" && ev.Phase != "B" {
		return errors.New("phase")
	}
	if ev.Selection != "genesis-maintenance" || ev.OptionalSource != (ev.Phase == "shared") {
		return errors.New("lease or hidden fallback")
	}
	if ev.Attempts < 1 || ev.Attempts > 128 {
		return errors.New("attempt bound")
	}
	raw, e := hex.DecodeString(ev.Header)
	if e != nil || hex.EncodeToString(raw) != ev.Header || len(raw) != 318 {
		return errors.New("header wire")
	}
	proof, e := base64.StdEncoding.DecodeString(ev.Proof)
	if e != nil || base64.StdEncoding.EncodeToString(proof) != ev.Proof || len(proof) != proofBytes {
		return errors.New("proof wire")
	}
	if string(raw[:6]) != "PNH1\x01\x00" {
		return errors.New("header version")
	}
	minerName := []byte("A")
	if ev.Phase == "B" {
		minerName = []byte("B")
	}
	minerID := H("research-miner", minerName)
	if !bytes.Equal(raw[150:182], minerID[:]) {
		return errors.New("miner identity")
	}
	network := H("w1-fork-research-network-v1", []byte("nonactivated"))
	parameters := H("w1-fork-research-parameters-v1", []byte("nonactivated"))
	genesis := H("w1-fork-research-genesis-v1", []byte("nonactivated"))
	taskA, taskB := matrixMaterial()
	task := H("task", toBytes(taskA), toBytes(taskB))
	if !bytes.Equal(raw[6:38], network[:]) || !bytes.Equal(raw[38:70], parameters[:]) || !bytes.Equal(raw[278:310], task[:]) {
		return errors.New("network/parameter/task")
	}
	if !bytes.Equal(raw[182:214], HBytes("research-empty-transactions", []byte("not-M06"))) ||
		!bytes.Equal(raw[246:278], HBytes("research-empty-receipts", []byte("not-M06"))) {
		return errors.New("synthetic root binding")
	}
	var parent Hash
	copy(parent[:], raw[70:102])
	expectedParent := v.TipA
	if ev.Phase == "B" {
		expectedParent = v.TipB
	}
	if parent != expectedParent {
		return errors.New("fork parent")
	}
	height := binary.LittleEndian.Uint64(raw[102:110])
	stamp := binary.LittleEndian.Uint64(raw[110:118])
	ancestry, e := v.ancestry(parent)
	if e != nil {
		return e
	}
	if height != ancestry[0].Height+1 {
		return errors.New("height")
	}
	if !bytes.Equal(raw[214:246], HBytes("research-state-not-M06", parent[:], raw[102:110])) {
		return errors.New("research state binding")
	}
	if binary.LittleEndian.Uint64(raw[310:318]) != uint64(ev.Attempts-1) {
		return errors.New("attempt/nonce")
	}
	exp, e := v.target(parent)
	if e != nil {
		return e
	}
	var target Hash
	copy(target[:], raw[118:150])
	if exp.Cmp(beInt(target)) != 0 {
		return errors.New("expected target")
	}
	times := make([]uint64, 0, 11)
	for i := 0; i < len(ancestry) && i < 11; i++ {
		times = append(times, ancestry[i].Time)
	}
	if stamp <= median(times) || stamp > ev.Now && stamp-ev.Now > 120 {
		return errors.New("timestamp")
	}
	ch := H("challenge", raw)
	if e := verifyW1(ch, task, target, proof); e != nil {
		return e
	}
	if strict {
		for nonce := 0; nonce < ev.Attempts; nonce++ {
			alternate := append([]byte{}, raw...)
			binary.LittleEndian.PutUint64(alternate[310:318], uint64(nonce))
			attemptChallenge := H("challenge", alternate)
			computed, e := prove(attemptChallenge, taskA, taskB)
			if e != nil {
				return e
			}
			digest := H("ticket", attemptChallenge[:], computed[len(computed)-32:])
			winner := bytes.Compare(digest[:], target[:]) <= 0
			if nonce == ev.Attempts-1 {
				if !winner || !bytes.Equal(computed, proof) {
					return errors.New("winning transcript mismatch")
				}
			}
			if nonce < ev.Attempts-1 && winner {
				return errors.New("hidden earlier W1 winner")
			}
		}
	}
	id := H("block", raw, proof[len(proof)-32:])
	if hex.EncodeToString(id[:]) != ev.BlockID {
		return errors.New("block id")
	}
	if _, ok := v.Rows[id]; ok {
		return errors.New("duplicate block")
	}
	chain := new(big.Int).Add(ancestry[0].Work, requiredWork(exp))
	v.Rows[id] = ChainBlock{ID: id, Parent: parent, Height: height, Time: stamp, Target: exp, Work: chain}
	if ev.Phase == "shared" {
		v.TipA = id
		v.TipB = id
	} else if ev.Phase == "A" {
		v.TipA = id
	} else {
		v.TipB = id
	}
	v.Winners++
	v.Attempts += ev.Attempts
	if parent == genesis && height != 1 {
		return errors.New("genesis height")
	}
	return nil
}
func HBytes(tag string, parts ...[]byte) []byte { h := H(tag, parts...); return h[:] }
func (v *Verifier) orphanCount(old, selected Hash) (int, error) {
	good, e := v.ancestry(selected)
	if e != nil {
		return 0, e
	}
	seen := map[Hash]bool{}
	for _, x := range good {
		seen[x.ID] = true
	}
	oldpath, e := v.ancestry(old)
	if e != nil {
		return 0, e
	}
	n := 0
	for _, x := range oldpath {
		if !seen[x.ID] {
			n++
		}
	}
	return n, nil
}
func check(path string, strict bool) error {
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(raw) > reportLimit {
		return errors.New("report too large")
	}
	var report Campaign
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&report); e != nil {
		return e
	}
	if report.Schema != "trnm-research-actual-w1-fork-outage-v1" || len(report.Events) < 17 || len(report.Events) > 192 {
		return errors.New("report schema/size")
	}
	state := newVerifier()
	a, b := 0, 0
	outage := false
	for i, ev := range report.Events {
		if ev.Phase != "shared" {
			outage = true
		} else if outage {
			return fmt.Errorf("event %d: false recovery", i)
		}
		if err := state.readFrame(ev, strict); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		if ev.Phase == "A" {
			a++
		}
		if ev.Phase == "B" {
			b++
		}
	}
	if a == 0 || b == 0 {
		return errors.New("no fork")
	}
	left, right := state.TipA, state.TipB
	selected := left
	if state.Rows[right].Work.Cmp(state.Rows[left].Work) > 0 {
		selected = right
	}
	summary := report.Summary
	if summary["real_w1_winning_proofs"] != float64(state.Winners) || summary["real_w1_prover_attempts"] != float64(state.Attempts) ||
		summary["real_lease_signatures"] != float64(0) || summary["native_w1_proofs"] != float64(0) || summary["native_consensus_activation"] != false ||
		summary["healed_tip"] != hex.EncodeToString(selected[:]) || summary["before_heal_a"] != hex.EncodeToString(left[:]) || summary["before_heal_b"] != hex.EncodeToString(right[:]) {
		return errors.New("summary authority or chainwork mismatch")
	}
	removedA, e := state.orphanCount(left, selected)
	if e != nil {
		return e
	}
	removedB, e := state.orphanCount(right, selected)
	if e != nil {
		return e
	}
	if summary["reorg_removed_on_a"] != float64(removedA) || summary["reorg_removed_on_b"] != float64(removedB) {
		return errors.New("reorg mismatch")
	}
	digest := sha256.Sum256(raw)
	fmt.Printf("{\"verifier\":\"independent-go-reference\",\"w1_winners\":%d,\"strict_search_attempts\":%d,\"reorg_a\":%d,\"reorg_b\":%d,\"sha256\":\"%x\",\"consensus_activated\":false}\n", state.Winners, state.Attempts, removedA, removedB, digest)
	return nil
}
func main() {
	path := flag.String("verify", "", "bounded existing JSON evidence file")
	strict := flag.Bool("strict-search", false, "recompute every failed and winning W1 attempt")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "required --verify")
		os.Exit(2)
	}
	if e := check(*path, *strict); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
