// Independently coded finite-field W1 work verifier and fork-time readback.
// Research-only: these are real PNW1 mathematics over SYNTHETIC application roots,
// not native Node admission, independent operators, or production-hardness proof.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
)

const (
	n                  = 64
	rank               = 8
	q           uint64 = 4294967291
	proofBytes         = 49188
	headerBytes        = 318
)

var one = big.NewInt(1)
var two256 = new(big.Int).Lsh(big.NewInt(1), 256)
var powLimit = new(big.Int).Sub(new(big.Int).Set(two256), one)
var initial = new(big.Int).Div(new(big.Int).Set(powLimit), big.NewInt(4))

type hash = [32]byte

func H(tag string, parts ...[]byte) hash {
	h := sha256.New()
	h.Write([]byte("TRNM-PON1\x00"))
	var le2 [2]byte
	binary.LittleEndian.PutUint16(le2[:], uint16(len(tag)))
	h.Write(le2[:])
	h.Write([]byte(tag))
	var le4 [4]byte
	for _, p := range parts {
		binary.LittleEndian.PutUint32(le4[:], uint32(len(p)))
		h.Write(le4[:])
		h.Write(p)
	}
	var out hash
	copy(out[:], h.Sum(nil))
	return out
}
func same(got []byte, want hash) bool { return bytes.Equal(got, want[:]) }
func u64le(v uint64) []byte           { var b [8]byte; binary.LittleEndian.PutUint64(b[:], v); return b[:] }
func median(times []uint64) (uint64, error) {
	if len(times) == 0 || len(times) > 11 {
		return 0, errors.New("MTP window")
	}
	x := append([]uint64(nil), times...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	return x[len(x)/2], nil
}
func targetWork(target *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Set(two256), new(big.Int).Add(new(big.Int).Set(target), one))
}
func mul(a, b []uint32, rows, inner, cols int) []uint32 {
	out := make([]uint32, rows*cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			var acc uint64
			for k := 0; k < inner; k++ {
				acc = (acc + uint64(a[i*inner+k])*uint64(b[k*cols+j])%q) % q
			}
			out[i*cols+j] = uint32(acc)
		}
	}
	return out
}
func add(a, b []uint32) []uint32 {
	r := make([]uint32, len(a))
	for i := range a {
		r[i] = uint32((uint64(a[i]) + uint64(b[i])) % q)
	}
	return r
}
func expand(challenge hash, label byte) ([]uint32, error) {
	out := make([]uint32, 0, n*rank)
	for k := uint32(0); k < 128 && len(out) < n*rank; k++ {
		var key [4]byte
		binary.LittleEndian.PutUint32(key[:], k)
		digest := H("noise", challenge[:], []byte{label}, key[:])
		for i := 0; i < 32 && len(out) < n*rank; i += 4 {
			v := binary.LittleEndian.Uint32(digest[i : i+4])
			if uint64(v) < q {
				out = append(out, v)
			}
		}
	}
	if len(out) != n*rank {
		return nil, errors.New("NOISE_BUDGET")
	}
	return out, nil
}
func decodeMatrix(b []byte) ([]uint32, error) {
	if len(b) != n*n*4 {
		return nil, errors.New("LENGTH")
	}
	v := make([]uint32, n*n)
	for i := range v {
		v[i] = binary.LittleEndian.Uint32(b[i*4 : i*4+4])
		if uint64(v[i]) >= q {
			return nil, errors.New("FIELD")
		}
	}
	return v, nil
}
func matSourceValid(a, b []uint32) bool {
	for i := 0; i < n*n; i++ {
		if a[i] != uint32((13*i+17)%257) || b[i] != uint32((29*i+31)%263) {
			return false
		}
	}
	return true
}
func ticketPrecheck(header, proof []byte) (hash, hash, error) {
	if len(header) != headerBytes || len(proof) != proofBytes {
		return hash{}, hash{}, errors.New("LENGTH")
	}
	if !bytes.Equal(header[:6], []byte("PNH1\x01\x00")) || !bytes.Equal(proof[:4], []byte("PNW1")) {
		return hash{}, hash{}, errors.New("VERSION")
	}
	a, b := proof[4:16388], proof[16388:32772]
	av, e := decodeMatrix(a)
	if e != nil {
		return hash{}, hash{}, e
	}
	bv, e := decodeMatrix(b)
	if e != nil {
		return hash{}, hash{}, e
	}
	if !matSourceValid(av, bv) {
		return hash{}, hash{}, errors.New("MAINTENANCE_MATERIAL")
	}
	if _, e = decodeMatrix(proof[32772:49156]); e != nil {
		return hash{}, hash{}, e
	}
	id := H("task", a, b)
	if !same(header[278:310], id) {
		return hash{}, hash{}, errors.New("TASK")
	}
	if bytes.Equal(header[118:150], make([]byte, 32)) {
		return hash{}, hash{}, errors.New("TARGET")
	}
	challenge := H("challenge", header)
	ticket := H("ticket", challenge[:], proof[49156:49188])
	if bytes.Compare(ticket[:], header[118:150]) > 0 {
		return hash{}, hash{}, errors.New("TARGET")
	}
	return challenge, ticket, nil
}
func fullVerify(header, proof []byte) (hash, hash, error) {
	challenge, ticket, e := ticketPrecheck(header, proof)
	if e != nil {
		return hash{}, hash{}, e
	}
	a, _ := decodeMatrix(proof[4:16388])
	b, _ := decodeMatrix(proof[16388:32772])
	c, _ := decodeMatrix(proof[32772:49156])
	noises := make([][]uint32, 4)
	for i := 0; i < 4; i++ {
		noises[i], e = expand(challenge, byte(i))
		if e != nil {
			return hash{}, hash{}, e
		}
	}
	el, er, fl, fr := noises[0], noises[1], noises[2], noises[3]
	aa := add(a, mul(el, er, n, rank, n))
	bb := add(b, mul(fl, fr, n, rank, n))
	cp := make([]uint32, n*n)
	tr := sha256.New()
	tr.Write(append([]byte("TRNM-PON-TRACE1\x00"), challenge[:]...))
	var little [4]byte
	for i0 := 0; i0 < n; i0 += rank {
		for j0 := 0; j0 < n; j0 += rank {
			for k0 := 0; k0 < n; k0 += rank {
				for i := i0; i < i0+rank; i++ {
					for j := j0; j < j0+rank; j++ {
						pos := i*n + j
						acc := uint64(cp[pos])
						for k := k0; k < k0+rank; k++ {
							acc = (acc + uint64(aa[i*n+k])*uint64(bb[k*n+j])%q) % q
						}
						cp[pos] = uint32(acc)
						binary.LittleEndian.PutUint32(little[:], cp[pos])
						tr.Write(little[:])
					}
				}
			}
		}
	}
	digest := tr.Sum(nil)
	if !bytes.Equal(digest, proof[49156:49188]) {
		return hash{}, hash{}, errors.New("TRANSCRIPT")
	}
	subtract1 := mul(mul(a, fl, n, n, rank), fr, n, rank, n)
	subtract2 := mul(el, mul(er, bb, rank, n, n), n, rank, n)
	for i := 0; i < n*n; i++ {
		expected := uint32((uint64(cp[i]) + 2*q - uint64(subtract1[i]) - uint64(subtract2[i])) % q)
		if expected != c[i] {
			return hash{}, hash{}, errors.New("PRODUCT")
		}
	}
	id := H("block", header, proof[49156:49188])
	return id, ticket, nil
}

type Receipt struct {
	Schema      string `json:"schema"`
	ProofCount  int    `json:"proof_count"`
	LogicalNow  uint64 `json:"logical_now"`
	ProofBytes  int    `json:"proof_bytes_per_packet"`
	Inventory   []Item `json:"proof_inventory"`
	HonestTip   Item   `json:"honest_tip"`
	EndpointTip Item   `json:"endpoint_push_tip"`
	Forged      struct {
		ValidWork string `json:"valid_chainwork_added"`
	} `json:"forged_false_trace"`
	Qualification struct {
		Native    bool `json:"native_Node_execution"`
		WAN       bool `json:"real_WAN"`
		Hardness  bool `json:"work_hardness_qualified"`
		Active    bool `json:"new_daa_activated"`
		Operators bool `json:"independent_operators"`
	} `json:"qualification"`
}
type Item struct {
	ID        string `json:"block_id"`
	Parent    string `json:"parent_id"`
	Height    uint64 `json:"height"`
	Timestamp uint64 `json:"timestamp"`
	Target    string `json:"target"`
	Ticket    string `json:"winning_ticket"`
	Digest    string `json:"proof_sha256"`
	Attempts  uint64 `json:"attempts_including_misses"`
	Chainwork string `json:"work_cumulative"`
}
type Block struct {
	Height    uint64
	Time      uint64
	Target    *big.Int
	Work      *big.Int
	Times     []uint64 // parent first for the future successor
	Ancestors []uint64 // genesis first through this block
}

func hex32(s string) (hash, error) {
	var h hash
	if len(s) != 64 {
		return h, errors.New("HEX")
	}
	x, e := hex.DecodeString(s)
	if e != nil || !bytes.Equal([]byte(s), []byte(hex.EncodeToString(x))) {
		return h, errors.New("HEX")
	}
	copy(h[:], x)
	return h, nil
}
func loadExact(path string, want int) ([]byte, error) {
	fi, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !fi.Mode().IsRegular() || fi.Size() != int64(want) {
		return nil, errors.New("MATERIAL_SIZE_OR_TYPE")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) != want {
		return nil, errors.New("MATERIAL_SIZE")
	}
	return b, nil
}
func validHeaderContext(header []byte, height uint64) bool {
	return same(header[6:38], H("research-network", []byte("maintenance-v12"))) &&
		same(header[38:70], H("research-parameters", []byte("proof-cost-no-activation"))) &&
		same(header[150:182], H("research-miner", []byte("operator0"))) &&
		same(header[182:214], H("research-nonexecuted-txs")) &&
		same(header[214:246], H("research-nonexecuted-state", u64le(height))) &&
		same(header[246:278], H("research-nonexecuted-receipts"))
}
func retarget(parent *big.Int, first, last uint64) *big.Int {
	observed := uint64(1)
	if last > first {
		observed = last - first
	}
	if observed < 38 {
		observed = 38
	}
	if observed > 600 {
		observed = 600
	}
	out := new(big.Int).Mul(parent, new(big.Int).SetUint64(observed))
	out.Div(out, big.NewInt(150))
	if out.Cmp(one) < 0 {
		out.Set(one)
	}
	if out.Cmp(powLimit) > 0 {
		out.Set(powLimit)
	}
	return out
}
func run(reportPath, dir string) (map[string]interface{}, error) {
	raw, e := loadCapped(reportPath, 100_000)
	if e != nil {
		return nil, e
	}
	var report Receipt
	if e = json.Unmarshal(raw, &report); e != nil {
		return nil, e
	}
	if report.Schema != "trnm-w1-maintenance-daa-real-proof-research-v1" || report.ProofCount != 31 || len(report.Inventory) != 31 || report.LogicalNow != 10000 || report.ProofBytes != proofBytes {
		return nil, errors.New("REPORT_SCOPE")
	}
	if report.Qualification.Native || report.Qualification.WAN || report.Qualification.Hardness || report.Qualification.Active || report.Qualification.Operators {
		return nil, errors.New("UNQUALIFIED_AUTHORITY")
	}
	rootID := H("genesis-maintenance-w1-daa-research-v1")
	known := map[hash]Block{rootID: {Height: 0, Time: 0, Target: new(big.Int).Set(initial), Work: big.NewInt(0), Times: []uint64{0}, Ancestors: []uint64{0}}}
	for _, item := range report.Inventory {
		expectedID, e := hex32(item.ID)
		if e != nil {
			return nil, e
		}
		pHeader, e := loadExact(filepath.Join(dir, item.ID+".pnh1"), headerBytes)
		if e != nil {
			return nil, e
		}
		pProof, e := loadExact(filepath.Join(dir, item.ID+".pnw1"), proofBytes)
		if e != nil {
			return nil, e
		}
		actualID, ticket, e := fullVerify(pHeader, pProof)
		if e != nil {
			return nil, e
		}
		claimedTicket, e := hex32(item.Ticket)
		if e != nil || actualID != expectedID || ticket != claimedTicket {
			return nil, errors.New("WORK_ID")
		}
		digest := sha256.Sum256(pProof)
		claimedDigest, e := hex32(item.Digest)
		if e != nil || digest != claimedDigest {
			return nil, errors.New("PROOF_DIGEST")
		}
		h := binary.LittleEndian.Uint64(pHeader[102:110])
		when := binary.LittleEndian.Uint64(pHeader[110:118])
		nonce := binary.LittleEndian.Uint64(pHeader[310:318])
		parentHash, e := hex32(item.Parent)
		if e != nil {
			return nil, errors.New("PARENT_HEX")
		}
		if !same(pHeader[70:102], parentHash) || h != item.Height || when != item.Timestamp || nonce+1 != item.Attempts {
			return nil, errors.New("REPORT_IDENTITY")
		}
		parent, ok := known[parentHash]
		if !ok || h != parent.Height+1 {
			return nil, errors.New("MISSING_PARENT")
		}
		if !validHeaderContext(pHeader, h) {
			return nil, errors.New("SYNTHETIC_CONTEXT")
		}
		m, e := median(parent.Times)
		if e != nil || when <= m || when > report.LogicalNow+120 {
			return nil, errors.New("HEADER_TIME")
		}
		target := new(big.Int).Set(parent.Target)
		if h%16 == 0 {
			target = retarget(parent.Target, parent.Ancestors[h-16], parent.Time)
		}
		if !bytes.Equal(pHeader[118:150], target.FillBytes(make([]byte, 32))) || hex.EncodeToString(target.FillBytes(make([]byte, 32))) != item.Target {
			return nil, errors.New("DAA_TARGET")
		}
		work := new(big.Int).Add(parent.Work, targetWork(target))
		if work.String() != item.Chainwork {
			return nil, errors.New("CHAINWORK")
		}
		if _, found := known[expectedID]; found {
			return nil, errors.New("DUPLICATE_BLOCK")
		}
		ancestors := append(append([]uint64(nil), parent.Ancestors...), when)
		times := append([]uint64{when}, parent.Times...)
		if len(times) > 11 {
			times = times[:11]
		}
		known[expectedID] = Block{Height: h, Time: when, Target: target, Work: work, Times: times, Ancestors: ancestors}
	}
	honestID, e := hex32(report.HonestTip.ID)
	if e != nil {
		return nil, e
	}
	warpID, e := hex32(report.EndpointTip.ID)
	if e != nil {
		return nil, e
	}
	honest, ok1 := known[honestID]
	warp, ok2 := known[warpID]
	if !ok1 || !ok2 || honest.Height != 16 || warp.Height != 16 || honest.Time != 160 || warp.Time != 601 || honest.Work.Cmp(warp.Work) <= 0 {
		return nil, errors.New("TIP_FORK_CHOICE")
	}
	if honest.Target.Cmp(initial) != 0 || warp.Target.Cmp(new(big.Int).Mul(initial, big.NewInt(4))) != 0 {
		return nil, errors.New("DAA_FORK_VALUE")
	}
	invalidHeader, e := loadExact(filepath.Join(dir, "invalid-claimed-transcript.pnh1"), headerBytes)
	if e != nil {
		return nil, e
	}
	honestHeader, e := loadExact(filepath.Join(dir, report.HonestTip.ID+".pnh1"), headerBytes)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(invalidHeader, honestHeader) {
		return nil, errors.New("FALSE_STATEMENT_MISMATCH")
	}
	invalidProof, e := loadExact(filepath.Join(dir, "invalid-claimed-transcript.pnw1"), proofBytes)
	if e != nil {
		return nil, e
	}
	if _, _, e = ticketPrecheck(invalidHeader, invalidProof); e != nil {
		return nil, errors.New("FALSE_TICKET_NOT_VALID")
	}
	if _, _, e = fullVerify(invalidHeader, invalidProof); e == nil || e.Error() != "TRANSCRIPT" {
		return nil, errors.New("FALSE_WORK_WAS_NOT_REJECTED")
	}
	if report.Forged.ValidWork != "0" {
		return nil, errors.New("FORGED_CHAINWORK")
	}
	return map[string]interface{}{"schema": "trnm-independent-go-w1-full-proof-readback-v1", "full_w1_mathematical_proofs": 31, "false_trace_rejected": true, "honest_heavier_by_work": true, "native_Node_acceptance": false, "independent_operator_acceptance": false}, nil
}
func loadCapped(path string, max int64) ([]byte, error) {
	fi, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, errors.New("REPORT_SIZE_OR_TYPE")
	}
	return os.ReadFile(path)
}
func main() {
	report := flag.String("report", "", "Existing JSON report from Python producer")
	dir := flag.String("artifact-dir", "", "Existing raw PNH1/PNW1 artifacts")
	flag.Parse()
	if *report == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "--report and --artifact-dir are required")
		os.Exit(2)
	}
	out, e := run(*report, *dir)
	if e != nil {
		fmt.Fprintln(os.Stderr, "GO_W1_INVALID:", e)
		os.Exit(2)
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
