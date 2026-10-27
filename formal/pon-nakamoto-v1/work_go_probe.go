// Research-only third-language W1 transcript and invalid-ticket probe.
// Not a consensus miner, protocol selector, source authorization or work-hardness proof.
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
	"os"
	"strconv"
	"time"
)

const (
	N                 = 64
	R                 = 8
	Q          uint64 = 4294967291
	Cells             = N * N
	ProofBytes        = 4 + 3*Cells*4 + 32
)

var magic = []byte("TRNM-PON1\x00")

func H(tag string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write(magic)
	var lb [4]byte
	binary.LittleEndian.PutUint16(lb[:2], uint16(len(tag)))
	h.Write(lb[:2])
	h.Write([]byte(tag))
	for _, p := range parts {
		binary.LittleEndian.PutUint32(lb[:], uint32(len(p)))
		h.Write(lb[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func FieldBytes(a []uint32) []byte {
	b := make([]byte, 4*len(a))
	for i, v := range a {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}
func MM(a, b []uint32, rows, inner, cols int) []uint32 {
	out := make([]uint32, rows*cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			var sum uint64
			for k := 0; k < inner; k++ {
				sum = (sum + (uint64(a[i*inner+k])*uint64(b[k*cols+j]))%Q) % Q
			}
			out[i*cols+j] = uint32(sum)
		}
	}
	return out
}
func Expand(c [32]byte, label byte, count int) ([]uint32, error) {
	out := make([]uint32, 0, count)
	for counter := uint32(0); len(out) < count; counter++ {
		if counter >= 128 {
			return nil, errors.New("NoiseBudget")
		}
		var index [4]byte
		binary.LittleEndian.PutUint32(index[:], counter)
		digest := H("noise", c[:], []byte{label}, index[:])
		for j := 0; j < 32 && len(out) < count; j += 4 {
			x := binary.LittleEndian.Uint32(digest[j : j+4])
			if uint64(x) < Q {
				out = append(out, x)
			}
		}
	}
	return out, nil
}
func Params(shape string, seed uint32) ([]uint32, []uint32, error) {
	a, b := make([]uint32, Cells), make([]uint32, Cells)
	for i := 0; i < Cells; i++ {
		b[i] = uint32((29*uint64(i) + 11*uint64(seed) + 31) % 1231)
		switch shape {
		case "dense":
			a[i] = uint32((13*uint64(i) + 3*uint64(seed) + 7) % 1009)
		case "zero":
			a[i] = 0
		case "rank1":
			a[i] = uint32(((1 + (uint64(i/64)*7+uint64(seed))%251) * (1 + uint64(i%64)*13%257)) % Q)
		case "sparse":
			if i%129 == 0 {
				a[i] = uint32((uint64(i) + uint64(seed)) % 101)
			}
		default:
			return nil, nil, errors.New("unsupported shape")
		}
	}
	return a, b, nil
}
func Eval(c [32]byte, a, b []uint32) ([]uint32, [32]byte, error) {
	if len(a) != Cells || len(b) != Cells {
		return nil, [32]byte{}, errors.New("Length")
	}
	for _, slice := range [][]uint32{a, b} {
		for _, v := range slice {
			if uint64(v) >= Q {
				return nil, [32]byte{}, errors.New("Field")
			}
		}
	}
	factors := make([][]uint32, 4)
	for i := 0; i < 4; i++ {
		var err error
		factors[i], err = Expand(c, byte(i), N*R)
		if err != nil {
			return nil, [32]byte{}, err
		}
	}
	el, er, fl, fr := factors[0], factors[1], factors[2], factors[3]
	e, f := MM(el, er, N, R, N), MM(fl, fr, N, R, N)
	ap, bp := make([]uint32, Cells), make([]uint32, Cells)
	for i := 0; i < Cells; i++ {
		ap[i] = uint32((uint64(a[i]) + uint64(e[i])) % Q)
		bp[i] = uint32((uint64(b[i]) + uint64(f[i])) % Q)
	}
	cp := make([]uint32, Cells)
	trace := sha256.New()
	trace.Write([]byte("TRNM-PON-TRACE1\x00"))
	trace.Write(c[:])
	var le [4]byte
	for bi := 0; bi < 8; bi++ {
		for bj := 0; bj < 8; bj++ {
			for bk := 0; bk < 8; bk++ {
				for i := bi * R; i < (bi+1)*R; i++ {
					for j := bj * R; j < (bj+1)*R; j++ {
						pos := i*N + j
						sum := uint64(cp[pos])
						for k := bk * R; k < (bk+1)*R; k++ {
							sum = (sum + (uint64(ap[i*N+k])*uint64(bp[k*N+j]))%Q) % Q
						}
						cp[pos] = uint32(sum)
						binary.LittleEndian.PutUint32(le[:], cp[pos])
						trace.Write(le[:])
					}
				}
			}
		}
	}
	c1 := MM(MM(a, fl, N, N, R), fr, N, R, N)
	c2 := MM(el, MM(er, bp, R, N, N), N, R, N)
	product := make([]uint32, Cells)
	for i := 0; i < Cells; i++ {
		product[i] = uint32((uint64(cp[i]) + 2*Q - uint64(c1[i]) - uint64(c2[i])) % Q)
	}
	var digest [32]byte
	copy(digest[:], trace.Sum(nil))
	return product, digest, nil
}
func Prove(c [32]byte, a, b []uint32) ([]byte, error) {
	product, t, err := Eval(c, a, b)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, ProofBytes)
	out = append(out, []byte("PNW1")...)
	out = append(out, FieldBytes(a)...)
	out = append(out, FieldBytes(b)...)
	out = append(out, FieldBytes(product)...)
	out = append(out, t[:]...)
	if len(out) != ProofBytes {
		return nil, errors.New("ProofLength")
	}
	return out, nil
}
func Decode(b []byte) ([]uint32, error) {
	if len(b)%4 != 0 {
		return nil, errors.New("Length")
	}
	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[i*4:])
		if uint64(out[i]) >= Q {
			return nil, errors.New("Field")
		}
	}
	return out, nil
}
func Precheck(c, task, target [32]byte, proof []byte) ([32]byte, error) {
	if len(proof) != ProofBytes {
		return [32]byte{}, errors.New("Length")
	}
	if !bytes.Equal(proof[:4], []byte("PNW1")) {
		return [32]byte{}, errors.New("Version")
	}
	if target == ([32]byte{}) {
		return [32]byte{}, errors.New("Target")
	}
	if _, err := Decode(proof[4 : 4+3*Cells*4]); err != nil {
		return [32]byte{}, err
	}
	if H("task", proof[4:4+Cells*4], proof[4+Cells*4:4+2*Cells*4]) != task {
		return [32]byte{}, errors.New("Task")
	}
	ticket := H("ticket", c[:], proof[ProofBytes-32:])
	if bytes.Compare(ticket[:], target[:]) > 0 {
		return [32]byte{}, errors.New("Target")
	}
	return ticket, nil
}
func Verify(c, task, target [32]byte, proof []byte) ([32]byte, error) {
	ticket, err := Precheck(c, task, target, proof)
	if err != nil {
		return ticket, err
	}
	a, _ := Decode(proof[4 : 4+Cells*4])
	b, _ := Decode(proof[4+Cells*4 : 4+2*Cells*4])
	product, t, err := Eval(c, a, b)
	if err != nil {
		return ticket, err
	}
	if !bytes.Equal(t[:], proof[ProofBytes-32:]) {
		return ticket, errors.New("Transcript")
	}
	if !bytes.Equal(FieldBytes(product), proof[4+2*Cells*4:4+3*Cells*4]) {
		return ticket, errors.New("Product")
	}
	return ticket, nil
}
func FalseClaim(c, target [32]byte, a, b []uint32, max uint64) ([]byte, uint64, error) {
	proof := make([]byte, 0, ProofBytes)
	proof = append(proof, []byte("PNW1")...)
	proof = append(proof, FieldBytes(a)...)
	proof = append(proof, FieldBytes(b)...)
	proof = append(proof, make([]byte, Cells*4)...)
	var nonce [8]byte
	for i := uint64(0); i < max; i++ {
		binary.LittleEndian.PutUint64(nonce[:], i)
		t := H("research-forged-trace", c[:], nonce[:])
		ticket := H("ticket", c[:], t[:])
		if bytes.Compare(ticket[:], target[:]) <= 0 {
			proof = append(proof, t[:]...)
			return proof, i + 1, nil
		}
	}
	return nil, max, errors.New("SearchExhausted")
}

// HonestSearch measures every full challenge-bound attempt under the SAME
// threshold as the cheap forged-ticket producer; no precomputed winning ticket.
// Synthetic challenges are NOT native block headers or mining certificates.
func HonestSearch(seedChallenge, task, target [32]byte, a, b []uint32, max uint64) ([32]byte, []byte, uint64, error) {
	var nonce [8]byte
	for attempt := uint64(0); attempt < max; attempt++ {
		binary.LittleEndian.PutUint64(nonce[:], attempt)
		c := H("research-attempt-challenge", seedChallenge[:], nonce[:])
		proof, err := Prove(c, a, b)
		if err != nil {
			return [32]byte{}, nil, attempt + 1, err
		}
		t := proof[len(proof)-32:]
		ticket := H("ticket", c[:], t)
		if bytes.Compare(ticket[:], target[:]) <= 0 {
			if _, err = Verify(c, task, target, proof); err != nil {
				return [32]byte{}, nil, attempt + 1, err
			}
			return c, proof, attempt + 1, nil
		}
	}
	return [32]byte{}, nil, max, errors.New("HonestSearchExhausted")
}

func main() {
	shape := flag.String("shape", "dense", "dense|zero|rank1|sparse")
	seed := flag.Uint("seed", 0, "public deterministic research seed")
	max := flag.Uint64("false-attempts", 4096, "maximum forged-ticket trials")
	flag.Parse()
	if *seed > 1<<16 || *max < 1 || *max > 100000 {
		fmt.Fprintln(os.Stderr, "invalid bounds")
		os.Exit(2)
	}
	a, b, err := Params(*shape, uint32(*seed))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	c := sha256.Sum256([]byte("trnm-w1-go-research-v1/" + strconv.FormatUint(uint64(*seed), 10)))
	task := H("task", FieldBytes(a), FieldBytes(b))
	target := [32]byte{127}
	for i := 1; i < 32; i++ {
		target[i] = 255
	}
	start := time.Now()
	validProof, err := Prove(c, a, b)
	productionNS := time.Since(start).Nanoseconds()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	// The research proof is not guaranteed to be a winning lottery ticket.
	full := [32]byte{}
	for i := range full {
		full[i] = 255
	}
	start = time.Now()
	_, err = Verify(c, task, full, validProof)
	validVerifyNS := time.Since(start).Nanoseconds()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	start = time.Now()
	winningChallenge, winningProof, winningAttempts, err := HonestSearch(c, task, target, a, b, *max)
	honestFullSearchNS := time.Since(start).Nanoseconds()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	winningSHA := sha256.Sum256(winningProof)
	start = time.Now()
	fakeProof, tries, err := FalseClaim(c, target, a, b, *max)
	fakeGenerationNS := time.Since(start).Nanoseconds()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	if _, err = Precheck(c, task, target, fakeProof); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	start = time.Now()
	_, err = Verify(c, task, target, fakeProof)
	rejectNS := time.Since(start).Nanoseconds()
	if err == nil || err.Error() != "Transcript" {
		fmt.Fprintln(os.Stderr, "bad expected rejection", err)
		os.Exit(3)
	}
	product, t, _ := Eval(c, a, b)
	if !bytes.Equal(FieldBytes(product), FieldBytes(MM(a, b, N, N, N))) {
		fmt.Fprintln(os.Stderr, "decoded useful product disagrees with direct AB")
		os.Exit(3)
	}
	wrongProduct := append([]byte(nil), validProof...)
	productOffset := 4 + 2*Cells*4
	original := binary.LittleEndian.Uint32(wrongProduct[productOffset:])
	binary.LittleEndian.PutUint32(wrongProduct[productOffset:], uint32((uint64(original)+1)%Q))
	if _, e := Verify(c, task, full, wrongProduct); e == nil || e.Error() != "Product" {
		fmt.Fprintln(os.Stderr, "product tampering not rejected as Product")
		os.Exit(3)
	}
	wrongTrace := append([]byte(nil), validProof...)
	wrongTrace[len(wrongTrace)-1] ^= 1
	if _, e := Verify(c, task, full, wrongTrace); e == nil || e.Error() != "Transcript" {
		fmt.Fprintln(os.Stderr, "trace tampering not rejected as Transcript")
		os.Exit(3)
	}
	wrongTask := task
	wrongTask[0] ^= 1
	if _, e := Verify(c, wrongTask, full, validProof); e == nil || e.Error() != "Task" {
		fmt.Fprintln(os.Stderr, "task substitution not rejected as Task")
		os.Exit(3)
	}
	if _, e := Verify(c, task, full, validProof[:len(validProof)-1]); e == nil || e.Error() != "Length" {
		fmt.Fprintln(os.Stderr, "truncation not rejected as Length")
		os.Exit(3)
	}
	proofHash := sha256.Sum256(validProof)
	productHash := sha256.Sum256(FieldBytes(product))
	report := map[string]any{
		"schema": "pon-w1-go-research-v1", "shape": *shape, "seed": *seed,
		"challenge": hex.EncodeToString(c[:]), "task": hex.EncodeToString(task[:]),
		"proof_sha256":           hex.EncodeToString(proofHash[:]),
		"decoded_product_sha256": hex.EncodeToString(productHash[:]),
		"transcript_sha256":      hex.EncodeToString(t[:]),
		"proof_bytes":            len(validProof), "valid_proof_full_target_verified": true, "negative_controls": 4,
		"false_ticket_passed": true, "false_proof_full_rejection": "Transcript",
		"honest_winner_attempts":            winningAttempts,
		"honest_winner_full_search_wall_ns": honestFullSearchNS,
		"honest_winning_challenge":          hex.EncodeToString(winningChallenge[:]),
		"honest_winning_proof_sha256":       hex.EncodeToString(winningSHA[:]),
		"same_target_hex":                   hex.EncodeToString(target[:]),
		"false_ticket_hash_attempts":        tries, "producer_wall_ns": productionNS,
		"verifier_wall_ns": validVerifyNS, "false_producer_wall_ns": fakeGenerationNS,
		"false_rejection_wall_ns": rejectNS, "cpu_scope": "not observed",
		"w1_native_rust_runs": 0, "public_attack_runs": 0, "production_eligible": false,
		"claim": "independent language math and local wall-cost scope only",
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
