// Package w1falsification is an independent research verifier of the fixed W1
// neural-matrix transcript. It is NOT consensus admission or proof of hardness.
package w1falsification

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

const (
	N          = 64
	Rank       = 8
	Cells      = N * N
	Q          = uint64(4294967291)
	ProofBytes = 4 + 3*Cells*4 + 32
)

type Digest = [32]byte

var (
	ErrLength     = errors.New("LENGTH")
	ErrVersion    = errors.New("VERSION")
	ErrField      = errors.New("FIELD")
	ErrTask       = errors.New("TASK")
	ErrTarget     = errors.New("TARGET")
	ErrTranscript = errors.New("TRANSCRIPT")
	ErrProduct    = errors.New("PRODUCT")
	ErrNoise      = errors.New("NOISE_BUDGET")
)

// H uses the unchanged, explicit PoN domain-length framing.
func H(tag string, parts ...[]byte) Digest {
	h := sha256.New()
	h.Write([]byte("TRNM-PON1\x00"))
	var tmp [4]byte
	binary.LittleEndian.PutUint16(tmp[:2], uint16(len(tag)))
	h.Write(tmp[:2])
	h.Write([]byte(tag))
	for _, p := range parts {
		binary.LittleEndian.PutUint32(tmp[:], uint32(len(p)))
		h.Write(tmp[:])
		h.Write(p)
	}
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

func parseField(raw []byte) ([]uint32, error) {
	if len(raw) != Cells*4 {
		return nil, ErrLength
	}
	out := make([]uint32, Cells)
	for i := 0; i < Cells; i++ {
		v := binary.LittleEndian.Uint32(raw[i*4:])
		if uint64(v) >= Q {
			return nil, ErrField
		}
		out[i] = v
	}
	return out, nil
}
func encodeField(values []uint32) []byte {
	out := make([]byte, len(values)*4)
	for i, v := range values {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}
func TaskID(a, b []uint32) (Digest, error) {
	if len(a) != Cells || len(b) != Cells {
		return Digest{}, ErrLength
	}
	for _, v := range append(append([]uint32(nil), a...), b...) {
		if uint64(v) >= Q {
			return Digest{}, ErrField
		}
	}
	return H("task", encodeField(a), encodeField(b)), nil
}
func expand(challenge Digest, label byte) ([]uint32, error) {
	out := make([]uint32, 0, N*Rank)
	for counter := uint32(0); len(out) < N*Rank; counter++ {
		if counter >= 128 {
			return nil, ErrNoise
		}
		var i [4]byte
		binary.LittleEndian.PutUint32(i[:], counter)
		h := H("noise", challenge[:], []byte{label}, i[:])
		for j := 0; j < 8; j++ {
			v := binary.LittleEndian.Uint32(h[j*4:])
			if uint64(v) < Q {
				out = append(out, v)
				if len(out) == N*Rank {
					break
				}
			}
		}
	}
	return out, nil
}

// 64-bit single-step modular sum is safe: (q-1)^2 + (q-1) < 2^64.
func addProduct(acc uint64, left, right uint32) uint64 { return (acc + uint64(left)*uint64(right)) % Q }

// MM independently computes a finite-field product with row-major operands.
func MM(a, b []uint32, n, k, m int) []uint32 {
	out := make([]uint32, n*m)
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			acc := uint64(0)
			for t := 0; t < k; t++ {
				acc = addProduct(acc, a[i*k+t], b[t*m+j])
			}
			out[i*m+j] = uint32(acc)
		}
	}
	return out
}
func add(a, b []uint32) []uint32 {
	out := make([]uint32, len(a))
	for i := range a {
		out[i] = uint32((uint64(a[i]) + uint64(b[i])) % Q)
	}
	return out
}
func minus3(a, b, c []uint32) []uint32 {
	out := make([]uint32, len(a))
	for i := range a {
		v := (uint64(a[i]) + 2*Q - uint64(b[i]) - uint64(c[i])) % Q
		out[i] = uint32(v)
	}
	return out
}

// Evaluate computes the exact challenge-dependent trace and decoded product.
func Evaluate(challenge Digest, a, b []uint32) ([]uint32, Digest, error) {
	if len(a) != Cells || len(b) != Cells {
		return nil, Digest{}, ErrLength
	}
	for _, v := range a {
		if uint64(v) >= Q {
			return nil, Digest{}, ErrField
		}
	}
	for _, v := range b {
		if uint64(v) >= Q {
			return nil, Digest{}, ErrField
		}
	}
	el, e := expand(challenge, 0)
	if e != nil {
		return nil, Digest{}, e
	}
	er, e := expand(challenge, 1)
	if e != nil {
		return nil, Digest{}, e
	}
	fl, e := expand(challenge, 2)
	if e != nil {
		return nil, Digest{}, e
	}
	fr, e := expand(challenge, 3)
	if e != nil {
		return nil, Digest{}, e
	}
	aa := add(a, MM(el, er, N, Rank, N))
	bb := add(b, MM(fl, fr, N, Rank, N))
	cp := make([]uint32, Cells)
	var traceHash hash.Hash = sha256.New()
	traceHash.Write([]byte("TRNM-PON-TRACE1\x00"))
	traceHash.Write(challenge[:])
	var tmp [4]byte
	for bi := 0; bi < N; bi += Rank {
		for bj := 0; bj < N; bj += Rank {
			for bk := 0; bk < N; bk += Rank {
				for i := bi; i < bi+Rank; i++ {
					for j := bj; j < bj+Rank; j++ {
						index := i*N + j
						sum := uint64(cp[index])
						for k := bk; k < bk+Rank; k++ {
							sum = addProduct(sum, aa[i*N+k], bb[k*N+j])
						}
						cp[index] = uint32(sum)
						binary.LittleEndian.PutUint32(tmp[:], cp[index])
						traceHash.Write(tmp[:])
					}
				}
			}
		}
	}
	part1 := MM(MM(a, fl, N, N, Rank), fr, N, Rank, N)
	part2 := MM(el, MM(er, bb, Rank, N, N), N, Rank, N)
	product := minus3(cp, part1, part2)
	var transcript Digest
	copy(transcript[:], traceHash.Sum(nil))
	return product, transcript, nil
}
func Proof(challenge Digest, a, b []uint32) ([]byte, error) {
	product, trace, e := Evaluate(challenge, a, b)
	if e != nil {
		return nil, e
	}
	proof := make([]byte, 0, ProofBytes)
	proof = append(proof, []byte("PNW1")...)
	proof = append(proof, encodeField(a)...)
	proof = append(proof, encodeField(b)...)
	proof = append(proof, encodeField(product)...)
	proof = append(proof, trace[:]...)
	return proof, nil
}

// CheapPrecheck establishes only basic syntax, task and target predicate.
// Its success CANNOT construct verified work or grant an output meter.
func CheapPrecheck(challenge, task, target Digest, proof []byte) error {
	if len(proof) != ProofBytes {
		return ErrLength
	}
	if string(proof[:4]) != "PNW1" {
		return ErrVersion
	}
	a, e := parseField(proof[4 : 4+Cells*4])
	if e != nil {
		return e
	}
	b, e := parseField(proof[4+Cells*4 : 4+2*Cells*4])
	if e != nil {
		return e
	}
	_, e = parseField(proof[4+2*Cells*4 : 4+3*Cells*4])
	if e != nil {
		return e
	}
	actual, _ := TaskID(a, b)
	if actual != task {
		return ErrTask
	}
	if target == (Digest{}) {
		return ErrTarget
	}
	ticket := H("ticket", challenge[:], proof[ProofBytes-32:])
	if bytes.Compare(ticket[:], target[:]) > 0 {
		return ErrTarget
	}
	return nil
}
func Verify(challenge, task, target Digest, proof []byte) ([]uint32, error) {
	if e := CheapPrecheck(challenge, task, target, proof); e != nil {
		return nil, e
	}
	a, _ := parseField(proof[4 : 4+Cells*4])
	b, _ := parseField(proof[4+Cells*4 : 4+2*Cells*4])
	p, _ := parseField(proof[4+2*Cells*4 : 4+3*Cells*4])
	product, trace, e := Evaluate(challenge, a, b)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(trace[:], proof[ProofBytes-32:]) {
		return nil, ErrTranscript
	}
	for i := range p {
		if p[i] != product[i] {
			return nil, ErrProduct
		}
	}
	return product, nil
}
