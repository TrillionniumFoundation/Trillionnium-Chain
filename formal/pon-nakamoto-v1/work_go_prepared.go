// Independent research-only prepared-product W1 producer. Reuses a verified
// mathematical AB product across challenge-bound transcript attempts. It does
// not change accepted W1 proof bytes, work cost, task identity or consensus.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

type PreparedW1Task struct {
	a       []uint32
	b       []uint32
	product []uint32
}

func PrepareW1Task(a, b []uint32) (*PreparedW1Task, error) {
	if len(a) != Cells || len(b) != Cells {
		return nil, errors.New("Length")
	}
	// A caller cannot replace certified inputs between attempts. Copy first,
	// then check field canonicality on the owned snapshots.
	ac := append([]uint32(nil), a...)
	bc := append([]uint32(nil), b...)
	for _, field := range [][]uint32{ac, bc} {
		for _, v := range field {
			if uint64(v) >= Q {
				return nil, errors.New("Field")
			}
		}
	}
	return &PreparedW1Task{a: ac, b: bc, product: MM(ac, bc, N, N, N)}, nil
}

// Prove performs every challenge-dependent noise expansion, augmented matrix
// multiplication and every ordered intermediate-cell transcript update. Only
// the mathematical product AB is reused. A forged trace cannot be substituted.
func (p *PreparedW1Task) Prove(challenge [32]byte) ([]byte, error) {
	if p == nil || len(p.a) != Cells || len(p.b) != Cells || len(p.product) != Cells {
		return nil, errors.New("Unprepared")
	}
	var noise [4][]uint32
	for label := range noise {
		values, err := Expand(challenge, byte(label), N*R)
		if err != nil {
			return nil, err
		}
		noise[label] = values
	}
	el, er, fl, fr := noise[0], noise[1], noise[2], noise[3]
	e := MM(el, er, N, R, N)
	f := MM(fl, fr, N, R, N)
	ap := make([]uint32, Cells)
	bp := make([]uint32, Cells)
	for k := 0; k < Cells; k++ {
		ap[k] = uint32((uint64(p.a[k]) + uint64(e[k])) % Q)
		bp[k] = uint32((uint64(p.b[k]) + uint64(f[k])) % Q)
	}
	cp := make([]uint32, Cells)
	transcript := sha256.New()
	transcript.Write([]byte("TRNM-PON-TRACE1\x00"))
	transcript.Write(challenge[:])
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
						transcript.Write(le[:])
					}
				}
			}
		}
	}
	cert := make([]byte, 0, ProofBytes)
	cert = append(cert, []byte("PNW1")...)
	cert = append(cert, FieldBytes(p.a)...)
	cert = append(cert, FieldBytes(p.b)...)
	cert = append(cert, FieldBytes(p.product)...)
	cert = append(cert, transcript.Sum(nil)...)
	if len(cert) != ProofBytes {
		return nil, errors.New("ProofLength")
	}
	return cert, nil
}

// HonestPreparedSearch uses the same public nonce stream and exact Ticket
// predicate as HonestSearch. Its one-time product preparation is charged
// before any winning/losing attempt; it does not turn a false ticket into work.
func HonestPreparedSearch(seedChallenge, task, target [32]byte, a, b []uint32, max uint64) ([32]byte, []byte, uint64, error) {
	producer, err := PrepareW1Task(a, b)
	if err != nil {
		return [32]byte{}, nil, 0, err
	}
	var nonce [8]byte
	for attempt := uint64(0); attempt < max; attempt++ {
		binary.LittleEndian.PutUint64(nonce[:], attempt)
		c := H("research-attempt-challenge", seedChallenge[:], nonce[:])
		proof, err := producer.Prove(c)
		if err != nil {
			return [32]byte{}, nil, attempt + 1, err
		}
		trace := proof[len(proof)-32:]
		ticket := H("ticket", c[:], trace)
		if bytes.Compare(ticket[:], target[:]) <= 0 {
			if _, err := Verify(c, task, target, proof); err != nil {
				return [32]byte{}, nil, attempt + 1, err
			}
			return c, proof, attempt + 1, nil
		}
	}
	return [32]byte{}, nil, max, errors.New("HonestSearchExhausted")
}
