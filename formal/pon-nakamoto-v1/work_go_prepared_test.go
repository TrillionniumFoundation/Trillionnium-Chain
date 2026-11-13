// Research proof byte-parity and amortization controls; no accepted hardness claim.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func preparedMaintenance() ([]uint32, []uint32) {
	a, b := make([]uint32, Cells), make([]uint32, Cells)
	for i := 0; i < Cells; i++ {
		a[i] = uint32((13*i + 17) % 257)
		b[i] = uint32((29*i + 31) % 263)
	}
	return a, b
}

func preparedMaterials(shape string, seed uint32) ([]uint32, []uint32, error) {
	if shape == "maintenance" {
		a, b := preparedMaintenance()
		return a, b, nil
	}
	return Params(shape, seed)
}

func preparedChallenge(shape string, seed, attempt uint32) [32]byte {
	var params [8]byte
	binary.LittleEndian.PutUint32(params[:4], seed)
	binary.LittleEndian.PutUint32(params[4:], attempt)
	return H("prepared-w1-test-challenge-v1", []byte(shape), params[:])
}

func TestPreparedFullCertificateByteIdentity(t *testing.T) {
	for _, shape := range []string{"maintenance", "dense", "zero", "rank1", "sparse"} {
		for seed := uint32(0); seed < 3; seed++ {
			a, b, err := preparedMaterials(shape, seed)
			if err != nil {
				t.Fatalf("%s seed=%d material: %v", shape, seed, err)
			}
			p, err := PrepareW1Task(a, b)
			if err != nil {
				t.Fatalf("%s seed=%d prepare: %v", shape, seed, err)
			}
			task := H("task", FieldBytes(a), FieldBytes(b))
			for attempt := uint32(0); attempt < 4; attempt++ {
				c := preparedChallenge(shape, seed, attempt)
				generic, err := Prove(c, a, b)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := p.Prove(c)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(generic, prepared) {
					t.Fatalf("different valid proofs: shape=%s seed=%d attempt=%d", shape, seed, attempt)
				}
				// Full reference verification checks the actual arithmetic and
				// transcript, not just the cheap ticket prefilter.
				var max [32]byte
				for i := range max {
					max[i] = 0xff
				}
				if _, err := Verify(c, task, max, prepared); err != nil {
					t.Fatalf("prepared proof invalid: %s %d %d %v", shape, seed, attempt, err)
				}
			}
		}
	}
}

func TestPreparedOwnsInputsAndChallengesRemainBound(t *testing.T) {
	a, b := preparedMaintenance()
	p, err := PrepareW1Task(a, b)
	if err != nil {
		t.Fatal(err)
	}
	a[0] = 999999
	b[0] = 888888
	challenge := preparedChallenge("maintenance", 1, 2)
	original, err := p.Prove(challenge)
	if err != nil {
		t.Fatal(err)
	}
	x, y := preparedMaintenance()
	reference, err := Prove(challenge, x, y)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, reference) {
		t.Fatal("input alias mutated prepared task")
	}
	different := preparedChallenge("maintenance", 1, 3)
	changed, err := p.Prove(different)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, changed) {
		t.Fatal("transcript did not bind challenge")
	}
	var max [32]byte
	for i := range max {
		max[i] = 255
	}
	task := H("task", FieldBytes(x), FieldBytes(y))
	if _, err := Verify(different, task, max, original); err == nil {
		t.Fatal("replayed old challenge accepted")
	}
	if _, err := Verify(different, task, max, changed); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), changed...)
	bad[len(bad)-1] ^= 1
	if _, err := Verify(different, task, max, bad); err == nil {
		t.Fatal("false trace accepted")
	}
	bad2 := append([]byte(nil), changed...)
	bad2[4+2*Cells*4] ^= 1
	if _, err := Verify(different, task, max, bad2); err == nil {
		t.Fatal("false product accepted")
	}
	malformed := make([]uint32, Cells)
	copy(malformed, x)
	malformed[0] = uint32(Q)
	if _, err := PrepareW1Task(malformed, y); err == nil {
		t.Fatal("noncanonical field accepted")
	}
	if _, err := PrepareW1Task(x[:Cells-1], y); err == nil {
		t.Fatal("short input accepted")
	}
}

// Search the exact same ticket stream: valid winning evidence, number of
// losing attempts and canonical proof bytes must not change when preprocessing.
func TestPreparedWinningLotteryMatchesOriginalFullSearch(t *testing.T) {
	target := [32]byte{127}
	for k := 1; k < 32; k++ {
		target[k] = 255
	}
	for _, shape := range []string{"maintenance", "dense", "zero", "rank1", "sparse"} {
		for seed := uint32(0); seed < 3; seed++ {
			a, b, err := preparedMaterials(shape, seed)
			if err != nil {
				t.Fatal(err)
			}
			task := H("task", FieldBytes(a), FieldBytes(b))
			seedChallenge := preparedChallenge(shape, seed, 99)
			c1, p1, n1, err := HonestSearch(seedChallenge, task, target, a, b, 128)
			if err != nil {
				t.Fatalf("generic winner: %s seed=%d: %v", shape, seed, err)
			}
			c2, p2, n2, err := HonestPreparedSearch(seedChallenge, task, target, a, b, 128)
			if err != nil {
				t.Fatalf("prepared winner: %s seed=%d: %v", shape, seed, err)
			}
			if c1 != c2 || n1 != n2 || !bytes.Equal(p1, p2) {
				t.Fatalf("lottery changed by legal preprocessing: %s seed=%d", shape, seed)
			}
			if _, err := Verify(c2, task, target, p2); err != nil {
				t.Fatal(err)
			}
		}
	}
	a, b := preparedMaintenance()
	task := H("task", FieldBytes(a), FieldBytes(b))
	seedChallenge := preparedChallenge("maintenance", 1, 0)
	if _, _, n, err := HonestPreparedSearch(seedChallenge, task, target, a, b, 0); err == nil || n != 0 {
		t.Fatal("zero-budget work succeeded")
	}
}

// The benchmark includes preparation for the prepared arm. It does not assert
// speedup because optimization benefit depends on hardware, build, workload,
// compilation and the number of subsequent challenges.
func BenchmarkPreparedVsGeneric(b *testing.B) {
	for _, shape := range []string{"maintenance", "dense", "zero", "rank1", "sparse"} {
		for _, rounds := range []int{1, 4, 16} {
			a, bb, err := preparedMaterials(shape, 5)
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%s/generic/%d", shape, rounds), func(b *testing.B) {
				b.ReportAllocs()
				for iter := 0; iter < b.N; iter++ {
					for j := 0; j < rounds; j++ {
						if _, err := Prove(preparedChallenge(shape, 5, uint32(j)), a, bb); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
			b.Run(fmt.Sprintf("%s/prepared/%d", shape, rounds), func(b *testing.B) {
				b.ReportAllocs()
				for iter := 0; iter < b.N; iter++ {
					p, err := PrepareW1Task(a, bb)
					if err != nil {
						b.Fatal(err)
					}
					for j := 0; j < rounds; j++ {
						if _, err := p.Prove(preparedChallenge(shape, 5, uint32(j))); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
