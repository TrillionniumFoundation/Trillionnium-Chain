// Research-only W1 producer with cached task output across many header challenges.
// Compiles alongside work_go_probe.go: go test work_go_probe.go work_go_reuse_test.go
// This grants no consensus validity, mining authorization, or work-hardness certification.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// A legitimate producer can cache C = A*B because A and B are invariant across
// W1 header challenges. The expensive challenge-dependent noisy transcript is
// still computed afresh, with the original tile visitation and hash bytes.
// It does NOT allow a cached transcript or a stale proof to win new headers.
type preparedW1Task struct {
	a       []uint32
	b       []uint32
	product []byte
}

func newPreparedW1Task(a, b []uint32) (*preparedW1Task, error) {
	if len(a) != Cells || len(b) != Cells {
		return nil, fmt.Errorf("Length")
	}
	for _, values := range [][]uint32{a, b} {
		for _, v := range values {
			if uint64(v) >= Q {
				return nil, fmt.Errorf("Field")
			}
		}
	}
	// Make owned copies: a caller changing the supplied slices after setup
	// cannot accidentally reuse old C with new A/B and manufacture authority.
	task := &preparedW1Task{
		a: append([]uint32(nil), a...),
		b: append([]uint32(nil), b...),
	}
	task.product = FieldBytes(MM(task.a, task.b, N, N, N))
	return task, nil
}

func (task *preparedW1Task) prove(challenge [32]byte) ([]byte, error) {
	factors := make([][]uint32, 4)
	for label := range factors {
		values, err := Expand(challenge, byte(label), N*R)
		if err != nil {
			return nil, err
		}
		factors[label] = values
	}
	el, er, fl, fr := factors[0], factors[1], factors[2], factors[3]
	e, f := MM(el, er, N, R, N), MM(fl, fr, N, R, N)
	left, right := make([]uint32, Cells), make([]uint32, Cells)
	for i := range left {
		left[i] = uint32((uint64(task.a[i]) + uint64(e[i])) % Q)
		right[i] = uint32((uint64(task.b[i]) + uint64(f[i])) % Q)
	}
	partial := make([]uint32, Cells)
	transcript := sha256.New()
	transcript.Write([]byte("TRNM-PON-TRACE1\x00"))
	transcript.Write(challenge[:])
	var field [4]byte
	for bi := 0; bi < 8; bi++ {
		for bj := 0; bj < 8; bj++ {
			for bk := 0; bk < 8; bk++ {
				for i := bi * R; i < (bi+1)*R; i++ {
					for j := bj * R; j < (bj+1)*R; j++ {
						pos := i*N + j
						acc := uint64(partial[pos])
						for k := bk * R; k < (bk+1)*R; k++ {
							acc = (acc + (uint64(left[i*N+k])*uint64(right[k*N+j]))%Q) % Q
						}
						partial[pos] = uint32(acc)
						binary.LittleEndian.PutUint32(field[:], partial[pos])
						transcript.Write(field[:])
					}
				}
			}
		}
	}
	proof := make([]byte, 0, ProofBytes)
	proof = append(proof, []byte("PNW1")...)
	proof = append(proof, FieldBytes(task.a)...)
	proof = append(proof, FieldBytes(task.b)...)
	proof = append(proof, task.product...)
	proof = append(proof, transcript.Sum(nil)...)
	if len(proof) != ProofBytes {
		return nil, fmt.Errorf("ProofLength")
	}
	return proof, nil
}

func maintenanceTask() ([]uint32, []uint32) {
	a, b := make([]uint32, Cells), make([]uint32, Cells)
	for i := range a {
		a[i] = uint32((13*i + 17) % 257)
		b[i] = uint32((29*i + 31) % 263)
	}
	return a, b
}

func frozenChallenge(seed uint64, attempt uint64) [32]byte {
	var input [16]byte
	binary.LittleEndian.PutUint64(input[:8], seed)
	binary.LittleEndian.PutUint64(input[8:], attempt)
	return H("w1-reuse-research-challenge-v1", input[:])
}

func maxResearchTarget() [32]byte {
	var max [32]byte
	for i := range max {
		max[i] = 0xff
	}
	return max
}

func TestW1PreparedProducerByteIdentityAndCurrentChallenge(t *testing.T) {
	cases := []struct {
		name string
		a, b []uint32
	}{}
	for _, shape := range []string{"dense", "zero", "rank1", "sparse"} {
		for _, seed := range []uint32{0, 1, 9} {
			a, b, err := Params(shape, seed)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, struct {
				name string
				a, b []uint32
			}{
				fmt.Sprintf("%s/%d", shape, seed), a, b,
			})
		}
	}
	a, b := maintenanceTask()
	cases = append(cases, struct {
		name string
		a, b []uint32
	}{"genesis-maintenance", a, b})
	var observed int
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prepared, err := newPreparedW1Task(c.a, c.b)
			if err != nil {
				t.Fatal(err)
			}
			taskID := H("task", FieldBytes(c.a), FieldBytes(c.b))
			for attempt := uint64(0); attempt < 4; attempt++ {
				challenge := frozenChallenge(uint64(i+1), attempt)
				original, err := Prove(challenge, c.a, c.b)
				if err != nil {
					t.Fatal(err)
				}
				cached, err := prepared.prove(challenge)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(original, cached) {
					t.Fatalf("legal cached producer changed W1 bytes for attempt %d", attempt)
				}
				if _, err := Verify(challenge, taskID, maxResearchTarget(), cached); err != nil {
					t.Fatalf("real full W1 relation not verified: %v", err)
				}
				observed++
			}
		})
	}
	if observed != 52 {
		t.Fatalf("incomplete complete-proof matrix: %d", observed)
	}
}

// Legitimate winning proofs must remain exactly identical under the original
// <= target predicate. Every loser is charged a complete fresh W1 trace.
// The challenges are synthetic research inputs, NOT installed block headers.
func TestW1PreparedAndReferenceFindSameTargetWinningProof(t *testing.T) {
	target := [32]byte{0x7f}
	for i := 1; i < 32; i++ {
		target[i] = 0xff
	}
	for caseIndex, shape := range []string{"dense", "zero", "rank1", "sparse", "maintenance"} {
		var a, b []uint32
		if shape == "maintenance" {
			a, b = maintenanceTask()
		} else {
			var err error
			a, b, err = Params(shape, 7)
			if err != nil {
				t.Fatal(err)
			}
		}
		prep, err := newPreparedW1Task(a, b)
		if err != nil {
			t.Fatal(err)
		}
		taskID := H("task", FieldBytes(a), FieldBytes(b))
		var winnerFound bool
		for attempt := uint64(0); attempt < 64; attempt++ {
			c := frozenChallenge(0x314159+uint64(caseIndex), attempt)
			original, err := Prove(c, a, b)
			if err != nil {
				t.Fatal(err)
			}
			reused, err := prep.prove(c)
			if err != nil || !bytes.Equal(reused, original) {
				t.Fatalf("search proof divergence shape=%s attempt=%d: %v", shape, attempt, err)
			}
			digest := H("ticket", c[:], reused[len(reused)-32:])
			if bytes.Compare(digest[:], target[:]) <= 0 {
				if _, err := Verify(c, taskID, target, reused); err != nil {
					t.Fatalf("winning full proof rejected: %v", err)
				}
				winnerFound = true
				break
			}
		}
		if !winnerFound {
			t.Fatalf("no winning proof in frozen 64-trial search: %s", shape)
		}
	}
}

func TestW1PreparedProducerCannotReuseStaleBytesOrAlterTask(t *testing.T) {
	a, b := maintenanceTask()
	beforeA, beforeB := append([]uint32(nil), a...), append([]uint32(nil), b...)
	prepared, err := newPreparedW1Task(a, b)
	if err != nil {
		t.Fatal(err)
	}
	a[0] = (a[0] + 1) % uint32(Q)
	b[0] = (b[0] + 1) % uint32(Q)
	c1, c2 := frozenChallenge(201, 1), frozenChallenge(201, 2)
	original, err := Prove(c1, beforeA, beforeB)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := prepared.prove(c1)
	if err != nil || !bytes.Equal(original, p1) {
		t.Fatalf("prepared arrays were mutable through caller alias: %v", err)
	}
	p2, err := prepared.prove(c2)
	if err != nil || bytes.Equal(p1, p2) {
		t.Fatalf("challenge was not bound: %v", err)
	}
	taskID := H("task", FieldBytes(beforeA), FieldBytes(beforeB))
	if _, err = Verify(c2, taskID, maxResearchTarget(), p1); err == nil || err.Error() != "Transcript" {
		t.Fatalf("stale challenge proof was accepted or misclassified: %v", err)
	}
	tampered := append([]byte(nil), p2...)
	offset := 4 + 2*Cells*4
	x := binary.LittleEndian.Uint32(tampered[offset:])
	binary.LittleEndian.PutUint32(tampered[offset:], uint32((uint64(x)+1)%Q))
	if _, err = Verify(c2, taskID, maxResearchTarget(), tampered); err == nil || err.Error() != "Product" {
		t.Fatalf("bad cached product was accepted or misclassified: %v", err)
	}
	mutatedTask := H("task", FieldBytes(a), FieldBytes(b))
	if _, err = Verify(c2, mutatedTask, maxResearchTarget(), p2); err == nil || err.Error() != "Task" {
		t.Fatalf("changed task was accepted or misclassified: %v", err)
	}
	bad := append([]uint32(nil), beforeA...)
	bad[0] = uint32(Q)
	if _, err := newPreparedW1Task(bad, beforeB); err == nil {
		t.Fatal("noncanonical field accepted")
	}
	if _, err := newPreparedW1Task(beforeA[:1], beforeB); err == nil {
		t.Fatal("short task accepted")
	}
}

// A recorded wall-clock experiment, not a speedup assertion. Every arm uses
// the same fixed task, challenge order and full proofs; the cached arm pays
// its preparation cost once per horizon. Invalid/stale task substitutions are
// excluded. Observe setup+search, not a final lottery hash in isolation.
func TestW1PreparedMaintenanceAmortizedCost(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode omits timing campaign")
	}
	a, b := maintenanceTask()
	for _, horizon := range []uint64{1, 4, 16, 64} {
		seed := uint64(20261025)
		start := time.Now()
		baseline := make([][]byte, 0, horizon)
		for attempt := uint64(0); attempt < horizon; attempt++ {
			proof, err := Prove(frozenChallenge(seed, attempt), a, b)
			if err != nil {
				t.Fatal(err)
			}
			baseline = append(baseline, proof)
		}
		referenceWall := time.Since(start)
		start = time.Now()
		prepared, err := newPreparedW1Task(a, b)
		if err != nil {
			t.Fatal(err)
		}
		preparationWall := time.Since(start)
		preparedProofs := make([][]byte, 0, horizon)
		for attempt := uint64(0); attempt < horizon; attempt++ {
			proof, err := prepared.prove(frozenChallenge(seed, attempt))
			if err != nil {
				t.Fatal(err)
			}
			preparedProofs = append(preparedProofs, proof)
		}
		preparedTotalWall := time.Since(start)
		for i := range baseline {
			if !bytes.Equal(baseline[i], preparedProofs[i]) {
				t.Fatal("W1 proof identity")
			}
		}
		t.Logf("RESEARCH_ONLY maintenance_horizon=%d reference_full_search_ns=%d cached_setup_ns=%d cached_inclusive_ns=%d valid_comparisons=%d", horizon, referenceWall.Nanoseconds(), preparationWall.Nanoseconds(), preparedTotalWall.Nanoseconds(), len(baseline))
	}
}

func BenchmarkW1MaintenanceReference(b *testing.B) {
	a, factors := maintenanceTask()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c := frozenChallenge(20261025, uint64(i))
		if _, err := Prove(c, a, factors); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkW1MaintenancePrepared(b *testing.B) {
	a, factors := maintenanceTask()
	prepared, err := newPreparedW1Task(a, factors)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := frozenChallenge(20261025, uint64(i))
		if _, err := prepared.prove(c); err != nil {
			b.Fatal(err)
		}
	}
}
