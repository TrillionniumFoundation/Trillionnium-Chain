// Retained ordinary conformance controls from the original research oracle.
// Historical cost/forgery drivers remain at their original Git source.
package w1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func wantHex(t *testing.T, got [32]byte, expected string) {
	t.Helper()
	if hex.EncodeToString(got[:]) != expected {
		t.Fatalf("hash mismatch: %x != %s", got, expected)
	}
}

func TestThirdLanguageW1ProofReferenceVector(t *testing.T) {
	var c [32]byte
	for i := range c {
		c[i] = byte(i)
	}
	a, b := make([]uint32, Cells), make([]uint32, Cells)
	for i := range a {
		a[i] = uint32(i % 97)
		b[i] = uint32(i % 83)
	}
	task := Hash("task", fieldBytes(a), fieldBytes(b))
	wantHex(t, task, "cac3c5379382194f355a87a5625a46d86241f0d491305a21c95a5d1c795e90da")
	proof, err := Proof(c, a, b)
	if err != nil {
		t.Fatal(err)
	}
	wantHex(t, sha256.Sum256(proof), "b6d53b8205e0f9c1054541722fd517b73dab3235810fa65195b8074f153ffb04")
	var trace [32]byte
	copy(trace[:], proof[ProofBytes-32:])
	wantHex(t, trace, "01c964f77a54e08bf174888a15c25ed0aea7756ced4b90bb8bebc26745b0d46e")
	var target [32]byte
	for i := range target {
		target[i] = 255
	}
	if err := Verify(c, task, target, proof); err != nil {
		t.Fatal(err)
	}
}

func TestGoW1EarlyAndLateRejectionOrder(t *testing.T) {
	var challenge [32]byte
	for i := range challenge {
		challenge[i] = byte(i)
	}
	a, b := make([]uint32, Cells), make([]uint32, Cells)
	for i := range a {
		a[i] = uint32(i % 97)
		b[i] = uint32(i % 83)
	}
	p, err := Proof(challenge, a, b)
	if err != nil {
		t.Fatal(err)
	}
	var target [32]byte
	for i := range target {
		target[i] = 255
	}
	task := Hash("task", fieldBytes(a), fieldBytes(b))
	requireErr := func(proof []byte, ch, task, target [32]byte, expected string) {
		t.Helper()
		err := Verify(ch, task, target, proof)
		if err == nil || err.Error() != expected {
			t.Fatalf("want %s, got %v", expected, err)
		}
	}
	requireErr(p[:len(p)-1], challenge, task, target, "Length")
	changed := append([]byte{}, p...)
	changed[0] ^= 1
	requireErr(changed, challenge, task, target, "Version")
	changed = append([]byte{}, p...)
	binary.LittleEndian.PutUint32(changed[4:], uint32(Q))
	requireErr(changed, challenge, task, target, "Field")
	wrongTask := task
	wrongTask[0] ^= 1
	requireErr(p, challenge, wrongTask, target, "Task")
	requireErr(p, challenge, task, [32]byte{}, "Target")
	changed = append([]byte{}, p...)
	changed[len(changed)-1] ^= 1
	requireErr(changed, challenge, task, target, "Transcript")
	changed = append([]byte{}, p...)
	first := binary.LittleEndian.Uint32(changed[4+2*Cells*4:])
	binary.LittleEndian.PutUint32(changed[4+2*Cells*4:], uint32((uint64(first)+1)%Q))
	requireErr(changed, challenge, task, target, "Product")
}
