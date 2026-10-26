// Command w1oracle emits deterministic scalar-W1 proof identities for a fixed
// public research task. Its challenge is NOT an admitted native block header.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"trillionnium.org/research/w1falsification"
)

func main() {
	a := make([]uint32, 4096)
	b := make([]uint32, 4096)
	for i := range a {
		a[i] = uint32((13*i + 17) % 257)
		b[i] = uint32((29*i + 31) % 263)
	}
	challenge := w1falsification.H("challenge", []byte("stable-pow-input"))
	task, e := w1falsification.TaskID(a, b)
	if e != nil {
		panic(e)
	}
	proof, e := w1falsification.Proof(challenge, a, b)
	if e != nil {
		panic(e)
	}
	digest := sha256.Sum256(proof)
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema": "pon-independent-w1-scalar-go-v1", "proof_sha256": hex.EncodeToString(digest[:]),
		"challenge": hex.EncodeToString(challenge[:]), "task": hex.EncodeToString(task[:]),
		"trace": hex.EncodeToString(proof[len(proof)-32:]), "proof_bytes": len(proof),
		"consensus_activation": false, "work_hardness_accepted": false,
	})
}
