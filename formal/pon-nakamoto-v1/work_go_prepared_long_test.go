// Extended reuse-horizon research. The measured costs include one preparation
// per horizon, every complete proof attempt, and all failed lottery attempts
// (there is no target-based early exit). This is not a hardware lower bound.
package main

import (
	"fmt"
	"testing"
)

func BenchmarkPreparedLongReuseHorizon(b *testing.B) {
	for _, shape := range []string{"maintenance", "dense", "zero", "rank1", "sparse"} {
		for _, attempts := range []int{64, 256} {
			a, bb, err := preparedMaterials(shape, 17)
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%s/generic/%d", shape, attempts), func(b *testing.B) {
				b.ReportAllocs()
				for sample := 0; sample < b.N; sample++ {
					for n := 0; n < attempts; n++ {
						if _, err := Prove(preparedChallenge(shape, 17, uint32(n)), a, bb); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
			b.Run(fmt.Sprintf("%s/prepared/%d", shape, attempts), func(b *testing.B) {
				b.ReportAllocs()
				for sample := 0; sample < b.N; sample++ {
					producer, err := PrepareW1Task(a, bb)
					if err != nil {
						b.Fatal(err)
					}
					for n := 0; n < attempts; n++ {
						if _, err := producer.Prove(preparedChallenge(shape, 17, uint32(n))); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
