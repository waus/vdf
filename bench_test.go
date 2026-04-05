package vdf

import (
	"fmt"
	"math/big"
	"testing"
)

func BenchmarkProve(b *testing.B) {
	benchmarkDifficulties := []int{500, 1000, 10_000, 1_000_000}
	payload := []byte("benchmark-payload")

	for _, difficulty := range benchmarkDifficulties {
		b.Run(fmt.Sprintf("difficulty=%d", difficulty), func(b *testing.B) {
			vdf := mustBenchmarkVDF(b)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := vdf.Prove(payload, difficulty); err != nil {
					b.Fatalf("prove: %v", err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	benchmarkDifficulties := []int{500, 1000, 10000}
	payload := []byte("benchmark-payload")

	for _, difficulty := range benchmarkDifficulties {
		b.Run(fmt.Sprintf("difficulty=%d", difficulty), func(b *testing.B) {
			prover := mustBenchmarkVDF(b)
			proof, err := prover.Prove(payload, difficulty)
			if err != nil {
				b.Fatalf("prove setup: %v", err)
			}

			verifier, err := NewWithPublicParams(prover.PublicParams())
			if err != nil {
				b.Fatalf("new verifier: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				ok, err := verifier.Verify(payload, difficulty, proof)
				if err != nil {
					b.Fatalf("verify: %v", err)
				}
				if !ok {
					b.Fatal("verification failed")
				}
			}
		})
	}
}

func mustBenchmarkVDF(b *testing.B) *Wesolowski {
	b.Helper()

	vdf, err := NewWithModulus(benchmarkModulus(), 128)
	if err != nil {
		b.Fatalf("new with modulus: %v", err)
	}
	return vdf
}

func benchmarkModulus() *big.Int {
	// Fixed odd composite modulus built from two known Mersenne primes:
	// (2^521 - 1) * (2^607 - 1). It keeps benchmarks deterministic and avoids
	// runtime RSA key generation noise in the measurements.
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 521), one)
	q := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 607), one)
	return new(big.Int).Mul(p, q)
}
