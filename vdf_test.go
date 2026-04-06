package vdf

import (
	"math/big"
	"testing"
)

var testChallengePrime = big.NewInt(65537)

func TestNextPrimeSmallValues(t *testing.T) {
	tests := []struct {
		in   int64
		want int64
	}{
		{-5, 2},
		{0, 2},
		{1, 2},
		{2, 2},
		{3, 3},
		{4, 5},
		{20, 23},
		{24, 29},
	}

	for _, tt := range tests {
		got := nextPrime(big.NewInt(tt.in))
		if got.Int64() != tt.want {
			t.Fatalf("nextPrime(%d) = %d, want %d", tt.in, got.Int64(), tt.want)
		}
	}
}

func TestNextPrimeRejectsKnownPseudoprimes(t *testing.T) {
	inputs := []string{
		"989",
		"3239",
		"5777",
		"10877",
		"1195068768795265792518361315725116351898245581",
	}

	for _, input := range inputs {
		n, ok := new(big.Int).SetString(input, 10)
		if !ok {
			t.Fatalf("parse test input %q", input)
		}

		prime := nextPrime(n)
		if prime.Cmp(n) == 0 {
			t.Fatalf("nextPrime(%s) returned composite input unchanged", input)
		}
		if !prime.ProbablyPrime(20) {
			t.Fatalf("nextPrime(%s) returned non-prime %s", input, prime.String())
		}
	}
}

func TestEvaluateAndVerify(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	x, err := vdf.Generate()
	if err != nil {
		t.Fatalf("generate x: %v", err)
	}

	l := testChallengePrime

	pi, y, err := vdf.Evaluate(l, x, 16)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	ok, err := vdf.NaiveVerify(x, y, 16, l, pi)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected proof to verify")
	}
}

func TestAggregateAndVerify(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	var (
		xs     []*big.Int
		ys     []*big.Int
		pis    []*big.Int
		alphas []*big.Int
	)

	l := testChallengePrime

	for range 4 {
		x, err := vdf.Generate()
		if err != nil {
			t.Fatalf("generate x: %v", err)
		}
		alpha, err := vdf.GenerateAlpha(vdf.K)
		if err != nil {
			t.Fatalf("generate alpha: %v", err)
		}
		pi, y, err := vdf.Evaluate(l, x, 8)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}

		xs = append(xs, x)
		ys = append(ys, y)
		pis = append(pis, pi)
		alphas = append(alphas, alpha)
	}

	piAgg, xAgg, yAgg, err := vdf.Aggregate(pis, xs, ys, alphas)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}

	ok, err := vdf.NaiveVerify(xAgg, yAgg, 8, l, piAgg)
	if err != nil {
		t.Fatalf("verify aggregate: %v", err)
	}
	if !ok {
		t.Fatal("expected aggregate proof to verify")
	}
}

func TestVerifyRejectsWrongOutput(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	x, err := vdf.Generate()
	if err != nil {
		t.Fatalf("generate x: %v", err)
	}

	l := testChallengePrime

	pi, y, err := vdf.Evaluate(l, x, 12)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	y.Add(y, one)
	ok, err := vdf.NaiveVerify(x, y, 12, l, pi)
	if err != nil {
		t.Fatalf("verify wrong output: %v", err)
	}
	if ok {
		t.Fatal("expected tampered output to fail verification")
	}
}

func TestPayloadAPIProveAndVerify(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	payload := []byte("hello payload")
	proof, err := vdf.Prove(payload, 10)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	ok, err := vdf.Verify(payload, 10, proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected payload proof to verify")
	}
}

func TestPayloadAPIDetectsPayloadMismatch(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	proof, err := vdf.Prove([]byte("payload-a"), 9)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	ok, err := vdf.Verify([]byte("payload-b"), 9, proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for different payload")
	}
}

func TestPayloadAPIDetectsDifficultyMismatch(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	proof, err := vdf.Prove([]byte("payload"), 9)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	ok, err := vdf.Verify([]byte("payload"), 10, proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for different difficulty")
	}
}

func TestPublicParamsAllowCrossInstanceVerification(t *testing.T) {
	prover, err := New(128, 32)
	if err != nil {
		t.Fatalf("new prover: %v", err)
	}

	proof, err := prover.Prove([]byte("payload"), 11)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	verifier, err := NewWithPublicParams(prover.PublicParams())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	ok, err := verifier.Verify([]byte("payload"), 11, proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed with shared public params")
	}
}
