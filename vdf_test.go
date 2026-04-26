package vdf

import (
	"math/big"
	"strings"
	"testing"
	"time"
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

func TestPayloadAPIVerifyCanonicalizesYBytes(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	payload := []byte("hello payload")
	proof, err := vdf.Prove(payload, 10)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	proof.Y = append([]byte{0}, proof.Y...)

	ok, err := vdf.Verify(payload, 10, proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected padded y proof to verify")
	}
}

func TestPayloadAPIVerifyRejectsOutOfRangeProofValues(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	payload := []byte("hello payload")
	proof, err := vdf.Prove(payload, 10)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	yProof := &Proof{
		Y:  new(big.Int).Add(new(big.Int).SetBytes(proof.Y), vdf.N).Bytes(),
		Pi: proof.Pi,
	}
	ok, err := vdf.Verify(payload, 10, yProof)
	if err != nil {
		t.Fatalf("verify y >= n: %v", err)
	}
	if ok {
		t.Fatal("expected y >= n to fail")
	}

	piProof := &Proof{
		Y:  proof.Y,
		Pi: new(big.Int).Add(new(big.Int).SetBytes(proof.Pi), vdf.N).Bytes(),
	}
	ok, err = vdf.Verify(payload, 10, piProof)
	if err != nil {
		t.Fatalf("verify pi >= n: %v", err)
	}
	if ok {
		t.Fatal("expected pi >= n to fail")
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

func TestProveAsyncProducesVerifiableProof(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	payload := []byte("async payload")
	status := vdf.ProveAsync(payload, 10)

	var proof Proof
	select {
	case got, ok := <-status.Result:
		if !ok {
			t.Fatal("result channel closed without proof")
		}
		proof = got
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for async prove")
	}

	ok, err := vdf.Verify(payload, 10, &proof)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected async proof to verify")
	}

	select {
	case err, ok := <-status.Err:
		if ok && err != nil {
			t.Fatalf("unexpected async error: %v", err)
		}
	default:
	}

	if progress := status.Progress; progress != 1 {
		t.Fatalf("expected progress to be 1, got %f", progress)
	}
}

func TestProveAsyncReturnsErrorForNegativeDifficulty(t *testing.T) {
	vdf, err := New(128, 32)
	if err != nil {
		t.Fatalf("new vdf: %v", err)
	}

	status := vdf.ProveAsync([]byte("payload"), -1)

	select {
	case err, ok := <-status.Err:
		if !ok {
			t.Fatal("error channel closed without error")
		}
		if err == nil {
			t.Fatal("expected non-nil error")
		}
		if !strings.Contains(err.Error(), "difficulty must be non-negative") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for async error")
	}

	select {
	case _, ok := <-status.Result:
		if ok {
			t.Fatal("unexpected proof on error path")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("result channel did not close after async error")
	}

	if progress := status.Progress; progress != 1 {
		t.Fatalf("expected progress to be 1, got %f", progress)
	}
}
