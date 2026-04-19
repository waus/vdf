package vdf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

var one = big.NewInt(1)
var two = big.NewInt(2)
var nextPrimeSmallTable = [...]int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
	67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
	139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
	223, 227, 229, 233, 239, 241, 251,
}
var nextPrimeSievePrimes = [...]uint16{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
	67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
	139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
	223, 227, 229, 233, 239, 241, 251,
}
var nextPrimeBigPrimes = func() []*big.Int {
	primes := make([]*big.Int, len(nextPrimeSievePrimes))
	for i, p := range nextPrimeSievePrimes {
		primes[i] = big.NewInt(int64(p))
	}
	return primes
}()

// Wesolowski implements the RSA-group VDF flow used by the original C++ code.
type Wesolowski struct {
	N      *big.Int
	P      *big.Int
	Q      *big.Int
	Lambda int
	K      int
	reader io.Reader
}

// PublicParams are the public VDF parameters needed for proof verification
// and for proof generation in another process that shares the same RSA modulus.
type PublicParams struct {
	Modulus []byte
	Lambda  int
	K       int
}

// Proof is the compact public proof format for payload-based proving and verification.
// Y is y = x^(2^difficulty) mod N, and Pi is the Wesolowski proof pi.
type Proof struct {
	Y  []byte
	Pi []byte
}

const (
	progressTickInterval     = 50 * time.Millisecond
	progressPhaseHeadroom    = 0.98
	defaultProgressNsPerUnit = int64(1_500)
)

// ProverStatus reports the state of an asynchronous proof generation.
type ProverStatus struct {
	Result <-chan Proof
	Err    <-chan error

	Progress float32
}

func (s *ProverStatus) setProgress(v float32) {
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	s.Progress = v
}

func New(lambda, k int) (*Wesolowski, error) {
	return NewWithReader(lambda, k, rand.Reader)
}

func NewWithModulus(modulus *big.Int, k int) (*Wesolowski, error) {
	return NewWithModulusAndReader(modulus, k, rand.Reader)
}

func NewWithPublicParams(params PublicParams) (*Wesolowski, error) {
	if len(params.Modulus) == 0 {
		return nil, errors.New("public modulus must not be empty")
	}

	modulus := new(big.Int).SetBytes(params.Modulus)
	if params.Lambda != 0 && modulus.BitLen() != params.Lambda {
		return nil, fmt.Errorf("lambda mismatch: got %d, modulus bit length is %d", params.Lambda, modulus.BitLen())
	}

	return NewWithModulusAndReader(modulus, params.K, rand.Reader)
}

func NewWithReader(lambda, k int, reader io.Reader) (*Wesolowski, error) {
	if lambda < 16 {
		return nil, fmt.Errorf("lambda must be at least 16 bits, got %d", lambda)
	}
	if lambda%2 != 0 {
		return nil, fmt.Errorf("lambda must be even, got %d", lambda)
	}
	if k < 2 {
		return nil, fmt.Errorf("k must be at least 2 bits, got %d", k)
	}
	if reader == nil {
		return nil, errors.New("reader must not be nil")
	}

	p, err := rand.Prime(reader, lambda/2)
	if err != nil {
		return nil, fmt.Errorf("generate p: %w", err)
	}

	q, err := rand.Prime(reader, lambda/2)
	if err != nil {
		return nil, fmt.Errorf("generate q: %w", err)
	}

	n := new(big.Int).Mul(p, q)

	return &Wesolowski{
		N:      n,
		P:      p,
		Q:      q,
		Lambda: lambda,
		K:      k,
		reader: reader,
	}, nil
}

func NewWithModulusAndReader(modulus *big.Int, k int, reader io.Reader) (*Wesolowski, error) {
	if modulus == nil {
		return nil, errors.New("modulus must not be nil")
	}
	if modulus.Cmp(two) <= 0 {
		return nil, errors.New("modulus must be greater than 2")
	}
	if modulus.Bit(0) == 0 {
		return nil, errors.New("modulus must be odd")
	}
	if k < 2 {
		return nil, fmt.Errorf("k must be at least 2 bits, got %d", k)
	}
	if reader == nil {
		return nil, errors.New("reader must not be nil")
	}

	return &Wesolowski{
		N:      new(big.Int).Set(modulus),
		Lambda: modulus.BitLen(),
		K:      k,
		reader: reader,
	}, nil
}

func (w *Wesolowski) PublicParams() PublicParams {
	return PublicParams{
		Modulus: append([]byte(nil), w.N.Bytes()...),
		Lambda:  w.N.BitLen(),
		K:       w.K,
	}
}

func (w *Wesolowski) Generate() (*big.Int, error) {
	return rand.Int(w.reader, w.N)
}

func (w *Wesolowski) GenerateAlpha(bitSize int) (*big.Int, error) {
	if bitSize <= 0 {
		return nil, fmt.Errorf("bit size must be positive, got %d", bitSize)
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bitSize))
	return rand.Int(w.reader, limit)
}

func (w *Wesolowski) Evaluate(l, x *big.Int, squarings int) (pi, y *big.Int, err error) {
	if l == nil || l.Sign() <= 0 {
		return nil, nil, errors.New("l must be a positive integer")
	}
	if x == nil || x.Sign() < 0 {
		return nil, nil, errors.New("x must be a non-negative integer")
	}
	if squarings < 0 {
		return nil, nil, fmt.Errorf("squarings must be non-negative, got %d", squarings)
	}

	exp := twoPow(squarings)
	y = new(big.Int).Exp(x, exp, w.N)

	q := new(big.Int).Quo(exp, l)
	pi = new(big.Int).Exp(x, q, w.N)

	return pi, y, nil
}

func (w *Wesolowski) Aggregate(piList, xList, yList, alphas []*big.Int) (piAgg, xAgg, yAgg *big.Int, err error) {
	size := len(piList)
	if size == 0 {
		return nil, nil, nil, errors.New("cannot aggregate an empty batch")
	}
	if len(xList) != size || len(yList) != size || len(alphas) != size {
		return nil, nil, nil, errors.New("batch slices must have identical lengths")
	}

	piAgg = big.NewInt(1)
	xAgg = big.NewInt(1)
	yAgg = big.NewInt(1)

	for i := 0; i < size; i++ {
		if piList[i] == nil || xList[i] == nil || yList[i] == nil || alphas[i] == nil {
			return nil, nil, nil, fmt.Errorf("nil element at index %d", i)
		}

		xPow := new(big.Int).Exp(xList[i], alphas[i], w.N)
		xAgg.Mul(xAgg, xPow).Mod(xAgg, w.N)

		piPow := new(big.Int).Exp(piList[i], alphas[i], w.N)
		piAgg.Mul(piAgg, piPow).Mod(piAgg, w.N)

		yPow := new(big.Int).Exp(yList[i], alphas[i], w.N)
		yAgg.Mul(yAgg, yPow).Mod(yAgg, w.N)
	}

	return piAgg, xAgg, yAgg, nil
}

func (w *Wesolowski) NaiveVerify(x, y *big.Int, squarings int, l, pi *big.Int) (bool, error) {
	if x == nil || y == nil || l == nil || pi == nil {
		return false, errors.New("x, y, l and pi must all be non-nil")
	}
	if squarings < 0 {
		return false, fmt.Errorf("squarings must be non-negative, got %d", squarings)
	}
	if l.Cmp(one) <= 0 {
		return false, errors.New("l must be greater than 1")
	}

	r := verifyExponent(squarings, l)

	left := new(big.Int).Exp(pi, l, w.N)
	right := new(big.Int).Exp(x, r, w.N)

	got := new(big.Int).Mul(left, right)
	got.Mod(got, w.N)

	return got.Cmp(y) == 0, nil
}

// Prove creates a proof for the given payload and difficulty.
// The payload is deterministically mapped into the RSA group, so the caller only
// needs the original payload, the agreed difficulty, and the returned proof bytes.
func (w *Wesolowski) Prove(payload []byte, difficulty int) (*Proof, error) {
	if difficulty < 0 {
		return nil, fmt.Errorf("difficulty must be non-negative, got %d", difficulty)
	}

	x := w.inputFromPayload(payload)
	exp := twoPow(difficulty)
	y := new(big.Int).Exp(x, exp, w.N)
	l := w.primeFromStatement(payload, difficulty, y.Bytes())

	q := new(big.Int).Quo(exp, l)
	pi := new(big.Int).Exp(x, q, w.N)

	return &Proof{
		Y:  y.Bytes(),
		Pi: pi.Bytes(),
	}, nil
}

// ProveAsync starts proving in a separate goroutine and reports progress in [0, 1].
// The progress estimator is based on the two dominant modular exponentiation phases.
func (w *Wesolowski) ProveAsync(payload []byte, difficulty int) *ProverStatus {
	resultCh := make(chan Proof, 1)
	errCh := make(chan error, 1)
	status := &ProverStatus{
		Result: resultCh,
		Err:    errCh,
	}
	status.setProgress(0)

	go func() {
		defer close(resultCh)
		defer close(errCh)

		if difficulty < 0 {
			errCh <- fmt.Errorf("difficulty must be non-negative, got %d", difficulty)
			status.setProgress(1)
			return
		}

		x := w.inputFromPayload(payload)
		exp := twoPow(difficulty)

		firstWork := estimatePow2ExpWork(difficulty)
		firstWeight := float32(0.5)
		stageOneDone := make(chan struct{})
		stageOneStart := time.Now()
		go runProgressAnimator(status, 0, firstWeight, firstWork, defaultProgressNsPerUnit, stageOneDone)

		y := new(big.Int).Exp(x, exp, w.N)
		close(stageOneDone)

		l := w.primeFromStatement(payload, difficulty, y.Bytes())
		q := new(big.Int).Quo(exp, l)
		secondWork := estimateExpWork(q)

		totalWork := firstWork + secondWork
		if totalWork > 0 {
			firstWeight = float32(firstWork) / float32(totalWork)
		}
		status.setProgress(firstWeight)

		nsPerUnit := estimateNsPerUnit(time.Since(stageOneStart), firstWork)
		secondWeight := float32(1) - firstWeight
		stageTwoDone := make(chan struct{})
		go runProgressAnimator(status, firstWeight, secondWeight, secondWork, nsPerUnit, stageTwoDone)

		pi := new(big.Int).Exp(x, q, w.N)
		close(stageTwoDone)

		status.setProgress(1)
		resultCh <- Proof{
			Y:  y.Bytes(),
			Pi: pi.Bytes(),
		}
	}()

	return status
}

// Verify checks a proof for the given payload and difficulty.
func (w *Wesolowski) Verify(payload []byte, difficulty int, proof *Proof) (bool, error) {
	if difficulty < 0 {
		return false, fmt.Errorf("difficulty must be non-negative, got %d", difficulty)
	}
	if proof == nil {
		return false, errors.New("proof must not be nil")
	}
	if len(proof.Y) == 0 {
		return false, errors.New("proof y must not be empty")
	}
	if len(proof.Pi) == 0 {
		return false, errors.New("proof pi must not be empty")
	}

	x := w.inputFromPayload(payload)
	y := new(big.Int).SetBytes(proof.Y)
	pi := new(big.Int).SetBytes(proof.Pi)
	l := w.primeFromStatement(payload, difficulty, proof.Y)

	return w.NaiveVerify(x, y, difficulty, l, pi)
}

func twoPow(power int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(power))
}

func (w *Wesolowski) inputFromPayload(payload []byte) *big.Int {
	x := w.expandHashToInt("rsavdf:x:v1", 0, payload, nil)
	x.Mod(x, w.N)
	if x.Sign() == 0 {
		x.Set(one)
	}
	return x
}

func (w *Wesolowski) primeFromStatement(payload []byte, difficulty int, output []byte) *big.Int {
	n := w.expandHashToInt("rsavdf:l:v1", difficulty, payload, output)
	return nextPrime(n)
}

func (w *Wesolowski) expandHashToInt(domain string, difficulty int, payload []byte, extra []byte) *big.Int {
	byteLen := (2*w.K + 7) / 8
	if byteLen < sha256.Size {
		byteLen = sha256.Size
	}

	buf := make([]byte, 0, byteLen)
	counter := uint32(0)
	diffBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(diffBytes, uint64(difficulty))

	for len(buf) < byteLen {
		h := sha256.New()
		h.Write([]byte(domain))
		h.Write(diffBytes)
		h.Write(payload)
		h.Write(extra)

		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		h.Write(counterBytes[:])

		buf = append(buf, h.Sum(nil)...)
		counter++
	}

	return new(big.Int).SetBytes(buf[:byteLen])
}

func nextPrime(n *big.Int) *big.Int {
	if n == nil {
		return big.NewInt(2)
	}

	candidate := new(big.Int).Set(n)
	if candidate.Cmp(two) < 0 {
		return big.NewInt(2)
	}
	if candidate.Cmp(two) == 0 {
		return big.NewInt(2)
	}
	if candidate.Bit(0) == 0 {
		candidate.Add(candidate, one)
	}

	if candidate.BitLen() <= 6 {
		value := candidate.Int64()
		for _, p := range nextPrimeSmallTable {
			if value <= p {
				return big.NewInt(p)
			}
		}
	}

	var residues [len(nextPrimeSievePrimes)]uint16
	var mod big.Int
	for i, p := range nextPrimeBigPrimes {
		mod.Mod(candidate, p)
		residues[i] = uint16(mod.Uint64())
	}

	for !passesSmallPrimeSieve(residues[:]) || !candidate.ProbablyPrime(0) {
		candidate.Add(candidate, two)
		advanceSieveResidues(residues[:])
	}
	return candidate
}

func passesSmallPrimeSieve(residues []uint16) bool {
	for _, residue := range residues {
		if residue == 0 {
			return false
		}
	}
	return true
}

func advanceSieveResidues(residues []uint16) {
	for i, residue := range residues {
		next := residue + 2
		modulus := nextPrimeSievePrimes[i]
		if next >= modulus {
			next -= modulus
		}
		residues[i] = next
	}
}

func verifyExponent(squarings int, l *big.Int) *big.Int {
	phiL := new(big.Int).Sub(l, one)
	tauMod := new(big.Int).SetInt64(int64(squarings))
	if phiL.Sign() > 0 {
		tauMod.Mod(tauMod, phiL)
	}
	return new(big.Int).Exp(two, tauMod, l)
}

func estimateExpWork(exp *big.Int) int {
	if exp == nil || exp.Sign() <= 0 {
		return 1
	}

	bitLen := exp.BitLen()
	if bitLen <= 1 {
		return 1
	}

	if new(big.Int).And(exp, new(big.Int).Sub(exp, one)).Sign() == 0 {
		return bitLen - 1
	}

	squarings := bitLen - 1
	expectedMultiplies := (bitLen + 1) / 2
	return squarings + expectedMultiplies
}

func estimatePow2ExpWork(power int) int {
	if power <= 0 {
		return 1
	}
	return power
}

func estimateNsPerUnit(duration time.Duration, work int) int64 {
	if duration <= 0 || work <= 0 {
		return defaultProgressNsPerUnit
	}
	ns := duration.Nanoseconds() / int64(work)
	if ns <= 0 {
		return defaultProgressNsPerUnit
	}
	return ns
}

func runProgressAnimator(status *ProverStatus, base, weight float32, work int, nsPerUnit int64, done <-chan struct{}) {
	if weight <= 0 {
		return
	}
	if work <= 0 {
		work = 1
	}
	if nsPerUnit <= 0 {
		nsPerUnit = defaultProgressNsPerUnit
	}

	estimate := time.Duration(int64(work) * nsPerUnit)
	if estimate < progressTickInterval {
		estimate = progressTickInterval
	}

	ticker := time.NewTicker(progressTickInterval)
	defer ticker.Stop()
	start := time.Now()

	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			frac := float32(now.Sub(start)) / float32(estimate)
			if frac < 0 {
				frac = 0
			}
			if frac > progressPhaseHeadroom {
				frac = progressPhaseHeadroom
			}
			status.setProgress(base + weight*frac)
		}
	}
}
