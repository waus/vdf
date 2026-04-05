package vdf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	N         *big.Int
	P         *big.Int
	Q         *big.Int
	Lambda    int
	K         int
	challenge *big.Int
	reader    io.Reader
}

// PublicParams are the public VDF parameters needed for proof verification
// and for proof generation in another process that shares the same RSA modulus.
type PublicParams struct {
	Modulus []byte
	Lambda  int
	K       int
}

// Proof is the compact public proof format for payload-based proving and verification.
// Output is y = x^(2^difficulty) mod N, and Witness is the Wesolowski proof pi.
type Proof struct {
	Output  []byte
	Witness []byte
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
		N:         n,
		P:         p,
		Q:         q,
		Lambda:    lambda,
		K:         k,
		challenge: new(big.Int),
		reader:    reader,
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
		N:         new(big.Int).Set(modulus),
		Lambda:    modulus.BitLen(),
		K:         k,
		challenge: new(big.Int),
		reader:    reader,
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

// HashPrime matches the current C++ behavior: it samples a random 2k-bit value once
// and reuses the next prime derived from it for all inputs in the batch.
func (w *Wesolowski) HashPrime(_ *big.Int) (*big.Int, error) {
	if w.challenge.Sign() == 0 {
		limit := new(big.Int).Lsh(big.NewInt(1), uint(2*w.K))
		challenge, err := rand.Int(w.reader, limit)
		if err != nil {
			return nil, fmt.Errorf("sample challenge: %w", err)
		}
		w.challenge.Set(challenge)
	}

	return nextPrime(w.challenge), nil
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
		Output:  y.Bytes(),
		Witness: pi.Bytes(),
	}, nil
}

// Verify checks a proof for the given payload and difficulty.
func (w *Wesolowski) Verify(payload []byte, difficulty int, proof *Proof) (bool, error) {
	if difficulty < 0 {
		return false, fmt.Errorf("difficulty must be non-negative, got %d", difficulty)
	}
	if proof == nil {
		return false, errors.New("proof must not be nil")
	}
	if len(proof.Output) == 0 {
		return false, errors.New("proof output must not be empty")
	}
	if len(proof.Witness) == 0 {
		return false, errors.New("proof witness must not be empty")
	}

	x := w.inputFromPayload(payload)
	y := new(big.Int).SetBytes(proof.Output)
	pi := new(big.Int).SetBytes(proof.Witness)
	l := w.primeFromStatement(payload, difficulty, proof.Output)

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
