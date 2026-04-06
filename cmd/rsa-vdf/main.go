package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/waus/vdf"
)

func main() {
	lambda := flag.Int("lambda", 1024, "RSA modulus size in bits")
	k := flag.Int("k", 128, "security parameter in bits")
	flag.Parse()

	if flag.NArg() != 2 {
		exitf("usage: rsa-vdf [--lambda bits] [--k bits] <t> <num-vdfs>")
	}

	t, numVDFs, err := parseArgs(flag.Arg(0), flag.Arg(1))
	if err != nil {
		exitf("parse args: %v", err)
	}

	if t >= strconv.IntSize-1 {
		exitf("t=%d is too large for this CLI on the current platform", t)
	}
	squarings := 1 << uint(t)

	start := time.Now()
	vdf, err := vdf.New(*lambda, *k)
	if err != nil {
		exitf("setup vdf: %v", err)
	}

	xs := make([]*big.Int, 0, numVDFs)
	ys := make([]*big.Int, 0, numVDFs)
	pis := make([]*big.Int, 0, numVDFs)
	alphas := make([]*big.Int, 0, numVDFs)

	for i := 0; i < numVDFs; i++ {
		x, err := vdf.Generate()
		if err != nil {
			exitf("generate x[%d]: %v", i, err)
		}
		alpha, err := vdf.GenerateAlpha(*k)
		if err != nil {
			exitf("generate alpha[%d]: %v", i, err)
		}

		xs = append(xs, x)
		alphas = append(alphas, alpha)
	}

	l := big.NewInt(65537)
	fmt.Printf("Time cost for setup: %v\n", time.Since(start).Seconds())

	start = time.Now()
	for i := 0; i < numVDFs; i++ {
		pi, y, err := vdf.Evaluate(l, xs[i], squarings)
		if err != nil {
			exitf("evaluate[%d]: %v", i, err)
		}
		pis = append(pis, pi)
		ys = append(ys, y)
	}
	fmt.Printf("Time cost for evaluate: %v\n", time.Since(start).Seconds())

	start = time.Now()
	piAgg, xAgg, yAgg, err := vdf.Aggregate(pis, xs, ys, alphas)
	if err != nil {
		exitf("aggregate: %v", err)
	}
	aggregateTime := time.Since(start)
	fmt.Printf("Time cost for aggregate: %v\n", aggregateTime.Seconds())

	start = time.Now()
	for i := 0; i < numVDFs; i++ {
		ok, err := vdf.NaiveVerify(xs[i], ys[i], squarings, l, pis[i])
		if err != nil {
			exitf("verify[%d]: %v", i, err)
		}
		if !ok {
			exitf("individual verification failed at index %d", i)
		}
	}
	fmt.Printf("Time cost for individual verification: %v\n", time.Since(start).Seconds())

	start = time.Now()
	ok, err := vdf.NaiveVerify(xAgg, yAgg, squarings, l, piAgg)
	if err != nil {
		exitf("batch verify: %v", err)
	}
	if !ok {
		exitf("batch verification failed")
	}
	fmt.Printf("Time cost for aggregation and batch verification: %v\n", aggregateTime.Seconds()+time.Since(start).Seconds())
}

func parseArgs(tArg, countArg string) (int, int, error) {
	var t, count int
	if _, err := fmt.Sscanf(tArg, "%d", &t); err != nil {
		return 0, 0, err
	}
	if _, err := fmt.Sscanf(countArg, "%d", &count); err != nil {
		return 0, 0, err
	}
	if t < 0 {
		return 0, 0, errors.New("t must be non-negative")
	}
	if count <= 0 {
		return 0, 0, errors.New("num-vdfs must be positive")
	}
	return t, count, nil
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
