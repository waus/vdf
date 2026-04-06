package vdf

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// These are repository-published compatibility vectors for the payload API on a
// fixed public modulus. I did not locate a maintained upstream Wesolowski RSA-VDF
// vector suite with ready-made output/witness pairs, so these vectors lock down
// this implementation's public API across refactors and across prover/verifier instances.
var payloadVectors = []struct {
	name       string
	payload    string
	difficulty int
	modulusHex string
	outputHex  string
	witnessHex string
}{
	{
		name:       "difficulty-0",
		payload:    "vector-1",
		difficulty: 0,
		modulusHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
		outputHex:  "84798b7e1b817980f962b2adf61f950f9d91f9f91b5bfc5d95a40fd78b771708",
		witnessHex: "01",
	},
	{
		name:       "difficulty-17",
		payload:    "vector-2",
		difficulty: 17,
		modulusHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
		outputHex:  "4ac17f16907772b2f21d3196a242f99cfbbd332c128998fc3bbbfde9c3a3a50b6d2d787cc4aca5aa934e33d9b8a0b097c6bbfa4cd6e1972c0b9090f7932a664c899cc5aeda95300e8aa42227f7dd2f05fc966d939b5369896a8aee46a5f8c80330de93cc73f5e904877a50dad1d01eaa1e6a87a0b287732670d6b8a8cb7ff8b8d33cc9b4516a5fd29f8d7ed720",
		witnessHex: "01",
	},
	{
		name:       "difficulty-257",
		payload:    "vector-3",
		difficulty: 257,
		modulusHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
		outputHex:  "e938ffbd7a2fcfcaafdd90d947e1de46175b2fce48ddc8cf261dff620ccc7d55b4c70919330d6d65fa6652130b81fd69caa872d2ede408f00906721747ded152551201ec017702e66262b928a68de392f58cf451fc22ce30e6d443a48f1e09989da995afe5a10a9095f040feb0626fa8b9abb22ddd087a6f181d02f126579ca38a6085a99273af010555edc0d7",
		witnessHex: "aa0cbb0fc4e4c68a289727fc9c1cf2d79059cb37785b220aa285602dbe21c7f1730fc3fdfc7928449d36405fb4e44b1c354940d40ad076fce190157c7765aefe14b539099f675e5bda024612e1c0a773297618cff7adc7409bad0ec47add9cd1",
	},
}

func TestPayloadVectors(t *testing.T) {
	for _, tc := range payloadVectors {
		t.Run(tc.name, func(t *testing.T) {
			modulus := mustDecodeHexInt(t, tc.modulusHex)

			prover, err := NewWithModulus(modulus, 128)
			if err != nil {
				t.Fatalf("new prover: %v", err)
			}

			proof, err := prover.Prove([]byte(tc.payload), tc.difficulty)
			if err != nil {
				t.Fatalf("prove: %v", err)
			}

			if got := hex.EncodeToString(proof.Y); got != tc.outputHex {
				t.Fatalf("unexpected output\nwant: %s\ngot:  %s", tc.outputHex, got)
			}
			if got := hex.EncodeToString(proof.Pi); got != tc.witnessHex {
				t.Fatalf("unexpected witness\nwant: %s\ngot:  %s", tc.witnessHex, got)
			}

			verifier, err := NewWithPublicParams(prover.PublicParams())
			if err != nil {
				t.Fatalf("new verifier: %v", err)
			}

			ok, err := verifier.Verify([]byte(tc.payload), tc.difficulty, proof)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Fatal("expected vector proof to verify")
			}
		})
	}
}

func mustDecodeHexInt(t *testing.T, s string) *big.Int {
	t.Helper()

	bytes, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return new(big.Int).SetBytes(bytes)
}
