# VDF

Implementations of Wesolowski's verifiable delay function.

## Go RSA-group port


High-level API:

```go
vdf, _ := rsavdf.New(1024, 128)
proof, _ := vdf.Prove([]byte("payload"), 20)
ok, _ := vdf.Verify([]byte("payload"), 20, proof)
```

Export and reuse public parameters in another process:

```go
prover, _ := rsavdf.New(1024, 128)
params := prover.PublicParams()

verifier, _ := rsavdf.NewWithPublicParams(params)
proof, _ := prover.Prove([]byte("payload"), 20)
ok, _ := verifier.Verify([]byte("payload"), 20, proof)
```

Benchmarks:

```bash
go test -bench . ./rsavdf
```

Run the demo CLI:

```bash
go run ./cmd/rsa-vdf 15 10
```

Optional flags:

```bash
go run ./cmd/rsa-vdf --lambda 1024 --k 128 15 10
```
