# VDF

Implementations of Wesolowski's verifiable delay function.

## Go RSA-group port


High-level API:

```go
vdf, _ := rsavdf.New(1024, 128)
proof, _ := vdf.Prove([]byte("payload"), 20)
ok, _ := vdf.Verify([]byte("payload"), 20, proof)
```

Async proving with progress:

```go
status := vdf.ProveAsync([]byte("payload"), 20)
for status.Progress < 1 {
	time.Sleep(50 * time.Millisecond)
}
if err, ok := <-status.Err; ok && err != nil {
	panic(err)
}
proof := <-status.Result
ok, _ := vdf.Verify([]byte("payload"), 20, &proof)
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

## Dart RSA-group port

High-level API:

```dart
final vdf = Wesolowski.create(1024, 128);
final proof = vdf.prove(Uint8List.fromList('payload'.codeUnits), 20);
final ok = vdf.verify(Uint8List.fromList('payload'.codeUnits), 20, proof);
```

Run tests:

```bash
/Users/user/sdk/flutter/bin/dart run test/vdf_test.dart
```

Run benchmarks:

```bash
/Users/user/sdk/flutter/bin/dart run benchmark/bench.dart
```

Run the demo CLI:

```bash
/Users/user/sdk/flutter/bin/dart run bin/rsa_vdf.dart 15 10
```
