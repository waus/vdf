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

Async proving with progress:

```dart
final proof = await vdf.proveAsync(
  Uint8List.fromList('payload'.codeUnits),
  20,
  onProgress: (progress) {
    print('${(progress.completion * 100).toStringAsFixed(1)}%');
  },
);
```

Run tests:

```bash
flutter/bin/dart run test/vdf_test.dart
```

Run benchmarks:

```bash
flutter/bin/dart run benchmark/bench.dart
```

## Rust RSA-group port

High-level API:

```rust
let vdf = optimized_vdf::Wesolowski::with_modulus(modulus, 128)?;
let proof = vdf.prove(b"payload", 20)?;
let ok = vdf.verify(b"payload", 20, &proof)?;
```

Run tests:

```bash
cargo test
```

Run the Rust benchmark:

```bash
cargo run --release --bin bench -- 15000000
```

Compare payload proving at a large difficulty across implementations:

```bash
cargo run --release --bin bench -- 15000000
VDF_BENCH_DIFFICULTIES=15000000 go test -run '^$' -bench 'BenchmarkProve' -benchtime=1x
VDF_BENCH_DIFFICULTIES=15000000 flutter/bin/dart run benchmark/bench.dart
```

The Dart benchmark uses the native Rust backend automatically when it is
available through the package's normal native asset loading or
`VDFRSA_NATIVE_LIB`.

Run the demo CLI:

```bash
flutter/bin/dart run bin/rsa_vdf.dart 15 10
```

Native acceleration is built from Rust and bundled through Dart/Flutter native
assets. Install the Rust toolchain and the target triples you need:

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

Then run the Dart or Flutter app normally:

```bash
flutter/bin/dart run example/native_backend_status.dart
flutter/bin/flutter run -d macos
```

The native assets build hook runs `cargo build --release --target <triple>` and
bundles
`libvdfrsa_native.dylib`/`.so`/`.dll` into the consuming application. In Flutter
macOS debug builds the library is expected in the app bundle under
`Contents/Frameworks/libvdfrsa_native.dylib`.

Manual native-library override remains available for debugging:

```bash
cargo build --release
export VDFRSA_NATIVE_LIB="$PWD/target/release/liboptimized_vdf.dylib" # macOS
```

`VDFRSA_NATIVE_LIB` takes precedence over the bundled asset. When neither the
override nor the bundled asset can be loaded, the package keeps the pure Dart
fallback and exposes the reason through `VdfNativeBackend.loadError`.

When available, the native backend accelerates `prove(...)` and
`proveAsync(...)` through Rust-backed `dart:ffi` bindings. Verification stays on
pure Dart. `Wesolowski.hasNativeBackend` and
`Wesolowski.proveWithNativeBackend(...)` remain available for explicit checks.
