import 'dart:convert';
import 'dart:typed_data';

import '../lib/vdf.dart';

const List<int> _proveDifficulties = <int>[500, 1000, 10000, 1000000];
const List<int> _verifyDifficulties = <int>[500, 1000, 10000];

const Map<int, int> _defaultProveIterations = <int, int>{
  500: 8,
  1000: 6,
  10000: 2,
  1000000: 1,
};

const Map<int, int> _defaultVerifyIterations = <int, int>{
  500: 200,
  1000: 150,
  10000: 60,
};

void main(List<String> args) {
  final multiplier = args.isNotEmpty ? int.parse(args.first) : 1;
  if (multiplier <= 0) {
    throw ArgumentError('iteration multiplier must be positive');
  }

  final payload = Uint8List.fromList(utf8.encode('benchmark-payload'));

  print('Dart Wesolowski VDF benchmark');
  print('iteration multiplier: $multiplier');
  print('');

  _benchmarkProve(payload, multiplier);
  print('');
  _benchmarkVerify(payload, multiplier);
}

void _benchmarkProve(Uint8List payload, int multiplier) {
  print('BenchmarkProve');

  for (final difficulty in _proveDifficulties) {
    final iterations = (_defaultProveIterations[difficulty] ?? 1) * multiplier;
    final vdf = _benchmarkVdf();

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      vdf.prove(payload, difficulty);
    }
    sw.stop();

    final totalMs = sw.elapsedMicroseconds / 1000.0;
    final avgMs = totalMs / iterations;

    print(
      '  difficulty=$difficulty iterations=$iterations '
      'total_ms=${totalMs.toStringAsFixed(3)} avg_ms=${avgMs.toStringAsFixed(3)}',
    );
  }
}

void _benchmarkVerify(Uint8List payload, int multiplier) {
  print('BenchmarkVerify');

  for (final difficulty in _verifyDifficulties) {
    final iterations = (_defaultVerifyIterations[difficulty] ?? 1) * multiplier;

    final prover = _benchmarkVdf();
    final proof = prover.prove(payload, difficulty);
    final verifier = Wesolowski.withPublicParams(prover.publicParams());

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      final ok = verifier.verify(payload, difficulty, proof);
      if (!ok) {
        throw StateError('verification failed at difficulty=$difficulty');
      }
    }
    sw.stop();

    final totalMs = sw.elapsedMicroseconds / 1000.0;
    final avgMs = totalMs / iterations;

    print(
      '  difficulty=$difficulty iterations=$iterations '
      'total_ms=${totalMs.toStringAsFixed(3)} avg_ms=${avgMs.toStringAsFixed(3)}',
    );
  }
}

Wesolowski _benchmarkVdf() {
  return Wesolowski.withModulus(_benchmarkModulus(), 128);
}

BigInt _benchmarkModulus() {
  final p = (BigInt.one << 521) - one;
  final q = (BigInt.one << 607) - one;
  return p * q;
}
