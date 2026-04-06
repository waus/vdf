import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../lib/vdf.dart';

class _NamedTest {
  const _NamedTest(this.name, this.body);

  final String name;
  final void Function() body;
}

class _PayloadVector {
  const _PayloadVector({
    required this.name,
    required this.payload,
    required this.difficulty,
    required this.modulusHex,
    required this.outputHex,
    required this.witnessHex,
  });

  final String name;
  final String payload;
  final int difficulty;
  final String modulusHex;
  final String outputHex;
  final String witnessHex;
}

final List<_PayloadVector> _payloadVectors = <_PayloadVector>[
  const _PayloadVector(
    name: 'difficulty-0',
    payload: 'vector-1',
    difficulty: 0,
    modulusHex:
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
    outputHex:
        '84798b7e1b817980f962b2adf61f950f9d91f9f91b5bfc5d95a40fd78b771708',
    witnessHex: '01',
  ),
  const _PayloadVector(
    name: 'difficulty-17',
    payload: 'vector-2',
    difficulty: 17,
    modulusHex:
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
    outputHex:
        '4ac17f16907772b2f21d3196a242f99cfbbd332c128998fc3bbbfde9c3a3a50b6d2d787cc4aca5aa934e33d9b8a0b097c6bbfa4cd6e1972c0b9090f7932a664c899cc5aeda95300e8aa42227f7dd2f05fc966d939b5369896a8aee46a5f8c80330de93cc73f5e904877a50dad1d01eaa1e6a87a0b287732670d6b8a8cb7ff8b8d33cc9b4516a5fd29f8d7ed720',
    witnessHex: '01',
  ),
  const _PayloadVector(
    name: 'difficulty-257',
    payload: 'vector-3',
    difficulty: 257,
    modulusHex:
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
    outputHex:
        'e938ffbd7a2fcfcaafdd90d947e1de46175b2fce48ddc8cf261dff620ccc7d55b4c70919330d6d65fa6652130b81fd69caa872d2ede408f00906721747ded152551201ec017702e66262b928a68de392f58cf451fc22ce30e6d443a48f1e09989da995afe5a10a9095f040feb0626fa8b9abb22ddd087a6f181d02f126579ca38a6085a99273af010555edc0d7',
    witnessHex:
        'aa0cbb0fc4e4c68a289727fc9c1cf2d79059cb37785b220aa285602dbe21c7f1730fc3fdfc7928449d36405fb4e44b1c354940d40ad076fce190157c7765aefe14b539099f675e5bda024612e1c0a773297618cff7adc7409bad0ec47add9cd1',
  ),
];
final BigInt _testChallengePrime = BigInt.from(65537);

void main() {
  final tests = <_NamedTest>[
    _NamedTest('nextPrime small values', _testNextPrimeSmallValues),
    _NamedTest('nextPrime rejects known pseudoprimes', _testPseudoprimes),
    _NamedTest('evaluate and verify', _testEvaluateAndVerify),
    _NamedTest('aggregate and verify', _testAggregateAndVerify),
    _NamedTest('verify rejects wrong output', _testVerifyRejectsWrongOutput),
    _NamedTest('payload prove and verify', _testPayloadApiProveAndVerify),
    _NamedTest('payload mismatch fails', _testPayloadMismatch),
    _NamedTest('difficulty mismatch fails', _testDifficultyMismatch),
    _NamedTest('public params cross-instance verification', _testPublicParams),
    _NamedTest('payload vectors compatibility', _testPayloadVectors),
  ];

  var failures = 0;
  final total = Stopwatch()..start();

  for (final test in tests) {
    final sw = Stopwatch()..start();
    try {
      test.body();
      sw.stop();
      stdout.writeln('PASS ${test.name} (${sw.elapsedMilliseconds} ms)');
    } catch (e, st) {
      sw.stop();
      failures++;
      stderr.writeln('FAIL ${test.name} (${sw.elapsedMilliseconds} ms)');
      stderr.writeln(e);
      stderr.writeln(st);
    }
  }

  total.stop();
  stdout.writeln('');
  stdout.writeln(
    'Ran ${tests.length} tests in ${total.elapsedMilliseconds} ms',
  );

  if (failures > 0) {
    stderr.writeln('Failures: $failures');
    exitCode = 1;
  } else {
    stdout.writeln('All tests passed');
  }
}

void _testNextPrimeSmallValues() {
  const cases = <MapEntry<int, int>>[
    MapEntry(-5, 2),
    MapEntry(0, 2),
    MapEntry(1, 2),
    MapEntry(2, 2),
    MapEntry(3, 3),
    MapEntry(4, 5),
    MapEntry(20, 23),
    MapEntry(24, 29),
  ];

  for (final c in cases) {
    final got = nextPrime(BigInt.from(c.key));
    _expect(
      got == BigInt.from(c.value),
      'nextPrime(${c.key}) = $got, want ${c.value}',
    );
  }
}

void _testPseudoprimes() {
  const inputs = <String>[
    '989',
    '3239',
    '5777',
    '10877',
    '1195068768795265792518361315725116351898245581',
  ];

  for (final raw in inputs) {
    final n = BigInt.parse(raw);
    final prime = nextPrime(n);
    _expect(prime != n, 'nextPrime($raw) returned composite input unchanged');
    _expect(
      nextPrime(prime) == prime,
      'nextPrime($raw) produced non-prime $prime',
    );
  }
}

void _testEvaluateAndVerify() {
  final vdf = Wesolowski.create(128, 32);
  final x = vdf.generate();
  final l = _testChallengePrime;
  final result = vdf.evaluate(l, x, 16);
  final ok = vdf.naiveVerify(x, result.y, 16, l, result.pi);
  _expect(ok, 'expected proof to verify');
}

void _testAggregateAndVerify() {
  final vdf = Wesolowski.create(128, 32);

  final xs = <BigInt>[];
  final ys = <BigInt>[];
  final pis = <BigInt>[];
  final alphas = <BigInt>[];

  final l = _testChallengePrime;

  for (var i = 0; i < 4; i++) {
    final x = vdf.generate();
    final alpha = vdf.generateAlpha(vdf.k);
    final result = vdf.evaluate(l, x, 8);

    xs.add(x);
    ys.add(result.y);
    pis.add(result.pi);
    alphas.add(alpha);
  }

  final agg = vdf.aggregate(pis, xs, ys, alphas);
  final ok = vdf.naiveVerify(agg.xAgg, agg.yAgg, 8, l, agg.piAgg);
  _expect(ok, 'expected aggregate proof to verify');
}

void _testVerifyRejectsWrongOutput() {
  final vdf = Wesolowski.create(128, 32);
  final x = vdf.generate();
  final l = _testChallengePrime;
  final result = vdf.evaluate(l, x, 12);

  final wrongY = result.y + one;
  final ok = vdf.naiveVerify(x, wrongY, 12, l, result.pi);
  _expect(!ok, 'expected tampered output to fail verification');
}

void _testPayloadApiProveAndVerify() {
  final vdf = Wesolowski.create(128, 32);
  final proof = vdf.prove(_bytes('hello payload'), 10);
  final ok = vdf.verify(_bytes('hello payload'), 10, proof);
  _expect(ok, 'expected payload proof to verify');
}

void _testPayloadMismatch() {
  final vdf = Wesolowski.create(128, 32);
  final proof = vdf.prove(_bytes('payload-a'), 9);
  final ok = vdf.verify(_bytes('payload-b'), 9, proof);
  _expect(!ok, 'expected verification to fail for different payload');
}

void _testDifficultyMismatch() {
  final vdf = Wesolowski.create(128, 32);
  final proof = vdf.prove(_bytes('payload'), 9);
  final ok = vdf.verify(_bytes('payload'), 10, proof);
  _expect(!ok, 'expected verification to fail for different difficulty');
}

void _testPublicParams() {
  final prover = Wesolowski.create(128, 32);
  final proof = prover.prove(_bytes('payload'), 11);

  final verifier = Wesolowski.withPublicParams(prover.publicParams());
  final ok = verifier.verify(_bytes('payload'), 11, proof);
  _expect(ok, 'expected verification to succeed with shared public params');
}

void _testPayloadVectors() {
  for (final tc in _payloadVectors) {
    final modulus = _decodeHexInt(tc.modulusHex);
    final prover = Wesolowski.withModulus(modulus, 128);
    final proof = prover.prove(_bytes(tc.payload), tc.difficulty);

    final outputHex = _hexEncode(proof.y);
    final witnessHex = _hexEncode(proof.pi);

    _expect(
      outputHex == tc.outputHex,
      '${tc.name}: unexpected output\nwant: ${tc.outputHex}\ngot:  $outputHex',
    );
    _expect(
      witnessHex == tc.witnessHex,
      '${tc.name}: unexpected witness\nwant: ${tc.witnessHex}\ngot:  $witnessHex',
    );

    final verifier = Wesolowski.withPublicParams(prover.publicParams());
    final ok = verifier.verify(_bytes(tc.payload), tc.difficulty, proof);
    _expect(ok, '${tc.name}: expected vector proof to verify');
  }
}

Uint8List _bytes(String s) => Uint8List.fromList(utf8.encode(s));

BigInt _decodeHexInt(String hex) {
  final clean = hex.trim();
  if (clean.isEmpty) {
    return BigInt.zero;
  }
  return BigInt.parse(clean, radix: 16);
}

String _hexEncode(Uint8List bytes) {
  final buf = StringBuffer();
  for (final b in bytes) {
    buf.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buf.toString();
}

void _expect(bool condition, String message) {
  if (!condition) {
    throw StateError(message);
  }
}
