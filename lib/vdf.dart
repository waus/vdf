import 'dart:async';
import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'src/native/rust_vdf_backend.dart';

export 'src/native/rust_vdf_backend.dart'
    show NativeModulusContext, VdfNativeBackend;

final BigInt one = BigInt.one;
final BigInt two = BigInt.from(2);

const double _progressPhaseHeadroom = 0.98;
const int _defaultProgressNsPerUnit = 1500;

const List<int> _nextPrimeSmallTable = <int>[
  2,
  3,
  5,
  7,
  11,
  13,
  17,
  19,
  23,
  29,
  31,
  37,
  41,
  43,
  47,
  53,
  59,
  61,
  67,
  71,
  73,
  79,
  83,
  89,
  97,
  101,
  103,
  107,
  109,
  113,
  127,
  131,
  137,
  139,
  149,
  151,
  157,
  163,
  167,
  173,
  179,
  181,
  191,
  193,
  197,
  199,
  211,
  223,
  227,
  229,
  233,
  239,
  241,
  251,
];

const List<int> _nextPrimeSievePrimes = <int>[
  3,
  5,
  7,
  11,
  13,
  17,
  19,
  23,
  29,
  31,
  37,
  41,
  43,
  47,
  53,
  59,
  61,
  67,
  71,
  73,
  79,
  83,
  89,
  97,
  101,
  103,
  107,
  109,
  113,
  127,
  131,
  137,
  139,
  149,
  151,
  157,
  163,
  167,
  173,
  179,
  181,
  191,
  193,
  197,
  199,
  211,
  223,
  227,
  229,
  233,
  239,
  241,
  251,
];

const List<int> _millerRabinBases = <int>[
  2,
  3,
  5,
  7,
  11,
  13,
  17,
  19,
  23,
  29,
  31,
  37,
  41,
  43,
  47,
  53,
  59,
  61,
  67,
  71,
  73,
  79,
  83,
  89,
  97,
  101,
  103,
  107,
  109,
  113,
  127,
  131,
  137,
  139,
  149,
  151,
  157,
  163,
  167,
  173,
  179,
  181,
  191,
  193,
  197,
  199,
  211,
  223,
  227,
  229,
  233,
  239,
  241,
  251,
  257,
  263,
  269,
  271,
  277,
  281,
  283,
  293,
  307,
  311,
];

class PublicParams {
  PublicParams({
    required Uint8List modulus,
    required this.lambda,
    required this.k,
  }) : modulus = Uint8List.fromList(modulus);

  final Uint8List modulus;
  final int lambda;
  final int k;
}

class Proof {
  Proof({required Uint8List y, required Uint8List pi})
    : y = Uint8List.fromList(y),
      pi = Uint8List.fromList(pi);

  final Uint8List y;
  final Uint8List pi;
}

final class ProveProgress {
  const ProveProgress({required this.completion, required this.elapsed});

  final double completion;
  final Duration elapsed;
}

class EvaluationResult {
  EvaluationResult({required this.pi, required this.y});

  final BigInt pi;
  final BigInt y;
}

class AggregateResult {
  AggregateResult({
    required this.piAgg,
    required this.xAgg,
    required this.yAgg,
  });

  final BigInt piAgg;
  final BigInt xAgg;
  final BigInt yAgg;
}

class Wesolowski {
  Wesolowski._({
    required this.n,
    this.p,
    this.q,
    required this.lambda,
    required this.k,
    required Random random,
  }) : _random = random;

  factory Wesolowski.create(int lambda, int k, {Random? random}) {
    if (lambda < 16) {
      throw ArgumentError('lambda must be at least 16 bits, got $lambda');
    }
    if (lambda.isOdd) {
      throw ArgumentError('lambda must be even, got $lambda');
    }
    if (k < 2) {
      throw ArgumentError('k must be at least 2 bits, got $k');
    }

    final rng = random ?? Random.secure();
    final p = _randomPrime(lambda ~/ 2, rng);
    var q = _randomPrime(lambda ~/ 2, rng);
    while (q == p) {
      q = _randomPrime(lambda ~/ 2, rng);
    }

    return Wesolowski._(
      n: p * q,
      p: p,
      q: q,
      lambda: lambda,
      k: k,
      random: rng,
    );
  }

  factory Wesolowski.withModulus(BigInt modulus, int k, {Random? random}) {
    if (modulus <= two) {
      throw ArgumentError('modulus must be greater than 2');
    }
    if (modulus.isEven) {
      throw ArgumentError('modulus must be odd');
    }
    if (k < 2) {
      throw ArgumentError('k must be at least 2 bits, got $k');
    }

    return Wesolowski._(
      n: modulus,
      lambda: modulus.bitLength,
      k: k,
      random: random ?? Random.secure(),
    );
  }

  factory Wesolowski.withPublicParams(PublicParams params, {Random? random}) {
    if (params.modulus.isEmpty) {
      throw ArgumentError('public modulus must not be empty');
    }

    final modulus = _bigIntFromBytes(params.modulus);
    if (params.lambda != 0 && modulus.bitLength != params.lambda) {
      throw ArgumentError(
        'lambda mismatch: got ${params.lambda}, modulus bit length is ${modulus.bitLength}',
      );
    }

    return Wesolowski.withModulus(modulus, params.k, random: random);
  }

  final BigInt n;
  final BigInt? p;
  final BigInt? q;
  final int lambda;
  final int k;

  final Random _random;
  late final NativeModulusContext? _nativeModulus = VdfNativeBackend.instance
      ?.createModulusContext(_bigIntToBytes(n));

  bool get hasNativeBackend => _nativeModulus != null;

  PublicParams publicParams() {
    return PublicParams(modulus: _bigIntToBytes(n), lambda: n.bitLength, k: k);
  }

  BigInt generate() {
    return _randomBelow(n, _random);
  }

  BigInt generateAlpha(int bitSize) {
    if (bitSize <= 0) {
      throw ArgumentError('bit size must be positive, got $bitSize');
    }
    final limit = one << bitSize;
    return _randomBelow(limit, _random);
  }

  EvaluationResult evaluate(BigInt l, BigInt x, int squarings) {
    if (l <= BigInt.zero) {
      throw ArgumentError('l must be a positive integer');
    }
    if (x < BigInt.zero) {
      throw ArgumentError('x must be a non-negative integer');
    }
    if (squarings < 0) {
      throw ArgumentError('squarings must be non-negative, got $squarings');
    }

    final exp = twoPow(squarings);
    final y = x.modPow(exp, n);
    final q = exp ~/ l;
    final pi = x.modPow(q, n);

    return EvaluationResult(pi: pi, y: y);
  }

  AggregateResult aggregate(
    List<BigInt> piList,
    List<BigInt> xList,
    List<BigInt> yList,
    List<BigInt> alphas,
  ) {
    final size = piList.length;
    if (size == 0) {
      throw ArgumentError('cannot aggregate an empty batch');
    }
    if (xList.length != size || yList.length != size || alphas.length != size) {
      throw ArgumentError('batch slices must have identical lengths');
    }

    var piAgg = one;
    var xAgg = one;
    var yAgg = one;

    for (var i = 0; i < size; i++) {
      final xPow = xList[i].modPow(alphas[i], n);
      xAgg = (xAgg * xPow) % n;

      final piPow = piList[i].modPow(alphas[i], n);
      piAgg = (piAgg * piPow) % n;

      final yPow = yList[i].modPow(alphas[i], n);
      yAgg = (yAgg * yPow) % n;
    }

    return AggregateResult(piAgg: piAgg, xAgg: xAgg, yAgg: yAgg);
  }

  bool naiveVerify(BigInt x, BigInt y, int squarings, BigInt l, BigInt pi) {
    if (squarings < 0) {
      throw ArgumentError('squarings must be non-negative, got $squarings');
    }
    if (l <= one) {
      throw ArgumentError('l must be greater than 1');
    }

    final r = _verifyExponent(squarings, l);
    final left = pi.modPow(l, n);
    final right = x.modPow(r, n);
    final got = (left * right) % n;

    return got == y;
  }

  Proof prove(Uint8List payload, int difficulty) {
    if (difficulty < 0) {
      throw ArgumentError('difficulty must be non-negative, got $difficulty');
    }

    final nativeModulus = _nativeModulus;
    if (nativeModulus != null) {
      final nativeProof = nativeModulus.prove(payload, difficulty, k);
      return Proof(y: nativeProof.y, pi: nativeProof.pi);
    }

    final x = _inputFromPayload(payload);
    final exp = twoPow(difficulty);
    final y = x.modPow(exp, n);
    final yBytes = _bigIntToBytes(y);

    final l = _primeFromStatement(payload, difficulty, yBytes);
    final q = exp ~/ l;
    final pi = x.modPow(q, n);

    return Proof(y: yBytes, pi: _bigIntToBytes(pi));
  }

  Proof proveWithNativeBackend(Uint8List payload, int difficulty) {
    if (difficulty < 0) {
      throw ArgumentError('difficulty must be non-negative, got $difficulty');
    }

    if (_nativeModulus == null) {
      throw StateError('native backend is not available');
    }
    return prove(payload, difficulty);
  }

  Future<Proof> proveAsync(
    Uint8List payload,
    int difficulty, {
    Duration progressInterval = const Duration(milliseconds: 50),
    void Function(ProveProgress progress)? onProgress,
  }) async {
    final elapsed = Stopwatch()..start();
    _emitProveProgress(onProgress, 0, elapsed.elapsed);

    if (difficulty < 0) {
      throw ArgumentError('difficulty must be non-negative, got $difficulty');
    }
    if (progressInterval <= Duration.zero) {
      throw ArgumentError('progressInterval must be positive');
    }

    final firstWork = _estimatePow2ExpWorkForDifficulty(difficulty);
    final messages = ReceivePort();
    Isolate? isolate;
    Timer? progressTimer;
    var currentBase = 0.0;
    var currentWeight = 0.5;
    var currentWork = firstWork;
    var currentNsPerUnit = _defaultProgressNsPerUnit;
    final phaseElapsed = Stopwatch();
    var completed = false;

    void stopProgressTimer() {
      progressTimer?.cancel();
      progressTimer = null;
      phaseElapsed.stop();
    }

    void startProgressTimer({
      required double base,
      required double weight,
      required int work,
      required int nsPerUnit,
    }) {
      stopProgressTimer();
      if (weight <= 0) {
        return;
      }

      currentBase = base;
      currentWeight = weight;
      currentWork = work <= 0 ? 1 : work;
      currentNsPerUnit = nsPerUnit <= 0 ? _defaultProgressNsPerUnit : nsPerUnit;
      phaseElapsed
        ..reset()
        ..start();

      progressTimer = Timer.periodic(progressInterval, (_) {
        final estimate = _progressPhaseEstimate(
          currentWork,
          currentNsPerUnit,
          progressInterval,
        );
        var frac = phaseElapsed.elapsedMicroseconds / estimate.inMicroseconds;
        if (frac < 0) {
          frac = 0;
        }
        if (frac > _progressPhaseHeadroom) {
          frac = _progressPhaseHeadroom;
        }
        _emitProveProgress(
          onProgress,
          currentBase + currentWeight * frac,
          elapsed.elapsed,
        );
      });
    }

    startProgressTimer(
      base: 0,
      weight: currentWeight,
      work: firstWork,
      nsPerUnit: _defaultProgressNsPerUnit,
    );

    try {
      isolate = await Isolate.spawn<_ProveIsolateRequest>(
        _proveIsolate,
        _ProveIsolateRequest(
          sendPort: messages.sendPort,
          modulus: n,
          k: k,
          payload: Uint8List.fromList(payload),
          difficulty: difficulty,
        ),
        errorsAreFatal: true,
        onError: messages.sendPort,
        onExit: messages.sendPort,
      );

      await for (final message in messages) {
        if (message is _ProvePhaseComplete) {
          stopProgressTimer();

          final totalWork = message.firstWork + message.secondWork;
          final firstWeight = totalWork > 0
              ? message.firstWork / totalWork
              : 0.5;
          _emitProveProgress(onProgress, firstWeight, elapsed.elapsed);

          final nsPerUnit = _estimateNsPerUnit(
            message.elapsed,
            message.firstWork,
          );
          startProgressTimer(
            base: firstWeight,
            weight: 1 - firstWeight,
            work: message.secondWork,
            nsPerUnit: nsPerUnit,
          );
        } else if (message is _ProveIsolateResult) {
          stopProgressTimer();
          completed = true;
          _emitProveProgress(onProgress, 1, elapsed.elapsed);
          return Proof(y: message.y, pi: message.pi);
        } else if (message is _ProveIsolateError) {
          throw StateError(message.message);
        } else if (message == null) {
          throw StateError('prove isolate exited without returning a proof');
        } else if (message is List && message.length >= 2) {
          throw StateError('${message[0]}\n${message[1]}');
        }
      }

      throw StateError('prove isolate exited without returning a proof');
    } finally {
      stopProgressTimer();
      messages.close();
      if (!completed) {
        isolate?.kill(priority: Isolate.immediate);
      }
    }
  }

  bool verify(Uint8List payload, int difficulty, Proof proof) {
    if (difficulty < 0) {
      throw ArgumentError('difficulty must be non-negative, got $difficulty');
    }
    if (proof.y.isEmpty) {
      throw ArgumentError('proof y must not be empty');
    }
    if (proof.pi.isEmpty) {
      throw ArgumentError('proof pi must not be empty');
    }

    final x = _inputFromPayload(payload);
    final y = _bigIntFromBytes(proof.y);
    final pi = _bigIntFromBytes(proof.pi);
    final l = _primeFromStatement(payload, difficulty, proof.y);

    return naiveVerify(x, y, difficulty, l, pi);
  }

  BigInt _inputFromPayload(Uint8List payload) {
    var x = _expandHashToInt('rsavdf:x:v1', 0, payload, null);
    x %= n;
    if (x == BigInt.zero) {
      x = one;
    }
    return x;
  }

  BigInt _primeFromStatement(
    Uint8List payload,
    int difficulty,
    Uint8List output,
  ) {
    final x = _expandHashToInt('rsavdf:l:v1', difficulty, payload, output);
    return nextPrime(x);
  }

  BigInt _expandHashToInt(
    String domain,
    int difficulty,
    Uint8List payload,
    Uint8List? extra,
  ) {
    var byteLen = (2 * k + 7) >> 3;
    if (byteLen < 32) {
      byteLen = 32;
    }

    final domainBytes = Uint8List.fromList(utf8.encode(domain));
    final diff = ByteData(8)..setUint64(0, difficulty, Endian.big);
    final diffBytes = diff.buffer.asUint8List();

    var counter = 0;
    final out = BytesBuilder(copy: false);

    while (out.length < byteLen) {
      final counterData = ByteData(4)..setUint32(0, counter, Endian.big);
      final counterBytes = counterData.buffer.asUint8List();

      final msg = BytesBuilder(copy: false)
        ..add(domainBytes)
        ..add(diffBytes)
        ..add(payload);
      if (extra != null) {
        msg.add(extra);
      }
      msg.add(counterBytes);

      out.add(_Sha256.hash(msg.takeBytes()));
      counter++;
    }

    final bytes = out.takeBytes();
    return _bigIntFromBytes(Uint8List.sublistView(bytes, 0, byteLen));
  }
}

BigInt twoPow(int power) {
  return one << power;
}

void _proveIsolate(_ProveIsolateRequest request) {
  try {
    final vdf = Wesolowski._(
      n: request.modulus,
      lambda: request.modulus.bitLength,
      k: request.k,
      random: Random(0),
    );
    final firstWork = _estimatePow2ExpWorkForDifficulty(request.difficulty);
    final nativeModulus = vdf._nativeModulus;
    if (nativeModulus != null) {
      NativeProveSession? nativeSession;
      try {
        final stageOne = Stopwatch()..start();
        final stage = nativeModulus.proveStage1(
          request.payload,
          request.difficulty,
          request.k,
        );
        stageOne.stop();
        nativeSession = stage.session;

        request.sendPort.send(
          _ProvePhaseComplete(
            firstWork: firstWork,
            secondWork: stage.secondWork,
            elapsed: stageOne.elapsed,
          ),
        );

        final piBytes = nativeSession.finish();
        request.sendPort.send(_ProveIsolateResult(y: stage.y, pi: piBytes));
      } finally {
        nativeSession?.close();
      }
      return;
    }

    final x = vdf._inputFromPayload(request.payload);
    final exp = twoPow(request.difficulty);

    final stageOne = Stopwatch()..start();
    final y = x.modPow(exp, vdf.n);
    stageOne.stop();
    final yBytes = _bigIntToBytes(y);

    final l = vdf._primeFromStatement(
      request.payload,
      request.difficulty,
      yBytes,
    );
    final q = exp ~/ l;
    final secondWork = _estimateExpWork(q);

    request.sendPort.send(
      _ProvePhaseComplete(
        firstWork: firstWork,
        secondWork: secondWork,
        elapsed: stageOne.elapsed,
      ),
    );

    final pi = x.modPow(q, vdf.n);
    request.sendPort.send(
      _ProveIsolateResult(y: yBytes, pi: _bigIntToBytes(pi)),
    );
  } catch (e, st) {
    request.sendPort.send(_ProveIsolateError('$e\n$st'));
  }
}

void _emitProveProgress(
  void Function(ProveProgress progress)? onProgress,
  double completion,
  Duration elapsed,
) {
  if (onProgress == null) {
    return;
  }
  onProgress(
    ProveProgress(completion: _clampProgress(completion), elapsed: elapsed),
  );
}

double _clampProgress(double value) {
  if (value.isNaN || value < 0) {
    return 0;
  }
  if (value > 1) {
    return 1;
  }
  return value;
}

int _estimateExpWork(BigInt? exp) {
  if (exp == null || exp <= BigInt.zero) {
    return 1;
  }

  final bitLen = exp.bitLength;
  if (bitLen <= 1) {
    return 1;
  }

  if ((exp & (exp - one)) == BigInt.zero) {
    return bitLen - 1;
  }

  final squarings = bitLen - 1;
  final expectedMultiplies = (bitLen + 1) >> 1;
  return squarings + expectedMultiplies;
}

int _estimatePow2ExpWorkForDifficulty(int difficulty) {
  if (difficulty <= 0) {
    return 1;
  }
  return difficulty;
}

int _estimateNsPerUnit(Duration duration, int work) {
  if (duration <= Duration.zero || work <= 0) {
    return _defaultProgressNsPerUnit;
  }

  final ns = duration.inMicroseconds * 1000 ~/ work;
  if (ns <= 0) {
    return _defaultProgressNsPerUnit;
  }
  return ns;
}

Duration _progressPhaseEstimate(
  int work,
  int nsPerUnit,
  Duration progressInterval,
) {
  final safeWork = work <= 0 ? 1 : work;
  final safeNs = nsPerUnit <= 0 ? _defaultProgressNsPerUnit : nsPerUnit;
  var estimate = Duration(microseconds: (safeWork * safeNs) ~/ 1000);
  if (estimate < progressInterval) {
    estimate = progressInterval;
  }
  return estimate;
}

class _ProveIsolateRequest {
  _ProveIsolateRequest({
    required this.sendPort,
    required this.modulus,
    required this.k,
    required this.payload,
    required this.difficulty,
  });

  final SendPort sendPort;
  final BigInt modulus;
  final int k;
  final Uint8List payload;
  final int difficulty;
}

class _ProvePhaseComplete {
  _ProvePhaseComplete({
    required this.firstWork,
    required this.secondWork,
    required this.elapsed,
  });

  final int firstWork;
  final int secondWork;
  final Duration elapsed;
}

class _ProveIsolateResult {
  _ProveIsolateResult({required this.y, required this.pi});

  final Uint8List y;
  final Uint8List pi;
}

class _ProveIsolateError {
  _ProveIsolateError(this.message);

  final String message;
}

BigInt nextPrime(BigInt? n) {
  if (n == null || n < two) {
    return two;
  }

  var candidate = n;
  if (candidate == two) {
    return two;
  }
  if (candidate.isEven) {
    candidate += one;
  }

  if (candidate.bitLength <= 6) {
    final value = candidate.toInt();
    for (final p in _nextPrimeSmallTable) {
      if (value <= p) {
        return BigInt.from(p);
      }
    }
  }

  final residues = List<int>.filled(_nextPrimeSievePrimes.length, 0);
  for (var i = 0; i < _nextPrimeSievePrimes.length; i++) {
    final mod = _nextPrimeSievePrimes[i];
    residues[i] = (candidate % BigInt.from(mod)).toInt();
  }

  while (!_passesSmallPrimeSieve(residues) || !_isProbablePrime(candidate)) {
    candidate += two;
    _advanceSieveResidues(residues);
  }

  return candidate;
}

bool _passesSmallPrimeSieve(List<int> residues) {
  for (final residue in residues) {
    if (residue == 0) {
      return false;
    }
  }
  return true;
}

void _advanceSieveResidues(List<int> residues) {
  for (var i = 0; i < residues.length; i++) {
    var next = residues[i] + 2;
    final modulus = _nextPrimeSievePrimes[i];
    if (next >= modulus) {
      next -= modulus;
    }
    residues[i] = next;
  }
}

BigInt _verifyExponent(int squarings, BigInt l) {
  final phiL = l - one;
  var tauMod = BigInt.from(squarings);
  if (phiL > BigInt.zero) {
    tauMod %= phiL;
  }
  return two.modPow(tauMod, l);
}

BigInt _randomPrime(int bitLength, Random random) {
  if (bitLength < 2) {
    throw ArgumentError('prime bit length must be at least 2, got $bitLength');
  }

  while (true) {
    var candidate = _randomBits(bitLength, random);
    candidate |= one << (bitLength - 1);
    candidate |= one;

    if (_isProbablePrime(candidate, rounds: 48)) {
      return candidate;
    }
  }
}

BigInt _randomBelow(BigInt limit, Random random) {
  if (limit <= BigInt.zero) {
    throw ArgumentError('limit must be positive');
  }

  final bitLength = limit.bitLength;
  while (true) {
    final candidate = _randomBits(bitLength, random);
    if (candidate < limit) {
      return candidate;
    }
  }
}

BigInt _randomBits(int bitLength, Random random) {
  if (bitLength <= 0) {
    return BigInt.zero;
  }

  final byteLength = (bitLength + 7) >> 3;
  final bytes = Uint8List(byteLength);

  for (var i = 0; i < byteLength; i++) {
    bytes[i] = random.nextInt(256);
  }

  final excessBits = byteLength * 8 - bitLength;
  if (excessBits > 0) {
    final mask = (1 << (8 - excessBits)) - 1;
    bytes[0] &= mask;
  }

  return _bigIntFromBytes(bytes);
}

bool _isProbablePrime(BigInt n, {int rounds = 32}) {
  if (n < two) {
    return false;
  }

  for (final p in _nextPrimeSmallTable) {
    final prime = BigInt.from(p);
    if (n == prime) {
      return true;
    }
    if (n % prime == BigInt.zero) {
      return false;
    }
  }

  var d = n - one;
  var s = 0;
  while (d.isEven) {
    d >>= 1;
    s++;
  }

  var usedRounds = 0;
  for (final base in _millerRabinBases) {
    if (usedRounds >= rounds) {
      break;
    }

    final a = BigInt.from(base);
    if (a >= n - one) {
      continue;
    }

    if (!_millerRabinRound(n, d, s, a)) {
      return false;
    }
    usedRounds++;
  }

  return true;
}

bool _millerRabinRound(BigInt n, BigInt d, int s, BigInt a) {
  var x = a.modPow(d, n);
  final nMinusOne = n - one;

  if (x == one || x == nMinusOne) {
    return true;
  }

  for (var r = 1; r < s; r++) {
    x = (x * x) % n;
    if (x == nMinusOne) {
      return true;
    }
  }

  return false;
}

BigInt _bigIntFromBytes(Uint8List bytes) {
  var value = BigInt.zero;
  for (final b in bytes) {
    value = (value << 8) | BigInt.from(b);
  }
  return value;
}

Uint8List _bigIntToBytes(BigInt value) {
  if (value < BigInt.zero) {
    throw ArgumentError('only non-negative BigInt is supported');
  }
  if (value == BigInt.zero) {
    return Uint8List(0);
  }

  final bytes = <int>[];
  var current = value;
  while (current > BigInt.zero) {
    bytes.add((current & BigInt.from(0xff)).toInt());
    current >>= 8;
  }

  return Uint8List.fromList(bytes.reversed.toList(growable: false));
}

class _Sha256 {
  static const List<int> _k = <int>[
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
  ];

  static Uint8List hash(Uint8List input) {
    final bitLen = input.lengthInBytes * 8;
    final paddingLen = (56 - ((input.lengthInBytes + 1) % 64) + 64) % 64;
    final totalLen = input.lengthInBytes + 1 + paddingLen + 8;

    final msg = Uint8List(totalLen);
    msg.setRange(0, input.lengthInBytes, input);
    msg[input.lengthInBytes] = 0x80;

    final msgData = ByteData.sublistView(msg);
    msgData.setUint32(totalLen - 8, (bitLen >> 32) & 0xffffffff, Endian.big);
    msgData.setUint32(totalLen - 4, bitLen & 0xffffffff, Endian.big);

    var h0 = 0x6a09e667;
    var h1 = 0xbb67ae85;
    var h2 = 0x3c6ef372;
    var h3 = 0xa54ff53a;
    var h4 = 0x510e527f;
    var h5 = 0x9b05688c;
    var h6 = 0x1f83d9ab;
    var h7 = 0x5be0cd19;

    final w = Uint32List(64);

    for (var offset = 0; offset < msg.lengthInBytes; offset += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = msgData.getUint32(offset + i * 4, Endian.big);
      }

      for (var i = 16; i < 64; i++) {
        final s0 =
            _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
      }

      var a = h0;
      var b = h1;
      var c = h2;
      var d = h3;
      var e = h4;
      var f = h5;
      var g = h6;
      var h = h7;

      for (var i = 0; i < 64; i++) {
        final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        final ch = (e & f) ^ ((~e) & g);
        final temp1 = (h + s1 + ch + _k[i] + w[i]) & 0xffffffff;
        final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        final maj = (a & b) ^ (a & c) ^ (b & c);
        final temp2 = (s0 + maj) & 0xffffffff;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) & 0xffffffff;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) & 0xffffffff;
      }

      h0 = (h0 + a) & 0xffffffff;
      h1 = (h1 + b) & 0xffffffff;
      h2 = (h2 + c) & 0xffffffff;
      h3 = (h3 + d) & 0xffffffff;
      h4 = (h4 + e) & 0xffffffff;
      h5 = (h5 + f) & 0xffffffff;
      h6 = (h6 + g) & 0xffffffff;
      h7 = (h7 + h) & 0xffffffff;
    }

    final out = ByteData(32)
      ..setUint32(0, h0, Endian.big)
      ..setUint32(4, h1, Endian.big)
      ..setUint32(8, h2, Endian.big)
      ..setUint32(12, h3, Endian.big)
      ..setUint32(16, h4, Endian.big)
      ..setUint32(20, h5, Endian.big)
      ..setUint32(24, h6, Endian.big)
      ..setUint32(28, h7, Endian.big);

    return out.buffer.asUint8List();
  }

  static int _rotr(int x, int n) {
    return ((x >> n) | ((x << (32 - n)) & 0xffffffff)) & 0xffffffff;
  }
}
