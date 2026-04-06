import 'dart:io';

import '../lib/vdf.dart';

void main(List<String> args) {
  var lambda = 1024;
  var k = 128;

  final positional = <String>[];
  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    if (arg == '--lambda') {
      if (i + 1 >= args.length) {
        _exit('missing value for --lambda');
      }
      lambda = int.parse(args[++i]);
      continue;
    }
    if (arg == '--k') {
      if (i + 1 >= args.length) {
        _exit('missing value for --k');
      }
      k = int.parse(args[++i]);
      continue;
    }
    positional.add(arg);
  }

  if (positional.length != 2) {
    _exit('usage: rsa_vdf.dart [--lambda bits] [--k bits] <t> <num-vdfs>');
  }

  final t = int.parse(positional[0]);
  final numVdfs = int.parse(positional[1]);
  if (t < 0) {
    _exit('t must be non-negative');
  }
  if (numVdfs <= 0) {
    _exit('num-vdfs must be positive');
  }

  final squarings = 1 << t;

  final setup = Stopwatch()..start();
  final vdf = Wesolowski.create(lambda, k);

  final xs = <BigInt>[];
  final ys = <BigInt>[];
  final pis = <BigInt>[];
  final alphas = <BigInt>[];

  for (var i = 0; i < numVdfs; i++) {
    xs.add(vdf.generate());
    alphas.add(vdf.generateAlpha(k));
  }

  final l = vdf.hashPrime(xs.first);
  setup.stop();
  stdout.writeln('Time cost for setup: ${setup.elapsedMilliseconds / 1000.0}');

  final eval = Stopwatch()..start();
  for (var i = 0; i < numVdfs; i++) {
    final result = vdf.evaluate(l, xs[i], squarings);
    pis.add(result.pi);
    ys.add(result.y);
  }
  eval.stop();
  stdout.writeln(
    'Time cost for evaluate: ${eval.elapsedMilliseconds / 1000.0}',
  );

  final aggSw = Stopwatch()..start();
  final agg = vdf.aggregate(pis, xs, ys, alphas);
  aggSw.stop();
  stdout.writeln(
    'Time cost for aggregate: ${aggSw.elapsedMilliseconds / 1000.0}',
  );

  final verify = Stopwatch()..start();
  for (var i = 0; i < numVdfs; i++) {
    final ok = vdf.naiveVerify(xs[i], ys[i], squarings, l, pis[i]);
    if (!ok) {
      _exit('individual verification failed at index $i');
    }
  }
  verify.stop();
  stdout.writeln(
    'Time cost for individual verification: ${verify.elapsedMilliseconds / 1000.0}',
  );

  final batchVerify = Stopwatch()..start();
  final ok = vdf.naiveVerify(agg.xAgg, agg.yAgg, squarings, l, agg.piAgg);
  if (!ok) {
    _exit('batch verification failed');
  }
  batchVerify.stop();
  final total = aggSw.elapsedMilliseconds + batchVerify.elapsedMilliseconds;
  stdout.writeln(
    'Time cost for aggregation and batch verification: ${total / 1000.0}',
  );
}

Never _exit(String message) {
  stderr.writeln(message);
  exit(1);
}
