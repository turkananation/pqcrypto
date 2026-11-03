/// Standalone benchmark harness for pqcrypto bench tools.
///
/// Forked from the pqlattice harness (`test/benchmarks/benchmark_harness.dart`
/// in the sibling repo) so numbers from the two packages share the same
/// discipline of record:
/// 200 warm-up iterations, 5 rounds x 1000 timed iterations, per-round
/// nanoseconds per operation, median reported, opaque sink defeats
/// dead-store elimination, RSS delta captured, full context on every row
/// (SDK, OS, CPU count, this repo's git SHA).
///
/// Bench-only: never imported by library code.
library;

import 'dart:io';
import 'dart:math';

const int kDefaultWarmup = 200;
const int kDefaultIterations = 1000;
const int kDefaultRounds = 5;

/// Opaque sink to defeat Dead Store Elimination. The `@pragma` prevents
/// inlining so the optimizer cannot see through the writes.
int _benchmarkSink = 0x5A5A5A5A;

@pragma('vm:never-inline')
void _benchmarkSinkObserve(int value) {
  _benchmarkSink ^= value;
}

/// Returns the current sink value and resets it.
int drainBenchmarkSink() {
  final s = _benchmarkSink;
  _benchmarkSink = 0x5A5A5A5A;
  return s;
}

/// Observes an int into the sink.
void observeInt(int v) {
  _benchmarkSinkObserve(v);
}

/// Runs [fn] for [iterations] iterations, preceded by [warmup] warm-up
/// iterations. Returns elapsed microseconds for the timed region only.
double timedRegion(
  void Function() fn,
  int iterations,
  int warmup,
  void Function(int) observe,
) {
  for (var i = 0; i < warmup; i++) {
    fn();
    observe(i);
  }
  final sw = Stopwatch()..start();
  for (var i = 0; i < iterations; i++) {
    fn();
    observe(i);
  }
  sw.stop();
  return sw.elapsedMicroseconds.toDouble();
}

/// Runs fn for [rounds] rounds of [iterations] iterations each, with
/// [warmup] warm-up before each timed region. Returns per-round
/// nanoseconds per iteration.
(List<double>, int?) measureRounds(
  void Function() fn, {
  required int iterations,
  required int rounds,
  required int warmup,
  required void Function(int) observe,
}) {
  final ns = <double>[];
  var before = 0;
  var rssCaptured = false;
  try {
    before = ProcessInfo.currentRss;
    rssCaptured = true;
  } catch (_) {}
  for (var r = 0; r < rounds; r++) {
    final us = timedRegion(fn, iterations, warmup, observe);
    ns.add(us * 1000.0 / iterations);
  }
  if (!rssCaptured) {
    return (ns, null);
  }
  var after = 0;
  try {
    after = ProcessInfo.currentRss;
  } catch (_) {
    return (ns, null);
  }
  return (ns, after - before);
}

/// Capture of the execution environment for result context.
class BenchmarkContext {
  final String sdkVersion;
  final String os;
  final int cpuCount;
  final String gitSha;

  BenchmarkContext({
    required this.sdkVersion,
    required this.os,
    required this.cpuCount,
    required this.gitSha,
  });

  static BenchmarkContext capture() {
    String? sha;
    try {
      final result = Process.runSync('git', [
        'rev-parse',
        '--short',
        'HEAD',
      ], workingDirectory: Directory.current.path);
      if (result.exitCode == 0) {
        sha = result.stdout.toString().trim();
      }
    } catch (_) {
      // git unavailable — leave the SHA blank rather than fail the bench.
    }
    return BenchmarkContext(
      sdkVersion: Platform.version,
      os: Platform.operatingSystem,
      cpuCount: Platform.numberOfProcessors,
      gitSha: sha ?? '',
    );
  }
}

/// One measurement row, matching the pqlattice battery TSV shape exactly
/// (same columns, same order) so rows from both packages compare directly.
class BenchmarkRow {
  final String suite;
  final String operation;
  final String profile;
  final int q;
  final int n;
  final String kernelMode;
  final String reduceStrategy;
  final String layout;
  final String domain;
  final String buildMode;
  final int iterationsPerRound;
  final int rounds;
  final int warmupIterations;
  final double meanNs;
  final double medianNs;
  final double minNs;
  final double maxNs;
  final double stdDevNs;
  final double rstdPct;
  final int sink;
  final BenchmarkContext ctx;
  final int? memoryRssBytes;

  BenchmarkRow({
    required this.suite,
    required this.operation,
    required this.profile,
    required this.q,
    required this.n,
    required this.kernelMode,
    required this.reduceStrategy,
    required this.layout,
    required this.domain,
    required this.buildMode,
    required this.iterationsPerRound,
    required this.rounds,
    required this.warmupIterations,
    required this.meanNs,
    required this.medianNs,
    required this.minNs,
    required this.maxNs,
    required this.stdDevNs,
    required this.rstdPct,
    required this.sink,
    required this.ctx,
    required this.memoryRssBytes,
  });

  factory BenchmarkRow.fromRounds({
    required String suite,
    required String operation,
    required String profile,
    required int q,
    required int n,
    required String kernelMode,
    required String reduceStrategy,
    required String layout,
    required String domain,
    required String buildMode,
    required int iterationsPerRound,
    required int rounds,
    required int warmupIterations,
    required List<double> roundNs,
    required int sink,
    required BenchmarkContext ctx,
    required int? memoryRssBytes,
  }) {
    var sum = 0.0;
    for (final v in roundNs) {
      sum += v;
    }
    final mean = sum / roundNs.length;
    final sorted = List<double>.from(roundNs)..sort();
    final mid = sorted.length ~/ 2;
    final median = sorted.length % 2 == 0
        ? (sorted[mid - 1] + sorted[mid]) / 2.0
        : sorted[mid];
    var min = roundNs.reduce((a, b) => a < b ? a : b);
    var max = roundNs.reduce((a, b) => a > b ? a : b);
    var sumSq = 0.0;
    for (final v in roundNs) {
      final d = v - mean;
      sumSq += d * d;
    }
    final stdDev = sqrt(sumSq / roundNs.length);
    return BenchmarkRow(
      suite: suite,
      operation: operation,
      profile: profile,
      q: q,
      n: n,
      kernelMode: kernelMode,
      reduceStrategy: reduceStrategy,
      layout: layout,
      domain: domain,
      buildMode: buildMode,
      iterationsPerRound: iterationsPerRound,
      rounds: rounds,
      warmupIterations: warmupIterations,
      meanNs: mean,
      medianNs: median,
      minNs: min,
      maxNs: max,
      stdDevNs: stdDev,
      rstdPct: mean == 0 ? 0 : stdDev / mean * 100.0,
      sink: sink,
      ctx: ctx,
      memoryRssBytes: memoryRssBytes,
    );
  }

  static String tsvHeader() {
    return [
      'suite',
      'operation',
      'profile',
      'q',
      'n',
      'kernelMode',
      'reduceStrategy',
      'layout',
      'domain',
      'buildMode',
      'iterationsPerRound',
      'rounds',
      'warmupIterations',
      'meanNs',
      'medianNs',
      'minNs',
      'maxNs',
      'stdDevNs',
      'rstdPct',
      'sink',
      'sdkVersion',
      'os',
      'cpuCount',
      'gitSha',
      'memoryRssBytes',
    ].join('\t');
  }

  String toTsv() {
    return [
      suite,
      operation,
      profile,
      q.toString(),
      n.toString(),
      kernelMode,
      reduceStrategy,
      layout,
      domain,
      buildMode,
      iterationsPerRound.toString(),
      rounds.toString(),
      warmupIterations.toString(),
      meanNs.toStringAsFixed(3),
      medianNs.toStringAsFixed(3),
      minNs.toStringAsFixed(3),
      maxNs.toStringAsFixed(3),
      stdDevNs.toStringAsFixed(3),
      rstdPct.toStringAsFixed(3),
      sink.toString(),
      ctx.sdkVersion,
      ctx.os,
      ctx.cpuCount.toString(),
      ctx.gitSha,
      memoryRssBytes?.toString() ?? '',
    ].join('\t');
  }
}
