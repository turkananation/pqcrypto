/// pqcrypto vs pqlattice side-by-side parity and timing benchmark.
///
/// Runs identical deterministic polynomials through:
/// - pqcrypto's internal `Poly.ntt` / `Poly.baseMul` / `Poly.invNtt` (kyber)
///   and `DilithiumNTT.ntt` / `DilithiumPoly.pointwiseMul` / `invNtt`
///   (dilithium),
/// - pqlattice's `NttEngine.forward` / `Basemul.mlKemPairs|pointwise` /
///   `NttEngine.inverse`,
///
/// asserts the results are bit-identical, and times each package per
/// operation with the shared harness discipline (200 warm-up iterations,
/// 5 rounds x 1000 timed iterations, median nanoseconds per operation),
/// emitting the same 25-column TSV as the pqlattice battery.
///
/// Scope: ML-KEM (kyber, q=3329 n=256) and ML-DSA (dilithium, q=8380417
/// n=256) - the two ring shapes both packages share. FN-DSA (Falcon,
/// q=12289) has no pqcrypto sibling in this repo (kyber, dilithium, slhdsa
/// only); it is covered by the pqlattice battery. SLH-DSA is not an NTT
/// workload and is out of scope.
///
/// Honest layout note: dilithium transforms are in-place and destructive,
/// so pqcrypto dilithium rows include the input copy inside the timed
/// region (layout `inPlace`; pqlattice rows are allocating). Kyber rows on
/// both sides are allocating (like-for-like).
///
/// Manual run (claim-quality requires AOT):
///   dart pub get
///   dart compile exe test/benchmarks/side_by_side.dart -o `<binary>`
///   `<binary>` > side_by_side_aot.tsv
/// Parity failures throw; the process exits non-zero. Progress and parity
/// lines print to stderr so stdout stays pure TSV.
///
/// This file needs pqlattice as a sibling checkout (dev path dependency
/// `../pqlattice`). Never imported by library code.
library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/src/algos/dilithium/ntt.dart' as dil_ntt;
import 'package:pqcrypto/src/algos/dilithium/poly.dart' as dil_poly;
import 'package:pqcrypto/src/algos/kyber/poly.dart' as kyber;
import 'package:pqlattice/pqlattice.dart';

import 'benchmark_harness.dart';

void main(List<String> args) {
  final ctx = BenchmarkContext.capture();
  final buildMode = _detectBuildMode();
  final peerSha = _capturePeerSha();

  final sha = ctx.gitSha.isEmpty ? 'unknown' : ctx.gitSha;
  stderr.writeln(
    'side_by_side packages=pqcrypto+pqlattice '
    'pqcryptoSha=$sha pqlatticeSha=${peerSha.isEmpty ? "unknown" : peerSha}',
  );
  stderr.writeln(
    'sdk=${ctx.sdkVersion.split(" ").first} os=${ctx.os} '
    'cpus=${ctx.cpuCount} buildMode=$buildMode',
  );
  stderr.writeln(
    'parity policy: identical deterministic inputs on both '
    'packages; bit-identity asserted coefficient-wise per trial; any '
    'mismatch aborts before timing.',
  );
  stderr.writeln(
    'scope: mlKem kyber q=3329 n=256; mlDsa dilithium '
    'q=8380417 n=256; fndsa has no pqcrypto sibling here (pqlattice '
    'battery covers it).',
  );

  stdout.writeln(BenchmarkRow.tsvHeader());

  final rows = <BenchmarkRow>[];

  _runMlKem(rows, ctx, buildMode);
  _runMlDsa(rows, ctx, buildMode);

  for (final r in rows) {
    stdout.writeln(r.toTsv());
  }
  drainBenchmarkSink();
}

String _detectBuildMode() {
  try {
    final exe = Platform.resolvedExecutable;
    final exeName = exe.split(Platform.pathSeparator).last;
    return exeName == 'dart' ? 'jit' : 'aot';
  } catch (_) {
    return 'unknown';
  }
}

String _capturePeerSha() {
  try {
    final r = Process.runSync('git', [
      'rev-parse',
      '--short',
      'HEAD',
    ], workingDirectory: '../pqlattice');
    if (r.exitCode == 0) {
      return r.stdout.toString().trim();
    }
  } catch (_) {}
  return '';
}

/// Adds one measured row for a timed function returning a coefficient.
void _addRow(
  List<BenchmarkRow> rows, {
  required BenchmarkContext ctx,
  required String buildMode,
  required String operation,
  required String profile,
  required int q,
  required int n,
  required String kernelMode,
  required String reduceStrategy,
  required String layout,
  required int Function() fn,
}) {
  final (ns, mem) = measureRounds(
    () {
      final v = fn();
      observeInt(v);
    },
    iterations: kDefaultIterations,
    rounds: kDefaultRounds,
    warmup: kDefaultWarmup,
    observe: observeInt,
  );
  rows.add(
    BenchmarkRow.fromRounds(
      suite: 'side_by_side',
      operation: operation,
      profile: profile,
      q: q,
      n: n,
      kernelMode: kernelMode,
      reduceStrategy: reduceStrategy,
      layout: layout,
      domain: 'plain',
      buildMode: buildMode,
      iterationsPerRound: kDefaultIterations,
      rounds: kDefaultRounds,
      warmupIterations: kDefaultWarmup,
      roundNs: ns,
      sink: drainBenchmarkSink(),
      ctx: ctx,
      memoryRssBytes: mem,
    ),
  );
}

// ─────────────────────────── ML-KEM (kyber) ──────────────────────────────

void _runMlKem(
  List<BenchmarkRow> rows,
  BenchmarkContext ctx,
  String buildMode,
) {
  const q = 3329;
  const n = 256;
  final ring = RingParams.mlKem;
  final engine = NttEngine(ring);
  final rnd = Random(0x1753); // E3-seed continuity.

  // Parity: 50 trials, identical inputs, coefficient-wise bit-identity on
  // both forward results and the shipped pipeline product.
  var ok = 0;
  for (var trial = 0; trial < 50; trial++) {
    final aCoeffs = List<int>.generate(n, (_) => rnd.nextInt(q));
    final bCoeffs = List<int>.generate(n, (_) => rnd.nextInt(q));

    final pAh = kyber.Poly.ntt(kyber.Poly(List<int>.from(aCoeffs)));
    final pBh = kyber.Poly.ntt(kyber.Poly(List<int>.from(bCoeffs)));
    final pCh = kyber.Poly.invNtt(kyber.Poly.baseMul(pAh, pBh));

    final aHat = engine.forward(Poly.fromCoeffs(ring, aCoeffs));
    final bHat = engine.forward(Poly.fromCoeffs(ring, bCoeffs));
    final cHat = Basemul.mlKemPairs(aHat, bHat, ring);
    final c = engine.inverse(cHat);

    for (var i = 0; i < n; i++) {
      _sameInt(pAh.coeffs[i], aHat.coeffs[i], 'mlKem', trial, i, 'aHat');
      _sameInt(pBh.coeffs[i], bHat.coeffs[i], 'mlKem', trial, i, 'bHat');
      _sameInt(pCh.coeffs[i], c.coeffs[i], 'mlKem', trial, i, 'product');
    }
    ok++;
  }
  stderr.writeln(
    'PARITY mlKem: $ok/50 trials bit-identical '
    '(aHat, bHat, full product)',
  );

  // Timing inputs: deterministic polys, identical on both packages
  // (E3 bench continuity: (i*17+3)%q and (i*31+5)%q).
  final aB = List<int>.generate(n, (i) => (i * 17 + 3) % q);
  final bB = List<int>.generate(n, (i) => (i * 31 + 5) % q);
  final aLat = Poly.fromCoeffs(ring, aB);
  final bLat = Poly.fromCoeffs(ring, bB);

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => kyber.Poly.ntt(kyber.Poly(aB)).coeffs[0],
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => engine.forward(aLat).coeffs[0],
  );

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward+inverse',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => kyber.Poly.invNtt(kyber.Poly.ntt(kyber.Poly(aB))).coeffs[0],
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward+inverse',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => engine.inverse(engine.forward(aLat)).coeffs[0],
  );

  final pAh = kyber.Poly.ntt(kyber.Poly(aB));
  final pBh = kyber.Poly.ntt(kyber.Poly(bB));
  final aHat = engine.forward(aLat);
  final bHat = engine.forward(bLat);
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'mlKemPairs',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => kyber.Poly.baseMul(pAh, pBh).coeffs[0],
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'mlKemPairs',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => Basemul.mlKemPairs(aHat, bHat, ring).coeffs[0],
  );

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'ntt+basemul+inv',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () => kyber.Poly.invNtt(
      kyber.Poly.baseMul(
        kyber.Poly.ntt(kyber.Poly(aB)),
        kyber.Poly.ntt(kyber.Poly(bB)),
      ),
    ).coeffs[0],
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'ntt+basemul+inv',
    profile: 'mlKem',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'barrett',
    layout: 'allocating',
    fn: () {
      final ah = engine.forward(aLat);
      final bh = engine.forward(bLat);
      return engine.inverse(Basemul.mlKemPairs(ah, bh, ring)).coeffs[0];
    },
  );
}

// ─────────────────────────── ML-DSA (dilithium) ──────────────────────────

void _runMlDsa(
  List<BenchmarkRow> rows,
  BenchmarkContext ctx,
  String buildMode,
) {
  const q = 8380417;
  const n = 256;
  final ring = RingParams.mlDsa;
  final engine = NttEngine(ring);
  final rnd = Random(0x1757);

  // Parity: 25 trials; compare both forward NTTs and the delivered product.
  var ok = 0;
  for (var trial = 0; trial < 25; trial++) {
    final aCoeffs = List<int>.generate(n, (_) => rnd.nextInt(q));
    final bCoeffs = List<int>.generate(n, (_) => rnd.nextInt(q));

    final pa = dil_poly.DilithiumPoly(Int32List.fromList(aCoeffs));
    final pb = dil_poly.DilithiumPoly(Int32List.fromList(bCoeffs));
    dil_ntt.DilithiumNTT.ntt(pa);
    dil_ntt.DilithiumNTT.ntt(pb);
    final ch = pa.pointwiseMul(pb);
    dil_ntt.DilithiumNTT.invNtt(ch);

    final aHat = engine.forward(Poly.fromCoeffs(ring, aCoeffs));
    final bHat = engine.forward(Poly.fromCoeffs(ring, bCoeffs));
    final c = engine.inverse(Basemul.pointwise(aHat, bHat, ring));

    for (var i = 0; i < n; i++) {
      _sameInt(pa.coeffs[i], aHat.coeffs[i], 'mlDsa', trial, i, 'aHat');
      _sameInt(pb.coeffs[i], bHat.coeffs[i], 'mlDsa', trial, i, 'bHat');
      _sameInt(ch.coeffs[i], c.coeffs[i], 'mlDsa', trial, i, 'product');
    }
    ok++;
  }
  stderr.writeln(
    'PARITY mlDsa: $ok/25 trials bit-identical '
    '(aHat, bHat, full product)',
  );

  // Timing inputs (mirrors the mlKem determinant pattern).
  final aSrc = List<int>.generate(n, (i) => (i * 17 + 3) % q);
  final bSrc = List<int>.generate(n, (i) => (i * 31 + 5) % q);
  final aLat = Poly.fromCoeffs(ring, aSrc);
  final bLat = Poly.fromCoeffs(ring, bSrc);

  final paFwd = dil_poly.DilithiumPoly(Int32List.fromList(aSrc));
  dil_ntt.DilithiumNTT.ntt(paFwd);
  final pbFwd = dil_poly.DilithiumPoly(Int32List.fromList(bSrc));
  dil_ntt.DilithiumNTT.ntt(pbFwd);
  final aHat = engine.forward(aLat);
  final bHat = engine.forward(bLat);

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    // Dilithium NTT reduces with plain %.
    reduceStrategy: 'percent',
    // In-place destructive transform: copy-in belongs to the op cost.
    layout: 'inPlace',
    fn: () {
      final p = dil_poly.DilithiumPoly(Int32List.fromList(aSrc));
      dil_ntt.DilithiumNTT.ntt(p);
      return p.coeffs[0];
    },
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'montgomery',
    layout: 'allocating',
    fn: () => engine.forward(aLat).coeffs[0],
  );

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward+inverse',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'percent',
    layout: 'inPlace',
    fn: () {
      final p = dil_poly.DilithiumPoly(Int32List.fromList(aSrc));
      dil_ntt.DilithiumNTT.ntt(p);
      dil_ntt.DilithiumNTT.invNtt(p);
      return p.coeffs[0];
    },
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'forward+inverse',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'montgomery',
    layout: 'allocating',
    fn: () => engine.inverse(engine.forward(aLat)).coeffs[0],
  );

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'pointwise',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'percent',
    layout: 'allocating',
    fn: () => paFwd.pointwiseMul(pbFwd).coeffs[0],
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'pointwise',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'montgomery',
    layout: 'allocating',
    fn: () => Basemul.pointwise(aHat, bHat, ring).coeffs[0],
  );

  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'ntt+basemul+inv',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'pqcrypto',
    reduceStrategy: 'percent',
    layout: 'inPlace',
    fn: () {
      final pa = dil_poly.DilithiumPoly(Int32List.fromList(aSrc));
      final pb = dil_poly.DilithiumPoly(Int32List.fromList(bSrc));
      dil_ntt.DilithiumNTT.ntt(pa);
      dil_ntt.DilithiumNTT.ntt(pb);
      final ch = pa.pointwiseMul(pb);
      dil_ntt.DilithiumNTT.invNtt(ch);
      return ch.coeffs[0];
    },
  );
  _addRow(
    rows,
    ctx: ctx,
    buildMode: buildMode,
    operation: 'ntt+basemul+inv',
    profile: 'mlDsa',
    q: q,
    n: n,
    kernelMode: 'accelerated',
    reduceStrategy: 'montgomery',
    layout: 'allocating',
    fn: () {
      final ah = engine.forward(aLat);
      final bh = engine.forward(bLat);
      return engine.inverse(Basemul.pointwise(ah, bh, ring)).coeffs[0];
    },
  );
}

void _sameInt(int pq, int pl, String ring, int trial, int idx, String what) {
  if (pq != pl) {
    throw StateError(
      'PARITY FAILED $ring trial=$trial coeff[$idx] ($what): '
      'pqcrypto=$pq pqlattice=$pl',
    );
  }
}
