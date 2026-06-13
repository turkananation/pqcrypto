/// FIPS 205 SLH-DSA parameter sets and parameter-derived sizes.
///
/// Reference: FIPS 205 Table 2 and Equations 5.1-5.4.
library;

import 'util.dart';

enum SlhDsaHashFamily { sha2, shake }

enum SlhDsaParameter {
  sha2128s,
  sha2128f,
  sha2192s,
  sha2192f,
  sha2256s,
  sha2256f,
  shake128s,
  shake128f,
  shake192s,
  shake192f,
  shake256s,
  shake256f,
}

/// One FIPS 205 parameter set with all dependent sizes derived in code.
final class SlhDsaParams {
  const SlhDsaParams._(this.name, this.hashFamily, this._row);

  final String name;
  final SlhDsaHashFamily hashFamily;
  final _SlhDsaParameterRow _row;

  int get securityCategory => _row.securityCategory;
  int get n => _row.n;
  int get h => _row.h;
  int get d => _row.d;
  int get a => _row.a;
  int get k => _row.k;
  bool get isFast => _row.isFast;
  int get lgW => 4;

  static const _row128s = _SlhDsaParameterRow(1, 16, 63, 7, 12, 14, false);
  static const _row128f = _SlhDsaParameterRow(1, 16, 66, 22, 6, 33, true);
  static const _row192s = _SlhDsaParameterRow(3, 24, 63, 7, 14, 17, false);
  static const _row192f = _SlhDsaParameterRow(3, 24, 66, 22, 8, 33, true);
  static const _row256s = _SlhDsaParameterRow(5, 32, 64, 8, 14, 22, false);
  static const _row256f = _SlhDsaParameterRow(5, 32, 68, 17, 9, 35, true);

  static const sha2128s = SlhDsaParams._(
    'SLH-DSA-SHA2-128s',
    SlhDsaHashFamily.sha2,
    _row128s,
  );
  static const sha2128f = SlhDsaParams._(
    'SLH-DSA-SHA2-128f',
    SlhDsaHashFamily.sha2,
    _row128f,
  );
  static const sha2192s = SlhDsaParams._(
    'SLH-DSA-SHA2-192s',
    SlhDsaHashFamily.sha2,
    _row192s,
  );
  static const sha2192f = SlhDsaParams._(
    'SLH-DSA-SHA2-192f',
    SlhDsaHashFamily.sha2,
    _row192f,
  );
  static const sha2256s = SlhDsaParams._(
    'SLH-DSA-SHA2-256s',
    SlhDsaHashFamily.sha2,
    _row256s,
  );
  static const sha2256f = SlhDsaParams._(
    'SLH-DSA-SHA2-256f',
    SlhDsaHashFamily.sha2,
    _row256f,
  );
  static const shake128s = SlhDsaParams._(
    'SLH-DSA-SHAKE-128s',
    SlhDsaHashFamily.shake,
    _row128s,
  );
  static const shake128f = SlhDsaParams._(
    'SLH-DSA-SHAKE-128f',
    SlhDsaHashFamily.shake,
    _row128f,
  );
  static const shake192s = SlhDsaParams._(
    'SLH-DSA-SHAKE-192s',
    SlhDsaHashFamily.shake,
    _row192s,
  );
  static const shake192f = SlhDsaParams._(
    'SLH-DSA-SHAKE-192f',
    SlhDsaHashFamily.shake,
    _row192f,
  );
  static const shake256s = SlhDsaParams._(
    'SLH-DSA-SHAKE-256s',
    SlhDsaHashFamily.shake,
    _row256s,
  );
  static const shake256f = SlhDsaParams._(
    'SLH-DSA-SHAKE-256f',
    SlhDsaHashFamily.shake,
    _row256f,
  );

  static const List<SlhDsaParams> values = <SlhDsaParams>[
    sha2128s,
    sha2128f,
    sha2192s,
    sha2192f,
    sha2256s,
    sha2256f,
    shake128s,
    shake128f,
    shake192s,
    shake192f,
    shake256s,
    shake256f,
  ];

  int get hPrime => h ~/ d;
  int get w => 1 << lgW;
  int get len1 => (8 * n + lgW - 1) ~/ lgW;
  int get len2 => genLen2(n, lgW);
  int get len => len1 + len2;
  int get t => 1 << a;

  int get forsMessageBytes => (k * a + 7) ~/ 8;
  int get treeIndexBytes => (h - hPrime + 7) ~/ 8;
  int get leafIndexBytes => (hPrime + 7) ~/ 8;
  int get messageDigestBytes =>
      forsMessageBytes + treeIndexBytes + leafIndexBytes;

  int get publicKeyBytes => 2 * n;
  int get secretKeyBytes => 4 * n;
  int get wotsSignatureBytes => len * n;
  int get forsSignatureBytes => k * (1 + a) * n;
  int get xmssSignatureBytes => (len + hPrime) * n;
  int get hypertreeSignatureBytes => (d * len + h) * n;
  int get signatureBytes => n + forsSignatureBytes + hypertreeSignatureBytes;

  static SlhDsaParams get(SlhDsaParameter parameter) => switch (parameter) {
    SlhDsaParameter.sha2128s => sha2128s,
    SlhDsaParameter.sha2128f => sha2128f,
    SlhDsaParameter.sha2192s => sha2192s,
    SlhDsaParameter.sha2192f => sha2192f,
    SlhDsaParameter.sha2256s => sha2256s,
    SlhDsaParameter.sha2256f => sha2256f,
    SlhDsaParameter.shake128s => shake128s,
    SlhDsaParameter.shake128f => shake128f,
    SlhDsaParameter.shake192s => shake192s,
    SlhDsaParameter.shake192f => shake192f,
    SlhDsaParameter.shake256s => shake256s,
    SlhDsaParameter.shake256f => shake256f,
  };
}

final class _SlhDsaParameterRow {
  const _SlhDsaParameterRow(
    this.securityCategory,
    this.n,
    this.h,
    this.d,
    this.a,
    this.k,
    this.isFast,
  ) : assert(h % d == 0);

  final int securityCategory;
  final int n;
  final int h;
  final int d;
  final int a;
  final int k;
  final bool isFast;
}
