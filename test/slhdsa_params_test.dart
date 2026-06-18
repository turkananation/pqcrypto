import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:pqcrypto/src/algos/slhdsa/util.dart';
import 'package:test/test.dart';

void main() {
  final expectedRows =
      <
        String,
        (
          SlhDsaHashFamily,
          int,
          int,
          int,
          int,
          int,
          int,
          int,
          bool,
          int,
          int,
          int,
          int,
        )
      >{
        'SLH-DSA-SHA2-128s': (
          SlhDsaHashFamily.sha2,
          1,
          16,
          63,
          7,
          12,
          14,
          30,
          false,
          32,
          64,
          7856,
          9,
        ),
        'SLH-DSA-SHA2-128f': (
          SlhDsaHashFamily.sha2,
          1,
          16,
          66,
          22,
          6,
          33,
          34,
          true,
          32,
          64,
          17088,
          3,
        ),
        'SLH-DSA-SHA2-192s': (
          SlhDsaHashFamily.sha2,
          3,
          24,
          63,
          7,
          14,
          17,
          39,
          false,
          48,
          96,
          16224,
          9,
        ),
        'SLH-DSA-SHA2-192f': (
          SlhDsaHashFamily.sha2,
          3,
          24,
          66,
          22,
          8,
          33,
          42,
          true,
          48,
          96,
          35664,
          3,
        ),
        'SLH-DSA-SHA2-256s': (
          SlhDsaHashFamily.sha2,
          5,
          32,
          64,
          8,
          14,
          22,
          47,
          false,
          64,
          128,
          29792,
          8,
        ),
        'SLH-DSA-SHA2-256f': (
          SlhDsaHashFamily.sha2,
          5,
          32,
          68,
          17,
          9,
          35,
          49,
          true,
          64,
          128,
          49856,
          4,
        ),
        'SLH-DSA-SHAKE-128s': (
          SlhDsaHashFamily.shake,
          1,
          16,
          63,
          7,
          12,
          14,
          30,
          false,
          32,
          64,
          7856,
          9,
        ),
        'SLH-DSA-SHAKE-128f': (
          SlhDsaHashFamily.shake,
          1,
          16,
          66,
          22,
          6,
          33,
          34,
          true,
          32,
          64,
          17088,
          3,
        ),
        'SLH-DSA-SHAKE-192s': (
          SlhDsaHashFamily.shake,
          3,
          24,
          63,
          7,
          14,
          17,
          39,
          false,
          48,
          96,
          16224,
          9,
        ),
        'SLH-DSA-SHAKE-192f': (
          SlhDsaHashFamily.shake,
          3,
          24,
          66,
          22,
          8,
          33,
          42,
          true,
          48,
          96,
          35664,
          3,
        ),
        'SLH-DSA-SHAKE-256s': (
          SlhDsaHashFamily.shake,
          5,
          32,
          64,
          8,
          14,
          22,
          47,
          false,
          64,
          128,
          29792,
          8,
        ),
        'SLH-DSA-SHAKE-256f': (
          SlhDsaHashFamily.shake,
          5,
          32,
          68,
          17,
          9,
          35,
          49,
          true,
          64,
          128,
          49856,
          4,
        ),
      };

  test('all 12 FIPS 205 Table 2 parameter sets and sizes are exact', () {
    expect(SlhDsaParams.values, hasLength(12));
    expect(SlhDsaParameter.values, hasLength(12));

    for (final params in SlhDsaParams.values) {
      final row = expectedRows[params.name]!;
      expect(params.hashFamily, row.$1, reason: params.name);
      expect(params.securityCategory, row.$2, reason: params.name);
      expect(params.n, row.$3, reason: params.name);
      expect(params.h, row.$4, reason: params.name);
      expect(params.d, row.$5, reason: params.name);
      expect(params.a, row.$6, reason: params.name);
      expect(params.k, row.$7, reason: params.name);
      expect(params.messageDigestBytes, row.$8, reason: params.name);
      expect(params.isFast, row.$9, reason: params.name);
      expect(params.publicKeyBytes, row.$10, reason: params.name);
      expect(params.secretKeyBytes, row.$11, reason: params.name);
      expect(params.signatureBytes, row.$12, reason: params.name);
      expect(params.hPrime, row.$13, reason: params.name);
    }
  });

  test('all dependent values are internally consistent', () {
    for (final params in SlhDsaParams.values) {
      expect(params.lgW, 4, reason: params.name);
      expect(params.w, 16, reason: params.name);
      expect(params.len1, 2 * params.n, reason: params.name);
      expect(params.len2, 3, reason: params.name);
      expect(params.len2, genLen2(params.n, params.lgW));
      expect(params.len, 2 * params.n + 3, reason: params.name);
      expect(params.t, 1 << params.a, reason: params.name);
      expect(params.h, params.d * params.hPrime, reason: params.name);
      expect(
        params.signatureBytes,
        params.n + params.forsSignatureBytes + params.hypertreeSignatureBytes,
        reason: params.name,
      );
      expect(
        params.hypertreeSignatureBytes,
        params.d * params.xmssSignatureBytes,
        reason: params.name,
      );
      expect(params.wotsSignatureBytes, params.len * params.n);
    }
  });

  test('enum lookup covers every parameter exactly once', () {
    expect(<SlhDsaParams>{
      for (final parameter in SlhDsaParameter.values)
        SlhDsaParams.get(parameter),
    }, hasLength(12));
  });
}
