import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/address.dart';
import 'package:pqcrypto/src/algos/slhdsa/hashing.dart';
import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:test/test.dart';

Uint8List _sequence(int start, int length) => Uint8List.fromList(
  List<int>.generate(length, (index) => (start + index) & 0xff),
);

Uint8List _hex(String value) => Uint8List.fromList(<int>[
  for (var i = 0; i < value.length; i += 2)
    int.parse(value.substring(i, i + 2), radix: 16),
]);

void main() {
  final params = SlhDsaParams.shake128f;
  final hashes = SlhDsaHashFunctions.forParams(params);
  final publicSeed = _sequence(0x00, 16);
  final secretSeed = _sequence(0x10, 16);
  final secretPrf = _sequence(0x20, 16);
  final optRand = _sequence(0x30, 16);
  final randomizer = _sequence(0x40, 16);
  final publicRoot = _sequence(0x50, 16);
  final message = Uint8List.fromList('SLH-DSA hashing test'.codeUnits);
  final address = Adrs.fromBytes(_sequence(0x00, 32));

  // Expected values were independently generated with OpenSSL 3.0.13
  // `openssl dgst -shake256 -xoflen <bytes>`.
  test(
    'SHAKE H_msg matches independent OpenSSL vector and outputs m bytes',
    () {
      final output = hashes.hMsg(randomizer, publicSeed, publicRoot, message);
      expect(output, hasLength(params.messageDigestBytes));
      expect(
        output,
        equals(
          _hex(
            '909b08630b7236ee333e3b1452a92d3778c89c82deb90ab061cab6568c78dc83'
            'eba0',
          ),
        ),
      );
    },
  );

  test('SHAKE PRF functions match independent OpenSSL vectors', () {
    expect(
      hashes.prf(publicSeed, secretSeed, address),
      equals(_hex('f781e0e851c0ea7e2e3d4621f519aa26')),
    );
    expect(
      hashes.prfMsg(secretPrf, optRand, message),
      equals(_hex('d35ce97ea48a777d6c115a08578d62be')),
    );
  });

  test('SHAKE tweakable hashes match independent OpenSSL vectors', () {
    expect(
      hashes.f(publicSeed, address, _sequence(0x60, params.n)),
      equals(_hex('36c1269fcec8e53fabb985212a4de222')),
    );
    expect(
      hashes.h(publicSeed, address, _sequence(0x60, 2 * params.n)),
      equals(_hex('9c2bb311edc26059a00e1ea97c79e8be')),
    );
    expect(
      hashes.tLen(publicSeed, address, _sequence(0x80, 3 * params.n)),
      equals(_hex('60ecf4b28b5fed1aa7162790bbb8bbe2')),
    );
  });

  test('factory selects the exact hash-family implementation', () {
    expect(
      SlhDsaHashFunctions.forParams(SlhDsaParams.sha2128f),
      isA<SlhDsaSha2HashFunctions>(),
    );
    expect(
      SlhDsaHashFunctions.forParams(SlhDsaParams.shake128f),
      isA<SlhDsaShakeHashFunctions>(),
    );
    expect(
      () => SlhDsaShakeHashFunctions(SlhDsaParams.sha2128f),
      throwsArgumentError,
    );
    expect(
      () => SlhDsaSha2HashFunctions(SlhDsaParams.shake128f),
      throwsArgumentError,
    );
  });

  // Expected values were independently generated with Python 3 hashlib/hmac.
  // They pin FIPS 205 Sections 11.2.1 and 11.2.2, including the category 3/5
  // split where PRF/F remain SHA-256 while H/T_len/H_msg/PRF_msg use SHA-512.
  test('SHA2 category 1 functions match independent vectors', () {
    _expectSha2Vectors(
      SlhDsaParams.sha2128f,
      hMsg:
          '9ed449809f3abab1ef685776c4251cd8892f'
          '3a86541116bf31971c9e52c6abf09975',
      prf: 'a626ee7e1a5ba2a8566b5b03fa1af45c',
      prfMsg: '7a78d4c30002e546e6f6baea476c8156',
      f: '6de504ca65726873991b68233633e994',
      h: '0b91f885e546b4c6aa93b0370634a0c5',
      tLen: '7e3df9443e569412d846e882bd5a7c86',
    );
  });

  test('SHA2 category 3 functions match independent split vectors', () {
    _expectSha2Vectors(
      SlhDsaParams.sha2192f,
      hMsg:
          '059bbe8b7684f3e9a72607d6150778319e8a7bb132'
          '659e6e374841b84ba32bd15e089f0abd88f3d4344c',
      prf: 'dd86ce22d44b424a4f0e01d90bd71f25f9a3db8f12dace29',
      prfMsg: '02e7999f3d86c852a93ccbbdd7ff338181f7950f7abd1875',
      f: '99fa21830b4dd2ca06832db9699af3a8c82ceab9bb3f9e1c',
      h: '5bd04d947102949927450b85410fa05d6cef9d2bed23b284',
      tLen: '4c4bb6a6be8e9a2786839319ab40b7e4822d6187315d6950',
    );
  });

  test('all 12 parameter sets return their exact derived lengths', () {
    for (final candidate in SlhDsaParams.values) {
      final candidateHashes = SlhDsaHashFunctions.forParams(candidate);
      final n = candidate.n;
      final candidateSeed = _sequence(0x00, n);
      final candidateAddress = Adrs();

      expect(
        candidateHashes.hMsg(
          _sequence(0x10, n),
          candidateSeed,
          _sequence(0x20, n),
          Uint8List(0),
        ),
        hasLength(candidate.messageDigestBytes),
        reason: candidate.name,
      );
      expect(
        candidateHashes.prf(
          candidateSeed,
          _sequence(0x30, n),
          candidateAddress,
        ),
        hasLength(n),
        reason: candidate.name,
      );
      expect(
        candidateHashes.prfMsg(
          _sequence(0x40, n),
          _sequence(0x50, n),
          Uint8List(0),
        ),
        hasLength(n),
        reason: candidate.name,
      );
      expect(
        candidateHashes.f(candidateSeed, candidateAddress, _sequence(0x60, n)),
        hasLength(n),
        reason: candidate.name,
      );
      expect(
        candidateHashes.h(
          candidateSeed,
          candidateAddress,
          _sequence(0x70, 2 * n),
        ),
        hasLength(n),
        reason: candidate.name,
      );
      expect(
        candidateHashes.tLen(
          candidateSeed,
          candidateAddress,
          _sequence(0x80, 3 * n),
        ),
        hasLength(n),
        reason: candidate.name,
      );
    }
  });

  test('all fixed-length inputs are validated', () {
    final short = Uint8List(params.n - 1);
    expect(
      () => hashes.hMsg(short, publicSeed, publicRoot, message),
      throwsArgumentError,
    );
    expect(
      () => hashes.hMsg(randomizer, short, publicRoot, message),
      throwsArgumentError,
    );
    expect(
      () => hashes.hMsg(randomizer, publicSeed, short, message),
      throwsArgumentError,
    );
    expect(() => hashes.prf(short, secretSeed, address), throwsArgumentError);
    expect(() => hashes.prf(publicSeed, short, address), throwsArgumentError);
    expect(() => hashes.prfMsg(short, optRand, message), throwsArgumentError);
    expect(() => hashes.prfMsg(secretPrf, short, message), throwsArgumentError);
    expect(() => hashes.f(publicSeed, address, short), throwsArgumentError);
    expect(
      () => hashes.h(publicSeed, address, Uint8List(2 * params.n - 1)),
      throwsArgumentError,
    );
    expect(
      () => hashes.tLen(publicSeed, address, Uint8List(0)),
      throwsArgumentError,
    );
    expect(
      () => hashes.tLen(publicSeed, address, Uint8List(params.n + 1)),
      throwsArgumentError,
    );

    final sha2Params = SlhDsaParams.sha2256f;
    final sha2Hashes = SlhDsaHashFunctions.forParams(sha2Params);
    final sha2Seed = Uint8List(sha2Params.n);
    final sha2Short = Uint8List(sha2Params.n - 1);
    expect(
      () => sha2Hashes.hMsg(sha2Short, sha2Seed, sha2Seed, Uint8List(0)),
      throwsArgumentError,
    );
    expect(
      () => sha2Hashes.prf(sha2Seed, sha2Short, Adrs()),
      throwsArgumentError,
    );
    expect(
      () => sha2Hashes.f(sha2Seed, Adrs(), sha2Short),
      throwsArgumentError,
    );
    expect(
      () => sha2Hashes.h(sha2Seed, Adrs(), Uint8List(2 * sha2Params.n - 1)),
      throwsArgumentError,
    );
  });

  test('caller-owned inputs and address remain unchanged', () {
    final seedBefore = Uint8List.fromList(publicSeed);
    final messageBefore = Uint8List.fromList(message);
    final addressBefore = address.toBytes();

    hashes.hMsg(randomizer, publicSeed, publicRoot, message);
    hashes.f(publicSeed, address, _sequence(0x60, params.n));

    expect(publicSeed, equals(seedBefore));
    expect(message, equals(messageBefore));
    expect(address.toBytes(), equals(addressBefore));
  });
}

void _expectSha2Vectors(
  SlhDsaParams params, {
  required String hMsg,
  required String prf,
  required String prfMsg,
  required String f,
  required String h,
  required String tLen,
}) {
  final hashes = SlhDsaHashFunctions.forParams(params);
  final n = params.n;
  final publicSeed = _sequence(0x00, n);
  final secretSeed = _sequence(0x10, n);
  final secretPrf = _sequence(0x20, n);
  final optRand = _sequence(0x30, n);
  final randomizer = _sequence(0x40, n);
  final publicRoot = _sequence(0x50, n);
  final message = Uint8List.fromList('SLH-DSA hashing test'.codeUnits);
  final address = Adrs.fromBytes(_sequence(0x00, 32));

  expect(
    hashes.hMsg(randomizer, publicSeed, publicRoot, message),
    equals(_hex(hMsg)),
  );
  expect(hashes.prf(publicSeed, secretSeed, address), equals(_hex(prf)));
  expect(hashes.prfMsg(secretPrf, optRand, message), equals(_hex(prfMsg)));
  expect(hashes.f(publicSeed, address, _sequence(0x60, n)), equals(_hex(f)));
  expect(
    hashes.h(publicSeed, address, _sequence(0x60, 2 * n)),
    equals(_hex(h)),
  );
  expect(
    hashes.tLen(publicSeed, address, _sequence(0x80, 3 * n)),
    equals(_hex(tLen)),
  );
}
