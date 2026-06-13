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

  test('factory rejects the not-yet-implemented SHA-2 family', () {
    expect(
      () => SlhDsaHashFunctions.forParams(SlhDsaParams.sha2128f),
      throwsUnsupportedError,
    );
    expect(
      () => SlhDsaShakeHashFunctions(SlhDsaParams.sha2128f),
      throwsArgumentError,
    );
  });

  test('all six SHAKE parameter sets return their exact derived lengths', () {
    final shakeSets = SlhDsaParams.values.where(
      (candidate) => candidate.hashFamily == SlhDsaHashFamily.shake,
    );
    for (final candidate in shakeSets) {
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
