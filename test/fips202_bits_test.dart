import 'dart:typed_data';

import 'package:pqcrypto/src/common/keccak.dart';
import 'package:test/test.dart';

import 'fips202_bit_string.dart';

void main() {
  const sha3Suffix = <int>[0, 1];
  const shakeSuffix = <int>[1, 1, 1, 1];

  test('a byte-aligned bit string matches the public SHA3-256 wrapper', () {
    final message = BitString(Uint8List.fromList(<int>[0x00, 0x01, 0xa3]), 24);
    expect(message.bitLength, 24);
    expect(
      fips202AbsorbBits(
        messageBits: message.absorptionBits(),
        rateBytes: 136,
        suffixBits: sha3Suffix,
        outputBytes: 32,
      ),
      sha3256(message.bytes),
    );
  });

  test('the empty SHAKE128 bit string matches the public wrapper', () {
    final message = BitString.fromAbsorptionBits('');
    expect(message.bytes, isEmpty);
    expect(message.bitLength, 0);
    expect(
      fips202AbsorbBits(
        messageBits: message.absorptionBits(),
        rateBytes: 168,
        suffixBits: shakeSuffix,
        outputBytes: 64,
      ),
      shake128(message.bytes, 64),
    );
  });

  test('SHA3-256 of the NIST 5-bit message', () {
    // SHA3-256_Msg5.pdf. The printed message bits are already in absorption
    // order: 1 1 0 0 1.
    final message = BitString.fromAbsorptionBits('11001');
    expect(message.bitLength, 5);
    expect(message.bytes, Uint8List.fromList(<int>[0x13]));
    expect(message.absorptionBits(), <int>[1, 1, 0, 0, 1]);
    expect(
      fips202AbsorbBits(
        messageBits: message.absorptionBits(),
        rateBytes: 136,
        suffixBits: sha3Suffix,
        outputBytes: 32,
      ),
      Uint8List.fromList(<int>[
        0x7b, 0x00, 0x47, 0xcf, 0x5a, 0x45, 0x68, 0x82, //
        0x36, 0x3c, 0xbf, 0x0f, 0xb0, 0x53, 0x22, 0xcf, //
        0x65, 0xf4, 0xb7, 0x05, 0x9a, 0x46, 0x36, 0x5e, //
        0x83, 0x01, 0x32, 0xe3, 0xb5, 0xd9, 0x57, 0xaf,
      ]),
    );
  });

  test('BitString rejects a bit that is not 0 or 1', () {
    expect(() => BitString.fromAbsorptionBits('11002'), throwsFormatException);
  });

  test('rejected bit strings produce no digest', () {
    expect(
      () => fips202AbsorbBits(
        messageBits: const <int>[2],
        rateBytes: 136,
        suffixBits: sha3Suffix,
        outputBytes: 32,
      ),
      throwsArgumentError,
    );
    expect(
      () => fips202AbsorbBits(
        messageBits: const <int>[],
        rateBytes: 136,
        suffixBits: const <int>[],
        outputBytes: 32,
      ),
      throwsArgumentError,
    );
  });
}
