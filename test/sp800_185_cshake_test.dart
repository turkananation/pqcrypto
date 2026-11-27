import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqcrypto/src/common/keccak.dart' show fips202AbsorbBits;
import 'package:test/test.dart';

/// NIST SP 800-185 cSHAKE samples from `test/data/SP800185/examples.json`.
///
/// The hex is inlined so this file can run on Chrome. The corpus file is read
/// with `dart:io` by the VM encoding test; this runner does not.
void main() {
  Uint8List hex(String value) {
    return Uint8List.fromList(<int>[
      for (var i = 0; i < value.length; i += 2)
        int.parse(value.substring(i, i + 2), radix: 16),
    ]);
  }

  Uint8List ascii(String value) => Uint8List.fromList(value.codeUnits);

  Uint8List concat(Uint8List left, Uint8List right) {
    final out = Uint8List(left.length + right.length);
    out.setRange(0, left.length, left);
    out.setRange(left.length, out.length, right);
    return out;
  }

  List<int> bytesToBits(Uint8List bytes) {
    return <int>[
      for (final byte in bytes)
        for (var bit = 0; bit < 8; bit++) (byte >> bit) & 1,
    ];
  }

  Uint8List cshake(
    int securityBits,
    Uint8List message, {
    required int outputLength,
    Uint8List? functionName,
    Uint8List? customization,
  }) {
    return switch (securityBits) {
      128 => CShake128.hash(
        message,
        outputLength: outputLength,
        functionName: functionName,
        customization: customization,
      ),
      256 => CShake256.hash(
        message,
        outputLength: outputLength,
        functionName: functionName,
        customization: customization,
      ),
      _ => throw ArgumentError.value(securityBits, 'securityBits'),
    };
  }

  group('NIST cSHAKE samples', () {
    const samples = <_Sample>[
      _Sample(
        number: 1,
        securityBits: 128,
        dataBitLength: 32,
        dataHex: '00010203',
        outputBitLength: 256,
        customization: 'Email Signature',
        bytepadHex:
            '01a801000178456d61696c205369676e6174757265000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        outputHex:
            'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5',
        rateBytes: 168,
      ),
      _Sample(
        number: 2,
        securityBits: 128,
        dataBitLength: 1600,
        dataHex:
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
        outputBitLength: 256,
        customization: 'Email Signature',
        bytepadHex:
            '01a801000178456d61696c205369676e6174757265000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        outputHex:
            'c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b',
        rateBytes: 168,
      ),
      _Sample(
        number: 3,
        securityBits: 256,
        dataBitLength: 32,
        dataHex: '00010203',
        outputBitLength: 512,
        customization: 'Email Signature',
        bytepadHex:
            '018801000178456d61696c205369676e617475726500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        outputHex:
            'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c',
        rateBytes: 136,
      ),
      _Sample(
        number: 4,
        securityBits: 256,
        dataBitLength: 1600,
        dataHex:
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
        outputBitLength: 512,
        customization: 'Email Signature',
        bytepadHex:
            '018801000178456d61696c205369676e617475726500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        outputHex:
            '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb',
        rateBytes: 136,
      ),
    ];

    test('covers cSHAKE samples 1 through 4', () {
      expect(samples, hasLength(4));
      expect(samples.map((sample) => sample.number), <int>[1, 2, 3, 4]);
    });

    for (final sample in samples) {
      test('sample ${sample.number} at ${sample.securityBits} bits matches '
          'outputHex with domain 0x04', () {
        expect(sample.outputBitLength % 8, 0);
        final outputBytes = sample.outputBitLength ~/ 8;
        final message = hex(sample.dataHex);
        final customization = ascii(sample.customization);
        expect(message.length * 8, sample.dataBitLength);
        expect(
          sample.rateBytes,
          sample.securityBits == 128
              ? Fips202Parameters.shake128.rateBytes
              : Fips202Parameters.shake256.rateBytes,
        );

        final prefix = bytepad(
          concat(encodeString(Uint8List(0)), encodeString(customization)),
          sample.rateBytes,
        );
        expect(prefix, hex(sample.bytepadHex));

        final actual = cshake(
          sample.securityBits,
          message,
          outputLength: outputBytes,
          functionName: Uint8List(0),
          customization: customization,
        );
        // Suffix bits 00, then pad10*1, pack as domain 0x04 and a final
        // 0x80. The bit sponge is the definition those bytes implement.
        final fromBits = fips202AbsorbBits(
          messageBits: bytesToBits(concat(prefix, message)),
          rateBytes: sample.rateBytes,
          suffixBits: const <int>[0, 0],
          outputBytes: outputBytes,
        );
        expect(fromBits, hex(sample.outputHex));
        expect(actual, hex(sample.outputHex));
      });
    }
  });

  test('domain 0x04 and the final 0x80 share the last rate byte', () {
    final customization = ascii('Email Signature');
    for (final securityBits in <int>[128, 256]) {
      final rate = securityBits == 128 ? 168 : 136;
      final message = Uint8List(rate - 1)..fillRange(0, rate - 1, 0xA5);
      final prefix = bytepad(
        concat(encodeString(Uint8List(0)), encodeString(customization)),
        rate,
      );
      expect(prefix.length, rate);
      final absorbed = concat(prefix, message);
      expect(absorbed.length % rate, rate - 1);

      final actual = cshake(
        securityBits,
        message,
        outputLength: 32,
        customization: customization,
      );
      expect(
        actual,
        fips202AbsorbBits(
          messageBits: bytesToBits(absorbed),
          rateBytes: rate,
          suffixBits: const <int>[0, 0],
          outputBytes: 32,
        ),
      );
    }
  });

  test('empty function name and customization match SHAKE', () {
    final message = Uint8List.fromList(<int>[9, 8, 7, 6, 5]);
    final empty = Uint8List(0);
    for (final length in <int>[0, 1, 16, 32, 200]) {
      expect(
        CShake128.hash(message, outputLength: length),
        shake128(message, length),
      );
      expect(
        CShake128.hash(
          message,
          outputLength: length,
          functionName: empty,
          customization: empty,
        ),
        shake128(message, length),
      );
      expect(
        CShake256.hash(message, outputLength: length),
        shake256(message, length),
      );
      expect(
        CShake256.hash(
          message,
          outputLength: length,
          functionName: empty,
          customization: empty,
        ),
        shake256(message, length),
      );
    }
    expect(CShake128.hash(empty, outputLength: 16), shake128(empty, 16));
  });

  test('different customization strings produce different output', () {
    final message = Uint8List.fromList(<int>[0, 1, 2, 3]);
    final left = ascii('tenant-a');
    final right = ascii('tenant-b');
    final cshake128Left = CShake128.hash(
      message,
      outputLength: 32,
      customization: left,
    );
    final cshake128Right = CShake128.hash(
      message,
      outputLength: 32,
      customization: right,
    );
    final cshake256Left = CShake256.hash(
      message,
      outputLength: 64,
      customization: left,
    );
    final cshake256Right = CShake256.hash(
      message,
      outputLength: 64,
      customization: right,
    );

    expect(cshake128Left, isNot(cshake128Right));
    expect(cshake256Left, isNot(cshake256Right));
    expect(cshake128Left, isNot(shake128(message, 32)));
    expect(cshake256Left, isNot(shake256(message, 64)));
    expect(
      cshake128Left,
      isNot(CShake256.hash(message, outputLength: 32, customization: left)),
    );
    expect(
      CShake128.hash(message, outputLength: 32, functionName: ascii('KMAC')),
      isNot(shake128(message, 32)),
    );
  });

  test('negative output lengths throw before any digest is returned', () {
    final message = Uint8List.fromList(<int>[1, 2, 3, 4]);
    final customization = ascii('Email Signature');
    for (final length in <int>[-1, -32]) {
      expect(
        () => CShake128.hash(message, outputLength: length),
        throwsA(
          isA<RangeError>().having(
            (error) => error.name,
            'name',
            'outputLength',
          ),
        ),
      );
      expect(
        () => CShake256.hash(
          message,
          outputLength: length,
          customization: customization,
        ),
        throwsA(
          isA<RangeError>().having(
            (error) => error.name,
            'name',
            'outputLength',
          ),
        ),
      );
    }
    expect(
      CShake128.hash(message, outputLength: 16, customization: customization),
      hasLength(16),
    );
  });

  test('hashing does not mutate the caller buffers', () {
    final message = Uint8List.fromList(<int>[0, 1, 2, 3]);
    final functionName = ascii('KMAC');
    final customization = ascii('Email Signature');
    final messageCopy = Uint8List.fromList(message);
    final functionNameCopy = Uint8List.fromList(functionName);
    final customizationCopy = Uint8List.fromList(customization);

    CShake128.hash(
      message,
      outputLength: 32,
      functionName: functionName,
      customization: customization,
    );
    CShake256.hash(
      message,
      outputLength: 64,
      functionName: functionName,
      customization: customization,
    );

    expect(message, messageCopy);
    expect(functionName, functionNameCopy);
    expect(customization, customizationCopy);
  });
}

class _Sample {
  const _Sample({
    required this.number,
    required this.securityBits,
    required this.dataBitLength,
    required this.dataHex,
    required this.outputBitLength,
    required this.customization,
    required this.bytepadHex,
    required this.outputHex,
    required this.rateBytes,
  });

  final int number;
  final int securityBits;
  final int dataBitLength;
  final String dataHex;
  final int outputBitLength;
  final String customization;
  final String bytepadHex;
  final String outputHex;
  final int rateBytes;
}
