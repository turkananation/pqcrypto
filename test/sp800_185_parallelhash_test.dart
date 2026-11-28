import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

/// NIST SP 800-185 ParallelHash and ParallelHashXOF samples.
///
/// Hex is inlined so this file runs on Chrome.
void main() {
  Uint8List hex(String value) {
    return Uint8List.fromList(<int>[
      for (var i = 0; i < value.length; i += 2)
        int.parse(value.substring(i, i + 2), radix: 16),
    ]);
  }

  Uint8List ascii(String value) => Uint8List.fromList(value.codeUnits);

  Uint8List digest(_Sample sample) {
    final message = hex(sample.dataHex);
    final customization = sample.customization.isEmpty
        ? null
        : ascii(sample.customization);
    final outputLength = sample.outputBitLength ~/ 8;
    return switch ((sample.xof, sample.securityBits)) {
      (false, 128) => ParallelHash128.hash(
        message,
        blockSize: sample.blockSize,
        outputLength: outputLength,
        customization: customization,
      ),
      (false, 256) => ParallelHash256.hash(
        message,
        blockSize: sample.blockSize,
        outputLength: outputLength,
        customization: customization,
      ),
      (true, 128) => ParallelHashXof128.hash(
        message,
        blockSize: sample.blockSize,
        outputLength: outputLength,
        customization: customization,
      ),
      (true, 256) => ParallelHashXof256.hash(
        message,
        blockSize: sample.blockSize,
        outputLength: outputLength,
        customization: customization,
      ),
      _ => throw ArgumentError.value(sample.securityBits, 'securityBits'),
    };
  }

  const samples = <_Sample>[
    _Sample(
      xof: false,
      number: 1,
      securityBits: 128,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 256,
      customization: '',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '010002',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 2,
      securityBits: 128,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 256,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '010002',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 3,
      securityBits: 128,
      blockSize: 12,
      dataBitLength: 576,
      dataHex:
          '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b',
      outputBitLength: 256,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '010c',
      encodedBlockCountHex: '0601',
      encodedOutputLengthHex: '010002',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 1,
      securityBits: 256,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 512,
      customization: '',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '020002',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429',
      rateBytes: 136,
    ),
    _Sample(
      xof: false,
      number: 2,
      securityBits: 256,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 512,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '020002',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110',
      rateBytes: 136,
    ),
    _Sample(
      xof: false,
      number: 3,
      securityBits: 256,
      blockSize: 12,
      dataBitLength: 576,
      dataHex:
          '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b',
      outputBitLength: 512,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '010c',
      encodedBlockCountHex: '0601',
      encodedOutputLengthHex: '020002',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          '69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d1b4568a6cce16b1cad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 1,
      securityBits: 128,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 256,
      customization: '',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '0001',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 2,
      securityBits: 128,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 256,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '0001',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'ea2a793140820f7a128b8eb70a9439f93257c6e6e79b4a540d291d6dae7098d7',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 3,
      securityBits: 128,
      blockSize: 12,
      dataBitLength: 576,
      dataHex:
          '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b',
      outputBitLength: 256,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '010c',
      encodedBlockCountHex: '0601',
      encodedOutputLengthHex: '0001',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          '0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 1,
      securityBits: 256,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 512,
      customization: '',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '0001',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          'c10a052722614684144d28474850b410757e3cba87651ba167a5cbddff7f466675fbf84bcae7378ac444be681d729499afca667fb879348bfdda427863c82f1c',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 2,
      securityBits: 256,
      blockSize: 8,
      dataBitLength: 192,
      dataHex: '000102030405060710111213141516172021222324252627',
      outputBitLength: 512,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '0108',
      encodedBlockCountHex: '0301',
      encodedOutputLengthHex: '0001',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          '538e105f1a22f44ed2f5cc1674fbd40be803d9c99bf5f8d90a2c8193f3fe6ea768e5c1a20987e2c9c65febed03887a51d35624ed12377594b5585541dc377efc',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 3,
      securityBits: 256,
      blockSize: 12,
      dataBitLength: 576,
      dataHex:
          '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b',
      outputBitLength: 512,
      customization: 'Parallel Data',
      encodedBlockSizeHex: '010c',
      encodedBlockCountHex: '0601',
      encodedOutputLengthHex: '0001',
      encodedNameHex: '0160506172616c6c656c48617368',
      outputHex:
          '6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bcefb7fe5b607b13a801c0be5c1170bdb794e339458fdb0e62a6af3d42558970249',
      rateBytes: 136,
    ),
  ];

  test('covers the twelve NIST ParallelHash samples', () {
    expect(samples, hasLength(12));
    expect(samples.where((sample) => sample.blockSize == 12), hasLength(4));
  });

  for (final sample in samples) {
    final label = sample.xof ? 'ParallelHashXOF' : 'ParallelHash';
    test('$label sample ${sample.number} at ${sample.securityBits} bits, '
        'block ${sample.blockSize}', () {
      expect(sample.outputBitLength % 8, 0);
      expect(sample.dataBitLength % 8, 0);
      final message = hex(sample.dataHex);
      expect(message.length * 8, sample.dataBitLength);
      expect(sample.blockSize > 0, isTrue);
      final blocks =
          (message.length + sample.blockSize - 1) ~/ sample.blockSize;
      expect(blocks > 1, isTrue);
      expect(
        sample.rateBytes,
        sample.securityBits == 128
            ? Fips202Parameters.shake128.rateBytes
            : Fips202Parameters.shake256.rateBytes,
      );
      expect(leftEncode(sample.blockSize), hex(sample.encodedBlockSizeHex));
      expect(rightEncode(blocks), hex(sample.encodedBlockCountHex));
      final lengthBits = sample.xof ? 0 : sample.outputBitLength;
      expect(rightEncode(lengthBits), hex(sample.encodedOutputLengthHex));
      expect(encodeString(ascii('ParallelHash')), hex(sample.encodedNameHex));

      final copy = Uint8List.fromList(message);
      expect(digest(sample), hex(sample.outputHex));
      expect(message, copy);
    });
  }

  test('one block and several blocks of the same bytes differ', () {
    final message = hex('000102030405060710111213141516172021222324252627');
    expect(
      ParallelHash128.hash(
        message,
        blockSize: message.length,
        outputLength: 32,
      ),
      isNot(ParallelHash128.hash(message, blockSize: 8, outputLength: 32)),
    );
    expect(
      ParallelHash256.hash(message, blockSize: 8, outputLength: 64),
      isNot(ParallelHash256.hash(message, blockSize: 12, outputLength: 64)),
    );
  });

  test('fixed-output ParallelHash and ParallelHashXOF differ', () {
    final message = hex('000102030405060710111213141516172021222324252627');
    final customization = ascii('Parallel Data');
    expect(
      ParallelHash128.hash(
        message,
        blockSize: 8,
        outputLength: 32,
        customization: customization,
      ),
      isNot(
        ParallelHashXof128.hash(
          message,
          blockSize: 8,
          outputLength: 32,
          customization: customization,
        ),
      ),
    );
    expect(
      ParallelHash256.hash(
        message,
        blockSize: 8,
        outputLength: 64,
        customization: customization,
      ),
      isNot(
        ParallelHashXof256.hash(
          message,
          blockSize: 8,
          outputLength: 64,
          customization: customization,
        ),
      ),
    );
  });

  test('a short final block is defined and an empty message is defined', () {
    final message = Uint8List.fromList(<int>[1, 2, 3, 4, 5]);
    final copy = Uint8List.fromList(message);
    final split = ParallelHash128.hash(message, blockSize: 3, outputLength: 32);
    final whole = ParallelHash128.hash(
      message,
      blockSize: message.length,
      outputLength: 32,
    );
    expect(split, isNot(whole));
    expect(split, hasLength(32));
    expect(message, copy);
    expect(
      ParallelHash128.hash(Uint8List(0), blockSize: 8, outputLength: 32),
      hasLength(32),
    );
    expect(
      ParallelHash128.hash(Uint8List(0), blockSize: 8, outputLength: 0),
      isEmpty,
    );
  });

  test('blockSize <= 0 throws before any output', () {
    final message = Uint8List.fromList(<int>[1, 2, 3, 4]);
    expect(
      () => ParallelHash128.hash(message, blockSize: 0, outputLength: 32),
      throwsArgumentError,
    );
    expect(
      () => ParallelHash256.hash(message, blockSize: -1, outputLength: 64),
      throwsArgumentError,
    );
    expect(
      () => ParallelHashXof128.hash(message, blockSize: 0, outputLength: 32),
      throwsArgumentError,
    );
    expect(
      ParallelHash128.hash(message, blockSize: 4, outputLength: 32),
      hasLength(32),
    );
  });

  test('a negative output length throws and names outputLength', () {
    final message = Uint8List.fromList(<int>[1]);
    expect(
      () => ParallelHash128.hash(message, blockSize: 8, outputLength: -1),
      throwsA(
        isA<RangeError>().having((error) => error.name, 'name', 'outputLength'),
      ),
    );
    expect(
      () => ParallelHashXof256.hash(message, blockSize: 8, outputLength: -1),
      throwsA(
        isA<RangeError>().having((error) => error.name, 'name', 'outputLength'),
      ),
    );
  });
}

class _Sample {
  const _Sample({
    required this.xof,
    required this.number,
    required this.securityBits,
    required this.blockSize,
    required this.dataBitLength,
    required this.dataHex,
    required this.outputBitLength,
    required this.customization,
    required this.encodedBlockSizeHex,
    required this.encodedBlockCountHex,
    required this.encodedOutputLengthHex,
    required this.encodedNameHex,
    required this.outputHex,
    required this.rateBytes,
  });

  final bool xof;
  final int number;
  final int securityBits;
  final int blockSize;
  final int dataBitLength;
  final String dataHex;
  final int outputBitLength;
  final String customization;
  final String encodedBlockSizeHex;
  final String encodedBlockCountHex;
  final String encodedOutputLengthHex;
  final String encodedNameHex;
  final String outputHex;
  final int rateBytes;
}
