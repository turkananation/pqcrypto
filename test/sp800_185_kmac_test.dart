import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

/// NIST SP 800-185 KMAC and KMACXOF samples.
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

  Uint8List mac(_Sample sample) {
    final key = hex(sample.keyHex);
    final message = hex(sample.dataHex);
    final customization = sample.customization.isEmpty
        ? null
        : ascii(sample.customization);
    final outputLength = sample.outputBitLength ~/ 8;
    return switch ((sample.xof, sample.securityBits)) {
      (false, 128) => Kmac128.mac(
        key,
        message,
        outputLength: outputLength,
        customization: customization,
      ),
      (false, 256) => Kmac256.mac(
        key,
        message,
        outputLength: outputLength,
        customization: customization,
      ),
      (true, 128) => KmacXof128.mac(
        key,
        message,
        outputLength: outputLength,
        customization: customization,
      ),
      (true, 256) => KmacXof256.mac(
        key,
        message,
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
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 32,
      dataHex: '00010203',
      outputBitLength: 256,
      customization: '',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '01a8020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '010002',
      encodedNameHex: '01204b4d4143',
      outputHex:
          'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 2,
      securityBits: 128,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 32,
      dataHex: '00010203',
      outputBitLength: 256,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '01a8020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '010002',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 3,
      securityBits: 128,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 1600,
      dataHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
      outputBitLength: 256,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '01a8020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '010002',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 4,
      securityBits: 256,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 32,
      dataHex: '00010203',
      outputBitLength: 512,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '0188020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '020002',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd',
      rateBytes: 136,
    ),
    _Sample(
      xof: false,
      number: 5,
      securityBits: 256,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 1600,
      dataHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
      outputBitLength: 512,
      customization: '',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '0188020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '020002',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69',
      rateBytes: 136,
    ),
    _Sample(
      xof: false,
      number: 6,
      securityBits: 256,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 1600,
      dataHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
      outputBitLength: 512,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '0188020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '020002',
      encodedNameHex: '01204b4d4143',
      outputHex:
          'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 1,
      securityBits: 128,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 32,
      dataHex: '00010203',
      outputBitLength: 256,
      customization: '',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '01a8020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '0001',
      encodedNameHex: '01204b4d4143',
      outputHex:
          'cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 2,
      securityBits: 128,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 32,
      dataHex: '00010203',
      outputBitLength: 256,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '01a8020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '0001',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 3,
      securityBits: 128,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 1600,
      dataHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
      outputBitLength: 256,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '01a8020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '0001',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 4,
      securityBits: 256,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 32,
      dataHex: '00010203',
      outputBitLength: 512,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '0188020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '0001',
      encodedNameHex: '01204b4d4143',
      outputHex:
          '1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 5,
      securityBits: 256,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 1600,
      dataHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
      outputBitLength: 512,
      customization: '',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '0188020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '0001',
      encodedNameHex: '01204b4d4143',
      outputHex:
          'ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02ca633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 6,
      securityBits: 256,
      keyBitLength: 256,
      keyHex:
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      dataBitLength: 1600,
      dataHex:
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7',
      outputBitLength: 512,
      customization: 'My Tagged Application',
      encodedKeyHex:
          '020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      keyBytepadHex:
          '0188020100404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      rightEncodedLengthHex: '0001',
      encodedNameHex: '01204b4d4143',
      outputHex:
          'd5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d',
      rateBytes: 136,
    ),
  ];

  test('covers the twelve NIST KMAC and KMACXOF samples', () {
    expect(samples, hasLength(12));
    expect(
      samples.where((sample) => !sample.xof).map((sample) => sample.number),
      <int>[1, 2, 3, 4, 5, 6],
    );
    expect(
      samples.where((sample) => sample.xof).map((sample) => sample.number),
      <int>[1, 2, 3, 4, 5, 6],
    );
  });

  for (final sample in samples) {
    final label = sample.xof ? 'KMACXOF' : 'KMAC';
    test('$label sample ${sample.number} at ${sample.securityBits} bits', () {
      expect(sample.outputBitLength % 8, 0);
      expect(sample.keyBitLength % 8, 0);
      expect(sample.dataBitLength % 8, 0);
      final key = hex(sample.keyHex);
      final message = hex(sample.dataHex);
      expect(key.length * 8, sample.keyBitLength);
      expect(message.length * 8, sample.dataBitLength);
      expect(
        sample.rateBytes,
        sample.securityBits == 128
            ? Fips202Parameters.shake128.rateBytes
            : Fips202Parameters.shake256.rateBytes,
      );
      expect(encodeString(ascii('KMAC')), hex(sample.encodedNameHex));
      expect(encodeString(key), hex(sample.encodedKeyHex));
      expect(
        bytepad(encodeString(key), sample.rateBytes),
        hex(sample.keyBytepadHex),
      );
      final lengthBits = sample.xof ? 0 : sample.outputBitLength;
      expect(rightEncode(lengthBits), hex(sample.rightEncodedLengthHex));

      final keyCopy = Uint8List.fromList(key);
      final messageCopy = Uint8List.fromList(message);
      expect(mac(sample), hex(sample.outputHex));
      expect(key, keyCopy);
      expect(message, messageCopy);
    });
  }

  test('fixed-output KMAC and KMACXOF differ at the same byte length', () {
    final key = hex(
      '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    );
    final message = hex('00010203');
    final customization = ascii('My Tagged Application');
    expect(
      Kmac128.mac(key, message, outputLength: 32, customization: customization),
      isNot(
        KmacXof128.mac(
          key,
          message,
          outputLength: 32,
          customization: customization,
        ),
      ),
    );
    expect(
      Kmac256.mac(key, message, outputLength: 64, customization: customization),
      isNot(
        KmacXof256.mac(
          key,
          message,
          outputLength: 64,
          customization: customization,
        ),
      ),
    );
  });

  test('an omitted customization matches an explicit empty one', () {
    final key = hex(
      '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    );
    final message = hex('00010203');
    final empty = Uint8List(0);
    expect(
      Kmac128.mac(key, message, outputLength: 32),
      Kmac128.mac(key, message, outputLength: 32, customization: empty),
    );
    expect(
      KmacXof256.mac(key, message, outputLength: 64),
      KmacXof256.mac(key, message, outputLength: 64, customization: empty),
    );
  });

  test('checked mode rejects a short key or tag before output', () {
    final shortKey = Uint8List(Kmac128.minimumRecommendedKeyBytes - 1);
    final message = Uint8List.fromList(<int>[1, 2, 3, 4]);
    expect(
      () => Kmac128.mac(shortKey, message, outputLength: 32, checked: true),
      throwsArgumentError,
    );
    expect(
      () => Kmac256.mac(
        Uint8List(Kmac256.minimumRecommendedKeyBytes - 1),
        message,
        outputLength: 64,
        checked: true,
      ),
      throwsArgumentError,
    );
    expect(
      () => Kmac128.mac(
        Uint8List(Kmac128.minimumRecommendedKeyBytes),
        message,
        outputLength: Kmac128.minimumRecommendedTagBytes - 1,
        checked: true,
      ),
      throwsArgumentError,
    );
    expect(
      () => KmacXof128.mac(shortKey, message, outputLength: 32, checked: true),
      throwsArgumentError,
    );
    expect(Kmac128.mac(shortKey, message, outputLength: 32), hasLength(32));
    expect(
      Kmac128.mac(
        Uint8List(Kmac128.minimumRecommendedKeyBytes),
        message,
        outputLength: Kmac128.minimumRecommendedTagBytes,
        checked: true,
      ),
      hasLength(Kmac128.minimumRecommendedTagBytes),
    );
  });

  test('a negative output length throws and names outputLength', () {
    final key = Uint8List(32);
    final message = Uint8List.fromList(<int>[1]);
    expect(
      () => Kmac128.mac(key, message, outputLength: -1),
      throwsA(
        isA<RangeError>().having((error) => error.name, 'name', 'outputLength'),
      ),
    );
    expect(
      () => KmacXof256.mac(key, message, outputLength: -1),
      throwsA(
        isA<RangeError>().having((error) => error.name, 'name', 'outputLength'),
      ),
    );
    expect(Kmac128.mac(key, message, outputLength: 0), isEmpty);
  });
}

class _Sample {
  const _Sample({
    required this.xof,
    required this.number,
    required this.securityBits,
    required this.keyBitLength,
    required this.keyHex,
    required this.dataBitLength,
    required this.dataHex,
    required this.outputBitLength,
    required this.customization,
    required this.encodedKeyHex,
    required this.keyBytepadHex,
    required this.rightEncodedLengthHex,
    required this.encodedNameHex,
    required this.outputHex,
    required this.rateBytes,
  });

  final bool xof;
  final int number;
  final int securityBits;
  final int keyBitLength;
  final String keyHex;
  final int dataBitLength;
  final String dataHex;
  final int outputBitLength;
  final String customization;
  final String encodedKeyHex;
  final String keyBytepadHex;
  final String rightEncodedLengthHex;
  final String encodedNameHex;
  final String outputHex;
  final int rateBytes;
}
