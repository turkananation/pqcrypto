import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/common/sha2.dart';

Uint8List _ascii(String s) => Uint8List.fromList(s.codeUnits);
String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

// The 56-byte and 112-byte messages are the canonical FIPS 180-2 examples,
// chosen to force a second compression block for SHA-256 and SHA-512/384.
const _m56 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
const _m112 =
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn'
    'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';

void main() {
  group('SHA-224 (FIPS 180-4)', () {
    test('abc', () {
      expect(
        _hex(sha224(_ascii('abc'))),
        '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
      );
    });
  });

  group('SHA-256 (FIPS 180-4)', () {
    test('empty', () {
      expect(
        _hex(sha256(Uint8List(0))),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });
    test('abc', () {
      expect(
        _hex(sha256(_ascii('abc'))),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });
    test('56-byte (two blocks)', () {
      expect(
        _hex(sha256(_ascii(_m56))),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      );
    });
  });

  group('SHA-384 (FIPS 180-4)', () {
    test('abc', () {
      expect(
        _hex(sha384(_ascii('abc'))),
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed'
        '8086072ba1e7cc2358baeca134c825a7',
      );
    });
    test('112-byte (two blocks)', () {
      expect(
        _hex(sha384(_ascii(_m112))),
        '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712'
        'fcc7c71a557e2db966c3e9fa91746039',
      );
    });
  });

  group('SHA-512 (FIPS 180-4)', () {
    test('empty', () {
      expect(
        _hex(sha512(Uint8List(0))),
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
        '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
      );
    });
    test('abc', () {
      expect(
        _hex(sha512(_ascii('abc'))),
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
      );
    });
    test('112-byte (two blocks)', () {
      expect(
        _hex(sha512(_ascii(_m112))),
        '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018'
        '501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
      );
    });
  });

  group('SHA-512 truncated variants (FIPS 180-4)', () {
    test('SHA-512/224 abc', () {
      expect(
        _hex(sha512224(_ascii('abc'))),
        '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa',
      );
    });

    test('SHA-512/256 abc', () {
      expect(
        _hex(sha512256(_ascii('abc'))),
        '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23',
      );
    });
  });
}
