import 'dart:typed_data';

import 'package:pqcrypto/src/common/keccak.dart';
import 'package:test/test.dart';

/// Direct FIPS 202 known-answer tests for the vendored Keccak (the code that
/// replaced the `pointycastle` dependency). These pin SHA3-256/512 and
/// SHAKE128/256 against published NIST values, independent of the ML-KEM KAT
/// corpus. The empty- and "abc"-message vectors fit in one block; the
/// 1,000,000-byte message exercises the multi-block absorb path; the SHAKE
/// stream-prefix property exercises multi-block squeeze.
void main() {
  Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);
  Uint8List hexToBytes(String h) {
    final out = Uint8List(h.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(h.substring(2 * i, 2 * i + 2), radix: 16);
    }
    return out;
  }

  final empty = Uint8List(0);
  final abc = ascii('abc');
  final millionA = Uint8List(1000000)..fillRange(0, 1000000, 0x61); // 'a'

  group('SHA3-256 (FIPS 202)', () {
    test('empty', () {
      expect(
        sha3256(empty),
        equals(
          hexToBytes(
            'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
          ),
        ),
      );
    });
    test('"abc"', () {
      expect(
        sha3256(abc),
        equals(
          hexToBytes(
            '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
          ),
        ),
      );
    });
    test('1,000,000 × "a" (multi-block absorb)', () {
      expect(
        sha3256(millionA),
        equals(
          hexToBytes(
            '5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1',
          ),
        ),
      );
    });
  });

  group('SHA3-512 (FIPS 202)', () {
    test('empty', () {
      expect(
        sha3512(empty),
        equals(
          hexToBytes(
            'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
            '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
          ),
        ),
      );
    });
    test('"abc"', () {
      expect(
        sha3512(abc),
        equals(
          hexToBytes(
            'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e'
            '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
          ),
        ),
      );
    });
    test('1,000,000 × "a" (multi-block absorb)', () {
      expect(
        sha3512(millionA),
        equals(
          hexToBytes(
            '3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859'
            'ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87',
          ),
        ),
      );
    });
  });

  group('SHAKE128 / SHAKE256 (FIPS 202)', () {
    test('SHAKE128 empty, 32 bytes', () {
      expect(
        shake128(empty, 32),
        equals(
          hexToBytes(
            '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
          ),
        ),
      );
    });
    test('SHAKE256 empty, 32 bytes', () {
      expect(
        shake256(empty, 32),
        equals(
          hexToBytes(
            '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
          ),
        ),
      );
    });

    // SHAKE output is a stream: the first M bytes of an N-byte squeeze (N > M)
    // must equal an M-byte squeeze. This validates the multi-block squeeze path
    // (output spanning several rate blocks) without a hard-coded long vector.
    test('SHAKE128 stream-prefix stability across block boundaries', () {
      final long = shake128(abc, 500); // > 2 × 168-byte rate
      expect(shake128(abc, 100), equals(long.sublist(0, 100)));
      expect(shake128(abc, 168), equals(long.sublist(0, 168)));
      expect(shake128(abc, 400), equals(long.sublist(0, 400)));
    });
    test('SHAKE256 stream-prefix stability across block boundaries', () {
      final long = shake256(abc, 500); // > 3 × 136-byte rate
      expect(shake256(abc, 100), equals(long.sublist(0, 100)));
      expect(shake256(abc, 136), equals(long.sublist(0, 136)));
      expect(shake256(abc, 300), equals(long.sublist(0, 300)));
    });
  });
}
