import 'dart:typed_data';

import 'package:pqcrypto/src/common/keccak.dart';
import 'package:pqcrypto/src/common/keccak_parameters.dart';
import 'package:test/test.dart';

/// Direct FIPS 202 known-answer tests for the vendored Keccak (the code that
/// replaced the `pointycastle` dependency). These pin the FIPS 202 functions
/// against published NIST values, independent of the ML-KEM KAT
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

  group('SHA3-224 (FIPS 202)', () {
    test('empty', () {
      expect(
        sha3224(empty),
        equals(
          hexToBytes(
            '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
          ),
        ),
      );
    });
    test('"abc"', () {
      expect(
        sha3224(abc),
        equals(
          hexToBytes(
            'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
          ),
        ),
      );
    });
  });

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

  group('SHA3-384 (FIPS 202)', () {
    test('empty', () {
      expect(
        sha3384(empty),
        equals(
          hexToBytes(
            '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a'
            'c3713831264adb47fb6bd1e058d5f004',
          ),
        ),
      );
    });
    test('"abc"', () {
      expect(
        sha3384(abc),
        equals(
          hexToBytes(
            'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b'
            '298d88cea927ac7f539f1edf228376d25',
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

    test('incremental squeeze is byte-identical across chunk shapes', () {
      for (final factory in <KeccakXof Function(Uint8List)>[
        shake128Xof,
        shake256Xof,
      ]) {
        final xof = factory(abc);
        final chunked = <int>[
          ...xof.squeeze(1),
          xof.squeezeByte(),
          ...xof.squeeze(133),
          ...xof.squeeze(0),
          ...xof.squeeze(379),
        ];
        final expected = factory(abc).squeeze(chunked.length);
        expect(Uint8List.fromList(chunked), equals(expected));
      }
    });

    test('zero output is empty and does not consume the stream', () {
      final xof = shake256Xof(abc);
      expect(xof.squeeze(0), isEmpty);
      expect(xof.squeeze(64), equals(shake256(abc, 64)));
      expect(shake128(abc, 0), isEmpty);
      expect(shake256(abc, 0), isEmpty);
    });

    test('negative output lengths are rejected', () {
      expect(() => shake128(abc, -1), throwsRangeError);
      expect(() => shake256(abc, -1), throwsRangeError);
      expect(() => shake128Xof(abc).squeeze(-1), throwsRangeError);
    });
  });

  group('Keccak-f[1600] parameters', () {
    test('round count and iota constants match FIPS 202', () {
      expect(KeccakF1600Parameters.stateBits, 1600);
      expect(KeccakF1600Parameters.rounds, 24);
      expect(
        KeccakF1600Parameters.roundConstantsLow32,
        equals(<int>[
          0x00000001,
          0x00008082,
          0x0000808a,
          0x80008000,
          0x0000808b,
          0x80000001,
          0x80008081,
          0x00008009,
          0x0000008a,
          0x00000088,
          0x80008009,
          0x8000000a,
          0x8000808b,
          0x0000008b,
          0x00008089,
          0x00008003,
          0x00008002,
          0x00000080,
          0x0000800a,
          0x8000000a,
          0x80008081,
          0x00008080,
          0x80000001,
          0x80008008,
        ]),
      );
      expect(
        KeccakF1600Parameters.roundConstantsHigh32,
        equals(<int>[
          0x00000000,
          0x00000000,
          0x80000000,
          0x80000000,
          0x00000000,
          0x00000000,
          0x80000000,
          0x80000000,
          0x00000000,
          0x00000000,
          0x00000000,
          0x00000000,
          0x00000000,
          0x80000000,
          0x80000000,
          0x80000000,
          0x80000000,
          0x80000000,
          0x00000000,
          0x80000000,
          0x80000000,
          0x80000000,
          0x00000000,
          0x80000000,
        ]),
      );
    });

    test('rho offsets match FIPS 202 Table 2', () {
      expect(
        KeccakF1600Parameters.rhoOffsets,
        equals(<int>[
          0,
          1,
          62,
          28,
          27,
          36,
          44,
          6,
          55,
          20,
          3,
          10,
          43,
          25,
          39,
          41,
          45,
          15,
          21,
          8,
          18,
          2,
          61,
          56,
          14,
        ]),
      );
    });

    test('rates, capacities, suffixes, and digest lengths are exact', () {
      final expected = <String, (int, int, int, int?)>{
        'SHA3-224': (144, 448, 0x06, 28),
        'SHA3-256': (136, 512, 0x06, 32),
        'SHA3-384': (104, 768, 0x06, 48),
        'SHA3-512': (72, 1024, 0x06, 64),
        'SHAKE128': (168, 256, 0x1f, null),
        'SHAKE256': (136, 512, 0x1f, null),
      };
      expect(Fips202Parameters.values, hasLength(expected.length));
      for (final parameters in Fips202Parameters.values) {
        final values = expected[parameters.name]!;
        expect(parameters.rateBytes, values.$1, reason: parameters.name);
        expect(parameters.capacityBits, values.$2, reason: parameters.name);
        expect(parameters.domain, values.$3, reason: parameters.name);
        expect(parameters.digestBytes, values.$4, reason: parameters.name);
        expect(
          parameters.rateBytes * 8 + parameters.capacityBits,
          KeccakF1600Parameters.stateBits,
          reason: parameters.name,
        );
      }
    });

    test('unsupported raw sponge arguments are rejected', () {
      expect(() => KeccakXof(empty, 0, 0x1f), throwsArgumentError);
      expect(() => KeccakXof(empty, 7, 0x1f), throwsArgumentError);
      expect(() => KeccakXof(empty, 200, 0x1f), throwsArgumentError);
      expect(() => KeccakXof(empty, 136, 0), throwsArgumentError);
      expect(() => KeccakXof(empty, 136, 0x80), throwsArgumentError);
    });
  });

  group('rate-boundary behavior', () {
    final profiles = <(String, int, Uint8List Function(Uint8List))>[
      ('SHA3-224', 144, sha3224),
      ('SHA3-256', 136, sha3256),
      ('SHA3-384', 104, sha3384),
      ('SHA3-512', 72, sha3512),
      ('SHAKE128', 168, (input) => shake128(input, 64)),
      ('SHAKE256', 136, (input) => shake256(input, 64)),
    ];

    for (final profile in profiles) {
      test('${profile.$1}: rate - 1, rate, rate + 1 are distinct', () {
        Uint8List message(int length) =>
            Uint8List.fromList(List<int>.generate(length, (i) => i & 0xff));

        final before = profile.$3(message(profile.$2 - 1));
        final exact = profile.$3(message(profile.$2));
        final after = profile.$3(message(profile.$2 + 1));

        expect(before, isNot(equals(exact)));
        expect(exact, isNot(equals(after)));
        expect(before, isNot(equals(after)));
      });
    }
  });
}
