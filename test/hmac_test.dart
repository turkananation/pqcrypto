import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/hmac.dart';
import 'package:test/test.dart';

void main() {
  group('RFC 4231 HMAC-SHA-256/SHA-512', () {
    for (final vector in _vectors) {
      test(vector.name, () {
        expect(_hex(hmacSha256(vector.key, vector.message)), vector.sha256);
        expect(_hex(hmacSha512(vector.key, vector.message)), vector.sha512);
      });
    }
  });
}

final List<_HmacVector> _vectors = <_HmacVector>[
  _HmacVector(
    'case 1: short binary key',
    Uint8List.fromList(List<int>.filled(20, 0x0b)),
    _ascii('Hi There'),
    'b0344c61d8db38535ca8afceaf0bf12b'
        '881dc200c9833da726e9376c2e32cff7',
    '87aa7cdea5ef619d4ff0b4241a1d6cb0'
        '2379f4e2ce4ec2787ad0b30545e17cde'
        'daa833b7d6b8a702038b274eaea3f4e4'
        'be9d914eeb61f1702e696c203a126854',
  ),
  _HmacVector(
    'case 2: ASCII key and message',
    _ascii('Jefe'),
    _ascii('what do ya want for nothing?'),
    '5bdcc146bf60754e6a042426089575c7'
        '5a003f089d2739839dec58b964ec3843',
    '164b7a7bfcf819e2e395fbe73b56e0a3'
        '87bd64222e831fd610270cd7ea250554'
        '9758bf75c05a994a6d034f65f8f0e6fd'
        'caeab1a34d4a6b4b636e070a38bce737',
  ),
  _HmacVector(
    'case 6: key larger than both hash blocks',
    Uint8List.fromList(List<int>.filled(131, 0xaa)),
    _ascii('Test Using Larger Than Block-Size Key - Hash Key First'),
    '60e431591ee0b67f0d8a26aacbf5b77f'
        '8e0bc6213728c5140546040f0ee37f54',
    '80b24263c7c1a3ebb71493c1dd7be8b4'
        '9b46d1f41b4aeec1121b013783f8f352'
        '6b56d037e05f2598bd0fd2215d6a1e52'
        '95e64f73f63f0aec8b915a985d786598',
  ),
];

final class _HmacVector {
  const _HmacVector(
    this.name,
    this.key,
    this.message,
    this.sha256,
    this.sha512,
  );

  final String name;
  final Uint8List key;
  final Uint8List message;
  final String sha256;
  final String sha512;
}

Uint8List _ascii(String value) => Uint8List.fromList(ascii.encode(value));

String _hex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
