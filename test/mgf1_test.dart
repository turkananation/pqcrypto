import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/mgf1.dart';
import 'package:test/test.dart';

void main() {
  group('RFC 8017 MGF1', () {
    test('zero-length mask', () {
      expect(mgf1Sha256(Uint8List(0), 0), isEmpty);
      expect(mgf1Sha512(Uint8List(0), 0), isEmpty);
    });

    test('empty seed, one complete digest block', () {
      expect(
        _hex(mgf1Sha256(Uint8List(0), 32)),
        'df3f619804a92fdb4057192dc43dd748'
        'ea778adc52bc498ce80524c014b81119',
      );
      expect(
        _hex(mgf1Sha512(Uint8List(0), 64)),
        'ec2d57691d9b2d40182ac565032054b7'
        'd784ba96b18bcb5be0bb4e70e3fb041e'
        'ff582c8af66ee50256539f2181d7f9e5'
        '3627c0189da7e75a4d5ef10ea93b20b3',
      );
    });

    test('multi-block output is truncated to the requested length', () {
      final seed = Uint8List.fromList(ascii.encode('foo'));
      expect(
        _hex(mgf1Sha256(seed, 100)),
        '3bdaba83cff13337b323ac383ca39958'
        '63e922f511b931b9efd4e0118cfc70f08'
        '678390d67e3c12dbeb2d7a78bdfa597b'
        '5a365cc1d0d86f5f941df8226f0663da'
        '27640b3c174e7bc1ee0ad5b7237ca6aa'
        '1f642b9978842d93d6f9c95b609abc8e'
        '95634fa',
      );
      expect(
        _hex(mgf1Sha512(seed, 100)),
        'e8ac84d032cd89026d0654d269a810e6'
        '1c81fc8f978e8b22b1556897463fe36c'
        '86955dfee5dc87f38c5e0c4b6faae03d'
        'a5c7b509f98a8f20f69bd69ba0d95f1'
        '5c047592edef000c8fa59b4746bf3bb4f'
        '7b9746a05c37207b702131daaeaa144c'
        'f2239a00',
      );
    });

    test('rejects invalid mask lengths', () {
      expect(() => mgf1Sha256(Uint8List(0), -1), throwsRangeError);
      expect(() => mgf1Sha512(Uint8List(0), -1), throwsRangeError);
    });
  });
}

String _hex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
