import 'dart:typed_data';

import 'package:pqcrypto/src/common/sp800_185.dart';
import 'package:test/test.dart';

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

  test('SP 800-185 section 2.3.1 encodes zero', () {
    // The standard prints these bit strings least-significant bit first.
    // 10000000 00000000 is the byte string 01 00.
    // 00000000 10000000 is the byte string 00 01.
    expect(leftEncode(0), hex('0100'));
    expect(rightEncode(0), hex('0001'));
  });

  test('integer encodings cross the one-byte boundary', () {
    expect(leftEncode(255), hex('01ff'));
    expect(leftEncode(256), hex('020100'));
    expect(rightEncode(256), hex('010002'));
    expect(rightEncode(512), hex('020002'));
  });

  test('encode_string uses the bit length', () {
    expect(encodeString(Uint8List(0)), hex('0100'));
    expect(
      encodeString(ascii('Email Signature')),
      hex('0178456d61696c205369676e6174757265'),
    );
    expect(encodeString(ascii('KMAC')), hex('01204b4d4143'));
  });

  test('bytepad uses the SP 800-185 rates', () {
    final email = bytepad(
      concat(
        encodeString(Uint8List(0)),
        encodeString(ascii('Email Signature')),
      ),
      168,
    );
    expect(email.length, 168);
    expect(
      email.sublist(0, 21),
      hex('01a801000178456d61696c205369676e6174757265'),
    );
    expect(email.sublist(21), everyElement(0));

    final name = bytepad(
      concat(encodeString(ascii('TupleHash')), encodeString(Uint8List(0))),
      136,
    );
    expect(name.length, 136);
    expect(name.length % 136, 0);
    expect(name.sublist(0, 2), hex('0188'));
  });

  test('invalid integers and widths throw before a result', () {
    expect(() => leftEncode(-1), throwsArgumentError);
    expect(() => rightEncode(-1), throwsArgumentError);
    expect(() => bytepad(Uint8List(0), 0), throwsArgumentError);
    expect(() => bytepad(ascii('nope'), -4), throwsArgumentError);
    expect(leftEncode(0), hex('0100'));
  });

  test('a 53-bit integer encodes above the dart2js shift width', () {
    // 2^53 - 1 is exact on the VM and on dart2js. It needs seven bytes.
    final value = ((BigInt.one << 53) - BigInt.one).toInt();
    expect(leftEncode(value), <int>[
      7, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    ]);
    expect(rightEncode(value).last, 7);
  });

  test('the largest VM int encodes below the 2^2040 ceiling', () {
    final largest = ((BigInt.one << 63) - BigInt.one).toInt();
    expect(leftEncode(largest), <int>[
      8, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    ]);
    expect(rightEncode(largest).last, 8);
  }, testOn: 'vm');

  test('substring follows SP 800-185 section 2.3.4', () {
    final bits = <int>[1, 0, 1, 1, 0];
    expect(substringBits(bits, 1, 4), <int>[0, 1, 1]);
    expect(substringBits(bits, 3, 3), isEmpty);
    expect(substringBits(bits, 5, 6), isEmpty);
    expect(substringBits(bits, 3, 9), <int>[1, 0]);
    expect(() => substringBits(bits, -1, 2), throwsArgumentError);
    expect(() => substringBits(<int>[0, 2], 0, 1), throwsArgumentError);
  });
}
