import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/address.dart';
import 'package:test/test.dart';

void main() {
  test('new address is exactly 32 zero bytes', () {
    final address = Adrs();
    expect(address.toBytes(), hasLength(32));
    expect(address.toBytes(), everyElement(0));
  });

  test('Table 1 fields use exact big-endian offsets', () {
    final address = Adrs()
      ..setLayerAddress(0x01020304)
      ..setTreeAddress(BigInt.parse('05060708090a0b0c0d0e0f10', radix: 16))
      ..setTypeAndClear(AdrsType.wotsHash)
      ..setKeyPairAddress(0x11121314)
      ..setChainAddress(0x15161718)
      ..setHashAddress(0x191a1b1c);

    expect(
      address.toBytes(),
      equals(<int>[
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
      ]),
    );
    expect(address.getKeyPairAddress(), 0x11121314);
    expect(address.getTreeIndex(), 0x191a1b1c);
  });

  test('tree aliases write the same Table 1 fields', () {
    final address = Adrs()
      ..setTreeHeight(0x01020304)
      ..setTreeIndex(0x05060708);
    expect(
      address.toBytes().sublist(24),
      equals(<int>[1, 2, 3, 4, 5, 6, 7, 8]),
    );
  });

  test('all seven type values are exact and clear the final 12 bytes', () {
    for (final type in AdrsType.values) {
      final address = Adrs()
        ..setKeyPairAddress(0xffffffff)
        ..setChainAddress(0xffffffff)
        ..setHashAddress(0xffffffff)
        ..setTypeAndClear(type);
      final bytes = address.toBytes();
      expect(bytes.sublist(16, 20), equals(<int>[0, 0, 0, type.value]));
      expect(bytes.sublist(20), everyElement(0));
    }
  });

  test('copy and byte views cannot mutate the source address', () {
    final address = Adrs()..setLayerAddress(7);
    final bytes = address.toBytes()..fillRange(0, 32, 0xff);
    final copy = address.copy()..setLayerAddress(8);

    expect(bytes, everyElement(0xff));
    expect(address.toBytes().sublist(0, 4), equals(<int>[0, 0, 0, 7]));
    expect(copy.toBytes().sublist(0, 4), equals(<int>[0, 0, 0, 8]));
  });

  test('copyBytesTo writes at an offset without exposing address storage', () {
    final address = Adrs.fromBytes(
      Uint8List.fromList(List<int>.generate(32, (index) => index)),
    );
    final destination = Uint8List(40)..fillRange(0, 40, 0xff);

    address.copyBytesTo(destination, 4);
    destination.fillRange(4, 36, 0);

    expect(destination.sublist(0, 4), everyElement(0xff));
    expect(destination.sublist(36), everyElement(0xff));
    expect(address.toBytes(), equals(List<int>.generate(32, (index) => index)));
  });

  test('copyBytesTo validates the complete destination range', () {
    final address = Adrs();
    expect(() => address.copyBytesTo(Uint8List(32), -1), throwsRangeError);
    expect(() => address.copyBytesTo(Uint8List(32), 1), throwsRangeError);
    expect(() => address.copyBytesTo(Uint8List(31), 0), throwsRangeError);
  });

  test('constructor and setters reject values outside their fields', () {
    expect(() => Adrs.fromBytes(Uint8List(31)), throwsArgumentError);
    expect(() => Adrs().setLayerAddress(-1), throwsRangeError);
    expect(() => Adrs().setLayerAddress(0x100000000), throwsRangeError);
    expect(() => Adrs().setTreeAddress(BigInt.from(-1)), throwsArgumentError);
    expect(() => Adrs().setTreeAddress(BigInt.one << 96), throwsRangeError);
    expect(() => Adrs().setTreeIndex(-1), throwsRangeError);
  });
}
