import 'dart:typed_data';

import 'package:pqcrypto/src/common/zeroize.dart';
import 'package:test/test.dart';

void main() {
  test('zeroization helpers overwrite each supported typed buffer', () {
    final bytes = Uint8List.fromList(<int>[1, 2, 3]);
    final lanes = Int16List.fromList(<int>[-1, 2, 3329]);
    final signedWords = Int32List.fromList(<int>[-1, 2, -3]);
    final unsignedWords = Uint32List.fromList(<int>[1, 0xffffffff, 3]);

    secureZero(bytes);
    secureZeroInt16(lanes);
    secureZeroInt32(signedWords);
    secureZeroUint32(unsignedWords);

    expect(bytes, everyElement(0));
    expect(lanes, everyElement(0));
    expect(signedWords, everyElement(0));
    expect(unsignedWords, everyElement(0));
  });

  test('fresh buffers are native on the VM and stay at one address', () {
    final bytes = allocUint8(32);
    expect(allocIsNative(bytes), allocUsesNativeHeap);
    if (!allocUsesNativeHeap) return;

    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0xA5;
    }
    final address = allocNativeAddress(bytes);
    expect(address, isNotNull);
    expect(address, isNot(0));

    // Ordinary Dart lists are what the scavenger copies. These allocations
    // give a collection something to move. The native address has to stay
    // put, and the payload has to still be the pattern.
    final junk = <Uint8List>[];
    for (var i = 0; i < 20000; i++) {
      junk.add(Uint8List(128));
    }
    junk.clear();

    expect(allocNativeAddress(bytes), address);
    expect(bytes.first, 0xA5);
    expect(bytes.last, 0xA5);
    final view = ByteData.sublistView(bytes);
    expect(view.getUint8(0), 0xA5);
    secureZero(bytes);
    expect(bytes, everyElement(0));
    expect(allocNativeAddress(bytes), address);
  });

  test('range copy does not alias the source', () {
    final source = Uint8List.fromList(<int>[1, 2, 3, 4]);
    final copy = allocUint8Copy(source, 1, 3);
    expect(copy, <int>[2, 3]);
    source[1] = 9;
    expect(copy[0], 2);
    expect(allocIsNative(copy), allocUsesNativeHeap);
  });

  test('zeroization helpers accept null', () {
    expect(() => secureZero(null), returnsNormally);
    expect(() => secureZeroInt16(null), returnsNormally);
    expect(() => secureZeroInt32(null), returnsNormally);
    expect(() => secureZeroUint32(null), returnsNormally);
  });
}
