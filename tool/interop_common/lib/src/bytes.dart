import 'dart:typed_data';

Uint8List sequence(int start, int length) => Uint8List.fromList(
  List<int>.generate(length, (index) => (start + index) & 0xff),
);

bool bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var i = 0; i < left.length; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference == 0;
}

String hex(List<int> bytes, {int maxBytes = 16}) {
  final shown = bytes.length > maxBytes ? bytes.sublist(0, maxBytes) : bytes;
  final encoded = shown
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();
  return bytes.length > maxBytes
      ? '$encoded... (${bytes.length} bytes)'
      : encoded;
}
