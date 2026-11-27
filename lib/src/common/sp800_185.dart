/// Byte-oriented encodings from NIST SP 800-185 section 2.3.
///
/// These helpers are the shared prefix for cSHAKE, KMAC, TupleHash, and
/// ParallelHash. Those functions are not implemented here. Nothing in this
/// file is a CMVP or FIPS 140 validation claim.
library;

import 'dart:typed_data';

/// Largest integer the SP 800-185 encodings accept, exclusive: `2^2040`.
const int _maximumEncodableBitLength = 2040;

/// `left_encode(x)` from SP 800-185 section 2.3.1.
///
/// The result is `enc8(n) || x1 || ... || xn`, where `n` is the smallest
/// positive byte count whose `2^(8n)` is greater than [x]. A negative [x]
/// throws [ArgumentError] before a result is produced. SP 800-185 also
/// rejects `x >= 2^2040`. A value that does not fit in a Dart `int` cannot
/// be passed here, and a value this function cannot encode exactly throws.
Uint8List leftEncode(int x) {
  final body = _base256(x);
  final out = Uint8List(body.length + 1);
  out[0] = body.length;
  out.setRange(1, out.length, body);
  return out;
}

/// `right_encode(x)` from SP 800-185 section 2.3.1.
///
/// The result is `x1 || ... || xn || enc8(n)`. The validity range matches
/// [leftEncode].
Uint8List rightEncode(int x) {
  final body = _base256(x);
  final out = Uint8List(body.length + 1);
  out.setRange(0, body.length, body);
  out[body.length] = body.length;
  return out;
}

/// `encode_string(S)` for a byte string, SP 800-185 section 2.3.2.
///
/// The length prefix is the length of [bytes] in bits, not in bytes. A bit
/// string whose length is not a multiple of 8 is rejected: this helper does
/// not return a partial byte.
Uint8List encodeString(Uint8List bytes) {
  final prefix = leftEncode(_byteStringBitLength(bytes));
  final out = Uint8List(prefix.length + bytes.length);
  out.setRange(0, prefix.length, prefix);
  out.setRange(prefix.length, out.length, bytes);
  return out;
}

/// `bytepad(X, w)` from SP 800-185 section 2.3.3.
///
/// [input] is a byte string, so the bit-padding step in the standard is
/// already satisfied. The result is `left_encode(w) || input`, followed by
/// zero bytes until its length is a multiple of [w]. Throws [ArgumentError]
/// before producing a result when [w] is not positive or [w] cannot be
/// encoded.
Uint8List bytepad(Uint8List input, int w) {
  if (w <= 0) {
    throw ArgumentError.value(w, 'w', 'must be positive');
  }
  final prefix = leftEncode(w);
  final unpadded = prefix.length + input.length;
  final remainder = unpadded % w;
  final padded = remainder == 0 ? unpadded : unpadded + (w - remainder);
  final out = Uint8List(padded);
  out.setRange(0, prefix.length, prefix);
  out.setRange(prefix.length, prefix.length + input.length, input);
  return out;
}

/// `substring(X, a, b)` from SP 800-185 section 2.3.4.
///
/// Bit positions are indexed from zero. Returns the empty list when [a] is
/// past the string or [a] is not less than [b]. A position past the end is
/// clamped to the end of [bits]. Negative positions and values other than
/// 0 or 1 throw [ArgumentError] before a result is returned.
///
/// This is the test-only bit helper. Byte-oriented callers use [encodeString]
/// and [bytepad].
List<int> substringBits(List<int> bits, int a, int b) {
  if (a < 0 || b < 0) {
    throw ArgumentError('substring positions must be non-negative');
  }
  for (final bit in bits) {
    if (bit != 0 && bit != 1) {
      throw ArgumentError.value(bit, 'bits', 'must contain only 0 and 1');
    }
  }
  if (a >= b || a >= bits.length) return <int>[];
  final end = b < bits.length ? b : bits.length;
  return List<int>.of(bits.getRange(a, end));
}

Uint8List _base256(int value) {
  if (value < 0 || value.bitLength > _maximumEncodableBitLength) {
    throw ArgumentError.value(value, 'x', 'must satisfy 0 <= x < 2^2040');
  }
  final count = value == 0 ? 1 : (value.bitLength + 7) >> 3;
  final bytes = Uint8List(count);
  var rest = value;
  for (var i = count - 1; i >= 0; i--) {
    // Division, not a shift: dart2js evaluates `>>` on 32 bits.
    bytes[i] = rest % 256;
    rest = rest ~/ 256;
  }
  if (rest != 0) {
    throw ArgumentError.value(value, 'x', 'cannot be encoded exactly');
  }
  return bytes;
}

int _byteStringBitLength(Uint8List bytes) {
  if (bytes.isNotEmpty &&
      bytes.length.bitLength + 3 > _maximumEncodableBitLength) {
    throw ArgumentError.value(
      bytes.length,
      'bytes',
      'bit length must satisfy 0 <= len(S) < 2^2040',
    );
  }
  return bytes.length * 8;
}
