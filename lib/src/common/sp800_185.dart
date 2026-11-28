/// Byte-oriented SP 800-185 encodings and cSHAKE128/cSHAKE256.
///
/// [leftEncode], [rightEncode], [encodeString], and [bytepad] are the shared
/// prefix from section 2.3. [CShake128] and [CShake256] are the cSHAKE XOFs.
/// KMAC is in `kmac.dart`. TupleHash is in `tuplehash.dart`. ParallelHash is
/// in `parallelhash.dart`. Nothing in
/// this file is a CMVP or FIPS 140 validation claim.
library;

import 'dart:typed_data';

import 'keccak.dart';
import 'keccak_parameters.dart';
import 'zeroize.dart';

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

/// Delimited suffix for a byte-aligned cSHAKE input.
///
/// SP 800-185 appends the bits `00` to
/// `bytepad(encode_string(N) || encode_string(S), rate) || X`. KECCAK then
/// applies `pad10*1`. Those two zeros and the first pad bit pack into the
/// domain byte `0x04`. [keccakAbsorbBytes] also sets the final pad bit
/// `0x80` at the end of the rate.
const int _cshakeDomainByte = 0x04;

/// cSHAKE128 from NIST SP 800-185.
///
/// [hash] returns bytes. When [CShake128.hash]'s function name and
/// customization are both omitted or empty, the result is SHAKE128 of the
/// same message and length. Otherwise the sponge absorbs
/// `bytepad(encode_string(N) || encode_string(S), 168) || message` with
/// domain byte `0x04` (KECCAK[256], rate 168).
///
/// The function-name string `N` stays empty for ordinary cSHAKE. Derived
/// functions set it to a fixed name. Different customization strings produce
/// unrelated outputs for the same message, within the SP 800-185 security
/// model.
///
/// Arguments are byte strings. Keccak-f[1600] runs a fixed 24-round
/// permutation. Copies allocated by [hash] go through the package's
/// best-effort wipe.
final class CShake128 {
  CShake128._();

  /// Returns [outputLength] bytes of cSHAKE128.
  ///
  /// A negative [outputLength] throws [RangeError] before any output bytes
  /// are produced. [functionName] and [customization] default to empty byte
  /// strings when omitted.
  static Uint8List hash(
    Uint8List message, {
    required int outputLength,
    Uint8List? functionName,
    Uint8List? customization,
  }) {
    return _cshake(
      message,
      outputLength: outputLength,
      functionName: functionName,
      customization: customization,
      rateBytes: Fips202Parameters.shake128.rateBytes,
      shake: shake128,
    );
  }
}

/// cSHAKE256 from NIST SP 800-185.
///
/// Same byte-string contract as [CShake128]. The empty-string fallback is
/// SHAKE256. The rate is 136 bytes (KECCAK[512]). The domain byte is `0x04`.
final class CShake256 {
  CShake256._();

  /// Returns [outputLength] bytes of cSHAKE256.
  ///
  /// A negative [outputLength] throws [RangeError] before any output bytes
  /// are produced. [functionName] and [customization] default to empty byte
  /// strings when omitted.
  static Uint8List hash(
    Uint8List message, {
    required int outputLength,
    Uint8List? functionName,
    Uint8List? customization,
  }) {
    return _cshake(
      message,
      outputLength: outputLength,
      functionName: functionName,
      customization: customization,
      rateBytes: Fips202Parameters.shake256.rateBytes,
      shake: shake256,
    );
  }
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

typedef _Shake = Uint8List Function(Uint8List input, int outputLength);

Uint8List _cshake(
  Uint8List message, {
  required int outputLength,
  required Uint8List? functionName,
  required Uint8List? customization,
  required int rateBytes,
  required _Shake shake,
}) {
  if (outputLength < 0) {
    throw RangeError.range(outputLength, 0, null, 'outputLength');
  }
  final nameEmpty = functionName == null || functionName.isEmpty;
  final customEmpty = customization == null || customization.isEmpty;
  if (nameEmpty && customEmpty) {
    return shake(message, outputLength);
  }

  Uint8List? encodedName;
  Uint8List? encodedCustom;
  Uint8List? joined;
  Uint8List? prefix;
  Uint8List? input;
  try {
    encodedName = encodeString(functionName ?? Uint8List(0));
    encodedCustom = encodeString(customization ?? Uint8List(0));
    joined = _concat(encodedName, encodedCustom);
    prefix = bytepad(joined, rateBytes);
    input = _concat(prefix, message);
    return keccakAbsorbBytes(input, rateBytes, _cshakeDomainByte, outputLength);
  } finally {
    secureZero(encodedName);
    secureZero(encodedCustom);
    secureZero(joined);
    secureZero(prefix);
    secureZero(input);
  }
}

Uint8List _concat(Uint8List left, Uint8List right) {
  final out = Uint8List(left.length + right.length);
  out.setRange(0, left.length, left);
  out.setRange(left.length, out.length, right);
  return out;
}
