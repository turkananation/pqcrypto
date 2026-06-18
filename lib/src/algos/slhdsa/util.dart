import 'dart:typed_data';

/// FIPS 205 Algorithm 1.
int genLen2(int n, int lgW) {
  if (n <= 0) {
    throw ArgumentError.value(n, 'n', 'must be positive');
  }
  if (lgW <= 0 || lgW > 8) {
    throw ArgumentError.value(lgW, 'lgW', 'must be between 1 and 8');
  }

  final w = 1 << lgW;
  var checksum = ((8 * n + lgW - 1) ~/ lgW) * (w - 1);
  var result = 0;
  do {
    result++;
    checksum ~/= w;
  } while (checksum > 0);
  return result;
}

/// FIPS 205 Algorithm 2: convert a big-endian byte string to an integer.
///
/// [BigInt] is required because SLH-DSA tree indices can exceed the exact
/// 53-bit integer range of the JavaScript backend.
BigInt toInt(Uint8List input) {
  var result = BigInt.zero;
  for (final byte in input) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

/// FIPS 205 Algorithm 3: encode a non-negative integer in exactly [length]
/// big-endian bytes.
Uint8List toByte(BigInt value, int length) {
  if (value.isNegative) {
    throw ArgumentError.value(value, 'value', 'must be non-negative');
  }
  if (length < 0) {
    throw RangeError.range(length, 0, null, 'length');
  }
  if (value >= (BigInt.one << (8 * length))) {
    throw RangeError('value does not fit in $length bytes');
  }

  final result = Uint8List(length);
  var remaining = value;
  for (var i = length - 1; i >= 0; i--) {
    result[i] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
  return result;
}

/// FIPS 205 Algorithm 4: extract [outputLength] base-2^[b] digits from [input].
///
/// Bits are consumed most-significant first. No implicit zero padding is
/// allowed: the requested output must fit in the supplied input.
List<int> base2b(Uint8List input, int b, int outputLength) {
  if (b <= 0 || b > 16) {
    throw ArgumentError.value(b, 'b', 'must be between 1 and 16');
  }
  if (outputLength < 0) {
    throw RangeError.range(outputLength, 0, null, 'outputLength');
  }
  if (outputLength * b > input.length * 8) {
    throw ArgumentError(
      'input has ${input.length * 8} bits, but '
      '${outputLength * b} bits were requested',
    );
  }

  final output = List<int>.filled(outputLength, 0);
  var inputIndex = 0;
  var bits = 0;
  var total = 0;
  final mask = (1 << b) - 1;

  for (var outputIndex = 0; outputIndex < outputLength; outputIndex++) {
    while (bits < b) {
      total = (total << 8) | input[inputIndex++];
      bits += 8;
    }
    bits -= b;
    output[outputIndex] = (total >> bits) & mask;
    total = bits == 0 ? 0 : total & ((1 << bits) - 1);
  }
  return output;
}

/// Return a copy of the leftmost [length] bytes.
Uint8List truncN(Uint8List input, int length) {
  if (length < 0 || length > input.length) {
    throw RangeError.range(length, 0, input.length, 'length');
  }
  return Uint8List.fromList(input.sublist(0, length));
}
