/// MGF1-SHA-256 and MGF1-SHA-512 for internal standards implementations.
///
/// The construction follows RFC 8017 Appendix B.2.1. It is intentionally not
/// exported from the package root.
library;

import 'dart:typed_data';

import 'sha2.dart';
import 'zeroize.dart';

typedef _Digest = Uint8List Function(Uint8List message);

/// Returns MGF1-SHA-256([seed], [maskLength]).
Uint8List mgf1Sha256(Uint8List seed, int maskLength) =>
    _mgf1(seed, maskLength, digestLength: 32, digest: sha256);

/// Returns MGF1-SHA-512([seed], [maskLength]).
Uint8List mgf1Sha512(Uint8List seed, int maskLength) =>
    _mgf1(seed, maskLength, digestLength: 64, digest: sha512);

Uint8List _mgf1(
  Uint8List seed,
  int maskLength, {
  required int digestLength,
  required _Digest digest,
}) {
  if (maskLength < 0) {
    throw RangeError.range(maskLength, 0, null, 'maskLength');
  }
  final maximumLength = BigInt.from(0xffffffff) * BigInt.from(digestLength);
  if (BigInt.from(maskLength) > maximumLength) {
    throw RangeError.value(
      maskLength,
      'maskLength',
      'must not exceed 2^32-1 digest blocks',
    );
  }

  final output = Uint8List(maskLength);
  if (maskLength == 0) return output;

  final input = Uint8List(seed.length + 4)..setRange(0, seed.length, seed);
  Uint8List? block;
  try {
    var offset = 0;
    for (var counter = 0; offset < maskLength; counter++) {
      input[seed.length] = (counter >>> 24) & 0xff;
      input[seed.length + 1] = (counter >>> 16) & 0xff;
      input[seed.length + 2] = (counter >>> 8) & 0xff;
      input[seed.length + 3] = counter & 0xff;

      block = digest(input);
      final copyLength = maskLength - offset < digestLength
          ? maskLength - offset
          : digestLength;
      output.setRange(offset, offset + copyLength, block);
      offset += copyLength;
      secureZero(block);
      block = null;
    }
    return output;
  } finally {
    secureZero(input);
    if (block != null) secureZero(block);
  }
}
