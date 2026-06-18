import 'dart:typed_data';

/// Best-effort zeroization of sensitive buffers.
///
/// IMPORTANT (Dart limitation): On the Dart VM and especially on
/// dart2js/dart2wasm, the runtime and garbage collector may copy buffers,
/// keep them alive, or place them in registers/JIT temporaries that this
/// function cannot reach. These helpers overwrite the *visible* backing store
/// in place and are a defense-in-depth measure, not a hard memory-erasure
/// guarantee. They are intentionally written so the compiler cannot trivially
/// prove the writes are dead (the loop touches every element).
void secureZero(Uint8List? b) {
  if (b == null) return;
  for (int i = 0; i < b.length; i++) {
    b[i] = 0;
  }
}

/// Best-effort zeroization of an [Int32List] (e.g. polynomial coefficients).
void secureZeroInt32(Int32List? b) {
  if (b == null) return;
  for (int i = 0; i < b.length; i++) {
    b[i] = 0;
  }
}

/// Best-effort zeroization of a [Uint32List] (e.g. sponge state words).
void secureZeroUint32(Uint32List? b) {
  if (b == null) return;
  for (int i = 0; i < b.length; i++) {
    b[i] = 0;
  }
}
