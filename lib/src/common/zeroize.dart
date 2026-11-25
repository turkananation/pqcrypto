/// Overwrite of a buffer this library can still name.
///
/// On the VM, [allocUint8], [allocInt16], [allocInt32], and [allocUint32]
/// place the bytes outside the Dart heap. The scavenger moves the wrapper,
/// not those bytes, so the loop below is the only copy of that allocation.
/// A from-space image of some earlier Dart-heap buffer is not reachable from
/// here: the collector does not return the old address. Caller-owned lists,
/// registers, JIT slots, dart2js, and dart2wasm stay outside this wipe.
///
/// Each wipe is `@pragma('vm:never-inline')` and finishes by mixing the last
/// stored element into [_wipeAnchor]. That read keeps the stores live so AOT
/// cannot treat the loop as a dead store. One zero pass only: there is no
/// caller-selectable pattern.
library;

import 'dart:typed_data';

import 'secret_alloc_stub.dart'
    if (dart.library.io) 'secret_alloc_io.dart'
    as pinned;

/// Observable sink for the post-wipe read. Not a secret.
int _wipeAnchor = 0;

@pragma('vm:never-inline')
void _wipe(List<int>? data) {
  if (data == null || data.isEmpty) return;
  for (var i = 0; i < data.length; i++) {
    data[i] = 0;
  }
  _observe(data[data.length - 1]);
}

@pragma('vm:never-inline')
void _observe(int value) {
  final next = _wipeAnchor | value;
  _wipeAnchor = next;
}

/// Overwrites every byte of [data]. Null and empty buffers are ignored.
@pragma('vm:never-inline')
void secureZero(Uint8List? data) => _wipe(data);

/// Overwrites every element of [data].
@pragma('vm:never-inline')
void secureZeroInt16(Int16List? data) => _wipe(data);

/// Overwrites every element of [data].
@pragma('vm:never-inline')
void secureZeroInt32(Int32List? data) => _wipe(data);

/// Overwrites every element of [data].
@pragma('vm:never-inline')
void secureZeroUint32(Uint32List? data) => _wipe(data);

/// Fresh byte buffer. Native memory on the VM; a normal list on web and wasm.
Uint8List allocUint8(int length) => pinned.allocUint8(length);

/// Fresh signed 16-bit buffer. Native memory on the VM.
Int16List allocInt16(int length) => pinned.allocInt16(length);

/// Fresh signed 32-bit buffer. Native memory on the VM.
Int32List allocInt32(int length) => pinned.allocInt32(length);

/// Fresh unsigned 32-bit buffer. Native memory on the VM.
Uint32List allocUint32(int length) => pinned.allocUint32(length);

/// Copies [source] from [start] inclusive to [end] exclusive into a fresh buffer.
///
/// Does not call [List.sublist], which would leave a movable typed-data copy.
Uint8List allocUint8Copy(List<int> source, [int start = 0, int? end]) {
  final stop = RangeError.checkValidRange(start, end, source.length);
  final out = allocUint8(stop - start);
  if (out.isNotEmpty) {
    out.setRange(0, out.length, source, start);
  }
  return out;
}

/// Element copy into a fresh signed 16-bit buffer. No intermediate `List`.
Int16List allocInt16Copy(List<int> source) {
  final out = allocInt16(source.length);
  for (var i = 0; i < source.length; i++) {
    out[i] = source[i];
  }
  return out;
}

/// Element copy into a fresh unsigned 32-bit buffer. No intermediate `List`.
Uint32List allocUint32Copy(List<int> source) {
  final out = allocUint32(source.length);
  for (var i = 0; i < source.length; i++) {
    out[i] = source[i];
  }
  return out;
}

bool allocIsNative(TypedData data) => pinned.allocIsNative(data);

int? allocNativeAddress(TypedData data) => pinned.allocNativeAddress(data);

const bool allocUsesNativeHeap = pinned.allocUsesNativeHeap;
