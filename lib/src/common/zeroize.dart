/// Best-effort overwrite of the visible backing store.
///
/// The Dart garbage collector may already have copied a buffer. These helpers
/// cannot reach that copy, a register, or a JIT temporary. They are not a
/// hard erasure guarantee on the VM, dart2js, or dart2wasm.
///
/// Each wipe is `@pragma('vm:never-inline')` and finishes by mixing the last
/// stored element into [_wipeAnchor]. That read keeps the stores live so AOT
/// cannot treat the loop as a dead store. One zero pass only: there is no
/// caller-selectable pattern.
library;

import 'dart:typed_data';

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
