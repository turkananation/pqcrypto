import 'dart:typed_data';

/// Web and wasm stand-in. These runtimes have no native heap this library
/// can allocate from, so the bytes live in a movable typed-data object.
Uint8List allocUint8(int length) => Uint8List(length);

Int16List allocInt16(int length) => Int16List(length);

Int32List allocInt32(int length) => Int32List(length);

Uint32List allocUint32(int length) => Uint32List(length);

bool allocIsNative(TypedData data) => false;

int? allocNativeAddress(TypedData data) => null;

const bool allocUsesNativeHeap = false;
