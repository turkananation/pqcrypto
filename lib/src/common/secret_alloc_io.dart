import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

/// VM allocation for secret bytes.
///
/// The Dart scavenger and compactor copy ordinary `Uint8List` / `Int16List`
/// objects, and the abandoned from-space image is not wiped when the live
/// object is overwritten. There is no API that returns that old address.
///
/// `calloc` (or `CoTaskMemAlloc` on Windows) puts the bytes outside the Dart
/// heap. [asTypedList] only stores a pointer in the wrapper. A collection
/// moves the wrapper, not the bytes, so a later overwrite covers the only
/// copy of this allocation. A buffer that already lived on the Dart heap is
/// a different object; copying out of it does not erase copies the collector
/// already made of that object.

@Native<Pointer Function(IntPtr, IntPtr)>(symbol: 'calloc')
external Pointer<Void> _posixCalloc(int count, int size);

@Native<Void Function(Pointer)>(symbol: 'free')
external void _posixFree(Pointer pointer);

final class _Slot {
  final Pointer<Uint8> ptr;
  final int bytes;
  _Slot(this.ptr, this.bytes);
}

final Expando<_Slot> _slots = Expando<_Slot>('pqcrypto.secret');

int _anchor = 0;

@pragma('vm:never-inline')
void _zeroNative(Pointer<Uint8> ptr, int bytes) {
  for (var i = 0; i < bytes; i++) {
    ptr[i] = 0;
  }
  if (bytes > 0) {
    _anchor |= ptr[bytes - 1];
  }
}

final Finalizer<_Slot> _finalizer = Finalizer<_Slot>((slot) {
  _zeroNative(slot.ptr, slot.bytes);
  if (Platform.isWindows) {
    _winFree(slot.ptr);
  } else {
    _posixFree(slot.ptr);
  }
});

DynamicLibrary? _ole32;
Pointer<Uint8> Function(int bytes)? _coTaskMemAlloc;
void Function(Pointer<Uint8> pointer)? _coTaskMemFree;

void _loadWindowsAllocator() {
  final library = _ole32 ??= DynamicLibrary.open('ole32.dll');
  _coTaskMemAlloc ??= library
      .lookupFunction<Pointer Function(IntPtr), Pointer<Uint8> Function(int)>(
        'CoTaskMemAlloc',
      );
  _coTaskMemFree ??= library
      .lookupFunction<Void Function(Pointer), void Function(Pointer<Uint8>)>(
        'CoTaskMemFree',
      );
}

void _winFree(Pointer<Uint8> ptr) {
  _loadWindowsAllocator();
  _coTaskMemFree!(ptr);
}

Pointer<Uint8> _allocate(int bytes) {
  if (bytes <= 0) {
    throw ArgumentError.value(bytes, 'bytes', 'must be positive');
  }
  final Pointer<Uint8> ptr;
  if (Platform.isWindows) {
    _loadWindowsAllocator();
    ptr = _coTaskMemAlloc!(bytes);
    if (ptr.address == 0) {
      throw ArgumentError('Could not allocate $bytes bytes.');
    }
    _zeroNative(ptr, bytes);
  } else {
    final raw = _posixCalloc(bytes, 1);
    if (raw.address == 0) {
      throw ArgumentError('Could not allocate $bytes bytes.');
    }
    ptr = raw.cast<Uint8>();
  }
  return ptr;
}

void _track(TypedData list, Pointer<Uint8> ptr, int bytes) {
  final slot = _Slot(ptr, bytes);
  _slots[list] = slot;
  _finalizer.attach(list, slot, detach: list);
}

Uint8List allocUint8(int length) {
  if (length == 0) return Uint8List(0);
  final ptr = _allocate(length);
  final list = ptr.asTypedList(length);
  _track(list, ptr, length);
  return list;
}

Int16List allocInt16(int length) {
  if (length == 0) return Int16List(0);
  final ptr = _allocate(length * 2);
  final list = ptr.cast<Int16>().asTypedList(length);
  _track(list, ptr, length * 2);
  return list;
}

Int32List allocInt32(int length) {
  if (length == 0) return Int32List(0);
  final ptr = _allocate(length * 4);
  final list = ptr.cast<Int32>().asTypedList(length);
  _track(list, ptr, length * 4);
  return list;
}

Uint32List allocUint32(int length) {
  if (length == 0) return Uint32List(0);
  final ptr = _allocate(length * 4);
  final list = ptr.cast<Uint32>().asTypedList(length);
  _track(list, ptr, length * 4);
  return list;
}

bool allocIsNative(TypedData data) => _slots[data] != null;

int? allocNativeAddress(TypedData data) => _slots[data]?.ptr.address;

const bool allocUsesNativeHeap = true;
