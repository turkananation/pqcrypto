import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  final kem = PqcKem.kyber768;

  // 1. Deterministic Seed
  // NIST KAT uses 48 bytes usually (seed for RNG).
  // We accepted 64 bytes (d || z) in our helper.
  // Let's create a 64-byte seed.
  final seed = Uint8List(64);
  for (int i = 0; i < 64; i++) seed[i] = i;

  // 2. KeyGen
  final (pk, sk) = kem.generateKeyPair(seed);

  // 3. Encapsulate
  // We need deterministic coins/nonce for Encaps to reproduce 'ct'
  // My encapsulate() accepts nonce (32 bytes).
  final nonce = Uint8List(32);
  for (int i = 0; i < 32; i++) nonce[i] = 0xAA;

  final (ct, ss) = kem.encapsulate(pk, nonce);

  // Output in RSP format
  print('# PQCkemKAT_1184.rsp');
  print('# Algorithm: ML-KEM-768');
  print('');
  print('count = 0');
  print('seed = ${_toHex(seed)}');
  print('pk = ${_toHex(pk)}');
  print('sk = ${_toHex(sk)}');
  print('ct = ${_toHex(ct)}');
  print('ss = ${_toHex(ss)}');
}

String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
