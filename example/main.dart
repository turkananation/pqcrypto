// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

void main() {
  print('--- pqcrypto FIPS 203/204 Demo ---');
  print('ML-KEM establishes a shared secret; ML-DSA signs payloads.');
  print('This package does not claim CMVP/FIPS 140 module validation.\n');

  _runMlKemExamples();
  _runMlDsaExamples();
  _runSignedHandshakeExample();
}

void _runMlKemExamples() {
  print('1. ML-KEM shared-secret agreement');

  _runKemExample('ML-KEM-512', PqcKem.kyber512);
  _runKemExample('ML-KEM-768', PqcKem.kyber768);
  _runKemExample('ML-KEM-1024', PqcKem.kyber1024);
}

void _runKemExample(String name, KyberKem kem) {
  final (publicKey, secretKey) = kem.generateKeyPair();
  final (ciphertext, clientSecret) = kem.encapsulate(publicKey);
  final serverSecret = kem.decapsulate(secretKey, ciphertext);

  final ok = _bytesEqual(clientSecret, serverSecret);
  print(
    '  $name: pk=${publicKey.length}, ct=${ciphertext.length}, '
    'sk=${secretKey.length}, ss=${clientSecret.length}, ok=$ok',
  );

  if (!ok) {
    throw StateError('$name shared secrets did not match');
  }
}

void _runMlDsaExamples() {
  print('\n2. ML-DSA signing and verification');

  _runDsaExample('ML-DSA-44', DilithiumParams.mlDsa44);
  _runDsaExample('ML-DSA-65', DilithiumParams.mlDsa65);
  _runDsaExample('ML-DSA-87', DilithiumParams.mlDsa87);
}

void _runDsaExample(String name, DilithiumParams params) {
  final (publicKey, secretKey) = MlDsa.generateKeyPair(params);
  final message = _utf8Bytes('pqcrypto ML-DSA demo message');
  final context = _utf8Bytes('pqcrypto-example-v1');
  final signature = MlDsa.sign(secretKey, message, params, ctx: context);

  final ok = MlDsa.verify(publicKey, message, signature, params, ctx: context);
  final wrongContextOk = MlDsa.verify(
    publicKey,
    message,
    signature,
    params,
    ctx: _utf8Bytes('wrong-context'),
  );

  print(
    '  $name: pk=${publicKey.length}, sk=${secretKey.length}, '
    'sig=${signature.length}, ok=$ok, wrongCtxOk=$wrongContextOk',
  );

  if (!ok || wrongContextOk) {
    throw StateError('$name signature verification failed');
  }
}

void _runSignedHandshakeExample() {
  print('\n3. Signed ML-KEM-768 handshake transcript');

  final kem = PqcKem.kyber768;
  final dsaParams = DilithiumParams.mlDsa65;
  final context = _utf8Bytes('pqcrypto-handshake-v1');

  final (serverKemPublicKey, serverKemSecretKey) = kem.generateKeyPair();
  final (clientSigningPublicKey, clientSigningSecretKey) =
      MlDsa.generateKeyPair(dsaParams);

  final clientNonce = _randomBytes(32);
  final timestampMs = DateTime.now().toUtc().millisecondsSinceEpoch;
  final (ciphertext, clientSecret) = kem.encapsulate(serverKemPublicKey);

  final transcript = _buildTranscript([
    _utf8Bytes('pqcrypto-example/serverpod-handshake/v1'),
    _utf8Bytes('ML-KEM-768'),
    _utf8Bytes('ML-DSA-65'),
    _utf8Bytes('server-key-epoch-1'),
    _uint64(timestampMs),
    clientNonce,
    serverKemPublicKey,
    clientSigningPublicKey,
    ciphertext,
  ]);

  final clientSignature = MlDsa.sign(
    clientSigningSecretKey,
    transcript,
    dsaParams,
    ctx: context,
  );

  final signatureOk = MlDsa.verify(
    clientSigningPublicKey,
    transcript,
    clientSignature,
    dsaParams,
    ctx: context,
  );
  final serverSecret = kem.decapsulate(serverKemSecretKey, ciphertext);
  final secretOk = _bytesEqual(clientSecret, serverSecret);

  print('  transcript bytes: ${transcript.length}');
  print('  client nonce: ${_hex(clientNonce.sublist(0, 8))}...');
  print('  ML-KEM shared secret match: $secretOk');
  print('  ML-DSA transcript signature valid: $signatureOk');

  if (!secretOk || !signatureOk) {
    throw StateError('Signed handshake example failed');
  }

  print('\nDone.');
}

Uint8List _buildTranscript(List<Uint8List> fields) {
  final framed = <Uint8List>[];
  for (final field in fields) {
    framed.add(_uint32(field.length));
    framed.add(field);
  }
  return _concat(framed);
}

Uint8List _concat(List<Uint8List> chunks) {
  final total = chunks.fold<int>(0, (sum, chunk) => sum + chunk.length);
  final out = Uint8List(total);
  var offset = 0;
  for (final chunk in chunks) {
    out.setRange(offset, offset + chunk.length, chunk);
    offset += chunk.length;
  }
  return out;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Uint8List _randomBytes(int length) {
  final rng = Random.secure();
  final out = Uint8List(length);
  for (var i = 0; i < out.length; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}

Uint8List _uint32(int value) {
  return Uint8List(4)..buffer.asByteData().setUint32(0, value, Endian.big);
}

Uint8List _uint64(int value) {
  return Uint8List(8)..buffer.asByteData().setUint64(0, value, Endian.big);
}

Uint8List _utf8Bytes(String value) => Uint8List.fromList(utf8.encode(value));

String _hex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
