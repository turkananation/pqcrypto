// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

void main() {
  _printIntro();

  _runMlKemExamples();
  _runMlDsaExamples();
  _runSlhDsaExamples();
  _runSignedHandshakeExample();

  print('\nDone.');
}

void _printIntro() {
  print('pqcrypto 0.4.0 example');
  print('Pure Dart NIST PQC primitives with zero runtime dependencies.');
  print('Families shown: ML-KEM, ML-DSA, and SLH-DSA.');
  print(
    'Evidence is KAT/ACVP/interop conformance, not CMVP/FIPS 140 validation.',
  );
}

void _runMlKemExamples() {
  _section('1. ML-KEM (FIPS 203): key encapsulation');
  print('ML-KEM establishes a shared secret; it is not encryption by itself.');
  _printRowHeader(<String>['Set', 'PK', 'SK', 'CT', 'SS', 'Match']);

  for (final example in <({String name, KyberKem kem})>[
    (name: 'ML-KEM-512', kem: PqcKem.kyber512),
    (name: 'ML-KEM-768', kem: PqcKem.kyber768),
    (name: 'ML-KEM-1024', kem: PqcKem.kyber1024),
  ]) {
    final (publicKey, secretKey) = example.kem.generateKeyPair();
    final (ciphertext, clientSecret) = example.kem.encapsulate(publicKey);
    final serverSecret = example.kem.decapsulate(secretKey, ciphertext);
    final ok = _bytesEqual(clientSecret, serverSecret);

    _printRow(<Object>[
      example.name,
      publicKey.length,
      secretKey.length,
      ciphertext.length,
      clientSecret.length,
      ok,
    ]);

    if (!ok) {
      throw StateError('${example.name} shared secrets did not match');
    }
  }
}

void _runMlDsaExamples() {
  _section('2. ML-DSA (FIPS 204): digital signatures');
  print('ML-DSA signs byte messages with an optional FIPS context string.');
  _printRowHeader(<String>['Set', 'PK', 'SK', 'SIG', 'Valid', 'Wrong ctx']);

  for (final example in <({String name, DilithiumParams params})>[
    (name: 'ML-DSA-44', params: DilithiumParams.mlDsa44),
    (name: 'ML-DSA-65', params: DilithiumParams.mlDsa65),
    (name: 'ML-DSA-87', params: DilithiumParams.mlDsa87),
  ]) {
    final (publicKey, secretKey) = MlDsa.generateKeyPair(example.params);
    final message = _utf8Bytes('pqcrypto ML-DSA demo message');
    final context = _utf8Bytes('pqcrypto-example-mldsa-v1');
    final signature = MlDsa.sign(
      secretKey,
      message,
      example.params,
      ctx: context,
    );
    final ok = MlDsa.verify(
      publicKey,
      message,
      signature,
      example.params,
      ctx: context,
    );
    final wrongContextOk = MlDsa.verify(
      publicKey,
      message,
      signature,
      example.params,
      ctx: _utf8Bytes('wrong-context'),
    );

    _printRow(<Object>[
      example.name,
      publicKey.length,
      secretKey.length,
      signature.length,
      ok,
      wrongContextOk,
    ]);

    if (!ok || wrongContextOk) {
      throw StateError('${example.name} signature verification failed');
    }
  }
}

void _runSlhDsaExamples() {
  _section('3. SLH-DSA (FIPS 205): stateless hash-based signatures');
  print('All 12 FIPS 205 parameter sets are supported.');
  print('The slow "s" sets are listed but not signed in this quick example.');
  _printRowHeader(<String>['Set', 'Cat', 'Hash', 'Mode', 'PK', 'SK', 'SIG']);

  for (final params in SlhDsaParams.supportedValues) {
    _printRow(<Object>[
      params.name,
      params.securityCategory,
      params.hashFamily.name.toUpperCase(),
      params.isFast ? 'fast' : 'small',
      params.publicKeyBytes,
      params.secretKeyBytes,
      params.signatureBytes,
    ]);
  }

  print('\nRunnable fast-set sign/verify checks:');
  _runSlhDsaSignExample(SlhDsaParams.sha2128f);
  _runSlhDsaSignExample(SlhDsaParams.shake128f);
}

void _runSlhDsaSignExample(SlhDsaParams params) {
  final (publicKey, secretKey) = SlhDsa.generateKeyPair(params);
  final message = _utf8Bytes('pqcrypto SLH-DSA demo message');
  final context = _utf8Bytes('pqcrypto-example-slhdsa-v1');
  final signature = SlhDsa.sign(
    secretKey,
    message,
    params,
    context: context,
    verifyAfterSign: true,
  );
  final ok = SlhDsa.verify(
    publicKey,
    message,
    signature,
    params,
    context: context,
  );
  final hashSignature = SlhDsa.hashSignDeterministic(
    secretKey,
    message,
    SlhDsaPreHash.sha3256,
    params,
    context: context,
  );
  final hashOk = SlhDsa.hashVerify(
    publicKey,
    message,
    hashSignature,
    SlhDsaPreHash.sha3256,
    params,
    context: context,
  );

  print(
    '  ${params.name}: sig=${signature.length}, pureOk=$ok, '
    'hashSig=${hashSignature.length}, hashOk=$hashOk',
  );

  if (!ok || !hashOk) {
    throw StateError('${params.name} SLH-DSA verification failed');
  }
}

void _runSignedHandshakeExample() {
  _section('4. ML-KEM + ML-DSA: signed handshake transcript');
  print('This composes primitives only. Applications still need KDF + AEAD,');
  print('authenticated key directories, replay storage, and session policy.');

  final kem = PqcKem.kyber768;
  final dsaParams = DilithiumParams.mlDsa65;
  final context = _utf8Bytes('pqcrypto-handshake-v1');

  final (serverKemPublicKey, serverKemSecretKey) = kem.generateKeyPair();
  final (clientSigningPublicKey, clientSigningSecretKey) =
      MlDsa.generateKeyPair(dsaParams);

  final clientNonce = _randomBytes(32);
  final timestampMs = DateTime.now().toUtc().millisecondsSinceEpoch;
  final (ciphertext, clientSecret) = kem.encapsulate(serverKemPublicKey);

  final transcript = _buildTranscript(<Uint8List>[
    _utf8Bytes('pqcrypto-example/signed-handshake/v1'),
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

  _printRowHeader(<String>['Field', 'Value']);
  _printRow(<Object>['Transcript bytes', transcript.length]);
  _printRow(<Object>['Client nonce prefix', '${_hex(clientNonce.take(8))}...']);
  _printRow(<Object>['Shared secret match', secretOk]);
  _printRow(<Object>['Transcript signature', signatureOk]);

  if (!secretOk || !signatureOk) {
    throw StateError('Signed handshake example failed');
  }
}

void _section(String title) {
  print('\n$title');
  print('-' * title.length);
}

void _printRowHeader(List<String> values) {
  print('  ${_formatColumns(values)}');
}

void _printRow(List<Object> values) {
  print('  ${_formatColumns(values.map((value) => '$value').toList())}');
}

String _formatColumns(List<String> values) {
  const widths = <int>[22, 8, 8, 8, 10, 10, 10];
  final cells = <String>[];
  for (var i = 0; i < values.length; i++) {
    final width = widths[i < widths.length ? i : widths.length - 1];
    cells.add(values[i].padRight(width));
  }
  return cells.join(' ');
}

Uint8List _buildTranscript(List<Uint8List> fields) {
  final framed = <Uint8List>[];
  for (final field in fields) {
    framed
      ..add(_uint32(field.length))
      ..add(field);
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

String _hex(Iterable<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
