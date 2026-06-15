// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

const Map<String, SlhDsaParams> _parameters = <String, SlhDsaParams>{
  'sha2128s': SlhDsaParams.sha2128s,
  'sha2128f': SlhDsaParams.sha2128f,
  'sha2192s': SlhDsaParams.sha2192s,
  'sha2192f': SlhDsaParams.sha2192f,
  'sha2256s': SlhDsaParams.sha2256s,
  'sha2256f': SlhDsaParams.sha2256f,
  'shake128s': SlhDsaParams.shake128s,
  'shake128f': SlhDsaParams.shake128f,
  'shake192s': SlhDsaParams.shake192s,
  'shake192f': SlhDsaParams.shake192f,
  'shake256s': SlhDsaParams.shake256s,
  'shake256f': SlhDsaParams.shake256f,
};

const String _compiledParameter = String.fromEnvironment(
  'SLHDSA_BENCH_PARAMETER',
);
const String _compiledTarget = String.fromEnvironment('SLHDSA_BENCH_TARGET');

void main(List<String> arguments) {
  final parameterName =
      _option(arguments, 'parameter') ??
      (_compiledParameter.isEmpty ? null : _compiledParameter);
  final target =
      _option(arguments, 'target') ??
      (_compiledTarget.isEmpty ? 'unspecified' : _compiledTarget);
  final selected = parameterName == null
      ? SlhDsaParams.supportedValues
      : <SlhDsaParams>[
          _parameters[parameterName] ??
              (throw ArgumentError.value(
                parameterName,
                'parameter',
                'expected one of ${_parameters.keys.join(', ')}',
              )),
        ];

  for (final params in selected) {
    _runBenchmark(params, target);
  }
}

void _runBenchmark(SlhDsaParams params, String target) {
  final message = Uint8List.fromList(
    List<int>.generate(64, (index) => (index * 17 + 3) & 0xff),
  );
  final context = Uint8List.fromList('pqcrypto-slh-dsa-benchmark'.codeUnits);

  final keyGenWatch = Stopwatch()..start();
  final (publicKey, secretKey) = SlhDsa.generateKeyPair(params);
  keyGenWatch.stop();

  final signWatch = Stopwatch()..start();
  final signature = SlhDsa.signDeterministic(
    secretKey,
    message,
    params,
    context: context,
    allowSlowSigning: true,
  );
  signWatch.stop();

  final verifyWatch = Stopwatch()..start();
  final verified = SlhDsa.verify(
    publicKey,
    message,
    signature,
    params,
    context: context,
  );
  verifyWatch.stop();

  if (!verified) {
    throw StateError('${params.name} benchmark signature did not verify');
  }

  print(
    jsonEncode(<String, Object>{
      'target': target,
      'parameter': params.name,
      'sampleCount': 1,
      'keyGenUs': keyGenWatch.elapsedMicroseconds,
      'signUs': signWatch.elapsedMicroseconds,
      'verifyUs': verifyWatch.elapsedMicroseconds,
      'publicKeyBytes': params.publicKeyBytes,
      'secretKeyBytes': params.secretKeyBytes,
      'signatureBytes': params.signatureBytes,
    }),
  );

  secretKey.fillRange(0, secretKey.length, 0);
  signature.fillRange(0, signature.length, 0);
}

String? _option(List<String> arguments, String name) {
  final prefix = '--$name=';
  for (final argument in arguments) {
    if (argument.startsWith(prefix)) {
      return argument.substring(prefix.length);
    }
  }
  return null;
}
