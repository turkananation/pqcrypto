import 'package:pqcrypto/pqcrypto.dart';

const int mlKemKeyPairSeedBytes = 64;
const int mlKemEncapsulationSeedBytes = 32;
const int mlDsaSeedBytes = 32;

/// Provider-neutral metadata for one ML-KEM parameter set.
final class MlKemInteropSet {
  const MlKemInteropSet({
    required this.name,
    required this.pqcrypto,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.ciphertextBytes,
  });

  final String name;
  final KyberKem pqcrypto;
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int ciphertextBytes;

  int get sharedSecretBytes => 32;
}

final List<MlKemInteropSet> mlKemInteropSets = <MlKemInteropSet>[
  MlKemInteropSet(
    name: 'ML-KEM-512',
    pqcrypto: PqcKem.kyber512,
    publicKeyBytes: 800,
    secretKeyBytes: 1632,
    ciphertextBytes: 768,
  ),
  MlKemInteropSet(
    name: 'ML-KEM-768',
    pqcrypto: PqcKem.kyber768,
    publicKeyBytes: 1184,
    secretKeyBytes: 2400,
    ciphertextBytes: 1088,
  ),
  MlKemInteropSet(
    name: 'ML-KEM-1024',
    pqcrypto: PqcKem.kyber1024,
    publicKeyBytes: 1568,
    secretKeyBytes: 3168,
    ciphertextBytes: 1568,
  ),
];

/// Provider-neutral metadata for one ML-DSA parameter set.
final class MlDsaInteropSet {
  const MlDsaInteropSet({required this.params});

  final DilithiumParams params;

  String get name => params.name;
  int get publicKeyBytes => params.publicKeyBytes;
  int get secretKeyBytes => params.secretKeyBytes;
  int get signatureBytes => params.signatureBytes;
}

const List<MlDsaInteropSet> mlDsaInteropSets = <MlDsaInteropSet>[
  MlDsaInteropSet(params: DilithiumParams.mlDsa44),
  MlDsaInteropSet(params: DilithiumParams.mlDsa65),
  MlDsaInteropSet(params: DilithiumParams.mlDsa87),
];

/// Provider-neutral metadata for one SLH-DSA parameter set.
final class SlhDsaInteropSet {
  const SlhDsaInteropSet({required this.params, required this.liboqsName});

  final SlhDsaParams params;

  /// liboqs distinguishes pure SLH-DSA from its pre-hash variants by name.
  final String liboqsName;

  String get name => params.name;
  int get publicKeyBytes => params.publicKeyBytes;
  int get secretKeyBytes => params.secretKeyBytes;
  int get signatureBytes => params.signatureBytes;
}

const List<SlhDsaInteropSet> slhDsaInteropSets = <SlhDsaInteropSet>[
  SlhDsaInteropSet(
    params: SlhDsaParams.sha2128s,
    liboqsName: 'SLH_DSA_PURE_SHA2_128S',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.sha2128f,
    liboqsName: 'SLH_DSA_PURE_SHA2_128F',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.sha2192s,
    liboqsName: 'SLH_DSA_PURE_SHA2_192S',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.sha2192f,
    liboqsName: 'SLH_DSA_PURE_SHA2_192F',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.sha2256s,
    liboqsName: 'SLH_DSA_PURE_SHA2_256S',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.sha2256f,
    liboqsName: 'SLH_DSA_PURE_SHA2_256F',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.shake128s,
    liboqsName: 'SLH_DSA_PURE_SHAKE_128S',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.shake128f,
    liboqsName: 'SLH_DSA_PURE_SHAKE_128F',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.shake192s,
    liboqsName: 'SLH_DSA_PURE_SHAKE_192S',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.shake192f,
    liboqsName: 'SLH_DSA_PURE_SHAKE_192F',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.shake256s,
    liboqsName: 'SLH_DSA_PURE_SHAKE_256S',
  ),
  SlhDsaInteropSet(
    params: SlhDsaParams.shake256f,
    liboqsName: 'SLH_DSA_PURE_SHAKE_256F',
  ),
];
