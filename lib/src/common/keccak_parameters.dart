/// Package-internal FIPS 202 parameters used by the Keccak implementation.
///
/// These values live separately so tests can pin the exact constants consumed
/// by the implementation rather than comparing against duplicated test-only
/// tables.
final class KeccakF1600Parameters {
  KeccakF1600Parameters._();

  static const int stateBits = 1600;
  static const int rounds = 24;

  /// Iota round constants split into low and high 32-bit words.
  static const List<int> roundConstantsLow32 = <int>[
    0x00000001,
    0x00008082,
    0x0000808a,
    0x80008000,
    0x0000808b,
    0x80000001,
    0x80008081,
    0x00008009,
    0x0000008a,
    0x00000088,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x0000008b,
    0x00008089,
    0x00008003,
    0x00008002,
    0x00000080,
    0x0000800a,
    0x8000000a,
    0x80008081,
    0x00008080,
    0x80000001,
    0x80008008,
  ];

  static const List<int> roundConstantsHigh32 = <int>[
    0x00000000,
    0x00000000,
    0x80000000,
    0x80000000,
    0x00000000,
    0x00000000,
    0x80000000,
    0x80000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x80000000,
    0x80000000,
    0x80000000,
    0x80000000,
    0x80000000,
    0x00000000,
    0x80000000,
    0x80000000,
    0x80000000,
    0x00000000,
    0x80000000,
  ];

  /// Rho rotation offsets indexed by lane `x + 5*y` (FIPS 202 Table 2).
  static const List<int> rhoOffsets = <int>[
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
  ];
}

/// One standardized FIPS 202 sponge profile.
final class Fips202Parameters {
  const Fips202Parameters._({
    required this.name,
    required this.rateBytes,
    required this.capacityBits,
    required this.domain,
    this.digestBytes,
  });

  final String name;
  final int rateBytes;
  final int capacityBits;

  /// Delimited suffix including the first `pad10*1` bit.
  final int domain;
  final int? digestBytes;

  static const int sha3Domain = 0x06;
  static const int shakeDomain = 0x1f;

  static const sha3224 = Fips202Parameters._(
    name: 'SHA3-224',
    rateBytes: 144,
    capacityBits: 448,
    domain: sha3Domain,
    digestBytes: 28,
  );
  static const sha3256 = Fips202Parameters._(
    name: 'SHA3-256',
    rateBytes: 136,
    capacityBits: 512,
    domain: sha3Domain,
    digestBytes: 32,
  );
  static const sha3384 = Fips202Parameters._(
    name: 'SHA3-384',
    rateBytes: 104,
    capacityBits: 768,
    domain: sha3Domain,
    digestBytes: 48,
  );
  static const sha3512 = Fips202Parameters._(
    name: 'SHA3-512',
    rateBytes: 72,
    capacityBits: 1024,
    domain: sha3Domain,
    digestBytes: 64,
  );
  static const shake128 = Fips202Parameters._(
    name: 'SHAKE128',
    rateBytes: 168,
    capacityBits: 256,
    domain: shakeDomain,
  );
  static const shake256 = Fips202Parameters._(
    name: 'SHAKE256',
    rateBytes: 136,
    capacityBits: 512,
    domain: shakeDomain,
  );

  static const List<Fips202Parameters> values = <Fips202Parameters>[
    sha3224,
    sha3256,
    sha3384,
    sha3512,
    shake128,
    shake256,
  ];
}
