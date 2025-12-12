class KyberParams {
  final int k;
  final int eta1;
  final int eta2;
  final int du;
  final int dv;

  const KyberParams({
    required this.k,
    required this.eta1,
    required this.eta2,
    required this.du,
    required this.dv,
  });

  int get polyBytes => 384;
  int get secretKeyBytes =>
      384 * k + publicKeyBytes + 32 + 32; // s + pk + h + z
  int get publicKeyBytes => 384 * k + 32;
  int get ciphertextBytes {
    int uBytes = (256 * k * du) ~/ 8;
    int vBytes = (256 * dv) ~/ 8;
    return uBytes + vBytes;
  }
}

enum KyberLevel { kem512, kem768, kem1024 }
