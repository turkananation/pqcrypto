import 'dart:math';
import 'dart:typed_data';
import '../../common/zeroize.dart';
import 'poly.dart';
import 'symmetric.dart';
import 'params.dart';
import 'ntt.dart';
import 'rounding.dart';
import 'packing.dart';

/// FIPS 204 (ML-DSA) Module-Lattice Digital Signature Algorithm.
///
/// This class exposes the FIPS 204 *external* functions
/// ([generateKeyPair], [sign], [verify], and the HashML-DSA variants) as the
/// recommended application surface, and the *internal* deterministic functions
/// ([generateKeyPairSeeded], [signInternal], [verifyInternal]) for tests,
/// CAVP-style known-answer vectors, and constrained deterministic use.
///
/// External signing is **hedged by default** (a fresh 32-byte `rnd` is drawn
/// from [Random.secure]). Deterministic signing ([signDeterministic]) is an
/// explicit, documented opt-in because it is harder to protect against
/// side-channel and fault attacks.
class MlDsa {
  MlDsa._();

  static final Random _secureRng = Random.secure();
  static final Uint8List _emptyCtx = Uint8List(0);

  static Uint8List _randomBytes(int len) {
    final b = Uint8List(len);
    for (int i = 0; i < len; i++) {
      b[i] = _secureRng.nextInt(256);
    }
    return b;
  }

  // ===========================================================================
  // FIPS 204 Algorithm 1 — ML-DSA.KeyGen (external)
  // ===========================================================================

  /// Generate a fresh key pair `(pk, sk)` for [params].
  ///
  /// Draws a fresh 32-byte seed `xi` from [Random.secure] and runs
  /// `ML-DSA.KeyGen_internal`. The seed is zeroized after use (best-effort).
  ///
  /// NOTE: [Random.secure] is the platform CSPRNG; this package makes no
  /// SP 800-90A/B validation claim about the entropy source.
  static (Uint8List, Uint8List) generateKeyPair(DilithiumParams params) {
    final xi = _randomBytes(32);
    try {
      return generateKeyPairSeeded(params, xi);
    } finally {
      secureZero(xi);
    }
  }

  // ===========================================================================
  // FIPS 204 Algorithm 6 — ML-DSA.KeyGen_internal (deterministic)
  // ===========================================================================

  /// Deterministic key generation from a 32-byte seed [seed] (`xi`).
  ///
  /// This is `ML-DSA.KeyGen_internal`. It is intended for tests and KAT
  /// fixtures; applications should prefer [generateKeyPair].
  static (Uint8List, Uint8List) generateKeyPairSeeded(
    DilithiumParams params,
    Uint8List seed,
  ) {
    if (seed.length != 32) {
      throw ArgumentError('Seed must be 32 bytes');
    }

    // (rho, rho', K) <- H(xi || IntegerToBytes(k,1) || IntegerToBytes(l,1), 128)
    final seedInput = Uint8List(32 + 1 + 1);
    seedInput.setRange(0, 32, seed);
    seedInput[32] = params.k;
    seedInput[33] = params.l;
    final expanded = DilithiumSymmetric.crh(seedInput, 128);
    final rho = Uint8List(32)..setRange(0, 32, expanded.sublist(0, 32));
    final rhoPrime = Uint8List(64)..setRange(0, 64, expanded.sublist(32, 96));
    final kKey = Uint8List(32)..setRange(0, 32, expanded.sublist(96, 128));

    DilithiumPolyVec? s1, s2;
    try {
      // 2. ExpandA(rho)
      final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

      // 3. (s1, s2) <- ExpandS(rho')
      final pair = DilithiumSymmetric.expandS(
        rhoPrime,
        params.k,
        params.l,
        params.eta,
      );
      s1 = pair.$1;
      s2 = pair.$2;

      // 4. s1Hat = NTT(s1), s2Hat = NTT(s2) (s1/s2 retained for skEncode)
      final s1Hat = DilithiumPolyVec.zero(params.l);
      for (int i = 0; i < params.l; i++) {
        s1Hat[i].coeffs.setAll(0, s1[i].coeffs);
        DilithiumNTT.ntt(s1Hat[i]);
      }
      final s2Hat = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        s2Hat[i].coeffs.setAll(0, s2[i].coeffs);
        DilithiumNTT.ntt(s2Hat[i]);
      }

      // 5. t_hat = A_hat * s1_hat + s2_hat
      final tHat = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        for (int j = 0; j < params.l; j++) {
          tHat[i] = tHat[i] + aHat[i][j].pointwiseMul(s1Hat[j]);
        }
        tHat[i] = tHat[i] + s2Hat[i];
      }

      // 6. t = InvNTT(t_hat) ; 7. (t1, t0) = Power2Round(t)
      final t1 = DilithiumPolyVec.zero(params.k);
      final t0 = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        DilithiumNTT.invNtt(tHat[i]);
        for (int c = 0; c < n; c++) {
          final (r1, r0) = power2Round(tHat[i].coeffs[c]);
          t1[i].coeffs[c] = r1;
          t0[i].coeffs[c] = r0;
        }
      }

      // 8. pk = pkEncode(rho, t1)
      final pk = packPK(rho, t1);

      // 9. tr = H(pk, 64)
      final tr = DilithiumSymmetric.crh(pk, 64);

      // 10. sk = skEncode(rho, K, tr, s1, s2, t0)
      final sk = packSK(rho, kKey, tr, s1, s2, t0, params.eta);

      return (pk, sk);
    } finally {
      secureZero(rhoPrime);
      secureZero(kKey);
      if (s1 != null) {
        for (final p in s1.components) {
          secureZeroInt32(p.coeffs);
        }
      }
      if (s2 != null) {
        for (final p in s2.components) {
          secureZeroInt32(p.coeffs);
        }
      }
    }
  }

  // ===========================================================================
  // FIPS 204 Algorithm 2 — ML-DSA.Sign (external, hedged by default)
  // ===========================================================================

  /// Sign [m] under secret key [sk].
  ///
  /// - [ctx] is the FIPS 204 context string (default empty); it must be at most
  ///   255 bytes or an [ArgumentError] is thrown.
  /// - [rnd] is the 32-byte hedging value. When omitted, a fresh value is drawn
  ///   from [Random.secure] (hedged signing — the recommended default). Pass a
  ///   value only for deterministic test vectors; see [signDeterministic].
  static Uint8List sign(
    Uint8List sk,
    Uint8List m,
    DilithiumParams params, {
    Uint8List? ctx,
    Uint8List? rnd,
  }) {
    ctx ??= _emptyCtx;
    if (ctx.length > 255) {
      throw ArgumentError('Context string must be at most 255 bytes');
    }
    if (rnd != null && rnd.length != 32) {
      throw ArgumentError('rnd must be 32 bytes');
    }
    final hedge = rnd ?? _randomBytes(32);
    final mPrime = _formatMessage(0x00, ctx, m, null);
    try {
      return signInternal(sk, mPrime, params, rnd: hedge);
    } finally {
      if (rnd == null) secureZero(hedge);
    }
  }

  /// Deterministic signing (`rnd = 0^32`). Explicit, discouraged for general
  /// use: deterministic ML-DSA is harder to protect against side-channel and
  /// fault attacks than hedged signing. Prefer [sign].
  static Uint8List signDeterministic(
    Uint8List sk,
    Uint8List m,
    DilithiumParams params, {
    Uint8List? ctx,
  }) {
    return sign(sk, m, params, ctx: ctx, rnd: Uint8List(32));
  }

  // ===========================================================================
  // FIPS 204 Algorithm 4 — HashML-DSA.Sign (external, pre-hashed)
  // ===========================================================================

  /// HashML-DSA signing: pre-hashes [m] with the approved hash for this
  /// security level (SHA-256 for ML-DSA-44, SHA-384 for ML-DSA-65, SHA-512 for
  /// ML-DSA-87) and signs the OID-domain-separated digest.
  static Uint8List hashSign(
    Uint8List sk,
    Uint8List m,
    DilithiumParams params, {
    Uint8List? ctx,
    Uint8List? rnd,
  }) {
    ctx ??= _emptyCtx;
    if (ctx.length > 255) {
      throw ArgumentError('Context string must be at most 255 bytes');
    }
    if (rnd != null && rnd.length != 32) {
      throw ArgumentError('rnd must be 32 bytes');
    }
    final hedge = rnd ?? _randomBytes(32);
    final ph = _preHash(m, params);
    final mPrime = _formatMessage(0x01, ctx, ph.$2, ph.$1);
    try {
      return signInternal(sk, mPrime, params, rnd: hedge);
    } finally {
      if (rnd == null) secureZero(hedge);
    }
  }

  // ===========================================================================
  // FIPS 204 Algorithm 7 — ML-DSA.Sign_internal (deterministic core)
  // ===========================================================================

  /// Internal signing over an already-formatted message `M'` ([mPrime]).
  ///
  /// This is `ML-DSA.Sign_internal`. Applications should call [sign]; this is
  /// exposed for KAT/CAVP fixtures and the `raw` test flavour. [rnd] defaults
  /// to 32 zero bytes (deterministic).
  static Uint8List signInternal(
    Uint8List sk,
    Uint8List mPrime,
    DilithiumParams params, {
    Uint8List? rnd,
  }) {
    final rndBytes = rnd ?? Uint8List(32);
    if (rndBytes.length != 32) {
      throw ArgumentError('rnd must be 32 bytes');
    }

    // 1. Unpack sk.
    final (rho, kKey, tr, s1, s2, t0) = unpackSK(
      sk,
      params.k,
      params.l,
      params.eta,
    );

    Uint8List? rhoPrime;
    try {
      // mu = H(tr || M', 64)
      final muInput = Uint8List(tr.length + mPrime.length);
      muInput.setRange(0, tr.length, tr);
      muInput.setRange(tr.length, muInput.length, mPrime);
      final mu = DilithiumSymmetric.crh(muInput);

      // rho' = H(K || rnd || mu, 64)
      final rhoPrimeInput = Uint8List(32 + 32 + 64);
      rhoPrimeInput.setRange(0, 32, kKey);
      rhoPrimeInput.setRange(32, 64, rndBytes);
      rhoPrimeInput.setRange(64, 128, mu);
      rhoPrime = DilithiumSymmetric.crh(rhoPrimeInput);

      final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

      final s1Hat = DilithiumPolyVec.zero(params.l);
      for (int i = 0; i < params.l; i++) {
        s1Hat[i].coeffs.setAll(0, s1[i].coeffs);
        DilithiumNTT.ntt(s1Hat[i]);
      }
      final s2Hat = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        s2Hat[i].coeffs.setAll(0, s2[i].coeffs);
        DilithiumNTT.ntt(s2Hat[i]);
      }
      final t0Hat = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        t0Hat[i].coeffs.setAll(0, t0[i].coeffs);
        DilithiumNTT.ntt(t0Hat[i]);
      }

      final alpha = 2 * params.gamma2;
      final w1Bits = (params.gamma2 == 95232) ? 6 : 4;
      int kappa = 0;

      while (true) {
        // y <- ExpandMask(rho', kappa)
        final y = DilithiumSymmetric.expandMask(
          rhoPrime,
          kappa,
          params.l,
          params.gamma1,
        );

        // w = A * y
        final yHat = DilithiumPolyVec.zero(params.l);
        for (int i = 0; i < params.l; i++) {
          yHat[i].coeffs.setAll(0, y[i].coeffs);
          DilithiumNTT.ntt(yHat[i]);
        }
        final w = DilithiumPolyVec.zero(params.k);
        for (int i = 0; i < params.k; i++) {
          for (int j = 0; j < params.l; j++) {
            w[i] = w[i] + aHat[i][j].pointwiseMul(yHat[j]);
          }
          DilithiumNTT.invNtt(w[i]);
        }

        // w1 = HighBits(w)
        final w1 = DilithiumPolyVec.zero(params.k);
        for (int i = 0; i < params.k; i++) {
          for (int j = 0; j < n; j++) {
            final (r1, _) = decompose(w[i].coeffs[j], alpha);
            w1[i].coeffs[j] = r1;
          }
        }

        // c~ = H(mu || w1Encode(w1), cTildeSize)
        final w1Packed = Uint8List(params.k * 32 * w1Bits);
        int w1Off = 0;
        for (int i = 0; i < params.k; i++) {
          final packed = simpleBitPack(w1[i], w1Bits);
          w1Packed.setRange(w1Off, w1Off + packed.length, packed);
          w1Off += packed.length;
        }
        final cInput = Uint8List(mu.length + w1Packed.length);
        cInput.setRange(0, mu.length, mu);
        cInput.setRange(mu.length, cInput.length, w1Packed);
        final cTilde = DilithiumSymmetric.crh(cInput, params.cTildeSize);

        // c = SampleInBall(c~); c_hat = NTT(c)
        final c = DilithiumSymmetric.sampleInBall(cTilde, params.tau);
        final cHat = DilithiumPoly.zero();
        cHat.coeffs.setAll(0, c.coeffs);
        DilithiumNTT.ntt(cHat);

        // z = y + c*s1
        final z = DilithiumPolyVec.zero(params.l);
        for (int i = 0; i < params.l; i++) {
          final cs1 = cHat.pointwiseMul(s1Hat[i]);
          DilithiumNTT.invNtt(cs1);
          z[i] = y[i] + cs1;
        }
        bool reject = false;
        for (int i = 0; i < params.l; i++) {
          if (_normExceeds(z[i], params.gamma1 - params.beta)) {
            reject = true;
            break;
          }
        }
        if (reject) {
          kappa += params.l;
          continue;
        }

        // r0 = LowBits(w - c*s2)
        final cs2 = DilithiumPolyVec.zero(params.k);
        for (int i = 0; i < params.k; i++) {
          cs2[i] = cHat.pointwiseMul(s2Hat[i]);
          DilithiumNTT.invNtt(cs2[i]);
        }
        final r0 = DilithiumPolyVec.zero(params.k);
        for (int i = 0; i < params.k; i++) {
          final diff = w[i] - cs2[i];
          for (int j = 0; j < n; j++) {
            final (_, r0Val) = decompose(diff.coeffs[j], alpha);
            r0[i].coeffs[j] = r0Val;
          }
          if (_normExceeds(r0[i], params.gamma2 - params.beta)) {
            reject = true;
            break;
          }
        }
        if (reject) {
          kappa += params.l;
          continue;
        }

        // ct0 = c*t0; reject if ||ct0||_inf >= gamma2
        final ct0 = DilithiumPolyVec.zero(params.k);
        for (int i = 0; i < params.k; i++) {
          ct0[i] = cHat.pointwiseMul(t0Hat[i]);
          DilithiumNTT.invNtt(ct0[i]);
          if (_normExceeds(ct0[i], params.gamma2)) {
            reject = true;
            break;
          }
        }
        if (reject) {
          kappa += params.l;
          continue;
        }

        // h = MakeHint(-ct0, w - c*s2 + ct0)
        final h = DilithiumPolyVec.zero(params.k);
        int hintCount = 0;
        for (int i = 0; i < params.k; i++) {
          final r = (w[i] - cs2[i]) + ct0[i];
          for (int j = 0; j < n; j++) {
            final hBit = makeHint(-ct0[i].coeffs[j], r.coeffs[j], alpha);
            h[i].coeffs[j] = hBit;
            hintCount += hBit;
          }
        }
        if (hintCount > params.omega) {
          kappa += params.l;
          continue;
        }

        for (int i = 0; i < params.l; i++) {
          z[i].reduce();
        }
        return packSig(cTilde, z, h, params.gamma1, params.omega);
      }
    } finally {
      secureZero(kKey);
      secureZero(rhoPrime);
      for (final p in s1.components) {
        secureZeroInt32(p.coeffs);
      }
      for (final p in s2.components) {
        secureZeroInt32(p.coeffs);
      }
      for (final p in t0.components) {
        secureZeroInt32(p.coeffs);
      }
    }
  }

  // ===========================================================================
  // FIPS 204 Algorithm 3 — ML-DSA.Verify (external)
  // ===========================================================================

  /// Verify [sig] over [m] under public key [pk].
  ///
  /// Returns `false` (never throws) for any malformed or attacker-controlled
  /// input: wrong pk/sig length, over-long [ctx], malformed hints, or a norm
  /// violation.
  static bool verify(
    Uint8List pk,
    Uint8List m,
    Uint8List sig,
    DilithiumParams params, {
    Uint8List? ctx,
  }) {
    ctx ??= _emptyCtx;
    if (ctx.length > 255) return false;
    final mPrime = _formatMessage(0x00, ctx, m, null);
    return verifyInternal(pk, mPrime, sig, params);
  }

  // ===========================================================================
  // FIPS 204 Algorithm 5 — HashML-DSA.Verify (external)
  // ===========================================================================

  /// HashML-DSA verification matching [hashSign].
  static bool hashVerify(
    Uint8List pk,
    Uint8List m,
    Uint8List sig,
    DilithiumParams params, {
    Uint8List? ctx,
  }) {
    ctx ??= _emptyCtx;
    if (ctx.length > 255) return false;
    final ph = _preHash(m, params);
    final mPrime = _formatMessage(0x01, ctx, ph.$2, ph.$1);
    return verifyInternal(pk, mPrime, sig, params);
  }

  // ===========================================================================
  // FIPS 204 Algorithm 8 — ML-DSA.Verify_internal
  // ===========================================================================

  /// Internal verification over an already-formatted message `M'` ([mPrime]).
  static bool verifyInternal(
    Uint8List pk,
    Uint8List mPrime,
    Uint8List sig,
    DilithiumParams params,
  ) {
    // Defensive length checks BEFORE any decode/sublist.
    if (pk.length != params.publicKeyBytes) return false;
    if (sig.length != params.signatureBytes) return false;

    final DilithiumPolyVec t1;
    final Uint8List rho;
    try {
      final pkParts = unpackPK(pk, params.k);
      rho = pkParts.$1;
      t1 = pkParts.$2;
    } catch (_) {
      return false;
    }

    final Uint8List cTilde;
    final DilithiumPolyVec z;
    final DilithiumPolyVec h;
    try {
      final res = unpackSig(
        sig,
        params.k,
        params.l,
        params.gamma1,
        params.omega,
        params.cTildeSize,
      );
      cTilde = res.$1;
      z = res.$2;
      h = res.$3;
    } catch (_) {
      return false;
    }

    // ||z||_inf < gamma1 - beta
    for (int i = 0; i < params.l; i++) {
      if (_normExceeds(z[i], params.gamma1 - params.beta)) {
        return false;
      }
    }

    final tr = DilithiumSymmetric.crh(pk, 64);
    final muInput = Uint8List(tr.length + mPrime.length);
    muInput.setRange(0, tr.length, tr);
    muInput.setRange(tr.length, muInput.length, mPrime);
    final mu = DilithiumSymmetric.crh(muInput);

    final c = DilithiumSymmetric.sampleInBall(cTilde, params.tau);
    final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

    final zHat = DilithiumPolyVec.zero(params.l);
    for (int i = 0; i < params.l; i++) {
      zHat[i].coeffs.setAll(0, z[i].coeffs);
      DilithiumNTT.ntt(zHat[i]);
    }
    final t1Hat = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      t1Hat[i].coeffs.setAll(0, t1[i].coeffs);
      DilithiumNTT.ntt(t1Hat[i]);
    }
    final cHat = DilithiumPoly.zero();
    cHat.coeffs.setAll(0, c.coeffs);
    DilithiumNTT.ntt(cHat);

    final az = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < params.l; j++) {
        az[i] = az[i] + aHat[i][j].pointwiseMul(zHat[j]);
      }
    }
    final ct1 = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      final prod = cHat.pointwiseMul(t1Hat[i]);
      DilithiumNTT.invNtt(prod);
      for (int x = 0; x < n; x++) {
        // Multiply by 2^d (NOT a left shift: dart2js '<<' is 32-bit and
        // prod*2^d can reach ~2^36; '*' stays exact within the 53-bit web int).
        prod.coeffs[x] = (prod.coeffs[x] * (1 << d)) % q;
      }
      ct1[i] = prod;
    }
    final wApprox = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      DilithiumNTT.invNtt(az[i]);
      wApprox[i] = az[i] - ct1[i];
      wApprox[i].reduce();
    }

    final alpha = 2 * params.gamma2;
    final w1Prime = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < n; j++) {
        w1Prime[i].coeffs[j] = useHint(
          h[i].coeffs[j],
          wApprox[i].coeffs[j],
          alpha,
        );
      }
    }

    final w1Bits = (params.gamma2 == 95232) ? 6 : 4;
    final w1Packed = Uint8List(params.k * 32 * w1Bits);
    int w1Off = 0;
    for (int i = 0; i < params.k; i++) {
      final packed = simpleBitPack(w1Prime[i], w1Bits);
      w1Packed.setRange(w1Off, w1Off + packed.length, packed);
      w1Off += packed.length;
    }
    final cInput = Uint8List(mu.length + w1Packed.length);
    cInput.setRange(0, mu.length, mu);
    cInput.setRange(mu.length, cInput.length, w1Packed);
    final cTildePrime = DilithiumSymmetric.crh(cInput, params.cTildeSize);

    // Constant-time comparison of the two challenge hashes.
    if (cTilde.length != cTildePrime.length) return false;
    int diff = 0;
    for (int i = 0; i < cTilde.length; i++) {
      diff |= cTilde[i] ^ cTildePrime[i];
    }
    return diff == 0;
  }

  // ===========================================================================
  // Helpers
  // ===========================================================================

  /// FIPS 204 external message formatting.
  ///
  /// For ML-DSA: `M' = domain || IntegerToBytes(|ctx|,1) || ctx || M` with
  /// `domain = 0x00`. For HashML-DSA: `domain = 0x01` and the trailing payload
  /// is `DER(OID) || PH(M)`, supplied as [oid] (DER OID) and [payload] (digest).
  static Uint8List _formatMessage(
    int domain,
    Uint8List ctx,
    Uint8List payload,
    Uint8List? oid,
  ) {
    final oidLen = oid?.length ?? 0;
    final out = Uint8List(2 + ctx.length + oidLen + payload.length);
    out[0] = domain;
    out[1] = ctx.length;
    int off = 2;
    out.setRange(off, off + ctx.length, ctx);
    off += ctx.length;
    if (oid != null) {
      out.setRange(off, off + oid.length, oid);
      off += oid.length;
    }
    out.setRange(off, off + payload.length, payload);
    return out;
  }

  /// Returns `(DER(OID), PH(M))` for the HashML-DSA pre-hash bound to this
  /// security level (FIPS 204 §5.4): SHA-256 (44), SHA-384 (65), SHA-512 (87).
  static (Uint8List, Uint8List) _preHash(Uint8List m, DilithiumParams params) {
    return DilithiumSymmetric.preHash(m, params.cTildeSize);
  }

  /// Infinity-norm bound check: returns `true` iff some coefficient's centered
  /// representative has absolute value `>= bound`.
  ///
  /// Hardening: every one of the 256 coefficients is evaluated with no early
  /// exit, so the loop length is independent of secret data (the dominant and
  /// most exploitable timing channel for this check is closed). Per-iteration
  /// branch directions remain a residual side channel; in a pure-Dart library
  /// that compiles to the VM, dart2js, and dart2wasm, fully branchless,
  /// constant-time arithmetic is not portably achievable, so this is a
  /// best-effort measure rather than a hard guarantee (see SECURITY_AUDIT.md).
  ///
  /// Uses only `%`, comparison, and subtraction so the result is identical on
  /// the VM and the web compilers (no reliance on `>>`/`<<` of signed values,
  /// which dart2js evaluates as 32-bit operations). Accepts coefficients in
  /// `[0, q)` or in a signed domain such as `[-gamma1+1, gamma1]`.
  static bool _normExceeds(DilithiumPoly p, int bound) {
    int flag = 0;
    for (int i = 0; i < n; i++) {
      int c = p.coeffs[i] % q;
      if (c < 0) c += q; // c in [0, q)
      if (c > (q >> 1)) c -= q; // centered representative in (-q/2, q/2]
      final a = c < 0 ? -c : c; // |centered|
      if (a >= bound) flag = 1; // accumulate; no early exit
    }
    return flag != 0;
  }
}
