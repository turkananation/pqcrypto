import 'dart:typed_data';
import '../../common/shake.dart';
import 'poly.dart';
import 'symmetric.dart';
import 'params.dart';
import 'ntt.dart';
import 'rounding.dart';
import 'packing.dart';

class MlDsa {
  /// Generate Key Pair (pk, sk) for the given parameters.
  /// [seed] must be exactly 32 bytes.
  static (Uint8List, Uint8List) generateKeyPair(
    DilithiumParams params,
    Uint8List seed, // 32 bytes
  ) {
    if (seed.length != 32) throw ArgumentError("Seed must be 32 bytes");

    // 1. Expand seed into rho (32), rho' (64), K (32)
    // FIPS 204 Alg 1: (rho, rho', K) <- SHAKE-256(seed, 128)
    final expanded = Shake256.shake(seed, 32 + 64 + 32);
    final rho = Uint8List(32);
    rho.setRange(0, 32, expanded.sublist(0, 32));

    final rhoPrime = Uint8List(64);
    rhoPrime.setRange(0, 64, expanded.sublist(32, 96));

    final kKey = Uint8List(32);
    kKey.setRange(0, 32, expanded.sublist(96, 128));

    // 2. ExpandA(rho)
    final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

    // 3. ExpandS(rho')
    final (s1, s2) = DilithiumSymmetric.expandS(
      rhoPrime,
      params.k,
      params.l,
      params.eta,
    );

    // 4. NTT(s1), NTT(s2)
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
        final prod = aHat[i][j].pointwiseMul(s1Hat[j]);
        tHat[i] = tHat[i] + prod;
      }
      tHat[i] = tHat[i] + s2Hat[i];
    }

    // 6. t = InvNTT(t_hat)
    // 7. t1, t0 = Power2Round(t, d=13)
    final t1 = DilithiumPolyVec.zero(params.k);
    final t0 = DilithiumPolyVec.zero(params.k);

    for (int i = 0; i < params.k; i++) {
      DilithiumNTT.invNtt(tHat[i]);

      final polyT1 = DilithiumPoly.zero();
      final polyT0 = DilithiumPoly.zero();

      for (int c = 0; c < 256; c++) {
        final (r1, r0) = power2Round(tHat[i].coeffs[c]);
        polyT1.coeffs[c] = r1;
        polyT0.coeffs[c] = r0;
      }
      t1[i] = polyT1;
      t0[i] = polyT0;
    }

    // 8. pk = Pack(rho, t1)
    final pk = packPK(rho, t1);

    // 9. tr = CRH(pk)
    final tr = Shake256.shake(pk, 64);

    // 10. sk = Pack(rho, K, tr, s1, s2, t0)
    final sk = packSK(rho, kKey, tr, s1, s2, t0, params.eta);

    return (pk, sk);
  }

  /// Sign message M using secret key sk.
  static Uint8List sign(
    Uint8List sk,
    Uint8List m,
    DilithiumParams params, {
    bool deterministic = false,
  }) {
    // 1. Unpack SK
    final (rho, kKey, tr, s1, s2, t0) = unpackSK(
      sk,
      params.k,
      params.l,
      params.eta,
    );

    // 2. mu = CRH(tr || M)
    final muInput = Uint8List(tr.length + m.length);
    muInput.setRange(0, tr.length, tr);
    muInput.setRange(tr.length, tr.length + m.length, m);
    final mu = DilithiumSymmetric.crh(muInput);

    // 3. rho' = CRH(K || mu)
    final rhoPrimeInput = Uint8List(kKey.length + mu.length);
    rhoPrimeInput.setRange(0, kKey.length, kKey);
    rhoPrimeInput.setRange(kKey.length, kKey.length + mu.length, mu);
    final rhoPrime = DilithiumSymmetric.crh(rhoPrimeInput); // 64 bytes

    // Expand Matrix A
    final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

    // Pre-computation: NTT(s1), NTT(s2), NTT(t0)
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

    int kappa = 0;
    DilithiumPolyVec? z;
    DilithiumPolyVec? h;
    Uint8List? cTilde;

    // Rejection Loop
    while (true) {
      // 4. Sample y
      final y = DilithiumSymmetric.expandMask(
        rhoPrime,
        kappa,
        params.l,
        params.gamma1,
      );

      // 5. w = A * y (via NTT)
      final yHat = DilithiumPolyVec.zero(params.l);
      for (int i = 0; i < params.l; i++) {
        yHat[i].coeffs.setAll(0, y[i].coeffs);
        DilithiumNTT.ntt(yHat[i]);
      }

      final wHat = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        for (int j = 0; j < params.l; j++) {
          wHat[i] = wHat[i] + aHat[i][j].pointwiseMul(yHat[j]);
        }
        DilithiumNTT.invNtt(wHat[i]); // w in Normal
      }

      // 6. w1 = HighBits(w, 2*gamma2)
      final w1 = DilithiumPolyVec.zero(params.k);
      final alpha = 2 * params.gamma2;

      for (int i = 0; i < params.k; i++) {
        for (int j = 0; j < 256; j++) {
          final (r1, _) = decompose(wHat[i].coeffs[j], alpha);
          w1[i].coeffs[j] = r1;
        }
      }

      // 7. c_tilde = CRH(mu || w1_encoded)
      int w1Bits = (params.gamma2 == 95232) ? 6 : 4;

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
      cTilde = DilithiumSymmetric.crh(cInput, params.cTildeSize);

      final cSeed = cTilde;

      // 8. c = SampleInBall(c_tilde)
      final c = DilithiumSymmetric.sampleInBall(cSeed, params.tau);

      final cHat = DilithiumPoly.zero();
      cHat.coeffs.setAll(0, c.coeffs);
      DilithiumNTT.ntt(cHat);

      // 9. z = y + c * s1
      final cs1 = DilithiumPolyVec.zero(params.l);
      for (int i = 0; i < params.l; i++) {
        cs1[i] = cHat.pointwiseMul(s1Hat[i]);
        DilithiumNTT.invNtt(cs1[i]);
      }

      final zCand = DilithiumPolyVec.zero(params.l);
      bool rejectZ = false;
      for (int i = 0; i < params.l; i++) {
        zCand[i] = y[i] + cs1[i];
        if (_checkNorm(zCand[i], params.gamma1 - params.beta)) {
          rejectZ = true;
          break;
        }
      }
      if (rejectZ) {
        kappa += params.l;
        continue;
      }

      // 10. r0 = LowBits(w - cs2, 2*gamma2)
      final cs2 = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        cs2[i] = cHat.pointwiseMul(s2Hat[i]);
        DilithiumNTT.invNtt(cs2[i]);
      }

      final r0 = DilithiumPolyVec.zero(params.k);
      bool rejectR0 = false;

      for (int i = 0; i < params.k; i++) {
        final diff = wHat[i] - cs2[i];

        for (int j = 0; j < 256; j++) {
          final (_, r0Val) = decompose(diff.coeffs[j], alpha);
          r0[i].coeffs[j] = r0Val;
        }

        if (_checkNorm(r0[i], params.gamma2 - params.beta)) {
          rejectR0 = true;
          break;
        }
      }
      if (rejectR0) {
        kappa += params.l;
        continue;
      }

      // 11. Check ||ct0|| >= gamma2
      final ct0 = DilithiumPolyVec.zero(params.k);
      bool rejectCT0 = false;
      for (int i = 0; i < params.k; i++) {
        ct0[i] = cHat.pointwiseMul(t0Hat[i]);
        DilithiumNTT.invNtt(ct0[i]);

        if (_checkNorm(ct0[i], params.gamma2)) {
          rejectCT0 = true;
          break;
        }
      }
      if (rejectCT0) {
        kappa += params.l;
        continue;
      }

      // 12. h = MakeHint(-ct0, w - cs2 + ct0, 2*gamma2)
      final hCand = DilithiumPolyVec.zero(params.k);
      int hintCount = 0;

      for (int i = 0; i < params.k; i++) {
        final diff = wHat[i] - cs2[i];
        final val = diff + ct0[i];

        for (int j = 0; j < 256; j++) {
          int zVal = -ct0[i].coeffs[j];
          int rVal = val.coeffs[j];

          int hBit = makeHint(zVal, rVal, alpha);
          hCand[i].coeffs[j] = hBit;
          if (hBit != 0) hintCount++;
        }
      }

      // Check weight
      if (hintCount > params.omega) {
        kappa += params.l;
        continue;
      }

      // Success
      for (int i = 0; i < params.l; i++) {
        zCand[i].reduce(); // Normalize z to [0, q-1]
      }
      z = zCand;
      h = hCand;

      cTilde = cSeed;
      break;
    }

    // Pack Sig
    return packSig(cTilde, z, h, params.gamma1, params.omega);
  }

  static bool _checkNorm(DilithiumPoly p, int bound) {
    for (int i = 0; i < 256; i++) {
      int t = p.coeffs[i];
      if (t > (q >> 1)) t -= q;
      if (t.abs() >= bound) return true;
    }
    return false;
  }

  /// Verify signature
  static bool verify(
    Uint8List pk,
    Uint8List m,
    Uint8List sig,
    DilithiumParams params,
  ) {
    // 1. Unpack PK -> rho, t1
    final (rho, t1) = unpackPK(pk, params.k);

    // 2. Unpack Sig -> c_tilde, z, h
    late final Uint8List cTilde;
    late final DilithiumPolyVec z;
    late final DilithiumPolyVec h;
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

    // 3. Check ||z|| < gamma1 - beta
    for (int i = 0; i < params.l; i++) {
      if (_checkNorm(z[i], params.gamma1 - params.beta)) {
        return false;
      }
    }

    // 4. tr = CRH(pk)
    final tr = DilithiumSymmetric.crh(pk);

    // 5. mu = CRH(tr || M)
    final muInput = Uint8List(tr.length + m.length);
    muInput.setRange(0, tr.length, tr);
    muInput.setRange(tr.length, tr.length + m.length, m);
    final mu = DilithiumSymmetric.crh(muInput);

    // 6. c = SampleInBall(c_tilde)
    final c = DilithiumSymmetric.sampleInBall(cTilde, params.tau);

    // 7. A = ExpandA(rho)
    final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

    // 8. w_approx = A * z - c * t1 * 2^d
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

      // Mult by 2^d (d=13)
      for (int x = 0; x < 256; x++) {
        prod.coeffs[x] = (prod.coeffs[x] << d) % q;
      }
      ct1[i] = prod;
    }

    // wApprox = az - ct1
    final wApprox = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      DilithiumNTT.invNtt(az[i]);
      wApprox[i] = az[i] - ct1[i];
    }

    // Normalize wApprox coefficients to [0, q-1]
    for (int i = 0; i < params.k; i++) {
      wApprox[i].reduce();
    }

    // 9. w1' = UseHint(h, wApprox, 2*gamma2)
    final w1Prime = DilithiumPolyVec.zero(params.k);
    final alpha = 2 * params.gamma2;

    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < 256; j++) {
        w1Prime[i].coeffs[j] = useHint(
          h[i].coeffs[j],
          wApprox[i].coeffs[j],
          alpha,
        );
      }
    }

    // 10. c_tilde' = CRH(mu || w1')
    int w1Bits = (params.gamma2 == 95232) ? 6 : 4;
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

    // Compare c_tilde == c_tilde'
    if (cTilde.length != cTildePrime.length) {
      return false;
    }

    for (int i = 0; i < params.cTildeSize; i++) {
      if (cTilde[i] != cTildePrime[i]) {
        return false;
      }
    }

    return true; // Verification Pass
  }
}
