import 'dart:typed_data';
import '../../common/shake.dart';
import '../../common/poly.dart' show Poly;
import 'poly.dart';
import 'symmetric.dart';
import 'params.dart';
import 'ntt.dart';
import 'rounding.dart';
import 'packing.dart';

class MlDsa {
  static String _toHex(Uint8List b) =>
      b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

  /// Generate Key Pair (pk, sk) for the given parameters.
  /// [seed] is optional 32-byte seed. If null, random seed is used?
  /// (User should provide random seed)
  static (Uint8List, Uint8List) generateKeyPair(
    DilithiumParams params,
    Uint8List seed, // 32 bytes
  ) {
    if (seed.length != 32) throw ArgumentError("Seed must be 32 bytes");
    // Helper for debug
    // String toHex(Uint8List b) =>
    //     b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

    // 1. Expand seed into rho (32), rho' (64), K (32)
    // FIPS 204: H(xi) -> rho || rho' || K.
    // H is SHAKE-256 with 32+64+32 = 128 bytes output? No.
    // Spec says:
    // rho <- H(seed)[0:32] ??
    // Actually Alg 5:
    // (rho, rho', K) <- H(seed, 128)??
    // Standard implementation: Shake256(seed, 128) -> rho, rho', K.

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
    // We need copies for packing later (s1, s2 Normal Domain)
    // Actually, creating copies is safer as NTT is in-place in our impl.
    final s1Hat = DilithiumPolyVec.zero(params.l);
    for (int i = 0; i < params.l; i++) {
      // Deep copy coeffs
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
      // Matrix vector mul row i
      for (int j = 0; j < params.l; j++) {
        final prod = aHat[i][j].pointwiseMul(s1Hat[j]);
        tHat[i] = tHat[i] + prod; // Operator + is defined
      }
      // Add s2_hat
      tHat[i] = tHat[i] + s2Hat[i];
    }

    // 6. t = InvNTT(t_hat)
    // 7. t1, t0 = Power2Round(t, d=13)
    final t1 = DilithiumPolyVec.zero(params.k);
    final t0 = DilithiumPolyVec.zero(params.k);

    for (int i = 0; i < params.k; i++) {
      DilithiumNTT.invNtt(tHat[i]); // In-place to normal
      // tHat[i] is now 't'

      // Power2Round per coefficient
      final polyT1 = DilithiumPoly.zero();
      final polyT0 = DilithiumPoly.zero();

      for (int c = 0; c < 256; c++) {
        final (r1, r0) = power2Round(tHat[i].coeffs[c]);
        polyT1.coeffs[c] = r1; // t1
        polyT0.coeffs[c] = r0; // t0
      }
      t1[i] = polyT1;
      t0[i] = polyT0;
    }

    // 8. pk = Pack(rho, t1)

    // Debug hashes
    // Update hashVec to use v.length
    Uint8List hashVec(DilithiumPolyVec v) {
      int len = v.components.length;
      final flat = Uint8List(len * 256 * 4);
      final view = ByteData.view(flat.buffer);
      int off = 0;
      for (int i = 0; i < len; i++) {
        for (int j = 0; j < 256; j++) {
          view.setInt32(off, v[i].coeffs[j], Endian.little);
          off += 4;
        }
      }
      return DilithiumSymmetric.crh(flat);
    }

    print("KeyGen: t1 Hash: ${_toHex(hashVec(t1)).substring(0, 20)}...");

    final pk = packPK(rho, t1);

    // 9. tr = CRH(pk)
    final tr = Shake256.shake(pk, 64);

    // 10. sk = Pack(rho, K, tr, s1, s2, t0) -> Use NORMAL s1, s2
    final sk = packSK(rho, kKey, tr, s1, s2, t0, params.eta);

    return (pk, sk);
  }

  /// Sign message M using secret key sk.
  static Uint8List sign(
    Uint8List sk,
    Uint8List m,
    DilithiumParams params, {
    bool deterministic =
        false, // For KATs? FIPS 204 uses random 'rho_prime' derived from SK?
    // FIPS 204 Alg 6:
    // (rho, K, tr, s1, s2, t0) <- Unpack(sk)
    // mu <- CRH(tr || M)
    // kappa <- 0, (z,h) <- null
    // rho' <- CRH(K || mu)
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

    // 3. rho' = CRH(K || mu) (Randomizer for y)
    final rhoPrimeInput = Uint8List(kKey.length + mu.length);
    rhoPrimeInput.setRange(0, kKey.length, kKey);
    rhoPrimeInput.setRange(kKey.length, kKey.length + mu.length, mu);
    // CRH is 64 bytes.
    final rhoPrime = DilithiumSymmetric.crh(rhoPrimeInput); // 64 bytes

    // Expand Matrix A
    final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

    // Pre-computation: NTT(s1), NTT(s2), NTT(t0)
    // s1, s2 are in normal domain from Unpack.

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

      // 5. w = A * y
      // y is Normal. Matrix calc needs NTT(y).
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
      // Encode w1: SimpleBitPack.
      // Bits? if gamma2 == 95232 (ML-DSA-44) -> 6 bits. Else 4 bits.
      // 44 has gamma2=95232.
      // 65/87 has gamma2=261888.
      int w1Bits = (params.gamma2 == 95232) ? 6 : 4;

      // Pack w1
      // w1 is vector of k polys.
      final w1Packed = Uint8List(params.k * 32 * w1Bits);
      int w1Off = 0;
      for (int i = 0; i < params.k; i++) {
        final packed = simpleBitPack(w1[i], w1Bits);
        w1Packed.setRange(w1Off, w1Off + packed.length, packed);
        w1Off += packed.length;
      }

      print("Sign Loop:");
      print("  mu: ${_toHex(mu).substring(0, 20)}...");
      print(
        "  w1Packed Hash: ${_toHex(DilithiumSymmetric.crh(w1Packed)).substring(0, 20)}...",
      );
      print("  w1Packed Len: ${w1Packed.length}");

      final cInput = Uint8List(mu.length + w1Packed.length);
      cInput.setRange(0, mu.length, mu);
      cInput.setRange(mu.length, cInput.length, w1Packed);
      cTilde = DilithiumSymmetric.crh(
        cInput,
        params.cTildeSize,
      ); // Dynamic size
      print("  cTilde: ${_toHex(cTilde)}");

      // SampleInBall takes cTilde (full size in 65/87, 32 bytes in 44).
      // FIPS 204 Alg 9 takes rho (which is c_tilde).
      // If cTildeSize > 32, we pass full buffer.
      // DilithiumSymmetric.sampleInBall implements Shake256(rho). Matches.
      final cSeed = cTilde; // Pass full cTilde

      // 8. c = SampleInBall(c_tilde)
      final c = DilithiumSymmetric.sampleInBall(cSeed, tau);

      // c is sparse poly in Normal domain.
      final cHat = DilithiumPoly.zero();
      cHat.coeffs.setAll(0, c.coeffs);
      DilithiumNTT.ntt(cHat);

      print("Sign Loop:");
      final cFlat = Uint8List(256 * 4);
      final cView = ByteData.view(cFlat.buffer);
      for (int j = 0; j < 256; j++)
        cView.setInt32(j * 4, c.coeffs[j], Endian.little);
      print(
        "  c Hash: ${_toHex(DilithiumSymmetric.crh(cFlat)).substring(0, 20)}...",
      );

      // 9. z = y + c * s1
      // c*s1 computed in NTT.
      // z computed in Normal?
      // FIPS 204: z = y + cs1.
      // y is Normal. s1 is Normal.
      // But s1 mult is expensive in Normal.
      // Better: z = y + InvNTT(cHat * s1Hat).

      final cs1 = DilithiumPolyVec.zero(params.l);
      for (int i = 0; i < params.l; i++) {
        cs1[i] = DilithiumPoly.zero(); // Accumulator
        // cHat * s1Hat[i]
        cs1[i] = cHat.pointwiseMul(s1Hat[i]);
        DilithiumNTT.invNtt(cs1[i]); // cs1 in Normal
      }

      final zCand = DilithiumPolyVec.zero(params.l);
      bool rejectZ = false;
      for (int i = 0; i < params.l; i++) {
        zCand[i] = y[i] + cs1[i];
        // Check ||z|| >= gamma1 - beta
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
      // Compute cs2
      final cs2 = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        cs2[i] = cHat.pointwiseMul(s2Hat[i]);
        DilithiumNTT.invNtt(cs2[i]);
      }

      final r0 = DilithiumPolyVec.zero(params.k);
      bool rejectR0 = false;

      for (int i = 0; i < params.k; i++) {
        // w - cs2
        // wHat[i] is defined above, wait. 'wHat' is w in Normal (impl detail: invNtt was called on it).
        // Yes, wHat[i] holds w in Normal domain.
        final diff = wHat[i] - cs2[i];

        // LowBits
        for (int j = 0; j < 256; j++) {
          final (_, r0Val) = decompose(diff.coeffs[j], alpha);
          r0[i].coeffs[j] = r0Val;
        }

        // Check ||r0|| >= gamma2 - beta
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
      // ct0 = c * t0
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
      // w - cs2 + ct0
      // Note: w - cs2 was 'diff'.
      final hCand = DilithiumPolyVec.zero(params.k);
      int hintCount = 0;

      for (int i = 0; i < params.k; i++) {
        final diff = wHat[i] - cs2[i];
        final val = diff + ct0[i];

        for (int j = 0; j < 256; j++) {
          // makeHint inputs: z, r, alpha.
          // FIPS 204: MakeHint(-ct0, w-cs2+ct0, 2*gamma2).
          // Logic: r = w-cs2+ct0. z = -ct0.
          // Spec says: MakeHint(z, r, alpha).
          // z here is NOT the signature z.
          // It uses 'ct0' logic.

          // Note: -ct0[i]
          int zVal = -ct0[i].coeffs[j];
          // Normalize zVal? decompose/makeHint handles int.

          int rVal = val.coeffs[j];

          int hBit = makeHint(zVal, rVal, alpha);
          hCand[i].coeffs[j] = hBit;
          if (hBit != 0) hintCount++;
        }
      }

      // DEBUG: Hash 'r' (which is 'val' here)
      // Reconstruct 'r' vector for hashing
      // The original rVec construction is replaced by the new debug block.
      print("Sign Loop Terms:");
      // DEBUG: Hash terms
      Uint8List hashVec(DilithiumPolyVec v) {
        final flat = Uint8List(params.k * 256 * 4);
        final view = ByteData.view(flat.buffer);
        int off = 0;
        for (int i = 0; i < params.k; i++) {
          for (int j = 0; j < 256; j++) {
            view.setInt32(off, v[i].coeffs[j], Endian.little);
            off += 4;
          }
        }
        return DilithiumSymmetric.crh(flat);
      }

      print("  wHat Hash: ${_toHex(hashVec(wHat)).substring(0, 20)}...");
      print("  cs2 Hash: ${_toHex(hashVec(cs2)).substring(0, 20)}...");
      print("  ct0 Hash: ${_toHex(hashVec(ct0)).substring(0, 20)}...");

      final rVec = DilithiumPolyVec.zero(params.k);
      for (int i = 0; i < params.k; i++) {
        rVec[i] = wHat[i] - cs2[i] + ct0[i];
        rVec[i].reduce(); // Normalize for hash comparison
      }
      print(
        "  r (w-cs2+ct0) Hash: ${_toHex(hashVec(rVec)).substring(0, 20)}...",
      );

      // Check weight
      if (hintCount > params.omega) {
        kappa += params.l;
        continue;
      }

      // Success
      for (int i = 0; i < params.l; i++)
        zCand[i].reduce(); // Normalize z to [0, q-1]
      z = zCand;
      h = hCand;
      print("Sign: z Hash: ${_toHex(hashVec(z)).substring(0, 20)}...");
      print("Sign: h Hash: ${_toHex(hashVec(h)).substring(0, 20)}...");

      // cTilde already set (use first 32 bytes for pack)
      cTilde = cSeed;
      break;
    }

    // Pack Sig
    return packSig(cTilde, z, h, params.gamma1, params.omega);
  }

  static bool _checkNorm(DilithiumPoly p, int bound) {
    for (int i = 0; i < 256; i++) {
      int t = p.coeffs[i];
      // Centered norm? No, coeffs in range.
      // FIPS 204 norm: |x mod+- q| >= bound?
      // Wait. z coeffs are integers.
      // check if abs(t) >= bound.
      // t might be negative if we use standard int arithmetic.
      // Our Poly arithmetic: _add, _sub use mod q.
      // So t is in [0, q-1].
      // We need centered norm.
      // if t > q/2: t = t - q.

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

    // DEBUG Verify t1 (Must define helper first or inline)
    // Inline check
    final t1Flat = Uint8List(params.k * 256 * 4);
    final t1View = ByteData.view(t1Flat.buffer);
    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < 256; j++) {
        t1View.setInt32((i * 256 + j) * 4, t1[i].coeffs[j], Endian.little);
      }
    }
    print(
      "Verify: t1 Hash: ${_toHex(DilithiumSymmetric.crh(t1Flat)).substring(0, 20)}...",
    );

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

      // DEBUG Helper Verify
      Uint8List hashVec(DilithiumPolyVec v) {
        final flat = Uint8List(params.k * 256 * 4);
        final view = ByteData.view(flat.buffer);
        int off = 0;
        // Wait, params.k? z is params.l.
        // We need generic size or pass it.
        // But params.k is for t1, wApprox. params.l for z.
        // Let's make it generic-ish or careful.
        // z has length params.l.
        // Quick fix: loop up to v.length
        int len = v.components.length;
        final flat2 = Uint8List(len * 256 * 4);
        final view2 = ByteData.view(flat2.buffer);
        int off2 = 0;
        for (int i = 0; i < len; i++) {
          for (int j = 0; j < 256; j++) {
            view2.setInt32(off2, v[i].coeffs[j], Endian.little);
            off2 += 4;
          }
        }
        return DilithiumSymmetric.crh(flat2);
      }

      print("Verify: z Hash: ${_toHex(hashVec(z)).substring(0, 20)}...");
      print("Verify: h Hash: ${_toHex(hashVec(h)).substring(0, 20)}...");
    } catch (e) {
      print("Verify: UnpackSig failed: $e");
      return false;
    }

    // 3. Check ||z|| < gamma1 - beta
    for (int i = 0; i < params.l; i++) {
      if (_checkNorm(z[i], params.gamma1 - params.beta)) {
        print("Verify: z norm check failed at $i");
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
    final c = DilithiumSymmetric.sampleInBall(cTilde, tau);

    // 7. A = ExpandA(rho)
    final aHat = DilithiumSymmetric.expandA(rho, params.k, params.l);

    // 8. w_approx = A * z - c * t1 * 2^d
    // Computation:
    // z is Normal. c is Normal. t1 is Normal?
    // unpackPK returns t1? Yes, t1 coeffs.
    // calculation needs NTT?
    // FIPS 204:
    // w' = UseHint(h, A*z - c*t1*2^d, 2*gamma2)
    // A*z computed in NTT. z needs NTT.
    // c*t1 computed in NTT.

    final zHat = DilithiumPolyVec.zero(params.l);
    for (int i = 0; i < params.l; i++) {
      zHat[i].coeffs.setAll(0, z[i].coeffs);
      DilithiumNTT.ntt(zHat[i]);
    }

    final t1Hat = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      t1Hat[i].coeffs.setAll(0, t1[i].coeffs);
      DilithiumNTT.ntt(t1Hat[i]); // t1 unpacked is poly t1.
    }

    final cHat = DilithiumPoly.zero();
    cHat.coeffs.setAll(0, c.coeffs);
    DilithiumNTT.ntt(cHat);

    final cFlat = Uint8List(256 * 4);
    final cView = ByteData.view(cFlat.buffer);
    for (int j = 0; j < 256; j++)
      cView.setInt32(j * 4, c.coeffs[j], Endian.little);
    print(
      "Verify: c Hash: ${_toHex(DilithiumSymmetric.crh(cFlat)).substring(0, 20)}...",
    );

    final az = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < params.l; j++) {
        az[i] = az[i] + aHat[i][j].pointwiseMul(zHat[j]);
      }
    }

    final ct1 = DilithiumPolyVec.zero(params.k);
    // c * t1 * 2^d
    // cHat * t1Hat
    // Shift logic in normal?
    // (c * t1) << d.
    // Do c*t1 in NTT -> InvNTT -> Shift.

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
    // az is in NTT. ct1 is Normal.
    // Convert az to Normal.
    final wApprox = DilithiumPolyVec.zero(params.k);
    for (int i = 0; i < params.k; i++) {
      DilithiumNTT.invNtt(az[i]);
      wApprox[i] = az[i] - ct1[i];
    }

    // wApprox = az - ct1
    // az converted to normal in loop above

    // Debug hashes
    Uint8List hashVec(DilithiumPolyVec v) {
      final flat = Uint8List(params.k * 256 * 4);
      final view = ByteData.view(flat.buffer);
      int off = 0;
      for (int i = 0; i < params.k; i++) {
        for (int j = 0; j < 256; j++) {
          view.setInt32(off, v[i].coeffs[j], Endian.little);
          off += 4;
        }
      }
      return DilithiumSymmetric.crh(flat);
    }

    // Note: az is now altered in place by invNtt. ct1 is normal.
    print(
      "Verify: az (Normal) Hash: ${_toHex(hashVec(az)).substring(0, 20)}...",
    );
    print("Verify: ct1 Hash: ${_toHex(hashVec(ct1)).substring(0, 20)}...");

    // Normalize wApprox for hash check
    for (int i = 0; i < params.k; i++) wApprox[i].reduce();
    print(
      "Verify: wApprox Hash: ${_toHex(hashVec(wApprox)).substring(0, 20)}...",
    );

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

    // 10. c_tilde' = CRH(mu || w1') (Pack w1')
    int w1Bits = (params.gamma2 == 95232) ? 6 : 4;
    final w1Packed = Uint8List(params.k * 32 * w1Bits);
    int w1Off = 0;
    for (int i = 0; i < params.k; i++) {
      final packed = simpleBitPack(w1Prime[i], w1Bits);
      w1Packed.setRange(w1Off, w1Off + packed.length, packed);
      w1Off += packed.length;
    }

    // String toHex(Uint8List b) =>
    //     b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
    print("Verify:");
    print("  mu: ${_toHex(mu).substring(0, 20)}...");
    print(
      "  w1Packed Hash: ${_toHex(DilithiumSymmetric.crh(w1Packed)).substring(0, 20)}...",
    );
    print("  w1Packed Len: ${w1Packed.length}");

    final cInput = Uint8List(mu.length + w1Packed.length);
    cInput.setRange(0, mu.length, mu);
    cInput.setRange(mu.length, cInput.length, w1Packed);
    final cTildePrime = DilithiumSymmetric.crh(cInput, params.cTildeSize);
    print("  cTildePrime: ${_toHex(cTildePrime)}");

    // Compare
    if (cTilde.length != cTildePrime.length) {
      print("Verify: cTilde length mismatch");
      return false;
    }

    for (int i = 0; i < params.cTildeSize; i++) {
      if (cTilde[i] != cTildePrime[i]) {
        print("Verify: cTilde mismatch at byte $i");
        // print("Sig cTilde: $cTilde");
        // print("Cal cTilde: $cTildePrime");
        return false;
      }
    }

    return true; // Verification Pass
  }
}
