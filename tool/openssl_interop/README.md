# OpenSSL interoperability

This unpublished tool package cross-checks `pqcrypto` against OpenSSL 3.5+:

- ML-KEM-512/768/1024, including bidirectional exchanges, seeded key
  equivalence, raw public-key round trips, and implicit rejection;
- ML-DSA-44/65/87 seeded key and hedged pure-signature byte equivalence;
- all 12 SLH-DSA parameter sets, including seeded keys and byte-exact internal
  and external signatures.

The package is outside `pqcrypto`'s publish surface:

```bash
cd tool/openssl_interop
dart pub get
bash tool/build_openssl.sh
LIBCRYPTO_PATH=.native/openssl-4.0.1/lib/libcrypto.so \
  dart test --concurrency=1
dart run bin/openssl_pqcrypto_interop.dart
```

The build script pins OpenSSL 4.0.1 and verifies the official source archive
digest before compilation. The shared library must expose OpenSSL's
standardized PQC algorithms. Interop is independent implementation evidence,
not a CMVP or FIPS 140 validation claim.
