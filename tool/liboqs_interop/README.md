# liboqs interoperability

This unpublished tool package cross-checks `pqcrypto` against liboqs:

- ML-KEM-512/768/1024 encapsulation and decapsulation in both directions;
- ML-DSA-44/65/87 pure signatures with context strings in both directions;
- all 12 pure SLH-DSA parameter sets with context strings in both directions.

The package is outside `pqcrypto`'s publish surface. The checked-in build
script pins liboqs 0.15.0 to an exact commit and builds only the 18 algorithms
under test: 3 ML-KEM, 3 ML-DSA, and 12 pure SLH-DSA variants. It also disables
liboqs's OpenSSL acceleration so this provider remains an independent native
implementation:

```bash
cd tool/liboqs_interop
dart pub get
bash tool/build_liboqs.sh
LIBOQS_PATH=.native/liboqs-0.15.0/lib/liboqs.so \
  dart test --concurrency=1
```

Interop is independent cross-implementation evidence. It is not a CMVP or
FIPS 140 validation claim.
