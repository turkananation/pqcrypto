# FIPS 202 example corpus

Checked-in normalization of the official NIST FIPS 202 example values.
The original PDFs are not stored in this repository. Each record carries the
source URL and the SHA-256 of the PDF bytes retrieved on 2026-11-25. Those
hashes are listed again in `manifest.json`.

Source page:
<https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>

| File | What it contains |
| --- | --- |
| `all_examples.json` | SHA3-224/256/384/512 and SHAKE128/256 for message lengths 0, 5, 30, 1600, 1605, and 1630 bits. Message bits are in NIST absorption order. |
| `shake_truncation.json` | SHAKE128 of the empty message at output lengths 4088 through 4096 bits. Lengths that are not a multiple of 8 use the FIPS 202 hex form: unused high bits of the final byte are zero. |
| `byte_aligned_vectors.json` | The earlier empty-message and 1600-bit subset. SHAKE records there keep the first 64 output bytes. |
| `manifest.json` | PDF file name, URL, and SHA-256. The `normalized` array is the SHA-256 of `all_examples.json`, `shake_truncation.json`, and `byte_aligned_vectors.json`. |

`test/fips202_examples_test.dart` is the discovered runner for all 36 message
examples and the SHAKE128 truncation samples. It reads the JSON text embedded
in `test/fips202_corpus.dart`, generated from these files, so the same vectors
run on the VM, Chrome, and dart2wasm. Byte-aligned messages are also checked
against the public byte API. Messages whose length is not a multiple of 8 are
checked with `fips202AbsorbBits` and the test-only `BitString` helper. Neither
is exported from `package:pqcrypto/pqcrypto.dart`.

Regenerate the embed and the normalized SHA-256 records with:

```bash
dart run tool/fips202/generate_corpus_library.dart
```

The 1600-bit message is 200 repetitions of byte `0xa3`. NIST prints each byte
least-significant bit first, so the bit string begins `1 1 0 0 0 1 0 1`.
