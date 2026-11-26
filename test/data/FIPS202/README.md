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
| `byte_aligned_vectors.json` | The earlier empty-message and 1600-bit subset used by `test/fips202_examples_test.dart`. SHAKE records there keep the first 64 output bytes. |
| `manifest.json` | PDF file name, URL, and SHA-256 for every file above. |

`test/fips202_conformance_test.dart` runs all 36 message examples through the
bit-string sponge and checks every byte-aligned example against the public
byte API. The public byte API does not accept a message whose length is not
a multiple of 8. Those examples are covered by `fips202AbsorbBits`, which is
not exported from `package:pqcrypto/pqcrypto.dart`.

The 1600-bit message is 200 repetitions of byte `0xa3`. NIST prints each byte
least-significant bit first, so the bit string begins `1 1 0 0 0 1 0 1`.
