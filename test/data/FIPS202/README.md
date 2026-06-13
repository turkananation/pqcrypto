# FIPS 202 byte-oriented examples

`byte_aligned_vectors.json` normalizes the official NIST FIPS 202 examples for
the empty message and the 1600-bit message for all six standardized functions.
The 1600-bit records use `messageHex: "a3"` with `messageRepeats: 200`; NIST
renders each byte least-significant bit first in the PDF bit-string display.

Source page:
<https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>

Retrieval date: 2026-06-13.

The JSON records each source PDF URL and its SHA-256 digest. SHAKE examples in
the PDFs contain 512 output bytes; this focused corpus records and tests the
first 64 bytes, which crosses neither function's squeeze rate. Multi-block
squeeze behavior is tested independently in `test/keccak_test.dart`.

Non-byte-aligned examples (`Msg5`, `Msg30`, `1605`, and `1630`) remain outside
the byte-oriented API boundary and are not represented here.
