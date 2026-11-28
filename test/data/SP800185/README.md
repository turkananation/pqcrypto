# SP 800-185 example corpus

Checked-in normalization of the official NIST SP 800-185 example values for
cSHAKE, KMAC, KMACXOF, TupleHash, TupleHashXOF, ParallelHash, and
ParallelHashXOF. The original PDFs are not stored in this repository. Each
sample carries the source URL and the SHA-256 of the PDF bytes retrieved on
2026-11-25. Those hashes are listed again in `manifest.json`. The same
manifest records the SHA-256 of `examples.json` under `normalized`.

Source page:
<https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>

The standard PDF SHA-256 recorded in the manifest is
`0ebcdfb5b145bcb6a8a0f49737a201e8fb30dce06951595a07010774d402d7c5`
for <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf>.

`examples.json` keeps the sample inputs, the printed encoding fields
(`encode_string`, `bytepad`, `left_encode`, and `right_encode`), and the
final output. `test/sp800_185_encoding_corpus_test.dart` checks the encoding
fields. `test/sp800_185_cshake_test.dart` and `test/sp800_185_kmac_test.dart`
match the cSHAKE and KMAC outputs. TupleHash and ParallelHash are not
executed here.
