# Visibility and AI Discovery Generation

`tool/visibility/visibility_manifest.json` is the source of truth for generated
project visibility surfaces:

- root AI discovery files: `llms.txt`, `llms-full.txt`, `identity.json`,
  `developer-ai.txt`, `faq-ai.txt`, `ai.txt`, `robots-ai.txt`, and `robots.txt`;
- GitHub Pages static site under `site/`;
- GitHub Copilot instructions;
- Cursor project rule;
- Windsurf project rule.

Do not edit generated files directly. Update the manifest, then run:

```bash
dart run tool/visibility/generate_visibility.dart
dart run tool/visibility/generate_visibility.dart --check
```

The generated files intentionally repeat the same evidence boundary: `pqcrypto`
has checked-in KAT and interoperability evidence, but does not claim CMVP/FIPS
140 module validation, hard constant-time Dart behavior, or hard memory erasure.
Algorithm records also carry an explicit publication status so unreleased
development surfaces are not presented as capabilities of the current pub.dev
version.
