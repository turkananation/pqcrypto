# Shared interoperability support

This unpublished package is the provider-neutral layer shared by
`tool/openssl_interop/` and `tool/liboqs_interop/`.

It owns only:

- the ML-KEM, ML-DSA, and SLH-DSA parameter-set inventory;
- standardized size and seed metadata used by both providers;
- small byte helpers used by interoperability tests.

Provider-specific FFI bindings, native library discovery, build scripts, and
test semantics remain in their provider projects. This keeps the two native
adapters independent without duplicating the algorithm matrix.

The package is outside the root package publish surface and has
`publish_to: none`.
