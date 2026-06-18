import 'dart:io';

String? resolveLibcryptoPath() {
  final override = Platform.environment['LIBCRYPTO_PATH'];
  if (override != null && override.isNotEmpty) {
    return File(override).existsSync() ? override : null;
  }

  for (final candidate in libcryptoProbePaths()) {
    if (File(candidate).existsSync()) return candidate;
  }
  return null;
}

List<String> libcryptoProbePaths() => <String>[
  if (Platform.isMacOS) ...[
    '/opt/homebrew/opt/openssl@4/lib/libcrypto.dylib',
    '/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib',
    '/opt/homebrew/opt/openssl@3.5/lib/libcrypto.dylib',
    '/opt/homebrew/opt/openssl/lib/libcrypto.dylib',
    '/usr/local/opt/openssl@4/lib/libcrypto.dylib',
    '/usr/local/opt/openssl@3.6/lib/libcrypto.dylib',
    '/usr/local/opt/openssl@3.5/lib/libcrypto.dylib',
    '/usr/local/opt/openssl/lib/libcrypto.dylib',
  ],
  if (Platform.isLinux) ...[
    '/usr/local/lib64/libcrypto.so',
    '/usr/local/lib/libcrypto.so',
  ],
];
