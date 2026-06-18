@TestOn('vm')
library;

import 'package:liboqs_pqcrypto_interop/liboqs.dart';
import 'package:test/test.dart';

void main() {
  final path = resolveLiboqsPath();
  if (path == null) {
    test(
      'liboqs minimal build profile',
      () {},
      skip:
          'No liboqs shared library found. Set LIBOQS_PATH. '
          'Probed: ${liboqsProbePaths().join(", ")}',
    );
    return;
  }

  final liboqs = LiboqsInterop.load(path);
  tearDownAll(liboqs.dispose);

  test('excludes unrelated signature families', () {
    expect(liboqs.isSignatureEnabled('Falcon-512'), isFalse);
  });
}
