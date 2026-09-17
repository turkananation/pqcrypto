@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('Cookbook markdown declared by dartdoc_options.yaml exists on disk', () {
    final options = File('dartdoc_options.yaml').readAsStringSync();
    expect(options, contains('markdown: doc/cookbook/README.md'));
    expect(
      File('doc/cookbook/README.md').existsSync(),
      isTrue,
      reason:
          '0.4.1 omitted this file from the pub.dev tarball and `dart doc` '
          'crashed (https://github.com/turkananation/pqcrypto/issues/60).',
    );
  });
}
