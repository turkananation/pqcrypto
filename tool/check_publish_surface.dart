/// Validates that the pub.dev archive contains the Cookbook markdown
/// `dartdoc_options.yaml` points at.
///
/// 0.4.1 shipped the yaml and omitted `doc/cookbook/README.md`, so `dart doc`
/// crashed while initializing categories
/// (https://github.com/turkananation/pqcrypto/issues/60). That also zeros
/// documentation points for dependents such as pqforge.
library;

import 'dart:convert';
import 'dart:io';

Future<void> main() async {
  final cookbook = File('doc/cookbook/README.md');
  if (!cookbook.existsSync()) {
    stderr.writeln('Missing doc/cookbook/README.md in the working tree.');
    exitCode = 1;
    return;
  }

  final process = await Process.start('dart', [
    'pub',
    'publish',
    '--dry-run',
    '--ignore-warnings',
  ]);
  final stdoutText = await utf8.decodeStream(process.stdout);
  final stderrText = await utf8.decodeStream(process.stderr);
  final code = await process.exitCode;
  final output = '$stdoutText$stderrText';

  if (code != 0) {
    stderr.write(output);
    exitCode = code;
    return;
  }

  final hasOptions = output.contains('dartdoc_options.yaml');
  final hasCookbookReadme = RegExp(
    r'cookbook\s*(?:\n.*)*?README\.md',
    multiLine: true,
  ).hasMatch(output);

  if (!hasOptions || !hasCookbookReadme) {
    stderr.writeln(
      'pub.dev archive is missing Cookbook/docs files '
      '(dartdoc_options.yaml=$hasOptions, '
      'doc/cookbook/README.md=$hasCookbookReadme).',
    );
    stderr.writeln(
      'dartdoc_options.yaml declares Cookbook → doc/cookbook/README.md; '
      'that file must ship in the tarball or `dart doc` crashes (issue #60).',
    );
    stderr.writeln();
    stderr.write(output);
    exitCode = 1;
    return;
  }

  stdout.writeln(
    'Pub archive includes dartdoc_options.yaml and doc/cookbook/README.md.',
  );
}
