import 'dart:io';

const _requiredFiles = [
  'doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md',
  'tool/agent_framework/pqc_framework.yaml',
  '.codex/skills/universal-pqc-framework/SKILL.md',
  '.claude/skills/universal-pqc-framework/SKILL.md',
  '.gemini/antigravity/skills/universal-pqc-framework/SKILL.md',
];

const _requiredMarkers = {
  'doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md': ['ML-KEM-768', 'ML-DSA-65'],
  'tool/agent_framework/pqc_framework.yaml': ['no_cmvp_fips_140_claim: true'],
  '.codex/skills/universal-pqc-framework/SKILL.md': ['universal-pqc-framework'],
  '.claude/skills/universal-pqc-framework/SKILL.md': [
    'universal-pqc-framework',
  ],
  '.gemini/antigravity/skills/universal-pqc-framework/SKILL.md': [
    'universal-pqc-framework',
  ],
};

void main() {
  final root =
      _findRepositoryRoot() ??
      _fail(
        'could not find the pqcrypto repository root; run this from the repo or '
        'a child directory',
      );

  for (final path in _requiredFiles) {
    final file = File('${root.path}/$path');
    if (!file.existsSync()) {
      _fail('missing required framework file: $path');
    }
  }

  for (final entry in _requiredMarkers.entries) {
    final file = File('${root.path}/${entry.key}');
    final contents = file.readAsStringSync();
    for (final marker in entry.value) {
      if (!contents.contains(marker)) {
        _fail('missing marker "$marker" in ${entry.key}');
      }
    }
  }

  stdout.writeln('Universal PQC agent framework setup is present.');
}

Directory? _findRepositoryRoot() {
  var directory = Directory.current.absolute;

  while (true) {
    final pubspec = File('${directory.path}/pubspec.yaml');
    final manifest = File(
      '${directory.path}/tool/agent_framework/pqc_framework.yaml',
    );

    if (pubspec.existsSync() && manifest.existsSync()) {
      return directory;
    }

    final parent = directory.parent;
    if (parent.path == directory.path) {
      return null;
    }
    directory = parent;
  }
}

Never _fail(String message) {
  stderr.writeln(message);
  exit(1);
}
