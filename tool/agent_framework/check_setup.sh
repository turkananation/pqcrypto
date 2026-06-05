#!/usr/bin/env bash
set -euo pipefail

required_files=(
  "doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md"
  "tool/agent_framework/pqc_framework.yaml"
  ".codex/skills/universal-pqc-framework/SKILL.md"
  ".claude/skills/universal-pqc-framework/SKILL.md"
  ".gemini/antigravity/skills/universal-pqc-framework/SKILL.md"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "missing required framework file: ${file}" >&2
    exit 1
  fi
done

grep -q "ML-KEM-768" doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md
grep -q "ML-DSA-65" doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md
grep -q "no_cmvp_fips_140_claim: true" tool/agent_framework/pqc_framework.yaml
grep -q "universal-pqc-framework" .codex/skills/universal-pqc-framework/SKILL.md
grep -q "universal-pqc-framework" .claude/skills/universal-pqc-framework/SKILL.md
grep -q "universal-pqc-framework" .gemini/antigravity/skills/universal-pqc-framework/SKILL.md

echo "Universal PQC agent framework setup is present."
