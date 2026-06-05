# Universal PQC Agent Framework Setup

This directory contains the project-level machine-readable setup for the
Universal Multi-Agent PQC Framework.

Canonical files:

- `doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md`
- `tool/agent_framework/pqc_framework.yaml`
- `.codex/skills/universal-pqc-framework/SKILL.md`
- `.claude/skills/universal-pqc-framework/SKILL.md`
- `.gemini/antigravity/skills/universal-pqc-framework/SKILL.md`

Run the setup check before committing framework changes:

```bash
bash tool/agent_framework/check_setup.sh
```

This setup is intentionally documentation and manifest only. It does not install
global user-level skills and does not implement a Serverpod/Flutter runtime.
