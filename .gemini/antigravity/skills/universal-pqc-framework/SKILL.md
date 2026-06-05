---
name: universal-pqc-framework
description: Project-level PQC multi-agent framework wrapper for Antigravity. Uses the canonical pqcrypto evidence-scoped manifest and docs for Cryptographic Architect, SecOps, Distinguished Engineer, and Client Integration workflows.
---

# Universal PQC Framework - Antigravity Wrapper

This wrapper is native to the project Antigravity setup. It is intentionally
thin.

Before answering or implementing:

1. Read `doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md`.
2. Read `tool/agent_framework/pqc_framework.yaml`.
3. Identify the requested role:
   - Cryptographic Architect
   - SecOps & Infrastructure Engineer
   - Distinguished Engineer
   - Client Integration Engineer
4. Keep all claims within the manifest evidence boundary.
5. If the user asks for Serverpod, Flutter, Vault, CloudHSM, KMS, HKDF library,
   or other framework/library implementation details, fetch current docs before
   coding or giving API-specific guidance.

Never claim CMVP/FIPS 140 validation. Never state hard constant-time or hard
memory-erasure guarantees for Dart. Treat Serverpod/Flutter material in this
repo as a contract sketch until a tested vertical slice exists.
