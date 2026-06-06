# Universal Multi-Agent PQC Framework

`pqcrypto` provides a canonical, machine-readable framework for collaborating with agentic LLMs (like Antigravity, Claude Code, and Codex) to build secure cryptographic integrations.

Because cryptography is notoriously difficult for LLMs to implement correctly without strict guardrails, we enforce a highly structured **Coordinate System** that bounds AI agents to evidence-backed claims and rigid byte contracts.

## 🤖 Native Agent Wrappers

Our framework natively integrates into popular agent environments via skills/wrappers. These wrappers exist in the repository root and act as strict launch pads:

- `.codex/skills/universal-pqc-framework/SKILL.md`
- `.claude/skills/universal-pqc-framework/SKILL.md`
- `.gemini/antigravity/skills/universal-pqc-framework/SKILL.md`

## 👔 The 4-Role Coordinate System

When instructing an agent to build a `pqcrypto` integration, you must explicitly assign it one of four distinct roles. Each role handles a specific layer of the security architecture:

1. **Cryptographic Architect:** Defines the primitive choices, exact byte lengths, transcript binding parameters, and HKDF inputs.
2. **SecOps & Infrastructure Engineer:** Designs KMS/HSM key loading, scheduled rotations (e.g., 14-day lifecycles), and emergency break-glass eviction logic.
3. **Distinguished Engineer:** Builds the backend (e.g., Serverpod) endpoints, implements strict length filtering, nonce replay rejection, and handles atomic pointer swaps for active key bundles.
4. **Client Integration Engineer:** Implements the frontend (e.g., Flutter) flow, offloading heavy cryptography to isolates (`compute()`), local session storage, and re-handshake triggers.

## 🛡️ Strict Claim Boundaries

The framework explicitly forbids agents from generating false compliance claims. Agents are strictly bound to the following wording limits:

- **ALLOWED:** *"FIPS 203-aligned ML-KEM implementation with checked-in KAT evidence."*
- **FORBIDDEN:** *"FIPS validated"*, *"CMVP certified"*, *"Constant-time Dart execution"*.

## 💬 Prompting Examples

To utilize the framework, instruct your agent using prompts like these:

**For the Backend (Distinguished Engineer):**
> *Use the universal-pqc-framework skill. Act as the Distinguished Engineer. Turn the manifest byte contracts into Serverpod `.spy.yaml` models, endpoint guards, replay rejection, and key-bundle hot-swap rules.*

**For the Frontend (Client Integration Engineer):**
> *Use the universal-pqc-framework skill. Act as the Client Integration Engineer. Build the Flutter handshake service around generated Serverpod client methods, offloading ML-KEM encapsulation and ML-DSA signing with compute().*

For the full machine-readable manifest, see `tool/agent_framework/pqc_framework.yaml` in the repository.
