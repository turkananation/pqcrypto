# AI Development Workflows for pqcrypto

This document provides structured workflows for AI models to contribute to the pqcrypto project. Each phase includes detailed prompts, tool usage instructions, and common pitfalls. Follow these step-by-step to ensure high-quality contributions.

## Exploration Phase

### Objective

Understand project structure, current implementation status, and identify areas for contribution.

### Detailed Prompt for AI

```text
You are exploring the pqcrypto Dart post-quantum cryptography library. Your task is to:

1. Analyze the overall architecture from docs/ARCHITECTURE.md
2. Review current implementation status from docs/PROGRESS_TRACKER.md and docs/ROADMAP.md
3. Examine test coverage and identify gaps
4. Understand security audit findings from docs/SECURITY_AUDIT.md
5. Map out the codebase structure in lib/src/
6. Identify which algorithms are production-ready vs in-development

Provide a structured summary with:
- Current project status (ML-KEM ready, ML-DSA near-ready)
- Key files to modify for common tasks
- Testing patterns and conventions
- Security requirements and known issues
- Performance bottlenecks and optimization opportunities

Focus on actionable insights for implementation work.
```

### Tool Usage Instructions

- Use `list_dir` to explore directory structures
- Use `read_file` to examine key files (start with README.md, then docs/INDEX.md)
- Use `grep_search` to find specific functions or patterns (e.g., "class.*Params")
- Use `semantic_search` for "post-quantum cryptography implementation patterns"
- Run `dart analyze` to check for lint issues
- Run `dart test` to see current test status and failures

### Common Pitfalls

- Assuming ML-DSA is production-ready (it's not - awaiting KAT validation)
- Modifying polynomial arithmetic without understanding the different rings (Kyber q=3329 incomplete NTT vs Dilithium q=8380417 complete NTT)
- Forgetting to update both Kyber and Dilithium implementations for symmetric changes
- Not implementing secret zeroization in finally blocks
- Using early returns in validation functions (creates timing channels)

## Implementation Phase

### Objective

Add new features, fix bugs, or optimize existing code following project conventions.

### Detailed Prompt for AI

```text
You are implementing changes to pqcrypto. Follow these guidelines:

1. Understand the change requirements and scope
2. Review relevant documentation (docs/ENGINEERING_GUIDE.md for math reference)
3. Examine existing similar implementations for patterns
4. Implement the change using project conventions:
   - Static methods for crypto operations
   - Pure modular arithmetic (no Montgomery)
   - Proper parameter objects
   - Domain separation for hashes
   - Constant-time operations where security-critical

5. Add comprehensive tests following existing patterns:
   - Round-trip serialization tests
   - Negative test cases
   - Integration tests
   - Size validation

6. Update documentation if public APIs change
7. Ensure security requirements are met (zeroization, constant-time)

For [specific task: e.g., adding new algorithm / fixing security issue / optimizing performance]:

Provide implementation with:
- Code changes with explanations
- Test additions
- Performance impact analysis
- Security validation steps
```

### Tool Usage Instructions

- Use `read_file` to study existing implementations (e.g., read kyber/kem.dart for API patterns)
- Use `grep_search` to find usage examples (e.g., "generateKeyPair")
- Use `vscode_listCodeUsages` to understand function dependencies
- Run `dart test [specific_test_file]` to validate changes
- Run `dart analyze` after changes to catch lint issues
- Use `run_in_terminal` for `dart run example/main.dart` to benchmark performance
- Use `get_errors` to check for compilation issues

### Common Pitfalls

- Implementing features for one algorithm without considering the other (ML-KEM vs ML-DSA)
- Not handling all parameter sets (3 security levels each)
- Forgetting to update serialization for new fields
- Breaking existing tests due to API changes
- Not validating against FIPS specifications
- Performance optimizations that compromise security (e.g., early exits)

## Testing Phase

### Objective

Ensure code changes are thoroughly tested and maintain existing functionality.

### Detailed Prompt for AI

```text
You are writing or updating tests for pqcrypto changes. Requirements:

1. Understand what needs testing (new feature, bug fix, regression)
2. Review existing test patterns in test/ directory
3. Implement appropriate test types:
   - Unit tests for individual functions
   - Round-trip tests for serialization
   - Negative tests for error conditions
   - Integration tests for full workflows
   - Performance regression tests

4. Use deterministic seeding for reproducible results
5. Test all parameter sets and security levels
6. Include size validation for all outputs
7. For crypto functions, test against known test vectors when available

For [specific test task]:

Provide:
- Test code with clear test names
- Expected vs actual behavior descriptions
- Edge cases covered
- Test vector sources (NIST KAT files)
```

### Tool Usage Instructions

- Use `read_file` to examine existing tests (e.g., test/dsa_sign_test.dart)
- Use `grep_search` for "test.*function" to find test patterns
- Run `dart test --coverage` to check coverage (if available)
- Run `dart test test/kat_evaluator.dart` for NIST compliance testing
- Use `run_in_terminal` for `dart test --reporter=json` to get detailed results
- Use `get_errors` on test files to check for issues

### Common Pitfalls

- Tests that pass locally but fail in CI due to randomness
- Not testing all parameter combinations
- Missing negative test cases (invalid inputs)
- Tests that don't validate output sizes
- Crypto tests without proper test vectors
- Performance tests without baseline measurements

## Documentation Phase

### Objective

Keep documentation accurate and comprehensive for contributors and users.

### Detailed Prompt for AI

```text
You are updating documentation for pqcrypto changes. Tasks:

1. Identify what documentation needs updating:
   - README.md for new features or API changes
   - docs/ files for architectural changes
   - Code comments for implementation details
   - CHANGELOG.md for version updates

2. Follow documentation conventions:
   - Clear, concise language
   - Code examples where helpful
   - Cross-references between docs
   - Security considerations highlighted

3. Update relevant sections:
   - Architecture diagrams if structure changes
   - Performance benchmarks if optimizations added
   - Security audit if issues addressed
   - Roadmap if priorities shift

For [specific documentation task]:

Provide:
- Updated content with change explanations
- New sections or files if needed
- Links to related documentation
- Validation that docs remain accurate
```

### Tool Usage Instructions

- Use `read_file` to review current documentation (start with docs/INDEX.md)
- Use `grep_search` for "TODO|FIXME|NOTE" to find documentation gaps
- Use `semantic_search` for "documentation patterns in crypto libraries"
- Run `dart doc` if generating API docs (check pubspec.yaml)
- Use `run_in_terminal` for `markdown-link-check` if available

### Common Pitfalls

- Documentation becoming outdated after code changes
- Not updating cross-references when files move
- Missing security warnings for new features
- Inconsistent terminology across docs
- Not including performance impact in change descriptions

## Security Auditing Phase

### Objective

Review code changes for security vulnerabilities and compliance issues.

### Detailed Prompt for AI

```text
You are performing a security audit on pqcrypto changes. Focus areas:

1. Cryptographic correctness:
   - Algorithm implementation matches FIPS specifications
   - No deviations from standards
   - Proper domain separation

2. Side-channel vulnerabilities:
   - Constant-time operations (no early returns on validation)
   - No timing leaks in comparisons
   - Proper secret zeroization

3. Memory safety:
   - No uninitialized memory usage
   - Proper bounds checking
   - Secret data cleared in finally blocks

4. Implementation security:
   - RNG usage is cryptographically secure
   - No hardcoded secrets or weak defaults
   - Proper error handling doesn't leak information

For [specific security audit task]:

Provide:
- Vulnerability assessment (severity: Critical/High/Medium/Low)
- Specific code locations with issues
- Recommended fixes with code examples
- Compliance validation steps
- References to relevant standards
```

### Tool Usage Instructions

- Use `read_file` to examine security-critical functions
- Use `grep_search` for "secret|key|random" to find sensitive operations
- Use `vscode_listCodeUsages` to trace data flow
- Run `dart test test/quick_wins_test.dart` for known security regression tests
- Use `run_in_terminal` for static analysis tools if available
- Review docs/SECURITY_AUDIT.md for known patterns

### Common Pitfalls

- Assuming existing code is secure (check for unresolved issues)
- Not auditing all code paths (including error handling)
- Missing side-channel analysis for new crypto operations
- Not validating against NIST test vectors
- Overlooking memory management in Dart (GC handles most, but zeroization needed)
- Forgetting to audit dependencies (pointycastle security)

## General Guidelines for All Phases

- Always run `dart analyze` and `dart test` before and after changes
- Follow the project's modular arithmetic approach (no Montgomery reduction)
- Use parameter objects consistently
- Implement security features (zeroization, constant-time) proactively
- Test against all security levels (3 for each algorithm)
- Update CHANGELOG.md for user-facing changes
- Reference FIPS documents for algorithm details
- Consult docs/ENGINEERING_GUIDE.md for mathematical background
