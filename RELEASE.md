# Release Process Guide

This document outlines the standard operating procedure for releasing new versions and hotfixes for the `pqcrypto` package.

## 1. Release Preparation

Releases are typically prepared on the `develop` branch before being merged into `main`, or directly on `main` if following a fast-forward merge strategy.

### Update Version & Changelog

1. **Update `pubspec.yaml`**: Bump the `version` field to the target release version (e.g., `0.4.0` or `0.3.1`) following [Semantic Versioning](https://semver.org/).
2. **Update `CHANGELOG.md`**: 
   - Fold all items under `## Unreleased` into a new section named `## X.Y.Z` (matching the version in `pubspec.yaml`).
   - Add a blank `## Unreleased` section at the top for future development.
   - Categorize changes into `### Added`, `### Changed`, `### Fixed`, and `### Security`.

### Pre-Release Verification

Run the full validation suite to ensure the package is ready for publication.

```bash
# 1. Static Analysis (Must have 0 issues)
dart analyze

# 2. Run all tests including NIST KAT runners
dart test

# 3. Web compiler checks (Optional but recommended)
dart test -p chrome
dart test -p chrome --compiler dart2wasm
```

### Dry Run Publication

Verify that the package layout is correct and no extraneous files are included.

```bash
dart pub publish --dry-run
```

- Ensure the **Total compressed archive size** is reasonable.
- Ensure there are **0 warnings**.
- Check that development artifacts (e.g., `.github/`, `.vscode/`, AI configuration files like `AGENTS.md`, `CLAUDE.md`) are properly excluded via `.pubignore`.

## 2. Commit and Tag

Once validation passes, commit the hygiene changes and create an annotated git tag.

```bash
# Commit the version bump and changelog
git add pubspec.yaml CHANGELOG.md
git commit -m "chore: prepare pqcrypto X.Y.Z release"

# Create an annotated tag with release notes
git tag -a vX.Y.Z -m "Release pqcrypto X.Y.Z

- Summary of feature 1
- Summary of feature 2
- Bug fixes"
```

> **Note**: Maintain the strict claim boundary in the release notes. Do not claim "FIPS 140 Validated" or "CMVP Certified". Use terms like "FIPS 203/204 aligned" and "byte-exact against official KAT corpus".

## 3. Push and Publish

Push the commits and tags to the remote repository, then publish to pub.dev.

```bash
# Push to main/develop
git push origin main

# Push the tag
git push origin vX.Y.Z

# Publish to pub.dev
dart pub publish
```

## 4. Post-Release

1. **GitHub Release**: Go to the GitHub repository and create a new release from the pushed tag. Copy the relevant section from `CHANGELOG.md` as the release description.
2. **Verify Pub.dev**: Check [pub.dev/packages/pqcrypto](https://pub.dev/packages/pqcrypto) to ensure the new version is live, the score is 130/130, and the README renders correctly.

---

## Hotfix Process

For critical bugs or security vulnerabilities found in a production release:

1. **Branch off the tag**: If `main` has moved forward, checkout the affected release tag and branch from it: `git checkout -b hotfix/vX.Y.Z-patch vX.Y.Z`.
2. **Apply the fix**: Write the minimal code needed to fix the issue. Add a regression test.
3. **Bump the patch version**: E.g., `0.3.0` -> `0.3.1`. Update `CHANGELOG.md`.
4. **Test and Dry Run**: Run `dart analyze`, `dart test`, and `dart pub publish --dry-run`.
5. **Tag and Publish**: Follow steps 2, 3, and 4 above using the new patch version tag.
6. **Merge back**: Ensure the hotfix is merged back into `main` and `develop` so the fix isn't lost in future releases.
