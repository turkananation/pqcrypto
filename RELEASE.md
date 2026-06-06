# Release Process Guide

This document outlines the standard operating procedure for moving changes from
feature branches to `develop`, promoting release candidates to `main`, and
publishing new versions or hotfixes for the `pqcrypto` package.

## 0. Branch and Pull Request Flow

Use `develop` as the integration branch and `main` as the publishable release
branch.

1. Create feature and fix branches from the latest `develop`.
2. Open feature PRs into `develop`; do not target `main` for ordinary work.
3. Keep each PR small enough to review for cryptographic correctness, tests,
   claim wording, package hygiene, and web portability.
4. Promote `develop` to `main` only through a release PR after release
   preparation and full validation pass.
5. Create release tags only from the exact commit on `main` that was published
   to pub.dev.

Repository administrators should protect both `develop` and `main` with:

- pull requests required before merging;
- required status checks for CI, web tests, OpenSSL interop, and CodeQL;
- branches required to be up to date before merging, or a merge queue when PR
  volume justifies it;
- stale review dismissal when a PR changes after approval; and
- direct pushes limited to documented emergency branch alignment or maintainer
  break-glass operations.

## 1. Release Preparation

Prepare releases on a release branch from `develop`.

```bash
git fetch origin
git switch develop
git merge --ff-only origin/develop
git switch -c release/vX.Y.Z
```

If `main` received a hotfix after the release branch was created, merge or
rebase the hotfix back through `develop` first, then refresh the release branch.

### Update Version & Changelog

1. **Update `pubspec.yaml`**: Bump the `version` field to the target release version (e.g., `0.4.0` or `0.3.1`) following [Semantic Versioning](https://semver.org/).
2. **Update `CHANGELOG.md`**:
   - Fold all items under `## Unreleased` into a new section named `## X.Y.Z` (matching the version in `pubspec.yaml`).
   - Add a blank `## Unreleased` section at the top for future development.
   - Categorize changes into `### Added`, `### Changed`, `### Fixed`, and `### Security`.

### Pre-Release Verification

Run the full validation suite before opening the release PR.

```bash
# 1. Formatting and static analysis
dart format --output=none --set-exit-if-changed .
dart analyze

# 2. Focused KAT evidence
dart test test/kat_evaluator_test.dart
dart test test/mldsa_kat_test.dart

# 3. Full VM suite
dart test

# 4. Web compiler checks
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

## 2. Commit and Promote

Once validation passes, commit the release hygiene changes on the release branch
and open a PR into `develop`.

```bash
# Commit the version bump and changelog
git add pubspec.yaml CHANGELOG.md
git commit -m "chore: prepare pqcrypto X.Y.Z release"

git push origin release/vX.Y.Z
```

Release PR requirements:

- target branch is `develop`;
- CI, web tests, OpenSSL interop, CodeQL, and publish dry run are green;
- `CHANGELOG.md`, `pubspec.yaml`, `README.md`, and relevant `doc/` files agree
  on version and evidence wording;
- the PR description states the exact validation commands and results; and
- release notes maintain the strict claim boundary.

After the release PR lands in `develop`, open a promotion PR from `develop` to
`main`. The promotion PR should contain only the reviewed release candidate
delta. Do not publish from `develop`.

> **Note**: Maintain the strict claim boundary in release notes. Do not claim
> "FIPS 140 Validated" or "CMVP Certified". Use terms like "FIPS 203/204
> aligned" and "byte-exact against the checked-in KAT corpus".

## 3. Tag and Publish

After the promotion PR lands, publish from a clean local checkout of `main`.

```bash
git fetch origin
git switch main
git merge --ff-only origin/main

# Confirm the release commit before tagging or publishing.
git rev-parse HEAD

# Re-run the package publication gate from main.
dart pub publish --dry-run

# Create an annotated tag with release notes on the main release commit.
git tag -a vX.Y.Z -m "Release pqcrypto X.Y.Z

- Summary of feature 1
- Summary of feature 2
- Bug fixes"

git push origin vX.Y.Z

dart pub publish
```

The tag and pub.dev package must refer to the same `main` commit. If the dry
run reports warnings, stop and fix them through the PR flow instead of editing
`main` directly.

## 4. Post-Release

1. **GitHub Release**: Create a GitHub release from the pushed tag. Copy the
   relevant section from `CHANGELOG.md` as the release description.
2. **Verify Pub.dev**: Check
   [pub.dev/packages/pqcrypto](https://pub.dev/packages/pqcrypto) to ensure the
   new version is live, the score is 130/130, and the README renders correctly.
3. **Verify branch state**: Confirm `main` contains the tagged release commit
   and `develop` contains the same release commit. If `develop` has moved on,
   record that expected divergence in the release notes or tracking issue.
4. **Resume development**: New work continues from `develop` after the release
   commit is present there.

---

## Hotfix Process

For critical bugs or security vulnerabilities found in a production release:

1. **Branch from `main` or the tag**: If `main` has moved forward, checkout the
   affected release tag and branch from it:
   `git checkout -b hotfix/vX.Y.Z-patch vX.Y.Z`.
2. **Apply the fix**: Write the minimal code needed to fix the issue. Add a regression test.
3. **Bump the patch version**: E.g., `0.3.0` -> `0.3.1`. Update `CHANGELOG.md`.
4. **Test and Dry Run**: Run `dart format --output=none --set-exit-if-changed .`,
   `dart analyze`, `dart test`, focused KAT tests, web tests, and
   `dart pub publish --dry-run`.
5. **PR to `main`**: Open the hotfix PR directly to `main` only for urgent
   production fixes.
6. **Tag and Publish**: Follow the tag and publish process above using the new
   patch version tag.
7. **Backport to `develop`**: Open a PR from `main` or a backport branch into
   `develop` immediately so the fix is not lost in future releases.
