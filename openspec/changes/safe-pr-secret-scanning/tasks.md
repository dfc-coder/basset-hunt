# Tasks

## 1. Disable inline suppression safely

- [x] 1.1 Configure the shared scanner to ignore inline allow markers and add synthetic end-to-end cases proving `gitleaks:allow` cannot suppress findings through `fs`, `stdin`, `records`, `staged`, and full-history Git; verify `cargo test --locked` and `python3 tests/e2e.py target/release/basset` pass.
- [x] 1.2 Document the intentional behavior change in README and verify examples/tests no longer imply inline markers suppress findings.

## 2. Add explicit Git range scanning

- [x] 2.1 Add a CLI range mode that resolves distinct base/head commits safely, documents usage in README, and fails closed on invalid, unavailable, equal, or shallow-history cases; verify success and failure cases in isolated temporary Git repositories.
- [x] 2.2 Enumerate commits reachable from head but not base; map added lines for non-merge commits, compare roots with the empty tree, and omit merge-result diffs to match TruffleHog v3.100.1; scan full new blobs but report only finding spans overlapping added lines. Verify unchanged, newly added, add-then-remove, multiline-context, root, merge-import, merge-resolution-gap, special-path, deletion-only, empty-file, and full-history cases.
- [x] 2.3 Bound changed input processing and report unsupported binary, malformed diff, oversized, and truncated cases as incomplete with exit code 2; verify partial findings are retained and no failure is presented as a clean result.

## 3. Emit bounded, secret-safe SARIF

- [x] 3.1 Add optional SARIF 2.1.0 serialization for range findings with repository-relative URIs, line regions, generic messages, commit metadata, and location-only fingerprints; verify output parses, fingerprints are stable for unchanged locations, and no synthetic secret or its digest appears in output.
- [x] 3.2 Include `runs[].invocations[].executionSuccessful`, preserve findings on partial scans, and enforce a global SARIF result cap; verify the cap and every incomplete path produces valid SARIF plus exit code 2 while complete findings return code 1.

## 4. Wire the PR workflow and align the roadmap

- [ ] 4.1 Update the GitHub Actions pull-request path to pass event base/head SHAs to range mode, retain SARIF artifacts on upload failure, and isolate SARIF upload behind least-privilege permissions; verify the workflow does not use `pull_request_target` or expose secrets to fork code.
- [ ] 4.2 Update `docs/plan-de-actualizacion.md` to record the new M3 contract, global inline-marker policy, Basset/TruffleHog status terminology difference, pinned TruffleHog v3.100.1 no-verification comparison, and deferred commit-metadata/decoder gaps; verify links and roadmap acceptance criteria match the specs.
- [ ] 4.3 Run `cargo build --release --locked`, `cargo test --locked`, `python3 tests/test_iam.py`, and `python3 tests/e2e.py target/release/basset`; verify a local SARIF fixture is secret-free and the PR workflow's expected exit/artifact behavior is documented.
