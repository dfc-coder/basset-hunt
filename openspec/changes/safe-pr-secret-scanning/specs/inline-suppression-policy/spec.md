# Spec Delta

## Purpose

Ensures that a scanned secret cannot be hidden by adding a suppression marker to the same untrusted content being analyzed.

## ADDED Requirements

### Requirement: Inline markers do not suppress findings
Every content-scanning mode SHALL report a detectable secret even when its line contains an inline marker such as `gitleaks:allow`. Inline markers MUST NOT suppress findings by default in filesystem, stdin, JSONL-record, staged-index, full-history, or commit-range scans.

#### Scenario: Marker on a detected line
- **WHEN** a scanned line contains a detectable secret followed by `gitleaks:allow`
- **THEN** Basset reports the finding as it would without the marker

#### Scenario: Marker in every scan source
- **WHEN** the same marked synthetic secret is scanned through filesystem, stdin, JSONL records, staged index, full Git history, or Git range mode
- **THEN** each applicable scan mode reports the finding and does not classify the scan as clean because of the marker

#### Scenario: Marker without a detectable secret
- **WHEN** a scanned line contains an inline marker but no detectable secret
- **THEN** Basset does not create a finding solely because the marker is present
