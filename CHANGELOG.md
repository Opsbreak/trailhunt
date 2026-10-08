# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-08

Initial release.

### Added

- Streaming ingestion of CloudTrail delivery files (plain / gzip), JSON Lines
  (CloudTrail Lake / Athena exports, including lower-cased columns and
  JSON-string columns), JSON arrays, directories and stdin; delivery-timestamp
  file ordering, bounded reorder buffer, eventID de-duplication,
  `--since/--until`, Windows long-path support.
- Event normalization with a stable `actor` key (assumed-role sessions mapped to
  the role, IAM Identity Center sessions kept per human, root detection) and
  derived fields (`ua_family`, `mfa`, `src_ip`, ...).
- YAML rule engine with four rule types: `match`, `threshold` (count / count
  distinct in a sliding window), `sequence` (per-key state machine with
  per-step `within`, repeated steps and trailing `absent` steps) and `new_value`
  (first-seen after a learning period or against a persisted `--state` file).
- Predicate operators: equals, in, glob, regex, cidr, exists, startswith,
  endswith, contains, numeric comparisons, field-to-field comparisons, negated
  variants and all/any/not composition; path transforms `json`, `account`,
  `net16`, `net24`, `lower`, `upper`, `str`, `len`.
- Rule-level `suppress` for match and threshold rules.
- Strict rule schema validation with file / rule / key-path error messages.
- Embedded rule unit tests and `trailhunt rules test`.
- 29 built-in rules mapped to MITRE ATT&CK.
- CLI: `hunt` (text, json, jsonl, markdown; `--min-severity`, `--fail-on`,
  `--rule-id`, `--state`), `timeline`, `stats`, `rules list|validate|test`.
- Deterministic synthetic dataset generator and a committed 9-day sample with
  embedded attack scenarios.

[Unreleased]: https://github.com/Opsbreak/trailhunt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Opsbreak/trailhunt/releases/tag/v0.1.0
