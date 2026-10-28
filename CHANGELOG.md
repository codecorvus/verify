# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-28

### Added

- `corvus-verify`: offline verification of CodeCorvus evidence exports (format
  `codecorvus.evidence-export.v1`): Ed25519 signature over the canonical content, record hashes, chaining,
  gaps and totals.
- `--key` to require the signature from the published public key (`/.well-known/codecorvus-evidence.pub`, lines
  `key_id:` and `public_key:`).
- JSON Schema of the export format (`schema/evidence-export.v1.json`), with English field names and the fixed list
  of keys that goes into each record hash.

[0.1.0]: https://github.com/codecorvus/verify/releases/tag/v0.1.0
