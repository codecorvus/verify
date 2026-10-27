# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- `corvus-verify`: offline verification of CodeCorvus evidence exports (format
  `codecorvus.exportacao-evidencia.v1`): Ed25519 signature over the canonical content, record hashes, chaining,
  gaps and totals.
- `--key` to require the signature from the published public key.
- JSON Schema of the export format.
