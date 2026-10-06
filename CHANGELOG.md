# Changelog

## [1.0.0] — 2026-10-06

### Added
- Initial public release as **S3RECON**.
- Support for Amazon S3, Google Cloud Storage, and Azure Blob Storage.
- Modular provider architecture.
- Discovery via targets, domains, wordlists, naming patterns.
- Permission assessment (listable / readable / denied / non-existent).
- Metadata-only object listing.
- Risk scoring: Critical / High / Medium / Low / Informational.
- CLI: `discover`, `inspect`, `scan`, `report`, `version`.
- Output: table, JSON, CSV, Markdown, HTML.
- YAML/TOML configuration with scope allowlisting.
- Rate limiting, concurrency, timeouts, retries.
- Unit tests with mocked HTTP (no live credentials).
- GitHub Actions CI, MIT license, SECURITY.md.
