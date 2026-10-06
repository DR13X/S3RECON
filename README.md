# S3RECON

```
   _____ ____  ____  ______________  _   __
  / ___// __ \/ __ \/ ____/ ____/ | / /  / /
  \__ \/ / / / /_/ / __/ / __/ /  |/ /  / /
 ___/ / /_/ / _, _/ /___/ /___/ /|  /  / /
/____/\____/_/ |_/_____/_____/_/ |_/  /_/
```

**Authorized cloud-storage exposure reconnaissance and auditing tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Only scan cloud resources that you own or have explicit authorization to assess.**

S3RECON helps security researchers and cloud engineers identify potentially publicly accessible cloud storage (Amazon S3, Google Cloud Storage, Azure Blob Storage) without destructive operations or downloading sensitive content.

## Features

- **Providers:** Amazon S3, GCS, Azure Blob (extensible)
- **Discovery:** Targets, domains, wordlists, naming patterns, passive candidates
- **Assessment:** Public listable / readable, access denied, non-existent
- **Safety:** Scope allowlists, rate limiting, no destructive ops, metadata-only
- **Output:** Table, JSON, CSV, Markdown, HTML reports
- **Risk model:** Critical / High / Medium / Low / Informational

## Installation

```bash
git clone https://github.com/DR13X/S3RECON.git
cd S3RECON
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Quick Start

```bash
cp scope.example.yaml scope.yaml
# Edit scope.yaml — only resources you are authorized to assess

s3recon discover --target example.com --passive
s3recon inspect --target example-assets --provider s3
s3recon scan --target example.com --scope scope.yaml --format html -o report.html
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `s3recon discover` | Generate candidate names within scope |
| `s3recon inspect` | Assess a single explicit target |
| `s3recon scan` | Full discovery + permission assessment |
| `s3recon report` | Re-format prior JSON results |
| `s3recon version` | Show version |

## Configuration

```yaml
scope:
  domains: [example.com]
  buckets: [example-assets]
  allow_any: false

scan:
  rate_limit: 5
  timeout: 10
  workers: 5

safety:
  metadata_only: true
  destructive_operations: false
  require_scope: true
```

## Risk Methodology

| Level | Meaning |
|-------|---------|
| Critical | Publicly writable / severe exposure |
| High | Publicly readable |
| Medium | Public listing |
| Low | Ambiguous signal |
| Informational | No public exposure confirmed |

## Security Model

- No destructive operations (no PUT/POST/DELETE)
- No content download by default
- No credential handling
- Scope-controlled targeting
- Rate limiting and timeouts

See [SECURITY.md](SECURITY.md).

## Development

```bash
pip install -e ".[dev]"
make test
make lint
```

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For authorized security assessment only. Always obtain proper authorization before scanning any system you do not own.
