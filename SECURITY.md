# Security Policy

## Authorized Use Only

**Only scan cloud resources that you own or have explicit authorization to assess.**

S3RECON is designed for defensive security research, authorized penetration testing, and cloud configuration auditing. Unauthorized scanning of third-party infrastructure may violate laws and provider terms of service.

## Safe Design Principles

- **No destructive operations** — Never uploads, modifies, deletes, or overwrites objects.
- **Metadata only by default** — Object content is never downloaded automatically.
- **No credential harvesting** — Does not collect, store, or transmit credentials or tokens.
- **No authentication bypass** — Public endpoints only; does not circumvent access controls.
- **Scope enforcement** — Targets constrained via configuration allowlists.
- **Rate limiting** — Built-in rate limits and concurrency controls.

## Reporting Vulnerabilities

Use GitHub Security Advisories for this repository. Do not open public issues for exploitable vulnerabilities.
