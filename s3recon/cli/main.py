"""S3RECON CLI entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import List, Optional

from s3recon import __version__
from s3recon.config.loader import load_config, merge_cli_overrides
from s3recon.core.engine import run_discover, run_inspect, run_scan
from s3recon.reporting.formatters import write_report
from s3recon.utils.logging import setup_logging

BANNER = r"""
   _____ ____  ____  ______________  _   __
  / ___// __ \/ __ \/ ____/ ____/ | / /  / /
  \__ \/ / / / /_/ / __/ / __/ /  |/ /  / /
 ___/ / /_/ / _, _/ /___/ /___/ /|  /  / /
/____/\____/_/ |_/_____/_____/_/ |_/  /_/

  Authorized Cloud Storage Exposure Reconnaissance & Auditing
  Only scan resources you own or have explicit authorization to assess.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s3recon",
        description="Authorized cloud-storage exposure reconnaissance and auditing tool.",
        epilog="Only scan cloud resources that you own or have explicit authorization to assess.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"S3RECON {__version__}")
    parser.add_argument("-c", "--config", help="Path to YAML/TOML configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    p_disc = sub.add_parser("discover", help="Discover candidate bucket/container names within scope")
    p_disc.add_argument("--target", "-t", help="Domain or seed name")
    p_disc.add_argument("--wordlist", "-w", help="Path to wordlist file")
    p_disc.add_argument("--provider", "-p", action="append", dest="providers", help="Provider (s3,gcs,azure)")
    p_disc.add_argument("--passive", action="store_true", help="Include passive candidates")
    p_disc.add_argument("--scope", help="Path to scope config (YAML/TOML)")
    p_disc.add_argument("--output", "-o", help="Write candidates to file")
    p_disc.add_argument("--format", choices=["table", "json", "csv", "md", "html"], default="table")

    p_insp = sub.add_parser("inspect", help="Inspect a single explicit bucket/container")
    p_insp.add_argument("--target", "-t", required=True, help="Bucket/container name")
    p_insp.add_argument("--provider", "-p", help="Provider (s3, gcs, azure)")
    p_insp.add_argument("--scope", help="Path to scope/config file")
    p_insp.add_argument("--threads", type=int, help="Concurrent workers")
    p_insp.add_argument("--rate-limit", type=float, help="Requests per second")
    p_insp.add_argument("--timeout", type=float, help="Request timeout seconds")
    p_insp.add_argument("--output", "-o", help="Output file path")
    p_insp.add_argument("--format", choices=["table", "json", "csv", "md", "html"], default="table")

    p_scan = sub.add_parser("scan", help="Discover candidates and assess permissions within scope")
    p_scan.add_argument("--target", "-t", help="Domain or seed name")
    p_scan.add_argument("--wordlist", "-w", help="Path to wordlist file")
    p_scan.add_argument("--provider", "-p", action="append", dest="providers", help="Provider filter")
    p_scan.add_argument("--passive", action="store_true", help="Include passive candidates")
    p_scan.add_argument("--scope", help="Path to scope/config YAML or TOML")
    p_scan.add_argument("--threads", type=int, help="Concurrent workers")
    p_scan.add_argument("--rate-limit", type=float, help="Max requests per second")
    p_scan.add_argument("--timeout", type=float, help="Request timeout in seconds")
    p_scan.add_argument("--output", "-o", help="Output file path")
    p_scan.add_argument("--format", choices=["table", "json", "csv", "md", "html"], default="table")

    p_rep = sub.add_parser("report", help="Re-format an existing JSON scan result")
    p_rep.add_argument("--input", "-i", required=True, help="Input JSON file from a prior scan")
    p_rep.add_argument("--output", "-o", help="Output file")
    p_rep.add_argument("--format", choices=["table", "json", "csv", "md", "html"], default="html")

    sub.add_parser("version", help="Show version")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command or args.command == "version":
        print(f"S3RECON {__version__}")
        if not args.command:
            print(BANNER)
            parser.print_help()
        return 0

    config_path = getattr(args, "scope", None) or getattr(args, "config", None)
    config = load_config(config_path)
    config = merge_cli_overrides(
        config,
        rate_limit=getattr(args, "rate_limit", None),
        timeout=getattr(args, "timeout", None),
        threads=getattr(args, "threads", None),
        verbose=getattr(args, "verbose", False),
        providers=getattr(args, "providers", None),
    )
    setup_logging(config.log_level, verbose=getattr(args, "verbose", False))

    if args.command != "report":
        print(BANNER)

    try:
        if args.command == "discover":
            return asyncio.run(_cmd_discover(args, config))
        if args.command == "inspect":
            return asyncio.run(_cmd_inspect(args, config))
        if args.command == "scan":
            return asyncio.run(_cmd_scan(args, config))
        if args.command == "report":
            return _cmd_report(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            raise
        return 1
    return 0


async def _cmd_discover(args, config) -> int:
    candidates = await run_discover(
        config, target=args.target, wordlist=args.wordlist,
        passive=args.passive, providers=args.providers,
    )
    if args.format == "json":
        import json
        out = json.dumps(candidates, indent=2)
    else:
        out = "\n".join(candidates) if candidates else "(no candidates)"
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {len(candidates)} candidates to {args.output}")
    else:
        print(out)
    return 0


async def _cmd_inspect(args, config) -> int:
    findings = await run_inspect(config, target=args.target, provider=args.provider)
    content = write_report(findings, args.format, args.output)
    if not args.output or args.format == "table":
        print(content)
    return 0


async def _cmd_scan(args, config) -> int:
    result = await run_scan(
        config, target=args.target, wordlist=args.wordlist,
        passive=args.passive, providers=args.providers,
    )
    content = write_report(result.findings, args.format, args.output, scan=result)
    if not args.output or args.format == "table":
        print(content)
    summary = result.summary()
    print(
        f"\nScan complete: {summary.get('targets_tested', 0)} targets, "
        f"{summary.get('total_findings', 0)} findings "
        f"(critical={summary.get('critical', 0)}, high={summary.get('high', 0)}, "
        f"medium={summary.get('medium', 0)})"
    )
    return 0


def _cmd_report(args) -> int:
    import json
    from pathlib import Path
    from s3recon.models.findings import (
        Evidence, ExposureType, Finding, ObjectMetadata, Provider, RiskLevel, ScanResult,
    )
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings = []
    for fd in data.get("findings", data if isinstance(data, list) else []):
        findings.append(Finding(
            target=fd["target"],
            provider=Provider(fd["provider"]),
            finding_type=ExposureType(fd["finding_type"]),
            risk_level=RiskLevel(fd["risk_level"]),
            evidence=Evidence(**fd.get("evidence", {})),
            timestamp=fd.get("timestamp", ""),
            remediation=fd.get("remediation", ""),
            objects=[ObjectMetadata(**o) for o in fd.get("objects", [])],
            notes=fd.get("notes"),
        ))
    scan = None
    if "scan_id" in data:
        scan = ScanResult(
            scan_id=data["scan_id"], started_at=data.get("started_at", ""),
            finished_at=data.get("finished_at"), targets_tested=data.get("targets_tested", 0),
            findings=findings,
        )
    content = write_report(findings, args.format, args.output, scan=scan)
    if not args.output or args.format == "table":
        print(content)
    return 0


if __name__ == "__main__":
    sys.exit(main())
