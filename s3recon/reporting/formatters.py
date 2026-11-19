"""Output formatters: table, JSON, CSV, Markdown, HTML."""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from s3recon.models.findings import Finding, RiskLevel, ScanResult

logger = logging.getLogger(__name__)


def findings_to_table(findings: List[Finding]) -> str:
    if not findings:
        return "No findings."
    headers = ["Target", "Provider", "Exposure", "Risk", "Status", "Notes"]
    rows = [
        [f.target[:40], f.provider.value, f.finding_type.value,
         f.risk_level.value, str(f.evidence.status_code or "-"), (f.notes or "")[:40]]
        for f in findings
    ]
    col_widths = [max(len(h), max((len(r[i]) for r in rows), default=0)) for i, h in enumerate(headers)]
    sep = " | "
    header_line = sep.join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    divider = "-+-".join("-" * w for w in col_widths)
    body = "\n".join(sep.join(c.ljust(col_widths[i]) for i, c in enumerate(row)) for row in rows)
    return f"{header_line}\n{divider}\n{body}"


def findings_to_json(findings: List[Finding], scan: Optional[ScanResult] = None) -> str:
    if scan:
        return json.dumps(scan.to_dict(), indent=2)
    return json.dumps([f.to_dict() for f in findings], indent=2)


def findings_to_csv(findings: List[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["target","provider","finding_type","risk_level","status_code","url","timestamp","remediation","notes","object_count"])
    for f in findings:
        writer.writerow([f.target, f.provider.value, f.finding_type.value, f.risk_level.value,
                         f.evidence.status_code, f.evidence.url, f.timestamp, f.remediation,
                         f.notes or "", len(f.objects)])
    return buf.getvalue()


def findings_to_markdown(findings: List[Finding], scan: Optional[ScanResult] = None) -> str:
    lines = ["# S3RECON Report", ""]
    if scan:
        lines += [f"**Scan ID:** `{scan.scan_id}`  ", f"**Started:** {scan.started_at}  ",
                  f"**Finished:** {scan.finished_at or 'N/A'}  ", f"**Targets tested:** {scan.targets_tested}  ", ""]
        lines += ["## Summary", ""]
        for k, v in scan.summary().items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")
    lines += ["## Findings", "", "| Target | Provider | Exposure | Risk | Status |",
              "|--------|----------|----------|------|--------|"]
    for f in findings:
        lines.append(f"| {f.target} | {f.provider.value} | {f.finding_type.value} | {f.risk_level.value} | {f.evidence.status_code or '-'} |")
    return "\n".join(lines)


def _esc(s: str) -> str:
    return s.replace("&","&").replace("<","<").replace(">",">").replace('"',""")


def findings_to_html(findings: List[Finding], scan: Optional[ScanResult] = None) -> str:
    summary = scan.summary() if scan else {
        "total_findings": len(findings),
        "targets_tested": len({f.target for f in findings}),
        "critical": sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL),
        "high": sum(1 for f in findings if f.risk_level == RiskLevel.HIGH),
        "medium": sum(1 for f in findings if f.risk_level == RiskLevel.MEDIUM),
        "low": sum(1 for f in findings if f.risk_level == RiskLevel.LOW),
        "informational": sum(1 for f in findings if f.risk_level == RiskLevel.INFORMATIONAL),
    }
    scan_id = scan.scan_id if scan else "n/a"
    started = scan.started_at if scan else datetime.now(timezone.utc).isoformat()
    finished = (scan.finished_at if scan else None) or "N/A"
    risk_colors = {"critical":"#8B0000","high":"#DC143C","medium":"#FF8C00","low":"#DAA520","informational":"#708090"}
    rows = []
    for f in findings:
        color = risk_colors.get(f.risk_level.value, "#333")
        rows.append(f'<tr><td><code>{_esc(f.target)}</code></td><td>{f.provider.value}</td>'
                    f'<td>{f.finding_type.value}</td><td style="color:{color};font-weight:bold">{f.risk_level.value}</td>'
                    f'<td>{f.evidence.status_code or "-"}</td><td>{_esc(f.notes or "")}</td>'
                    f'<td>{_esc(f.remediation[:120])}...</td></tr>')
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>S3RECON Report - {scan_id}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:2rem;background:#f8f9fa;color:#212529}}
h1{{color:#0d47a1}}.summary{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.card{{background:white;border-radius:8px;padding:1rem 1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.12);min-width:120px}}
.card .num{{font-size:1.8rem;font-weight:bold}}
table{{width:100%;border-collapse:collapse;background:white;box-shadow:0 1px 3px rgba(0,0,0,.12)}}
th,td{{padding:.6rem .8rem;text-align:left;border-bottom:1px solid #dee2e6}}th{{background:#e9ecef}}
.warning{{background:#fff3cd;border:1px solid #ffc107;padding:1rem;border-radius:6px;margin-bottom:1.5rem}}
footer{{margin-top:2rem;color:#6c757d;font-size:.9rem}}
</style></head><body>
<h1>S3RECON Report</h1>
<p><strong>Scan ID:</strong> {scan_id} | <strong>Started:</strong> {started} | <strong>Finished:</strong> {finished}</p>
<div class="warning"><strong>Authorization reminder:</strong> Only scan cloud resources that you own or have explicit authorization to assess.</div>
<h2>Executive Summary</h2>
<div class="summary">
<div class="card"><div class="num">{summary.get('targets_tested',0)}</div>Targets tested</div>
<div class="card"><div class="num">{summary.get('total_findings',0)}</div>Findings</div>
<div class="card"><div class="num" style="color:#8B0000">{summary.get('critical',0)}</div>Critical</div>
<div class="card"><div class="num" style="color:#DC143C">{summary.get('high',0)}</div>High</div>
<div class="card"><div class="num" style="color:#FF8C00">{summary.get('medium',0)}</div>Medium</div>
<div class="card"><div class="num" style="color:#708090">{summary.get('informational',0)}</div>Informational</div>
</div>
<h2>All Findings</h2>
<table><thead><tr><th>Resource</th><th>Provider</th><th>Exposure Type</th><th>Risk</th><th>HTTP Status</th><th>Notes</th><th>Remediation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>Generated by S3RECON - authorized cloud storage exposure reconnaissance.</footer>
</body></html>"""


def write_report(findings: List[Finding], fmt: str, output: Optional[str] = None, scan: Optional[ScanResult] = None) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        content = findings_to_json(findings, scan)
    elif fmt == "csv":
        content = findings_to_csv(findings)
    elif fmt in ("md", "markdown"):
        content = findings_to_markdown(findings, scan)
    elif fmt == "html":
        content = findings_to_html(findings, scan)
    else:
        content = findings_to_table(findings)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info("Report written to %s", path)
    return content
