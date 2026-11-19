"""Data models for findings, risks, and scan results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ExposureType(str, Enum):
    PUBLIC_LISTABLE = "public_listable"
    PUBLIC_READABLE = "public_readable"
    PUBLIC_WRITABLE = "public_writable"
    AUTHENTICATED_ONLY = "authenticated_only"
    NON_EXISTENT = "non_existent"
    ACCESS_DENIED = "access_denied"
    UNKNOWN = "unknown"
    ERROR = "error"


class Provider(str, Enum):
    AWS_S3 = "s3"
    GCP_STORAGE = "gcs"
    AZURE_BLOB = "azure"


@dataclass
class Evidence:
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    api_message: Optional[str] = None
    method: str = "HEAD"
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ObjectMetadata:
    name: str
    size: Optional[int] = None
    last_modified: Optional[str] = None
    content_type: Optional[str] = None
    etag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    target: str
    provider: Provider
    finding_type: ExposureType
    risk_level: RiskLevel
    evidence: Evidence
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    remediation: str = ""
    objects: List[ObjectMetadata] = field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["provider"] = self.provider.value
        data["finding_type"] = self.finding_type.value
        data["risk_level"] = self.risk_level.value
        return data


@dataclass
class ScanResult:
    scan_id: str
    started_at: str
    finished_at: Optional[str] = None
    targets_tested: int = 0
    findings: List[Finding] = field(default_factory=list)
    scope: Dict[str, Any] = field(default_factory=dict)
    config_summary: Dict[str, Any] = field(default_factory=dict)
    errors inter List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "targets_tested": self.targets_tested,
            "findings": [f.to_dict() for f in self.findings],
            "scope": self.scope,
            "config_summary": self.config_summary,
            "errors": self.errors,
            "summary": self.summary(),
        }

    def summary(self) -> Dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for f in self.findings:
            counts[f.risk_level.value] += 1
        counts["total_findings"] = len(self.findings)
        counts["targets_tested"] = self.targets_tested
        return counts


DEFAULT_REMEDIATIONS: Dict[ExposureType, str] = {
    ExposureType.PUBLIC_WRITABLE: (
        "Immediately remove public write permissions. Enable versioning and logging. "
        "Review IAM policies and ACLs. Rotate any potentially compromised credentials."
    ),
    ExposureType.PUBLIC_READABLE: (
        "Restrict public read access unless intentionally required. Use signed URLs "
        "or CDN with access controls for legitimate public assets. Audit objects for sensitive data."
    ),
    ExposureType.PUBLIC_LISTABLE: (
        "Disable public listing of bucket/container contents. Public listing can reveal "
        "object names and structure even when objects themselves are private."
    ),
    ExposureType.AUTHENTICATED_ONLY: (
        "No public exposure detected. Continue least-privilege principles and monitor access logs."
    ),
    ExposureType.NON_EXISTENT: "Resource does not appear to exist. No action required.",
    ExposureType.ACCESS_DENIED: (
        "Access was denied. Resource may exist but is properly restricted."
    ),
    ExposureType.UNKNOWN: "Unable to determine exposure status. Manual verification recommended.",
    ExposureType.ERROR: (
        "An error occurred while assessing the resource. Retry or investigate connectivity/API issues."
    ),
}
