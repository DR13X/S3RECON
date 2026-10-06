"""Configuration schema and defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScopeConfig:
    domains: List[str] = field(default_factory=list)
    buckets: List[str] = field(default_factory=list)
    allow_any: bool = False
    organization: Optional[str] = None
    notes: Optional[str] = None

    def is_target_allowed(self, target: str) -> bool:
        if self.allow_any:
            return True
        target_lower = target.lower().strip()
        if not target_lower:
            return False
        for b in self.buckets:
            if target_lower == b.lower() or target_lower.startswith(b.lower() + "."):
                return True
        for d in self.domains:
            d_clean = d.lower().removeprefix("www.").split(":")[0]
            base = d_clean.split(".")[0] if "." in d_clean else d_clean
            if (
                target_lower == d_clean
                or target_lower.endswith("." + d_clean)
                or base in target_lower
                or target_lower.startswith(base)
            ):
                return True
        return False


@dataclass
class ScanConfig:
    rate_limit: float = 5.0
    timeout: float = 10.0
    workers: int = 5
    max_retries: int = 2
    backoff_factor: float = 0.5
    user_agent: str = "S3RECON/1.0 (+https://github.com/DR13X/S3RECON)"


@dataclass
class SafetyConfig:
    metadata_only: bool = True
    destructive_operations: bool = False
    require_scope: bool = True
    max_objects_listed: int = 50
    download_content: bool = False


@dataclass
class RiskConfig:
    public_writable: str = "critical"
    public_readable: str = "high"
    public_listable: str = "medium"
    authenticated_only: str = "informational"
    non_existent: str = "informational"
    access_denied: str = "informational"
    unknown: str = "low"
    error: str = "low"


@dataclass
class Config:
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    providers: List[str] = field(default_factory=lambda: ["s3", "gcs", "azure"])
    output_dir: str = "reports"
    log_level: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": {
                "domains": self.scope.domains,
                "buckets": self.scope.buckets,
                "allow_any": self.scope.allow_any,
                "organization": self.scope.organization,
            },
            "scan": {
                "rate_limit": self.scan.rate_limit,
                "timeout": self.scan.timeout,
                "workers": self.scan.workers,
                "max_retries": self.scan.max_retries,
            },
            "safety": {
                "metadata_only": self.safety.metadata_only,
                "destructive_operations": self.safety.destructive_operations,
                "require_scope": self.safety.require_scope,
                "max_objects_listed": self.safety.max_objects_listed,
            },
            "providers": self.providers,
            "log_level": self.log_level,
        }
