"""Load configuration from YAML/TOML files and CLI overrides."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from s3recon.config.schema import (
    Config,
    RiskConfig,
    SafetyConfig,
    ScanConfig,
    ScopeConfig,
)

logger = logging.getLogger(__name__)


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to load YAML config files. Install with: pip install pyyaml"
        ) from exc
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_toml(path: Path) -> Dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "tomllib/tomli required for TOML config. Use Python 3.11+ or install tomli."
            ) from exc
    with path.open("rb") as fh:
        return tomllib.load(fh)


def load_config(path: Optional[str] = None) -> Config:
    cfg = Config()
    if not path:
        return cfg

    p = Path(path)
    if not p.exists():
        logger.warning("Config file not found: %s — using defaults", path)
        return cfg

    suffix = p.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        data = _load_yaml(p)
    elif suffix == ".toml":
        data = _load_toml(p)
    else:
        raise ValueError(f"Unsupported config format: {suffix}. Use .yaml, .yml, or .toml")

    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping")

    scope_data = data.get("scope", {})
    if isinstance(scope_data, dict):
        cfg.scope = ScopeConfig(
            domains=list(scope_data.get("domains", [])),
            buckets=list(scope_data.get("buckets", [])),
            allow_any=bool(scope_data.get("allow_any", False)),
            organization=scope_data.get("organization"),
            notes=scope_data.get("notes"),
        )

    scan_data = data.get("scan", {})
    if isinstance(scan_data, dict):
        cfg.scan = ScanConfig(
            rate_limit=float(scan_data.get("rate_limit", 5.0)),
            timeout=float(scan_data.get("timeout", 10.0)),
            workers=int(scan_data.get("workers", 5)),
            max_retries=int(scan_data.get("max_retries", 2)),
            backoff_factor=float(scan_data.get("backoff_factor", 0.5)),
            user_agent=str(
                scan_data.get(
                    "user_agent",
                    "S3RECON/1.0 (+https://github.com/DR13X/S3RECON)",
                )
            ),
        )

    safety_data = data.get("safety", {})
    if isinstance(safety_data, dict):
        cfg.safety = SafetyConfig(
            metadata_only=bool(safety_data.get("metadata_only", True)),
            destructive_operations=False,
            require_scope=bool(safety_data.get("require_scope", True)),
            max_objects_listed=int(safety_data.get("max_objects_listed", 50)),
            download_content=False,
        )

    risk_data = data.get("risk", {})
    if isinstance(risk_data, dict):
        cfg.risk = RiskConfig(
            public_writable=str(risk_data.get("public_writable", "critical")),
            public_readable=str(risk_data.get("public_readable", "high")),
            public_listable=str(risk_data.get("public_listable", "medium")),
            authenticated_only=str(risk_data.get("authenticated_only", "informational")),
            non_existent=str(risk_data.get("non_existent", "informational")),
            access_denied=str(risk_data.get("access_denied", "informational")),
            unknown=str(risk_data.get("unknown", "low")),
            error=str(risk_data.get("error", "low")),
        )

    if "providers" in data:
        cfg.providers = list(data["providers"])
    if "output_dir" in data:
        cfg.output_dir = str(data["output_dir"])
    if "log_level" in data:
        cfg.log_level = str(data["log_level"]).upper()

    return cfg


def merge_cli_overrides(cfg: Config, **kwargs: Any) -> Config:
    if kwargs.get("rate_limit") is not None:
        cfg.scan.rate_limit = float(kwargs["rate_limit"])
    if kwargs.get("timeout") is not None:
        cfg.scan.timeout = float(kwargs["timeout"])
    if kwargs.get("threads") is not None:
        cfg.scan.workers = int(kwargs["threads"])
    if kwargs.get("verbose"):
        cfg.log_level = "DEBUG"
    if kwargs.get("providers"):
        cfg.providers = list(kwargs["providers"])
    return cfg
