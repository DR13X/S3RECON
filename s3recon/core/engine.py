"""Main scan / discover / inspect orchestration engine."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from s3recon.config.schema import Config
from s3recon.discovery.engine import discover_candidates
from s3recon.models.findings import Finding, ScanResult
from s3recon.permissions.assessor import assess_targets
from s3recon.providers.registry import get_all_providers

logger = logging.getLogger(__name__)


async def run_discover(
    config: Config,
    target: Optional[str] = None,
    wordlist: Optional[str] = None,
    passive: bool = False,
    providers: Optional[List[str]] = None,
) -> List[str]:
    provs = get_all_providers(config, names=providers)
    return discover_candidates(
        config, provs, target=target, wordlist_path=wordlist, passive=passive
    )


async def run_inspect(
    config: Config, target: str, provider: Optional[str] = None
) -> List[Finding]:
    if config.safety.require_scope and not config.scope.allow_any:
        if not config.scope.is_target_allowed(target):
            logger.warning(
                "Target '%s' may be outside configured scope. "
                "Ensure you have authorization.",
                target,
            )
    names = [provider] if provider else None
    provs = get_all_providers(config, names=names)
    return await assess_targets(provs, [target], config)


async def run_scan(
    config: Config,
    target: Optional[str] = None,
    wordlist: Optional[str] = None,
    passive: bool = False,
    providers: Optional[List[str]] = None,
) -> ScanResult:
    scan_id = str(uuid.uuid4())[:8]
    started = datetime.now(timezone.utc).isoformat()
    logger.info("Starting scan %s", scan_id)

    if (
        config.safety.require_scope
        and not config.scope.domains
        and not config.scope.buckets
        and not target
    ):
        raise ValueError(
            "No scope defined. Provide --target, or configure scope.domains / scope.buckets "
            "in a config file. Only scan resources you own or are authorized to assess."
        )

    if config.safety.destructive_operations:
        config.safety.destructive_operations = False
        logger.warning("destructive_operations forced to False")

    provs = get_all_providers(config, names=providers)
    candidates = discover_candidates(
        config, provs, target=target, wordlist_path=wordlist, passive=passive
    )
    findings = await assess_targets(provs, candidates, config)
    finished = datetime.now(timezone.utc).isoformat()
    result = ScanResult(
        scan_id=scan_id,
        started_at=started,
        finished_at=finished,
        targets_tested=len(candidates),
        findings=findings,
        scope=config.to_dict().get("scope", {}),
        config_summary={
            "rate_limit": config.scan.rate_limit,
            "workers": config.scan.workers,
            "providers": [p.name for p in provs],
            "metadata_only": config.safety.metadata_only,
        },
    )
    logger.info(
        "Scan %s finished: %d targets, %d findings",
        scan_id, result.targets_tested, len(result.findings),
    )
    return result
