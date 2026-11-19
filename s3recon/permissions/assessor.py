"""Permission assessment orchestrator."""

from __future__ import annotations

import asyncio
import logging
from typing import List

from s3recon.config.schema import Config
from s3recon.models.findings import ExposureType, Finding, RiskLevel
from s3recon.providers.base import CloudProvider
from s3recon.utils.rate_limit import ConcurrencyLimiter, RateLimiter

logger = logging.getLogger(__name__)


def map_risk(finding_type: ExposureType, config: Config) -> RiskLevel:
    risk_cfg = config.risk
    mapping = {
        ExposureType.PUBLIC_WRITABLE: risk_cfg.public_writable,
        ExposureType.PUBLIC_READABLE: risk_cfg.public_readable,
        ExposureType.PUBLIC_LISTABLE: risk_cfg.public_listable,
        ExposureType.AUTHENTICATED_ONLY: risk_cfg.authenticated_only,
        ExposureType.NON_EXISTENT: risk_cfg.non_existent,
        ExposureType.ACCESS_DENIED: risk_cfg.access_denied,
        ExposureType.UNKNOWN: risk_cfg.unknown,
        ExposureType.ERROR: risk_cfg.error,
    }
    level_str = mapping.get(finding_type, "low")
    try:
        return RiskLevel(level_str.lower())
    except ValueError:
        return RiskLevel.LOW


async def assess_one(
    provider: CloudProvider, name: str, config: Config, concurrency: ConcurrencyLimiter
) -> Finding:
    async with concurrency:
        logger.debug("Assessing %s via %s", name, provider.name)
        finding = await provider.check_existence(name)
        finding.risk_level = map_risk(finding.finding_type, config)
        if (
            finding.finding_type == ExposureType.PUBLIC_LISTABLE
            and config.safety.metadata_only
            and not config.safety.download_content
        ):
            try:
                objects = await provider.list_objects(
                    name, max_keys=config.safety.max_objects_listed
                )
                finding.objects = objects
                if objects:
                    finding.notes = (
                        (finding.notes or "")
                        + f"; Listed {len(objects)} object(s) (metadata only)"
                    ).strip("; ")
            except Exception as exc:
                logger.debug("Object listing failed for %s: %s", name, exc)
        return finding


async def assess_targets(
    providers: List[CloudProvider], targets: List[str], config: Config
) -> List[Finding]:
    rate_limiter = RateLimiter(config.scan.rate_limit)
    for p in providers:
        p.rate_limiter = rate_limiter
    concurrency = ConcurrencyLimiter(config.scan.workers)
    tasks = [
        assess_one(provider, target, config, concurrency)
        for target in targets
        for provider in providers
    ]
    results: List[Finding] = []
    if not tasks:
        return results
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for item in gathered:
        if isinstance(item, Exception):
            logger.error("Assessment task failed: %s", item)
            continue
        results.append(item)
    return results
