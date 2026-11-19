"""Google Cloud Storage provider adapter - read-only."""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from s3recon.config.schema import Config
from s3recon.models.findings import (
    DEFAULT_REMEDIATIONS,
    Evidence,
    ExposureType,
    Finding,
    ObjectMetadata,
    Provider,
    RiskLevel,
)
from s3recon.providers.base import CloudProvider
from s3recon.utils.http import safe_request
from s3recon.utils.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


class GCSProvider(CloudProvider):
    name = "gcs"
    provider_enum = Provider.GCP_STORAGE.value

    def __init__(self, config: Config, rate_limiter: Optional[RateLimiter] = None) -> None:
        super().__init__(config, rate_limiter)

    def _urls_for_bucket(self, bucket: str) -> List[str]:
        return [
            f"https://storage.googleapis.com/{bucket}",
            f"https://storage.googleapis.com/storage/v1/b/{bucket}",
            f"https://{bucket}.storage.googleapis.com/",
        ]

    async def check_existence(self, name: str) -> Finding:
        evidence = Evidence(method="GET", url=None)
        finding_type = ExposureType.UNKNOWN
        risk = RiskLevel.LOW
        notes: List[str] = []
        status = None
        headers: dict = {}
        body = None
        used_url = None

        for url in self._urls_for_bucket(name):
            status, headers, body = await safe_request(
                "GET", url,
                timeout=self.config.scan.timeout,
                rate_limiter=self.rate_limiter,
                max_retries=self.config.scan.max_retries,
                backoff_factor=self.config.scan.backoff_factor,
            )
            used_url = url
            if status is not None:
                break

        evidence.status_code = status
        evidence.response_headers = headers or {}
        evidence.response_snippet = body
        evidence.url = used_url

        if status is None:
            finding_type = ExposureType.ERROR
            risk = RiskLevel.LOW
        elif status == 404:
            finding_type = ExposureType.NON_EXISTENT
            risk = RiskLevel.INFORMATIONAL
        elif status == 403:
            finding_type = ExposureType.ACCESS_DENIED
            risk = RiskLevel.INFORMATIONAL
            notes.append("Bucket may exist but public access denied")
        elif status == 200:
            if body and ("items" in body or "kind" in body or "<ListBucketResult" in body):
                finding_type = ExposureType.PUBLIC_LISTABLE
                risk = RiskLevel.MEDIUM
                notes.append("Public listing or metadata accessible")
            else:
                finding_type = ExposureType.PUBLIC_READABLE
                risk = RiskLevel.HIGH
                notes.append("200 OK on bucket endpoint")
        else:
            finding_type = ExposureType.UNKNOWN
            risk = RiskLevel.LOW
            notes.append(f"Status {status}")

        remediation = DEFAULT_REMEDIATIONS.get(
            finding_type, DEFAULT_REMEDIATIONS[ExposureType.UNKNOWN]
        )
        return Finding(
            target=name,
            provider=Provider.GCP_STORAGE,
            finding_type=finding_type,
            risk_level=risk,
            evidence=evidence,
            remediation=remediation,
            notes="; ".join(notes) if notes else None,
        )

    async def list_objects(self, name: str, max_keys: int = 50) -> List[ObjectMetadata]:
        max_keys = min(max_keys, self.config.safety.max_objects_listed)
        objects: List[ObjectMetadata] = []
        url = f"https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults={max_keys}"
        status, _, body = await safe_request(
            "GET", url, timeout=self.config.scan.timeout, rate_limiter=self.rate_limiter
        )
        if status != 200 or not body:
            return objects
        try:
            data = json.loads(body)
            for item in data.get("items", [])[:max_keys]:
                objects.append(
                    ObjectMetadata(
                        name=item.get("name", ""),
                        size=int(item["size"]) if item.get("size") else None,
                        last_modified=item.get("updated") or item.get("timeCreated"),
                        content_type=item.get("contentType"),
                        etag=item.get("etag"),
                    )
                )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            logger.debug("Failed to parse GCS listing for %s: %s", name, exc)
        return objects

    def build_candidate_names(self, seed: str, wordlist: Optional[List[str]] = None) -> List[str]:
        seed = seed.lower().strip().replace(" ", "-").replace("_", "-")
        base = seed.split(".")[0] if "." in seed else seed
        candidates = {
            seed, base, f"{base}-backup", f"{base}-assets", f"{base}-public",
            f"{base}-data", f"{base}-static", f"{base}-dev", f"{base}-prod",
            f"gs-{base}", f"{base}-gcs",
        }
        if wordlist:
            for word in wordlist:
                w = word.strip().lower()
                if w:
                    candidates.add(f"{base}-{w}")
                    candidates.add(f"{w}-{base}")
        return sorted(c for c in candidates if 3 <= len(c) <= 63)
