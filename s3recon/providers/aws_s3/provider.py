"""Amazon S3 provider adapter - read-only, authorized reconnaissance only."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import List, Optional
from urllib.parse import quote

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


class S3Provider(CloudProvider):
    name = "s3"
    provider_enum = Provider.AWS_S3.value
    REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]

    def __init__(self, config: Config, rate_limiter: Optional[RateLimiter] = None) -> None:
        super().__init__(config, rate_limiter)

    def _urls_for_bucket(self, bucket: str) -> List[str]:
        urls = [
            f"https://{bucket}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{quote(bucket)}/",
        ]
        for region in self.REGIONS:
            urls.append(f"https://{bucket}.s3.{region}.amazonaws.com/")
            urls.append(f"https://s3.{region}.amazonaws.com/{quote(bucket)}/")
        return urls

    async def check_existence(self, name: str) -> Finding:
        evidence = Evidence(method="GET", url=None)
        finding_type = ExposureType.UNKNOWN
        risk = RiskLevel.LOW
        notes_parts: List[str] = []

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
            notes_parts.append("Network/timeout error while probing")
        elif status == 404:
            finding_type = ExposureType.NON_EXISTENT
            risk = RiskLevel.INFORMATIONAL
        elif status == 403:
            finding_type = ExposureType.ACCESS_DENIED
            risk = RiskLevel.INFORMATIONAL
            notes_parts.append("Bucket appears to exist but public access is denied")
        elif status == 200:
            if body and ("<ListBucketResult" in body or "<Contents" in body):
                finding_type = ExposureType.PUBLIC_LISTABLE
                risk = RiskLevel.MEDIUM
                notes_parts.append("Bucket listing is publicly accessible")
            else:
                finding_type = ExposureType.PUBLIC_READABLE
                risk = RiskLevel.HIGH
                notes_parts.append("Received 200 OK - possible public read")
        elif status in (301, 302, 307, 308):
            finding_type = ExposureType.UNKNOWN
            risk = RiskLevel.LOW
            notes_parts.append(f"Redirect ({status}) - may indicate region mismatch")
        else:
            finding_type = ExposureType.UNKNOWN
            risk = RiskLevel.LOW
            notes_parts.append(f"Unexpected status {status}")

        remediation = DEFAULT_REMEDIATIONS.get(
            finding_type, DEFAULT_REMEDIATIONS[ExposureType.UNKNOWN]
        )
        return Finding(
            target=name,
            provider=Provider.AWS_S3,
            finding_type=finding_type,
            risk_level=risk,
            evidence=evidence,
            remediation=remediation,
            notes="; ".join(notes_parts) if notes_parts else None,
        )

    async def list_objects(self, name: str, max_keys: int = 50) -> List[ObjectMetadata]:
        max_keys = min(max_keys, self.config.safety.max_objects_listed)
        objects: List[ObjectMetadata] = []
        url = f"https://{name}.s3.amazonaws.com/?list-type=2&max-keys={max_keys}"
        status, _, body = await safe_request(
            "GET", url, timeout=self.config.scan.timeout, rate_limiter=self.rate_limiter
        )
        if status != 200 or not body:
            return objects
        try:
            root = ET.fromstring(body)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            contents = root.findall(".//s3:Contents", ns) or root.findall(".//Contents")
            for item in contents[:max_keys]:
                key_el = item.find("s3:Key", ns) or item.find("Key")
                size_el = item.find("s3:Size", ns) or item.find("Size")
                mod_el = item.find("s3:LastModified", ns) or item.find("LastModified")
                etag_el = item.find("s3:ETag", ns) or item.find("ETag")
                key = key_el.text if key_el is not None else None
                if not key:
                    continue
                size = int(size_el.text) if size_el is not None and size_el.text else None
                objects.append(
                    ObjectMetadata(
                        name=key,
                        size=size,
                        last_modified=mod_el.text if mod_el is not None else None,
                        etag=etag_el.text.strip('"') if etag_el is not None and etag_el.text else None,
                    )
                )
        except ET.ParseError as exc:
            logger.debug("Failed to parse S3 listing XML for %s: %s", name, exc)
        return objects

    def build_candidate_names(self, seed: str, wordlist: Optional[List[str]] = None) -> List[str]:
        seed = seed.lower().strip().replace(" ", "-").replace("_", "-")
        base = seed.split(".")[0] if "." in seed else seed
        candidates = {
            seed, base,
            f"{base}-backup", f"{base}-backups", f"{base}-dev", f"{base}-prod",
            f"{base}-staging", f"{base}-assets", f"{base}-static", f"{base}-media",
            f"{base}-data", f"{base}-logs", f"{base}-public", f"{base}-private",
            f"backup-{base}", f"assets-{base}", f"{base}.com", f"{base}-s3",
        }
        if wordlist:
            for word in wordlist:
                w = word.strip().lower()
                if w:
                    candidates.add(f"{base}-{w}")
                    candidates.add(f"{w}-{base}")
                    candidates.add(w)
        return sorted(
            c for c in candidates
            if 3 <= len(c) <= 63 and c.replace("-", "").replace(".", "").isalnum()
        )
