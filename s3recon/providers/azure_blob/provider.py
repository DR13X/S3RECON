"""Azure Blob Storage provider adapter - read-only."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
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


class AzureBlobProvider(CloudProvider):
    name = "azure"
    provider_enum = Provider.AZURE_BLOB.value

    def __init__(self, config: Config, rate_limiter: Optional[RateLimiter] = None) -> None:
        super().__init__(config, rate_limiter)

    def _urls_for_container(self, name: str) -> List[str]:
        urls = [
            f"https://{name}.blob.core.windows.net/?comp=list",
            f"https://{name}.blob.core.windows.net/",
        ]
        if "/" in name:
            account, container = name.split("/", 1)
            urls.insert(0, f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list")
            urls.insert(0, f"https://{account}.blob.core.windows.net/{container}")
        return urls

    async def check_existence(self, name: str) -> Finding:
        evidence = Evidence(method="GET", url=None)
        finding_type = ExposureType.UNKNOWN
        risk = RiskLevel.LOW
        notes: List[str] = []
        status = None
        headers: dict = {}
        body = None
        used_url = None

        for url in self._urls_for_container(name):
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
            notes.append("Resource may exist but public access denied")
        elif status == 200:
            if body and ("<EnumerationResults" in body or "<Blobs>" in body or "<Containers>" in body):
                finding_type = ExposureType.PUBLIC_LISTABLE
                risk = RiskLevel.MEDIUM
                notes.append("Public listing accessible")
            else:
                finding_type = ExposureType.PUBLIC_READABLE
                risk = RiskLevel.HIGH
                notes.append("200 OK on Azure blob endpoint")
        else:
            finding_type = ExposureType.UNKNOWN
            risk = RiskLevel.LOW
            notes.append(f"Status {status}")

        remediation = DEFAULT_REMEDIATIONS.get(
            finding_type, DEFAULT_REMEDIATIONS[ExposureType.UNKNOWN]
        )
        return Finding(
            target=name,
            provider=Provider.AZURE_BLOB,
            finding_type=finding_type,
            risk_level=risk,
            evidence=evidence,
            remediation=remediation,
            notes="; ".join(notes) if notes else None,
        )

    async def list_objects(self, name: str, max_keys: int = 50) -> List[ObjectMetadata]:
        max_keys = min(max_keys, self.config.safety.max_objects_listed)
        objects: List[ObjectMetadata] = []
        if "/" in name:
            account, container = name.split("/", 1)
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&maxresults={max_keys}"
        else:
            url = f"https://{name}.blob.core.windows.net/?comp=list&maxresults={max_keys}"
        status, _, body = await safe_request(
            "GET", url, timeout=self.config.scan.timeout, rate_limiter=self.rate_limiter
        )
        if status != 200 or not body:
            return objects
        try:
            root = ET.fromstring(body)
            for blob in root.findall(".//Blob")[:max_keys]:
                name_el = blob.find("Name")
                props = blob.find("Properties")
                size = last_mod = content_type = etag = None
                if props is not None:
                    cl = props.find("Content-Length")
                    if cl is not None and cl.text:
                        size = int(cl.text)
                    lm = props.find("Last-Modified")
                    if lm is not None:
                        last_mod = lm.text
                    ct = props.find("Content-Type")
                    if ct is not None:
                        content_type = ct.text
                    et = props.find("Etag")
                    if et is not None:
                        etag = et.text
                if name_el is not None and name_el.text:
                    objects.append(
                        ObjectMetadata(
                            name=name_el.text, size=size, last_modified=last_mod,
                            content_type=content_type, etag=etag,
                        )
                    )
        except ET.ParseError as exc:
            logger.debug("Failed to parse Azure listing for %s: %s", name, exc)
        return objects

    def build_candidate_names(self, seed: str, wordlist: Optional[List[str]] = None) -> List[str]:
        seed = seed.lower().strip().replace(" ", "").replace("_", "").replace(".", "")
        base = seed[:24]
        candidates = {
            base, f"{base}storage", f"{base}data", f"{base}backup",
            f"{base}assets", f"{base}prod", f"{base}dev", f"st{base}",
        }
        if wordlist:
            for word in wordlist:
                w = word.strip().lower().replace("-", "").replace("_", "")[:10]
                if w:
                    candidates.add(f"{base}{w}"[:24])
        return sorted(c for c in candidates if 3 <= len(c) <= 24 and c.isalnum())
