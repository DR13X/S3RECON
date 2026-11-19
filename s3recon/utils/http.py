"""Safe HTTP client helpers with retries and timeouts."""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Tuple

import httpx

from s3recon.utils.rate_limit import RateLimiter

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "S3RECON/1.0 (+https://github.com/DR13X/S3RECON)",
    "Accept": "*/*",
}


async def safe_request(
    method: str,
    url: str,
    *,
    timeout: float = 10.0,
    rate_limiter: Optional[RateLimiter] = None,
    max_retries: int = 2,
    backoff_factor: float = 0.5,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> Tuple[Optional[int], Dict[str, str], Optional[str]]:
    if rate_limiter:
        await rate_limiter.acquire()

    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    merged_headers.pop("Authorization", None)
    merged_headers.pop("authorization", None)

    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=allow_redirects, verify=True
            ) as client:
                resp = await client.request(method.upper(), url, headers=merged_headers)
                body_snippet = None
                if resp.content and len(resp.content) < 4096:
                    try:
                        body_snippet = resp.text[:1024]
                    except Exception:
                        body_snippet = None
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status_code, hdrs, body_snippet
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
            last_exc = exc
            if attempt < max_retries:
                delay = backoff_factor * (2**attempt)
                logger.debug("Request to %s failed (%s), retrying in %.1fs", url, exc, delay)
                await asyncio.sleep(delay)
            else:
                logger.debug("Request to %s ultimately failed: %s", url, exc)
    return None, {}, str(last_exc) if last_exc else "unknown error"
