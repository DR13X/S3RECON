"""Provider registry and factory."""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from s3recon.config.schema import Config
from s3recon.providers.azure_blob.provider import AzureBlobProvider
from s3recon.providers.aws_s3.provider import S3Provider
from s3recon.providers.base import CloudProvider
from s3recon.providers.gcp_storage.provider import GCSProvider
from s3recon.utils.rate_limit import RateLimiter

_REGISTRY: Dict[str, Type[CloudProvider]] = {
    "s3": S3Provider,
    "aws": S3Provider,
    "aws_s3": S3Provider,
    "gcs": GCSProvider,
    "gcp": GCSProvider,
    "gcp_storage": GCSProvider,
    "azure": AzureBlobProvider,
    "azure_blob": AzureBlobProvider,
}


def get_provider(
    name: str, config: Config, rate_limiter: Optional[RateLimiter] = None
) -> CloudProvider:
    key = name.lower().strip()
    cls = _REGISTRY.get(key)
    if cls is None:
        raise ValueError(
            f"Unknown provider '{name}'. Supported: {', '.join(sorted(set(_REGISTRY.keys())))}"
        )
    return cls(config, rate_limiter)


def list_providers() -> List[str]:
    return ["s3", "gcs", "azure"]


def get_all_providers(
    config: Config,
    rate_limiter: Optional[RateLimiter] = None,
    names: Optional[List[str]] = None,
) -> List[CloudProvider]:
    selected = names or config.providers or list_providers()
    return [get_provider(n, config, rate_limiter) for n in selected]
