"""Abstract base class for cloud storage providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from s3recon.config.schema import Config
from s3recon.models.findings import Finding, ObjectMetadata
from s3recon.utils.rate_limit import RateLimiter


class CloudProvider(ABC):
    name: str = "base"
    provider_enum: str = "base"

    def __init__(self, config: Config, rate_limiter: Optional[RateLimiter] = None) -> None:
        self.config = config
        self.rate_limiter = rate_limiter or RateLimiter(config.scan.rate_limit)

    @abstractmethod
    async def check_existence(self, name: str) -> Finding:
        ...

    @abstractmethod
    async def list_objects(self, name: str, max_keys: int = 50) -> List[ObjectMetadata]:
        ...

    @abstractmethod
    def build_candidate_names(self, seed: str, wordlist: Optional[List[str]] = None) -> List[str]:
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
