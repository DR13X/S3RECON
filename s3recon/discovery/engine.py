"""Discovery engine — generates candidate names within authorized scope."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Set

from s3recon.config.schema import Config, ScopeConfig
from s3recon.providers.base import CloudProvider

logger = logging.getLogger(__name__)


def load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        logger.warning("Wordlist not found: %s", path)
        return []
    words: List[str] = []
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w)
    return words


def extract_domain_seeds(domains: List[str]) -> List[str]:
    seeds: Set[str] = set()
    for d in domains:
        d = d.lower().strip().removeprefix("www.")
        seeds.add(d)
        parts = d.split(".")
        if parts:
            seeds.add(parts[0])
        for part in parts[:-1]:
            if len(part) >= 3:
                seeds.add(part)
    return sorted(seeds)


def passive_candidates_from_ct(domain: str) -> List[str]:
    domain = domain.lower().strip().removeprefix("www.")
    base = domain.split(".")[0]
    return [
        f"{base}-assets", f"{base}-static", f"{base}-media", f"{base}-cdn",
        f"cdn.{domain}", f"static.{domain}", f"assets.{domain}", f"media.{domain}",
        f"files.{domain}", f"storage.{domain}", f"backup.{domain}", f"data.{domain}",
    ]


def discover_candidates(
    config: Config,
    providers: List[CloudProvider],
    target: Optional[str] = None,
    wordlist_path: Optional[str] = None,
    passive: bool = False,
) -> List[str]:
    scope: ScopeConfig = config.scope
    candidates: Set[str] = set()

    for b in scope.buckets:
        candidates.add(b.lower().strip())

    seeds: List[str] = []
    if target:
        target = target.lower().strip()
        seeds.append(target)
        if "." in target:
            seeds.extend(extract_domain_seeds([target]))
        else:
            seeds.append(target)

    seeds.extend(extract_domain_seeds(scope.domains))
    wordlist = load_wordlist(wordlist_path)

    for seed in seeds:
        for provider in providers:
            for name in provider.build_candidate_names(seed, wordlist):
                candidates.add(name)
        if passive:
            for name in passive_candidates_from_ct(seed):
                token = name.split(".")[0] if "." in name else name
                candidates.add(token.lower())

    allowed: List[str] = []
    for c in sorted(candidates):
        if config.safety.require_scope and not scope.allow_any:
            if not scope.is_target_allowed(c) and c not in {b.lower() for b in scope.buckets}:
                if not any(s in c or c in s for s in seeds):
                    logger.debug("Skipping out-of-scope candidate: %s", c)
                    continue
        allowed.append(c)

    max_candidates = 500
    if len(allowed) > max_candidates:
        logger.warning("Truncating candidates from %d to %d", len(allowed), max_candidates)
        allowed = allowed[:max_candidates]

    logger.info("Discovered %d candidate names within scope", len(allowed))
    return allowed
