from __future__ import annotations

import random
from typing import List, Optional


def load_tranco_domains(list_path: str) -> List[str]:
    domains: List[str] = []
    with open(list_path, "r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            if "," in text:
                _, domain = text.split(",", 1)
                domain = domain.strip()
            else:
                domain = text
            if domain:
                domains.append(domain)
    return domains


def sample_tranco_domains(list_path: str, sample_size: int, seed: Optional[int] = None) -> List[str]:
    domains = load_tranco_domains(list_path)
    if seed is not None:
        random.seed(seed)
    if sample_size >= len(domains):
        return domains
    return random.sample(domains, sample_size)
