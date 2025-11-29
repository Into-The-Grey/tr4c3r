"""Username variant generation helpers.

This module contains functions for generating common variants of a given
username.  Variants are useful for fuzzy OSINT searches, where a subject may
use slightly different handles across platforms.  Only generate plausible
variants to avoid unnecessary network requests.
"""

from __future__ import annotations

import itertools
import re
from typing import Iterable, List, Set


def generate_variants(username: str, max_variants: int = 50) -> List[str]:
    """Generate a list of plausible username variants.

    Variants include added separators, appended numbers and common character
    substitutions (e.g. ``0`` <-> ``o``).  The number of generated variants
    is capped by ``max_variants`` to prevent combinatorial explosion.

    Parameters
    ----------
    username: str
        The base username.
    max_variants: int
        Maximum number of variants to return.
    """
    variants: Set[str] = {username}

    # Insert common separators
    separators = [".", "_", "-"]
    for sep in separators:
        variants.add(f"{username}{sep}")
        variants.add(f"{sep}{username}")
        variants.add(f"{username}{sep}{username}")

    # Append year suffixes (e.g. birth year or 2‑digit year)
    for year in range(1970, 2025):
        variants.add(f"{username}{year}")
    for yy in range(70, 100):
        variants.add(f"{username}{yy}")

    # Character substitutions
    substitutions = {"o": "0", "0": "o", "l": "1", "1": "l"}
    for pattern, replacement in substitutions.items():
        if pattern in username:
            variants.add(username.replace(pattern, replacement))

    # Always preserve the original username at the start
    limited = [username] + [v for v in variants if v != username]
    return limited[:max_variants]
