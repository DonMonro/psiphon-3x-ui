"""Psiphon-3X-UI management panel.

A FastAPI application that installs Psiphon alongside Sanaei's 3x-ui, exposes a
first-run setup wizard, and clones 3x-ui inbounds per selected country.

This is a Phase-0 skeleton; routers and runtime logic land in later phases.
See ``plans/ROADMAP.md`` for the full plan.
"""

import json
import re
from functools import lru_cache
from pathlib import Path

__version__ = "1.1.0"
_BUILD_METADATA = Path(__file__).resolve().parent / "data" / "build.json"


@lru_cache(maxsize=1)
def get_build_revision() -> str | None:
    """Identity of this running wheel, never inferred from a mutable checkout.

    Legacy wheels and dirty development builds have no known revision. A marker
    from another package version must not make this process claim that build.
    """
    try:
        with _BUILD_METADATA.open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return None
        marker = json.loads(raw)
        if not isinstance(marker, dict) or marker.get("version") != __version__:
            return None
        revision = marker.get("revision")
        if isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision):
            return revision
    except (OSError, ValueError):
        pass
    return None
