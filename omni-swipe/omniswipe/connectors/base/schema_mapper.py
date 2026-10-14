from abc import ABC, abstractmethod
import hashlib
from typing import List, Tuple

from omniswipe.udm.models import Asset, Permission, Record, Relation

PREVIEW_CHARS = 500


class SchemaMapper(ABC):
    """Translates system-specific raw data into UDM. No network access here."""

    @abstractmethod
    def map_asset(self, raw: dict) -> Asset: ...

    @abstractmethod
    def map_permissions(self, raw: dict) -> List[Permission]: ...

    @abstractmethod
    def map_relations(self, raw: dict, asset: Asset) -> List[Relation]: ...

    def map_records(self, asset: Asset, contents: List[Tuple[str, str]]) -> List[Record]:
        """Default: one Record per (location, text). Override if a system needs more."""
        out = []
        for location, text in contents:
            data = text.encode("utf-8", errors="replace")
            out.append(Record(
                asset_id=asset.id,
                location=location,
                content_hash=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
                content_preview=text[:PREVIEW_CHARS],
            ))
        return out
