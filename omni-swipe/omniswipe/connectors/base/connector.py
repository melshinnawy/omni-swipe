from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator, List, Tuple

from omniswipe.connectors.base.protocol import ProtocolAdapter
from omniswipe.connectors.base.schema_mapper import SchemaMapper
from omniswipe.udm.models import Asset, Record, Relation


@dataclass
class DiscoveredAsset:
    asset: Asset
    relations: List[Relation] = field(default_factory=list)
    # (location, text) pairs. Kept as raw text only in memory, never persisted.
    contents: List[Tuple[str, str]] = field(default_factory=list)


class Connector(ABC):
    """Orchestrates one ProtocolAdapter and one SchemaMapper."""
    name: str

    def __init__(self, protocol: ProtocolAdapter, mapper: SchemaMapper):
        self.protocol = protocol
        self.mapper = mapper

    def discover(self, with_content: bool = True) -> Iterator[DiscoveredAsset]:
        for raw in self.protocol.discover():
            asset = self.mapper.map_asset(raw)
            asset.permissions = self.mapper.map_permissions(raw)
            relations = self.mapper.map_relations(raw, asset)
            contents = list(self.protocol.read_content(raw)) if with_content else []
            yield DiscoveredAsset(asset, relations, contents)
