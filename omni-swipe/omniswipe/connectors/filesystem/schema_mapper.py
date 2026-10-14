import os
import stat as stat_mod
from datetime import datetime, timezone
from typing import List

from omniswipe.connectors.base.schema_mapper import SchemaMapper
from omniswipe.udm.models import Asset, AssetType, Permission, Relation


def _ts(v: float) -> datetime:
    return datetime.fromtimestamp(v, tz=timezone.utc)


class FilesystemSchemaMapper(SchemaMapper):
    SYSTEM = "filesystem"

    def _id(self, raw: dict) -> str:
        t = "directory" if raw["kind"] == "directory" else "file"
        return f"{self.SYSTEM}:{t}:{raw['path']}"

    def map_asset(self, raw: dict) -> Asset:
        st = raw["stat"]
        is_dir = raw["kind"] == "directory"
        return Asset(
            id=self._id(raw),
            source_system=self.SYSTEM,
            asset_type=AssetType.DIRECTORY if is_dir else AssetType.FILE,
            name=os.path.relpath(raw["path"], raw["root"]) if not is_dir else raw["path"],
            metadata={"mode": oct(stat_mod.S_IMODE(st["mode"])), "size_bytes": st["size"]},
            owners=[str(st["uid"])],
            created_at=_ts(st["ctime"]),
            updated_at=_ts(st["mtime"]),
        )

    def map_permissions(self, raw: dict) -> List[Permission]:
        mode = raw["stat"]["mode"]
        out = []
        for who, shifts in (("owner", 6), ("group", 3), ("other", 0)):
            bits = (mode >> shifts) & 0b111
            for action, bit in (("read", 4), ("write", 2), ("execute", 1)):
                if bits & bit:
                    out.append(Permission(actor=who, action=action, scope="resource",
                                          granted_by="posix_mode"))
        return out

    def map_relations(self, raw: dict, asset: Asset) -> List[Relation]:
        if raw["path"] == raw["root"]:
            return []
        root_id = f"{self.SYSTEM}:directory:{raw['root']}"
        return [Relation(source_asset_id=root_id, target_asset_id=asset.id,
                         relation_type="contains")]
