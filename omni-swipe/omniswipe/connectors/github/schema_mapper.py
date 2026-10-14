from datetime import datetime
from typing import List, Optional

from omniswipe.connectors.base.schema_mapper import SchemaMapper
from omniswipe.udm.models import Asset, AssetType, Permission, Relation


def _dt(v: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None


class GitHubSchemaMapper(SchemaMapper):
    SYSTEM = "github"

    def map_asset(self, repo: dict) -> Asset:
        return Asset(
            id=f"{self.SYSTEM}:repo:{repo['id']}",
            source_system=self.SYSTEM,
            asset_type=AssetType.REPOSITORY,
            name=repo["full_name"],
            metadata={
                "description": repo.get("description"),
                "default_branch": repo.get("default_branch"),
                "visibility": repo.get("visibility", "private" if repo.get("private") else "public"),
                "archived": repo.get("archived", False),
                "fork": repo.get("fork", False),
            },
            owners=[repo["owner"]["login"]],
            created_at=_dt(repo.get("created_at")),
            updated_at=_dt(repo.get("updated_at")),
            tags=["public"] if not repo.get("private") else ["private"],
        )

    def map_permissions(self, repo: dict) -> List[Permission]:
        perms = repo.get("permissions") or {}
        mapping = {"admin": "admin", "push": "write", "pull": "read"}
        return [Permission(actor="authenticated_token", action=mapping[k], scope="repo",
                           granted_by="github_acl")
                for k, v in perms.items() if v and k in mapping]

    def map_relations(self, repo: dict, asset: Asset) -> List[Relation]:
        owner = repo["owner"]
        return [Relation(source_asset_id=f"github:{owner.get('type', 'User').lower()}:{owner['id']}",
                         target_asset_id=asset.id, relation_type="owns")]
