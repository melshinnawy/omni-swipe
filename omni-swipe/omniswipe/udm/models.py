"""Universal Data Model (UDM). The engine only ever sees these types."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class SensitivityLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return ["public", "internal", "confidential", "restricted"].index(self.value)


class AssetType(str, Enum):
    # Infrastructure
    REPOSITORY = "repository"
    STORAGE_ACCOUNT = "storage_account"
    DATABASE = "database"
    SERVER = "server"
    CONTAINER = "container"
    # SaaS
    SITE = "site"
    DOCUMENT = "document"
    RECORD = "record"
    TICKET = "ticket"
    # Identity
    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    ROLE = "role"
    # Data
    DIRECTORY = "directory"
    FILE = "file"
    TABLE = "table"
    BUCKET = "bucket"
    API_ENDPOINT = "api_endpoint"
    UNKNOWN = "unknown"


class Permission(BaseModel):
    actor: str          # user, group or service account
    action: str         # read | write | admin | delete
    scope: str          # repo | org | bucket | resource
    granted_by: str     # role, policy or ACL


class Secret(BaseModel):
    type: str           # aws_access_key, github_token, private_key ...
    exposure: str       # committed | hardcoded | env_var
    severity: str       # critical | high | medium
    location: str       # path[:line] or URL
    matched_pattern: str  # rule name. The secret value itself is NEVER stored.
    redacted_sample: str = ""


class Asset(BaseModel):
    """The universal asset. Everything is an Asset."""
    id: str             # globally unique: "<source_system>:<type>:<native id>"
    source_system: str
    asset_type: AssetType
    name: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    owners: List[str] = Field(default_factory=list)
    permissions: List[Permission] = Field(default_factory=list)
    sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC
    tags: List[str] = Field(default_factory=list)

    @field_validator("id", mode="before")
    @classmethod
    def _id_to_str(cls, v: Any) -> str:
        return str(v)


class Record(BaseModel):
    """Content-level facts about an asset (or a part of it), separate from asset metadata."""
    asset_id: str
    location: str = ""  # e.g. file path inside a repo
    content_hash: str   # SHA-256
    size_bytes: int
    content_preview: Optional[str] = None
    classifications: List[str] = Field(default_factory=list)  # pii, secret, financial
    sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC
    pii_fields: List[str] = Field(default_factory=list)
    secrets_found: List[Secret] = Field(default_factory=list)


class Relation(BaseModel):
    """Graph edge."""
    source_asset_id: str
    target_asset_id: str
    relation_type: str  # contains | owns | accesses | flows_to
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: Optional[str] = None


class ArtifactRef(BaseModel):
    kind: str           # "scan_record", "api_response", "screenshot"
    uri: str


class Evidence(BaseModel):
    """Compliance evidence (used from v0.2)."""
    control_id: str     # e.g. "ASC-001"
    asset_id: str
    finding_type: str   # pass | fail | partial
    description: str
    artifacts: List[ArtifactRef] = Field(default_factory=list)
    collected_at: datetime
