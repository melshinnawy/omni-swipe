from typing import Optional

from omniswipe.connectors.base.connector import Connector
from omniswipe.connectors.github.protocol import GitHubProtocol
from omniswipe.connectors.github.schema_mapper import GitHubSchemaMapper


class GitHubConnector(Connector):
    name = "github"

    def __init__(self, token: Optional[str], owner: str, owner_kind: str = "user",
                 max_repos: int = 50):
        super().__init__(GitHubProtocol(token, owner, owner_kind, max_repos), GitHubSchemaMapper())
