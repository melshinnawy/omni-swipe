from omniswipe.connectors.base.connector import Connector
from omniswipe.connectors.filesystem.protocol import FilesystemProtocol
from omniswipe.connectors.filesystem.schema_mapper import FilesystemSchemaMapper


class FilesystemConnector(Connector):
    name = "filesystem"

    def __init__(self, root: str):
        super().__init__(FilesystemProtocol(root), FilesystemSchemaMapper())
