from abc import ABC, abstractmethod
from typing import Iterator, Tuple


class ProtocolAdapter(ABC):
    """Talks to the system (auth, pagination, rate limits). Returns RAW dicts only."""

    @abstractmethod
    def discover(self) -> Iterator[dict]:
        """Yield one raw dict per top-level asset."""

    @abstractmethod
    def read_content(self, raw: dict) -> Iterator[Tuple[str, str]]:
        """Yield (location, text) pairs for text content of a raw asset."""
