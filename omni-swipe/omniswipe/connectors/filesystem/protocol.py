import os
from pathlib import Path
from typing import Iterator, Tuple

from omniswipe.connectors.base.protocol import ProtocolAdapter

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
MAX_BYTES = 1_000_000


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


class FilesystemProtocol(ProtocolAdapter):
    def __init__(self, root: str):
        self.root = Path(root).resolve()

    def discover(self) -> Iterator[dict]:
        yield {"kind": "directory", "path": str(self.root), "root": str(self.root),
               "stat": self._stat(self.root)}
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.is_symlink():
                    continue
                try:
                    yield {"kind": "file", "path": str(p), "root": str(self.root),
                           "stat": self._stat(p)}
                except OSError:
                    continue

    @staticmethod
    def _stat(p: Path) -> dict:
        st = p.stat()
        return {"mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid,
                "size": st.st_size, "mtime": st.st_mtime, "ctime": st.st_ctime}

    def read_content(self, raw: dict) -> Iterator[Tuple[str, str]]:
        if raw["kind"] != "file" or raw["stat"]["size"] > MAX_BYTES:
            return
        try:
            with open(raw["path"], "rb") as f:
                data = f.read(MAX_BYTES)
        except OSError:
            return
        if _looks_binary(data[:4096]):
            return
        yield os.path.relpath(raw["path"], raw["root"]), data.decode("utf-8", errors="replace")
