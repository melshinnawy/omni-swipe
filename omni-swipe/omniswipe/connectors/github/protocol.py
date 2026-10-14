import base64
import json
import time
import urllib.error
import urllib.request
from typing import Iterator, Optional, Tuple

from omniswipe.connectors.base.protocol import ProtocolAdapter

API = "https://api.github.com"
MAX_FILES_PER_REPO = 200
MAX_FILE_BYTES = 200_000
TEXT_EXT_SKIP = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".woff", ".woff2",
                 ".ico", ".exe", ".bin", ".lock", ".so", ".dll", ".jar")


class GitHubProtocol(ProtocolAdapter):
    """GitHub REST client: auth, pagination, rate-limit handling. Scope: one user or org."""

    def __init__(self, token: Optional[str], owner: str, owner_kind: str = "user",
                 max_repos: int = 50):
        self.token = token
        self.owner = owner
        self.owner_kind = owner_kind  # "user" | "org" | "self" (token's own repos)
        self.max_repos = max_repos

    def _get(self, url: str):
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omniswipe",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
        })
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read().decode()), r.headers
            except urllib.error.HTTPError as e:
                if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
                    reset = int(e.headers.get("X-RateLimit-Reset", "0"))
                    time.sleep(min(max(reset - time.time(), 1), 60))
                    continue
                raise
        raise RuntimeError("GitHub rate limit not cleared after retries")

    def _paginate(self, url: str) -> Iterator[dict]:
        page = 1
        while True:
            sep = "&" if "?" in url else "?"
            data, _ = self._get(f"{url}{sep}per_page=100&page={page}")
            if not data:
                return
            yield from data
            page += 1

    def discover(self) -> Iterator[dict]:
        if self.owner_kind == "org":
            url = f"{API}/orgs/{self.owner}/repos?type=all"
        elif self.owner_kind == "self":
            url = f"{API}/user/repos?affiliation=owner"
        else:
            url = f"{API}/users/{self.owner}/repos"
        for i, repo in enumerate(self._paginate(url)):
            if i >= self.max_repos:
                return
            yield repo

    def read_content(self, raw: dict) -> Iterator[Tuple[str, str]]:
        full, branch = raw["full_name"], raw.get("default_branch", "main")
        try:
            tree, _ = self._get(f"{API}/repos/{full}/git/trees/{branch}?recursive=1")
        except urllib.error.HTTPError:
            return  # empty repo or no access
        n = 0
        for item in tree.get("tree", []):
            if item["type"] != "blob" or item.get("size", 0) > MAX_FILE_BYTES:
                continue
            if item["path"].lower().endswith(TEXT_EXT_SKIP):
                continue
            if n >= MAX_FILES_PER_REPO:
                break
            blob, _ = self._get(f"{API}/repos/{full}/git/blobs/{item['sha']}")
            try:
                text = base64.b64decode(blob["content"]).decode("utf-8")
            except (UnicodeDecodeError, KeyError, ValueError):
                continue
            n += 1
            yield item["path"], text
