import argparse
import json
import os
import sys

from omniswipe.connectors.filesystem.connector import FilesystemConnector
from omniswipe.connectors.github.connector import GitHubConnector
from omniswipe.engine.orchestrator import run_scan
from omniswipe.output.json_reporter import summarize, write_json


def _build_connectors(args):
    conns = []
    for name in [c.strip() for c in args.connectors.split(",") if c.strip()]:
        if name == "filesystem":
            conns.append(FilesystemConnector(args.path))
        elif name == "github":
            token = os.environ.get("GITHUB_TOKEN")
            owner = args.github_owner
            kind = args.github_kind
            if not owner and not token:
                sys.exit("github: pass --github-owner or set GITHUB_TOKEN")
            conns.append(GitHubConnector(token, owner or "", "self" if not owner else kind,
                                         args.max_repos))
        else:
            sys.exit(f"unknown connector: {name}")
    return conns


def main(argv=None):
    p = argparse.ArgumentParser(prog="omniswipe")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--connectors", default="filesystem")
        sp.add_argument("--path", default=".", help="filesystem root")
        sp.add_argument("--github-owner")
        sp.add_argument("--github-kind", choices=["user", "org"], default="user")
        sp.add_argument("--max-repos", type=int, default=50)
        sp.add_argument("--output", "-o", default=None)

    common(sub.add_parser("discover", help="list assets only (no content read)"))
    common(sub.add_parser("scan", help="discover + extract + classify"))
    rp = sub.add_parser("report", help="summarize a scan JSON")
    rp.add_argument("--input", "-i", required=True)

    args = p.parse_args(argv)

    if args.cmd == "report":
        print(summarize(json.load(open(args.input))))
        return 0

    result = run_scan(_build_connectors(args), classify=(args.cmd == "scan"))
    data = result.to_dict()
    if args.output:
        write_json(data, args.output)
    print(summarize(data))
    # Non-zero exit when secrets are found, so CI can gate on it.
    return 2 if (args.cmd == "scan" and data["summary"]["secrets"]) else 0


if __name__ == "__main__":
    sys.exit(main())
