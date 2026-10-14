import json
from pathlib import Path


def write_json(data: dict, path: str) -> None:
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def summarize(data: dict) -> str:
    s = data["summary"]
    lines = [f"Scan {data['scan_id']}: {s['assets']} assets, {s['secrets']} secrets, "
             f"{s['pii']} records with PII across {', '.join(s['systems']) or 'no systems'}"]
    for sec in data["secrets"]:
        lines.append(f"  [{sec['severity'].upper()}] {sec['type']} at {sec['location']}")
    for e in data.get("errors", []):
        lines.append(f"  ERROR {e}")
    return "\n".join(lines)
