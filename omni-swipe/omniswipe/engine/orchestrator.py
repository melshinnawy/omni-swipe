import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, List

from omniswipe.connectors.base.connector import Connector
from omniswipe.engine.classifier import classify_record
from omniswipe.udm.models import Asset, Record, Relation, SensitivityLevel


class ScanResult:
    def __init__(self):
        self.scan_id = uuid.uuid4().hex[:8]
        self.timestamp = datetime.now(timezone.utc)
        self.assets: List[Asset] = []
        self.records: List[Record] = []
        self.relations: List[Relation] = []
        self.errors: List[str] = []

    def to_dict(self) -> dict:
        by_asset = defaultdict(list)
        for r in self.records:
            by_asset[r.asset_id].append(r)
        secrets = [s.model_dump(mode="json") for r in self.records for s in r.secrets_found]
        assets_out = []
        for a in self.assets:
            recs = by_asset.get(a.id, [])
            assets_out.append({
                "id": a.id, "source_system": a.source_system, "asset_type": a.asset_type.value,
                "name": a.name, "sensitivity": a.sensitivity.value,
                "secrets_found": sum(len(r.secrets_found) for r in recs),
                "pii_fields": sorted({f for r in recs for f in r.pii_fields}),
            })
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "assets": len(self.assets),
                "secrets": len(secrets),
                "pii": sum(1 for r in self.records if r.pii_fields),
                "systems": sorted({a.source_system for a in self.assets}),
                "errors": len(self.errors),
            },
            "assets": assets_out,
            "secrets": secrets,
            "relations": [r.model_dump(mode="json") for r in self.relations],
            "errors": self.errors,
        }


def run_scan(connectors: Iterable[Connector], classify: bool = True) -> ScanResult:
    result = ScanResult()
    for conn in connectors:
        try:
            for d in conn.discover(with_content=classify):
                records = conn.mapper.map_records(d.asset, d.contents)
                text_by_loc = dict(d.contents)
                top = SensitivityLevel.PUBLIC
                for rec in records:
                    classify_record(rec, text_by_loc.get(rec.location, ""))
                    # Raw text is dropped here. Only the preview of non-sensitive records is kept.
                    if rec.secrets_found or rec.pii_fields:
                        rec.content_preview = None
                    if rec.sensitivity.rank > top.rank:
                        top = rec.sensitivity
                d.asset.sensitivity = top
                result.assets.append(d.asset)
                result.records.extend(r for r in records if r.classifications)
                result.relations.extend(d.relations)
        except Exception as e:  # one broken connector must not kill the scan
            result.errors.append(f"{conn.name}: {type(e).__name__}: {e}")
    return result
