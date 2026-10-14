# OMNI-SWIPE

Discover, classify and map sensitive data across systems through one Universal Data Model (UDM).

```
Connector = ProtocolAdapter (talks to API)  +  SchemaMapper (raw -> UDM)
Engine only ever sees UDM: Asset, Record, Secret, Permission, Relation, Evidence
```

## Quick start
```bash
pip install -e ".[dev]"
pytest
omniswipe scan --connectors filesystem --path . -o scan.json
GITHUB_TOKEN=... omniswipe scan --connectors github,filesystem --path ./src --github-owner myorg --github-kind org
omniswipe report -i scan.json
```
`scan` exits with code 2 when secrets are found (CI gate). Secret values are never stored, only rule, location and a redacted sample.

## Adding a system
1. `connectors/<name>/protocol.py` (subclass `ProtocolAdapter`)
2. `connectors/<name>/schema_mapper.py` (subclass `SchemaMapper`)
3. `connectors/<name>/connector.py` wiring both. The engine needs zero changes.

## Roadmap
- v0.1 (this): UDM, github + filesystem, regex secrets + PII, CLI
- v0.2: policy engine (YAML), Evidence + ASC reporter, Azure connector, gitleaks wrapper
- v0.3: Neo4j graph, lineage (`flows_to`, `copied_to`)
