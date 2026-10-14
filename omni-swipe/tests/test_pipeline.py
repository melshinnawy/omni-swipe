from omniswipe.connectors.filesystem.connector import FilesystemConnector
from omniswipe.engine.classifier import detect_pii, detect_secrets
from omniswipe.engine.orchestrator import run_scan
from omniswipe.udm.models import SensitivityLevel


def _fake_aws_key():
    return "AKIA" + "ABCDEFGHIJKLMNOP"  # built at runtime so this file doesn't trip scanners


def test_secret_detection_redacts_value():
    s = detect_secrets(f"key = '{_fake_aws_key()}'", "cfg.py")
    assert s and s[0].type == "aws_access_key"
    assert _fake_aws_key() not in s[0].redacted_sample
    assert s[0].location == "cfg.py:L1"


def test_placeholder_credentials_ignored():
    assert detect_secrets('password = "changeme123"', "x") == []


def test_pii_luhn():
    assert "credit_card" in detect_pii("card 4111 1111 1111 1111")
    assert "credit_card" not in detect_pii("order 1234 5678 9012 3456")
    assert "email" in detect_pii("mail me: a@b.co")


def test_filesystem_end_to_end(tmp_path):
    (tmp_path / "ok.txt").write_text("hello")
    (tmp_path / "bad.py").write_text(f"AWS = '{_fake_aws_key()}'\n")
    res = run_scan([FilesystemConnector(str(tmp_path))])
    d = res.to_dict()
    assert d["summary"]["secrets"] == 1
    bad = next(a for a in d["assets"] if a["name"] == "bad.py")
    assert bad["sensitivity"] == SensitivityLevel.RESTRICTED.value
    assert any(r.relation_type == "contains" for r in res.relations)
    assert d["summary"]["systems"] == ["filesystem"]
