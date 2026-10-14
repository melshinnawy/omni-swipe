"""Classification: secret detection + basic PII. Works on Record, source-agnostic.

Secret values are never stored. Only rule name, location and a redacted sample.
"""
import re
from typing import List, Tuple

from omniswipe.udm.models import Record, Secret, SensitivityLevel

# (type, severity, regex)
SECRET_RULES = [
    ("aws_access_key", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", "critical", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github_fine_grained_token", "critical", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("private_key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("slack_token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_live_key", "critical", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("generic_credential", "medium",
     re.compile(r"""(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["']([^"'\s]{8,})["']""")),
]

PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]|<.*>|xxxx|dummy|placeholder|\$\{|\{\{)")

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _redact(s: str) -> str:
    return s[:4] + "…" + "*" * 4 if len(s) > 8 else "*" * len(s)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def detect_secrets(text: str, location: str) -> List[Secret]:
    found: List[Secret] = []
    for stype, sev, rx in SECRET_RULES:
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            if stype == "generic_credential" and PLACEHOLDER.search(value):
                continue
            found.append(Secret(
                type=stype, exposure="committed", severity=sev,
                location=f"{location}:L{_line_of(text, m.start())}",
                matched_pattern=stype, redacted_sample=_redact(value),
            ))
    return found


def detect_pii(text: str) -> List[str]:
    fields = set()
    if EMAIL.search(text):
        fields.add("email")
    if SSN.search(text):
        fields.add("ssn")
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            fields.add("credit_card")
            break
    return sorted(fields)


def classify_record(record: Record, text: str) -> Record:
    secrets = detect_secrets(text, record.location or record.asset_id)
    pii = detect_pii(text)
    record.secrets_found = secrets
    record.pii_fields = pii
    cls = []
    if secrets:
        cls.append("secret")
    if pii:
        cls.append("pii")
    record.classifications = cls
    if any(s.severity in ("critical", "high") for s in secrets) or {"ssn", "credit_card"} & set(pii):
        record.sensitivity = SensitivityLevel.RESTRICTED
    elif secrets or pii:
        record.sensitivity = SensitivityLevel.CONFIDENTIAL
    return record
