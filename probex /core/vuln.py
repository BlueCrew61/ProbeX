"""Model dan format temuan untuk Vulnerability Scanner (ProbeX).

Format temuan wajib (disimpan sebagai JSON dan ditampilkan di UI):

{
  "id": "",
  "type": "idor|injection|ssrf|auth_session|xss|misconfig|data_exposure|business_logic",
  "severity": "Tinggi|Sedang|Bervariasi",
  "confidence": "Tinggi|Sedang|Rendah",
  "title": "",
  "description": "",
  "location": {
    "url": "",
    "method": "",
    "parameter": "",
    "parameter_in": "query|body|header|cookie",
    "file": "",
    "line": 0,
    "snippet": ""
  },
  "evidence": "bukti singkat (rahasia disamarkan)",
  "recommendation": "langkah perbaikan (bahasa Indonesia)",
  "references": ["OWASP ...", "CWE-..."]
}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

TYPE_IDOR = "idor"
TYPE_INJECTION = "injection"
TYPE_SSRF = "ssrf"
TYPE_AUTH_SESSION = "auth_session"
TYPE_XSS = "xss"
TYPE_MISCONFIG = "misconfig"
TYPE_DATA_EXPOSURE = "data_exposure"
TYPE_BUSINESS_LOGIC = "business_logic"

ALL_TYPES = (
    TYPE_IDOR,
    TYPE_INJECTION,
    TYPE_SSRF,
    TYPE_AUTH_SESSION,
    TYPE_XSS,
    TYPE_MISCONFIG,
    TYPE_DATA_EXPOSURE,
    TYPE_BUSINESS_LOGIC,
)

SEVERITY_HIGH = "Tinggi"
SEVERITY_MEDIUM = "Sedang"
SEVERITY_VARIES = "Bervariasi"

CONF_HIGH = "Tinggi"
CONF_MEDIUM = "Sedang"
CONF_LOW = "Rendah"

PARAM_IN_QUERY = "query"
PARAM_IN_BODY = "body"
PARAM_IN_HEADER = "header"
PARAM_IN_COOKIE = "cookie"

SEVERITY_LEGACY = {
    SEVERITY_HIGH: "high",
    SEVERITY_MEDIUM: "medium",
    SEVERITY_VARIES: "medium",
}

# Pola nilai rahasia yang WAJIB disamarkan di laporan (API key, token,
# password, NIK, dst.). Kunci dipertahankan, nilainya diganti [REDACTED].
_SECRET_KV = re.compile(
    r"([A-Za-z0-9_-]*?(?:api[_-]?key|secret|token|password|passwd|nik)[A-Za-z0-9_-]*)\s*[:=]\s*\S+",
    re.I,
)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{24,}\b")


def mask_secret(text: str) -> str:
    """Samarkan nilai rahasia dalam teks sebelum dilaporkan/dicetak."""
    if not text:
        return text
    text = _SECRET_KV.sub(lambda m: m.group(1) + "= [REDACTED]", text)
    text = _LONG_TOKEN.sub(" [REDACTED]", text)
    return text


@dataclass
class Location:
    url: str = ""
    method: str = ""
    parameter: str = ""
    parameter_in: str = ""
    file: str = ""
    line: int = 0
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "parameter_in": self.parameter_in,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass
class Finding:
    id: str = ""
    type: str = ""
    severity: str = SEVERITY_MEDIUM
    confidence: str = CONF_MEDIUM
    title: str = ""
    description: str = ""
    location: Location = field(default_factory=Location)
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "location": self.location.to_dict(),
            "evidence": mask_secret(self.evidence),
            "recommendation": self.recommendation,
            "references": list(self.references),
        }
